use proptest::prelude::*;
use rand::RngCore;
use secureusb_rs::vault::{SecureVault, CHUNK_SIZE, HEADER_SIZE};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use tempfile::tempdir;

// ============================================================================
// 1. INTEGRATION TEST: Pipeline Multi-Core Rayon + Bit-Flip & Troncamento
// ============================================================================

#[test]
fn test_rayon_parallel_multichunk_and_tamper_integration() {
    let dir = tempdir().unwrap();
    let vault = SecureVault::init_or_open(dir.path(), "Rust-Master-Key-2026!", true).unwrap();

    let size = 2 * CHUNK_SIZE + (CHUNK_SIZE / 3);
    let mut payload = vec![0u8; size];
    for i in 0..(size / 2) {
        payload[i] = (i % 251) as u8;
    }
    rand::thread_rng().fill_bytes(&mut payload[size / 2..]);

    vault.write_file("/video/4k_sample.bin", &payload).unwrap();

    let stat = vault.stat("/video/4k_sample.bin").unwrap();
    assert_eq!(stat.chunk_sizes.len(), 3);

    let decrypted = vault.read_file("/video/4k_sample.bin").unwrap();
    assert_eq!(payload, decrypted);

    let blob_path = dir
        .path()
        .join(".secure_vault")
        .join("blocks")
        .join(&stat.blob_id);
    let raw_disk = fs::read(&blob_path).unwrap();

    let mut corrupted = raw_disk.clone();
    corrupted[HEADER_SIZE + 32] ^= 0xFF;
    fs::write(&blob_path, &corrupted).unwrap();
    assert!(
        vault.read_file("/video/4k_sample.bin").is_err(),
        "Poly1305 deve bloccare qualsiasi bit-flip"
    );

    let first_chunk_end = HEADER_SIZE + 4 + (stat.chunk_sizes[0] as usize);
    fs::write(&blob_path, &raw_disk[..first_chunk_end]).unwrap();
    assert!(
        vault.read_file("/video/4k_sample.bin").is_err(),
        "Il motore deve rilevare il troncamento prematuro (EOF mancante)"
    );
}

// ============================================================================
// 2. INTEGRATION TEST: import_dir & export_dir Ricorsivi + Esclusione Junk Files
// ============================================================================

#[test]
fn test_import_and_export_dir_recursive_with_junk_filter_integration() {
    let vault_dir = tempdir().unwrap();
    let src_parent = tempdir().unwrap();
    let export_parent = tempdir().unwrap();

    let project_root = src_parent.path().join("WorkspaceSicuro");
    let sub_src = project_root.join("src").join("crypto");
    let sub_docs = project_root.join("docs");
    let junk_folder = project_root.join(".Trashes");

    fs::create_dir_all(&sub_src).unwrap();
    fs::create_dir_all(&sub_docs).unwrap();
    fs::create_dir_all(&junk_folder).unwrap();

    // 3 file validi
    let f1_content = b"# Workspace Sicuro Rust\n".repeat(100);
    let f2_content = b"pub fn aead_simd() {}\n".repeat(2000);
    let f3_content = b"%PDF-1.7 documento riservato";

    fs::write(project_root.join("README.md"), &f1_content).unwrap();
    fs::write(sub_src.join("lib.rs"), &f2_content).unwrap();
    fs::write(sub_docs.join("architettura.pdf"), f3_content).unwrap();

    // File temporanei / spazzatura di sistema che DEVONO essere ignorati
    fs::write(project_root.join(".DS_Store"), b"macos junk").unwrap();
    fs::write(project_root.join("Thumbs.db"), b"windows junk").unwrap();
    fs::write(sub_src.join("desktop.ini"), b"ini junk").unwrap();
    fs::write(sub_src.join("._lib.rs"), b"appledouble junk").unwrap();
    fs::write(sub_docs.join("~$architettura.pdf"), b"office lock").unwrap();
    fs::write(sub_docs.join("temp_swap.tmp"), b"tmp file").unwrap();
    fs::write(junk_folder.join("deleted.bin"), b"trash content").unwrap();

    let vault = SecureVault::init_or_open(vault_dir.path(), "FolderKey2026!", true).unwrap();
    vault.create_dir("/Backup").unwrap();

    // 1. Importazione ricorsiva
    let imported_count = vault.import_dir(&project_root, "/Backup").unwrap();
    assert_eq!(imported_count, 3, "Devono essere importati solo i 3 file validi");

    // Verifica assenza dei file temporanei nell'indice
    for forbidden in [
        "/Backup/WorkspaceSicuro/.DS_Store",
        "/Backup/WorkspaceSicuro/Thumbs.db",
        "/Backup/WorkspaceSicuro/src/crypto/desktop.ini",
        "/Backup/WorkspaceSicuro/src/crypto/._lib.rs",
        "/Backup/WorkspaceSicuro/docs/~$architettura.pdf",
        "/Backup/WorkspaceSicuro/docs/temp_swap.tmp",
        "/Backup/WorkspaceSicuro/.Trashes/deleted.bin",
    ] {
        assert!(
            vault.stat(forbidden).is_none(),
            "Il file spazzatura {forbidden} non doveva essere importato"
        );
    }

    // 2. Esportazione ricorsiva
    let exported_count = vault
        .export_dir("/Backup/WorkspaceSicuro", export_parent.path())
        .unwrap();
    assert_eq!(exported_count, 3);

    // 3. Verifica byte-per-byte dei file esportati
    let exp_root = export_parent.path().join("WorkspaceSicuro");
    assert_eq!(fs::read(exp_root.join("README.md")).unwrap(), f1_content);
    assert_eq!(
        fs::read(exp_root.join("src").join("crypto").join("lib.rs")).unwrap(),
        f2_content
    );
    assert_eq!(
        fs::read(exp_root.join("docs").join("architettura.pdf")).unwrap(),
        f3_content
    );
}

// ============================================================================
// 3. END-TO-END (E2E) TEST: Ciclo completo + Seeker O(1) + HTTP 206 Range
// ============================================================================

#[test]
fn test_full_lifecycle_seeker_and_http_range_e2e() {
    let dir = tempdir().unwrap();
    let pass = "E2E-UltraSecret-Pass!";

    let v1 = SecureVault::init_or_open(dir.path(), pass, true).unwrap();
    v1.create_dir("/Cinema").unwrap();

    let mut movie = vec![0u8; 2 * CHUNK_SIZE + 512 * 1024];
    for (i, b) in movie.iter_mut().enumerate() {
        *b = ((i * 17) & 0xFF) as u8;
    }
    v1.write_file("/Cinema/matrix.mp4", &movie).unwrap();
    drop(v1);

    assert!(SecureVault::init_or_open(dir.path(), "PasswordErrata", false).is_err());

    let v2 = SecureVault::init_or_open(dir.path(), pass, false).unwrap();
    let mut seeker = v2.open_read_seeker("/Cinema/matrix.mp4").unwrap();

    let boundary = (CHUNK_SIZE - 256) as u64;
    seeker.seek(SeekFrom::Start(boundary)).unwrap();
    let mut window = vec![0u8; 1024];
    seeker.read_exact(&mut window).unwrap();
    assert_eq!(&window[..], &movie[boundary as usize..(boundary as usize) + 1024]);

    let stream_url = v2.get_stream_url("/Cinema/matrix.mp4").unwrap();
    let without_proto = stream_url.strip_prefix("http://").unwrap();
    let (host_port, req_path) = without_proto.split_once('/').unwrap();

    let mut tcp = TcpStream::connect(host_port).unwrap();
    let r_start = CHUNK_SIZE + 1024;
    let r_end = r_start + 2047;
    let http_req = format!(
        "GET /{req_path} HTTP/1.1\r\nHost: {host_port}\r\nRange: bytes={r_start}-{r_end}\r\nConnection: close\r\n\r\n"
    );
    tcp.write_all(http_req.as_bytes()).unwrap();

    let mut resp_bytes = Vec::new();
    tcp.read_to_end(&mut resp_bytes).unwrap();
    let resp_str = String::from_utf8_lossy(&resp_bytes);
    assert!(
        resp_str.starts_with("HTTP/1.1 206 Partial Content"),
        "Atteso HTTP 206, ricevuto: {}",
        resp_str.lines().next().unwrap_or("")
    );

    let body_pos = resp_bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert_eq!(&resp_bytes[body_pos..], &movie[r_start..=r_end]);
}

// ============================================================================
// 4. INTEGRATION TEST: Cambio Password Istantaneo (Key Wrapping) & Scrubbing Integrità
// ============================================================================

#[test]
fn test_change_password_and_verify_integrity_scrubbing() {
    let dir = tempdir().unwrap();
    let pass_a = "InitialPassword123!";
    let pass_b = "NewSecretPassword456!";

    let vault = SecureVault::init_or_open(dir.path(), pass_a, true).unwrap();
    let test_data = b"Dati crittografati con DEK a 256 bit".repeat(500);
    vault.write_file("/docs/segreto.txt", &test_data).unwrap();

    // 1. Verifica integrità iniziale
    let rep = vault.verify_integrity();
    assert_eq!(rep.files_checked, 1);
    assert_eq!(rep.chunks_verified, 1);
    assert!(rep.corrupted_files.is_empty());

    // 2. Cambio password con password vecchia errata deve fallire
    assert!(vault.change_password("WrongPassword!", pass_b).is_err());

    // 3. Cambio password valido (Key Wrapping istantaneo)
    vault.change_password(pass_a, pass_b).unwrap();
    drop(vault);

    // 4. Riapertura con vecchia password deve fallire
    assert!(SecureVault::init_or_open(dir.path(), pass_a, false).is_err());

    // 5. Riapertura con nuova password deve avere successo e leggere i dati intatti
    let vault_reopened = SecureVault::init_or_open(dir.path(), pass_b, false).unwrap();
    let read_back = vault_reopened.read_file("/docs/segreto.txt").unwrap();
    assert_eq!(read_back, test_data);

    // 6. Test manomissione e rilevamento scrubbing
    let stat = vault_reopened.stat("/docs/segreto.txt").unwrap();
    let blob_path = dir
        .path()
        .join(".secure_vault")
        .join("blocks")
        .join(&stat.blob_id);
    let mut raw_bytes = fs::read(&blob_path).unwrap();
    raw_bytes[HEADER_SIZE + 20] ^= 0xFF; // corruzione bit-flip nel ciphertext
    fs::write(&blob_path, &raw_bytes).unwrap();

    let rep_corrupted = vault_reopened.verify_integrity();
    assert_eq!(rep_corrupted.corrupted_files.len(), 1);
    assert!(rep_corrupted.corrupted_files[0].contains("/docs/segreto.txt"));
}

// ============================================================================
// 5. PROPERTY & FUZZ TESTING (Proptest: Round-Trip + Random-Access ReadAt)
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn fuzz_roundtrip_and_seeker_proptest(
        payload in proptest::collection::vec(any::<u8>(), 0..131072),
        seek_offset in 0u64..200000u64,
        read_len in 1usize..16384usize
    ) {
        let dir = tempdir().unwrap();
        let vault = SecureVault::init_or_open(dir.path(), "FuzzKey", true).unwrap();

        vault.write_file("/fuzz.bin", &payload).unwrap();
        let roundtrip = vault.read_file("/fuzz.bin").unwrap();
        prop_assert_eq!(&payload, &roundtrip);

        if !payload.is_empty() {
            let mut seeker = vault.open_read_seeker("/fuzz.bin").unwrap();
            let norm_off = seek_offset % (payload.len() as u64);
            let max_avail = payload.len() - (norm_off as usize);
            let req_len = read_len.min(max_avail);

            let mut buf = vec![0u8; req_len];
            let n = seeker.read_at(&mut buf, norm_off).unwrap();
            prop_assert_eq!(&buf[..n], &payload[(norm_off as usize)..(norm_off as usize) + n]);
        }
    }
}
