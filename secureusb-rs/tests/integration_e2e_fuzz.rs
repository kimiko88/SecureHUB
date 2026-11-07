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

    // 9.5 MB (attraversa 3 chunk da 4 MB)
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

    // Verifica rilevamento manomissione (Bit-Flip sul primo chunk)
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

    // Verifica rilevamento troncamento (rimozione ultimo chunk con flag EOF)
    let first_chunk_end = HEADER_SIZE + 4 + (stat.chunk_sizes[0] as usize);
    fs::write(&blob_path, &raw_disk[..first_chunk_end]).unwrap();
    assert!(
        vault.read_file("/video/4k_sample.bin").is_err(),
        "Il motore deve rilevare il troncamento prematuro (EOF mancante)"
    );
}

// ============================================================================
// 2. END-TO-END (E2E) TEST: Ciclo completo + Seeker O(1) + HTTP 206 Range
// ============================================================================

#[test]
fn test_full_lifecycle_seeker_and_http_range_e2e() {
    let dir = tempdir().unwrap();
    let pass = "E2E-UltraSecret-Pass!";

    let v1 = SecureVault::init_or_open(dir.path(), pass, true).unwrap();
    v1.create_dir("/Cinema").unwrap();

    // 8.5 MB (3 chunk)
    let mut movie = vec![0u8; 2 * CHUNK_SIZE + 512 * 1024];
    for (i, b) in movie.iter_mut().enumerate() {
        *b = ((i * 17) & 0xFF) as u8;
    }
    v1.write_file("/Cinema/matrix.mp4", &movie).unwrap();
    drop(v1);

    // Password errata deve fallire
    assert!(SecureVault::init_or_open(dir.path(), "PasswordErrata", false).is_err());

    // Riapertura con password corretta
    let v2 = SecureVault::init_or_open(dir.path(), pass, false).unwrap();
    let mut seeker = v2.open_read_seeker("/Cinema/matrix.mp4").unwrap();

    // Seek esattamente a cavallo del confine dei 4 MB tra chunk 0 e chunk 1
    let boundary = (CHUNK_SIZE - 256) as u64;
    seeker.seek(SeekFrom::Start(boundary)).unwrap();
    let mut window = vec![0u8; 1024];
    seeker.read_exact(&mut window).unwrap();
    assert_eq!(&window[..], &movie[boundary as usize..(boundary as usize) + 1024]);

    // Test Server HTTP di Streaming con header Range
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
// 3. PROPERTY & FUZZ TESTING (Proptest: Round-Trip + Random-Access ReadAt)
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
