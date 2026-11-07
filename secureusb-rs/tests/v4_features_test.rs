use secureusb_rs::vault::SecureVault;
use std::fs;
use std::io::Cursor;
use tempfile::tempdir;

#[test]
fn test_v4_plausible_deniability_dual_vault_rust() {
    let dir = tempdir().unwrap();
    let primary_pass = "Primary-Cover-Pass-2026!";
    let shadow_pass = "Hidden-Stego-Pass-999!";

    let v_primary = SecureVault::init_or_open(dir.path(), primary_pass, true).unwrap();
    v_primary
        .write_file("/vacanze.txt", b"Foto al mare")
        .unwrap();
    v_primary.configure_shadow_vault(shadow_pass).unwrap();
    drop(v_primary);

    // Sblocco con Password Segreta -> monta index.shadow
    let v_shadow = SecureVault::init_or_open(dir.path(), shadow_pass, false).unwrap();
    assert!(v_shadow.is_shadow_session());
    assert!(v_shadow.stat("/vacanze.txt").is_none());
    v_shadow
        .write_file("/brevetto_segreto.txt", b"Formula chimica riservata")
        .unwrap();
    drop(v_shadow);

    // Riapertura con Password Primaria -> i dati dello Shadow Vault sono invisibili
    let v_check = SecureVault::init_or_open(dir.path(), primary_pass, false).unwrap();
    assert!(!v_check.is_shadow_session());
    assert!(v_check.stat("/brevetto_segreto.txt").is_none());
    assert!(v_check.stat("/vacanze.txt").is_some());
}

#[test]
fn test_v4_blake3_content_addressed_deduplication_rust() {
    let dir = tempdir().unwrap();
    let v = SecureVault::init_or_open(dir.path(), "Blake3DedupKey!", true).unwrap();

    // 5 MB (2 chunk)
    let data = b"BloccoMacchinaVirtualeRipetuto_32B".repeat((5 * 1024 * 1024) / 34 + 1);
    let hits1 = v
        .write_stream_dedup("/vm/base.img", Cursor::new(&data))
        .unwrap();
    assert_eq!(hits1, 0);

    let hits2 = v
        .write_stream_dedup("/vm/clone.img", Cursor::new(&data))
        .unwrap();
    assert_eq!(hits2, 2, "Entrambi i chunk devono risultare deduplicati");

    let stat_clone = v.stat("/vm/clone.img").unwrap();
    assert_eq!(stat_clone.disk_size, 0, "Zero byte aggiuntivi scritti su disco");

    let read_back = v.read_dedup_file("/vm/clone.img").unwrap();
    assert_eq!(read_back, data);
}

#[test]
fn test_v4_reed_solomon_bitrot_auto_repair_rust() {
    let dir = tempdir().unwrap();
    let pass = "ReedSolomonRustKey!";

    let v = SecureVault::init_or_open(dir.path(), pass, true).unwrap();
    v.write_file("/contratto.txt", b"Protetto da Reed-Solomon GF(256)")
        .unwrap();
    drop(v);

    // Danneggia il 20% dei byte di index.meta simulando bit-rot sulla memoria NAND
    let idx_path = dir.path().join(".secure_vault").join("index.meta");
    let mut raw = fs::read(&idx_path).unwrap();
    let corrupt_len = raw.len() / 5;
    for b in &mut raw[8..8 + corrupt_len] {
        *b ^= 0xFF;
    }
    fs::write(&idx_path, &raw).unwrap();

    // All'apertura, verify_and_heal_with_ecc ripara index.meta prima di Poly1305!
    let v_healed = SecureVault::init_or_open(dir.path(), pass, false)
        .expect("Reed-Solomon ECC avrebbe dovuto riparare automaticamente index.meta");
    let plain = v_healed.read_file("/contratto.txt").unwrap();
    assert_eq!(plain, b"Protetto da Reed-Solomon GF(256)");
}
