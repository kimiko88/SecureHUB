#![no_main]
use libfuzzer_sys::fuzz_target;
use secureusb_rs::vault::SecureVault;
use tempfile::tempdir;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let seek_seed = u16::from_le_bytes([data[0], data[1]]) as u64;
    let len_seed = u16::from_le_bytes([data[2], data[3]]) as usize;
    let payload = &data[4..];

    let Ok(dir) = tempdir() else { return };
    let Ok(vault) = SecureVault::init_or_open(dir.path(), "FuzzPass", true) else { return };

    if vault.write_file("/f.bin", payload).is_ok() {
        let dec = vault.read_file("/f.bin").expect("Decifratura round-trip fallita");
        assert_eq!(payload, dec.as_slice());

        if !payload.is_empty() {
            let mut seeker = vault.open_read_seeker("/f.bin").unwrap();
            let off = seek_seed % (payload.len() as u64);
            let max_len = (payload.len() - (off as usize)).min(len_seed.max(1));
            let mut buf = vec![0u8; max_len];
            let n = seeker.read_at(&mut buf, off).unwrap();
            assert_eq!(&buf[..n], &payload[(off as usize)..(off as usize) + n]);
        }
    }
});
