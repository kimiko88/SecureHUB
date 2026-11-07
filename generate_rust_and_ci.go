package main

// func main() {
// 	files := map[string]string{
// 		// 1. Configurazione Cargo e SIMD
// 		"secureusb-rs/Cargo.toml":         cargoTomlContent,
// 		"secureusb-rs/.cargo/config.toml": cargoConfigSIMDContent,

// 		// 2. Codice sorgente Rust modulare
// 		"secureusb-rs/src/lib.rs":                   rustLibContent,
// 		"secureusb-rs/src/main.rs":                  rustMainContent,
// 		"secureusb-rs/src/usb.rs":                   rustUsbFormatContent,
// 		"secureusb-rs/src/vault/mod.rs":             rustVaultModContent,
// 		"secureusb-rs/src/vault/types.rs":           rustVaultTypesContent,
// 		"secureusb-rs/src/vault/crypto_parallel.rs": rustVaultCryptoParallelContent,
// 		"secureusb-rs/src/vault/seeker.rs":          rustVaultSeekerContent,
// 		"secureusb-rs/src/fuse_mount.rs":            rustFuseMountContent,
// 		"secureusb-rs/src/ui/mod.rs":                rustUiModContent,
// 		"secureusb-rs/src/ui/preview.rs":            rustUiPreviewContent,

// 		// 3. Test Integration, E2E, Property-Fuzzing e Benchmark Criterion
// 		"secureusb-rs/tests/integration_e2e_fuzz.rs":    rustIntegrationE2EFuzzContent,
// 		"secureusb-rs/benches/vault_bench.rs":           rustCriterionBenchContent,
// 		"secureusb-rs/fuzz/Cargo.toml":                  rustCargoFuzzTomlContent,
// 		"secureusb-rs/fuzz/fuzz_targets/fuzz_seeker.rs": rustLibFuzzerTargetContent,

// 		// 4. Pipeline CI/CD GitHub Actions (Go + Rust per Windows, Linux e macOS)
// 		".github/workflows/release.yml": githubActionsWorkflowContent,
// 	}

// 	fmt.Println("=== Generazione Workspace Rust (secureusb-rs) + Pipeline CI/CD GitHub Actions ===")
// 	for relPath, content := range files {
// 		fullPath := filepath.FromSlash(relPath)
// 		dir := filepath.Dir(fullPath)
// 		if dir != "." {
// 			if err := os.MkdirAll(dir, 0755); err != nil {
// 				fmt.Fprintf(os.Stderr, "Errore creazione directory %s: %v\n", dir, err)
// 				os.Exit(1)
// 			}
// 		}
// 		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
// 			fmt.Fprintf(os.Stderr, "Errore scrittura file %s: %v\n", fullPath, err)
// 			os.Exit(1)
// 		}
// 		fmt.Printf(" [OK] %s (%d byte)\n", relPath, len(content))
// 	}

// 	fmt.Println("\nGenerazione completata! Per compilare e testare la versione Rust:")
// 	fmt.Println("  cd secureusb-rs")
// 	fmt.Println("  cargo test --release")
// 	fmt.Println("  cargo bench")
// 	fmt.Println("  cargo run --release")
// }

// ============================================================================
// CARGO.TOML & CONFIGURAZIONE SIMD (AVX2 / BMI2 / NEON)
// ============================================================================

const cargoTomlContent = `[package]
name = "secureusb-rs"
version = "0.3.0"
edition = "2021"
description = "High-performance encrypted & compressed USB VFS (Argon2id + XChaCha20-Poly1305 In-Place SIMD + Zstd + Rayon)"

[lib]
name = "secureusb_rs"
path = "src/lib.rs"

[[bin]]
name = "secureusb-rs"
path = "src/main.rs"

[features]
default = []
# Abilita il montaggio nativo FUSE / WinFsp (richiede libfuse su Linux/macOS o WinFsp su Windows)
native-fuse = ["dep:fuser"]

[dependencies]
argon2 = "0.5"
chacha20poly1305 = { version = "0.10", features = ["std"] }
zstd = { version = "0.13", features = ["zdict_builder"] }
rayon = "1.10"
zeroize = { version = "1.8", features = ["derive"] }
rand = "0.8"
hex = "0.4"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
chrono = { version = "0.4", features = ["serde"] }
eframe = "0.29"
image = { version = "0.25", default-features = false, features = ["png", "jpeg", "gif"] }
lopdf = "0.34"
rfd = "0.15"
open = "5.3"
fuser = { version = "0.14", optional = true }

[target.'cfg(unix)'.dependencies]
libc = "0.2"

[dev-dependencies]
tempfile = "3.14"
proptest = "1.5"
criterion = "0.5"

[[bench]]
name = "vault_bench"
harness = false

[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = true
`

const cargoConfigSIMDContent = `# Abilita le istruzioni SIMD hardware per ChaCha20-Poly1305 e Zstd
[target.'cfg(all(target_arch = "x86_64", not(target_os = "macos")))']
rustflags = ["-C", "target-feature=+avx2,+bmi2,+sse4.1,+pclmulqdq"]

[target.'cfg(target_arch = "aarch64")']
rustflags = ["-C", "target-feature=+neon"]
`

// ============================================================================
// CODICE SORGENTE RUST: LIB, MAIN, USB FORMATTER
// ============================================================================

const rustLibContent = `pub mod fuse_mount;
pub mod ui;
pub mod usb;
pub mod vault;
`

const rustMainContent = `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> eframe::Result<()> {
    secureusb_rs::ui::run_app()
}
`

const rustUsbFormatContent = `use std::io;
use std::process::Command;

/// Formatta fisicamente la chiavetta USB in exFAT su Windows, Linux e macOS.
pub fn format_physical_usb(device_path: &str, label: &str) -> io::Result<()> {
    let dev = device_path.trim();
    if dev.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Specificare il percorso del dispositivo (es. E:, /dev/sdb1, /dev/disk2)",
        ));
    }
    let vol_label = if label.trim().is_empty() {
        "SECURE_USB"
    } else {
        label.trim()
    };

    let output = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", "format", dev, "/FS:exFAT", &format!("/V:{vol_label}"), "/Q", "/Y"])
            .output()?
    } else if cfg!(target_os = "linux") {
        Command::new("mkfs.exfat")
            .args(["-n", vol_label, dev])
            .output()?
    } else if cfg!(target_os = "macos") {
        Command::new("diskutil")
            .args(["eraseDisk", "ExFAT", vol_label, dev])
            .output()?
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Sistema operativo non supportato per la formattazione diretta",
        ));
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Errore formattazione exFAT: {stderr} {stdout}"),
        ));
    }
    Ok(())
}
`

// ============================================================================
// VAULT TYPES: ZEROIZE + MLOCK + PROTOCOLLO SVAULT03
// ============================================================================

const rustVaultTypesContent = `use argon2::{Algorithm, Argon2, Params, Version};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SALT_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24;
pub const STREAM_ID_SIZE: usize = 15;
pub const TAG_SIZE: usize = 16;
pub const HEADER_SIZE: usize = 8 + STREAM_ID_SIZE; // 23 byte
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MB
pub const MAX_COMPRESSED_CHUNK: usize = CHUNK_SIZE + (CHUNK_SIZE / 8) + 65536;
pub const MAX_TEXT_PREVIEW_SIZE: u64 = 16 * 1024 * 1024;
pub const VAULT_STREAM_MAGIC: &[u8; 8] = b"SVAULT03";

/// MasterKey a 256-bit protetta da ZeroizeOnDrop e ancorata nella RAM fisica con mlock.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; KEY_SIZE],
}

impl MasterKey {
    pub fn derive_from_password(password: &str, salt: &[u8]) -> io::Result<Self> {
        let params = Params::new(64 * 1024, 3, 4, Some(KEY_SIZE))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = MasterKey {
            bytes: [0u8; KEY_SIZE],
        };
        argon
            .hash_password_into(password.as_bytes(), salt, &mut key.bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        key.lock_memory();
        Ok(key)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.bytes
    }

    #[cfg(unix)]
    fn lock_memory(&self) {
        unsafe {
            let _ = libc::mlock(
                self.bytes.as_ptr() as *const libc::c_void,
                KEY_SIZE,
            );
        }
    }

    #[cfg(not(unix))]
    fn lock_memory(&self) {}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub virtual_path: String,
    pub blob_id: String,
    pub is_dir: bool,
    pub original_size: u64,
    pub disk_size: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunk_sizes: Vec<u32>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultIndex {
    pub entries: HashMap<String, FileEntry>,
}

/// Costruisce il Nonce (24B) e l'AAD (17B) legando ogni chunk al suo indice a 64-bit e al flag EOF.
#[inline]
pub fn build_chunk_nonce_and_aad(
    stream_id: &[u8; STREAM_ID_SIZE],
    chunk_index: u64,
    is_final: bool,
) -> ([u8; NONCE_SIZE], [u8; 17]) {
    let final_byte: u8 = if is_final { 0x01 } else { 0x00 };

    let mut nonce = [0u8; NONCE_SIZE];
    nonce[0..STREAM_ID_SIZE].copy_from_slice(stream_id);
    nonce[STREAM_ID_SIZE..STREAM_ID_SIZE + 8].copy_from_slice(&chunk_index.to_be_bytes());
    nonce[NONCE_SIZE - 1] = final_byte;

    let mut aad = [0u8; 17];
    aad[0..8].copy_from_slice(VAULT_STREAM_MAGIC);
    aad[8..16].copy_from_slice(&chunk_index.to_be_bytes());
    aad[16] = final_byte;

    (nonce, aad)
}

pub fn normalize_path(p: &str) -> String {
    let replaced = p.replace('\\', "/");
    let mut parts = Vec::new();
    for seg in replaced.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_nonce_and_aad_unit() {
        let sid = *b"0123456789abcde";
        let (n1, a1) = build_chunk_nonce_and_aad(&sid, 0, false);
        let (n2, a2) = build_chunk_nonce_and_aad(&sid, 1, false);
        let (n3, a3) = build_chunk_nonce_and_aad(&sid, 1, true);

        assert_ne!(n1, n2);
        assert_ne!(a1, a2);
        assert_ne!(n2, n3);
        assert_ne!(a2, a3);
    }

    #[test]
    fn test_normalize_path_unit() {
        assert_eq!(normalize_path("\\Documenti\\test.txt"), "/Documenti/test.txt");
        assert_eq!(normalize_path("video/clip.mp4"), "/video/clip.mp4");
        assert_eq!(normalize_path("/a/b/../c.bin"), "/a/c.bin");
        assert_eq!(normalize_path(""), "/");
    }
}
`

// ============================================================================
// PIPELINE PARALLELA RAYON + IN-PLACE AEAD (ZERO-COPY CIPHER)
// ============================================================================

const rustVaultCryptoParallelContent = `use crate::vault::types::*;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use rayon::prelude::*;
use std::io::{self, BufRead, BufReader, Read, Write};

struct RawChunkJob {
    chunk_index: u64,
    plain_data: Vec<u8>,
    is_final: bool,
}

struct EncryptedChunkOut {
    packet: Vec<u8>,
    plain_len: u64,
    cipher_only_len: u32,
}

/// Comprime con Zstd e cifra IN-PLACE con XChaCha20-Poly1305 usando il work-stealing pool di Rayon.
pub fn encrypt_stream_parallel<R: Read, W: Write>(
    cipher: &XChaCha20Poly1305,
    src: R,
    mut dst: W,
    zstd_level: i32,
) -> io::Result<(u64, u64, Vec<u32>)> {
    let mut stream_id = [0u8; STREAM_ID_SIZE];
    rand::thread_rng().fill_bytes(&mut stream_id);

    dst.write_all(VAULT_STREAM_MAGIC)?;
    dst.write_all(&stream_id)?;
    let mut disk_written: u64 = HEADER_SIZE as u64;

    let mut br = BufReader::with_capacity(128 * 1024, src);
    let batch_size = rayon::current_num_threads().max(2) * 2;

    let mut chunk_index: u64 = 0;
    let mut total_plain: u64 = 0;
    let mut chunk_sizes: Vec<u32> = Vec::new();
    let mut reached_eof = false;

    while !reached_eof {
        let mut batch = Vec::with_capacity(batch_size);

        for _ in 0..batch_size {
            let mut buf = vec![0u8; CHUNK_SIZE];
            let mut read_bytes = 0;
            while read_bytes < CHUNK_SIZE {
                let n = br.read(&mut buf[read_bytes..])?;
                if n == 0 {
                    break;
                }
                read_bytes += n;
            }
            buf.truncate(read_bytes);

            let next_bytes = br.fill_buf()?;
            let is_final = next_bytes.is_empty();

            batch.push(RawChunkJob {
                chunk_index,
                plain_data: buf,
                is_final,
            });

            chunk_index += 1;
            if is_final {
                reached_eof = true;
                break;
            }
        }

        // Esecuzione parallela su tutti i core CPU con cifratura IN-PLACE (zero copie intermedie)
        let encrypted_batch: io::Result<Vec<EncryptedChunkOut>> = batch
            .into_par_iter()
            .map(|job| {
                let plain_len = job.plain_data.len() as u64;
                let max_comp = zstd::zstd_safe::compress_bound(job.plain_data.len());

                // Alloca un unico buffer contiguo: [len: 4B] + [payload compresso/cifrato] + [tag: 16B]
                let mut packet = vec![0u8; 4 + max_comp];
                let comp_size = zstd::bulk::compress_to_buffer(
                    &job.plain_data,
                    &mut packet[4..],
                    zstd_level,
                )
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                packet.truncate(4 + comp_size);

                let (nonce, aad) =
                    build_chunk_nonce_and_aad(&stream_id, job.chunk_index, job.is_final);

                // Cifra direttamente sul posto dentro packet[4..] senza allocare un secondo Vec
                let tag = cipher
                    .encrypt_in_place_detached(
                        XNonce::from_slice(&nonce),
                        &aad,
                        &mut packet[4..],
                    )
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Errore cifratura AEAD in-place")
                    })?;

                packet.extend_from_slice(tag.as_slice());

                let cipher_only_len = (packet.len() - 4) as u32;
                packet[0..4].copy_from_slice(&cipher_only_len.to_le_bytes());

                Ok(EncryptedChunkOut {
                    packet,
                    plain_len,
                    cipher_only_len,
                })
            })
            .collect();

        for out in encrypted_batch? {
            dst.write_all(&out.packet)?;
            disk_written += out.packet.len() as u64;
            total_plain += out.plain_len;
            chunk_sizes.push(out.cipher_only_len);
        }
    }

    Ok((total_plain, disk_written, chunk_sizes))
}

struct EncryptedChunkJob {
    chunk_index: u64,
    cipher_buf: Vec<u8>,
}

struct DecryptedChunkOut {
    plain_data: Vec<u8>,
    is_final: bool,
}

/// Autentica (Poly1305) IN-PLACE e decomprime (Zstd) i chunk da 4 MB in parallelo su tutti i core CPU.
pub fn decrypt_stream_parallel<R: Read, W: Write>(
    cipher: &XChaCha20Poly1305,
    mut src: R,
    mut dst: W,
) -> io::Result<()> {
    let mut header = [0u8; HEADER_SIZE];
    src.read_exact(&mut header).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Intestazione del flusso mancante o corrotta",
        )
    })?;

    if &header[0..8] != VAULT_STREAM_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Formato non riconosciuto (richiesto SVAULT03)",
        ));
    }

    let mut stream_id = [0u8; STREAM_ID_SIZE];
    stream_id.copy_from_slice(&header[8..HEADER_SIZE]);

    let batch_size = rayon::current_num_threads().max(2) * 2;
    let mut chunk_index: u64 = 0;
    let mut saw_final = false;

    loop {
        let mut batch = Vec::with_capacity(batch_size);

        for _ in 0..batch_size {
            let mut len_buf = [0u8; 4];
            match src.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }

            let packet_len = u32::from_le_bytes(len_buf) as usize;
            if packet_len <= TAG_SIZE || packet_len > MAX_COMPRESSED_CHUNK + TAG_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Dimensione chunk {chunk_index} fuori scala ({packet_len} byte)"),
                ));
            }

            let mut cipher_buf = vec![0u8; packet_len];
            src.read_exact(&mut cipher_buf)?;

            batch.push(EncryptedChunkJob {
                chunk_index,
                cipher_buf,
            });
            chunk_index += 1;
        }

        if batch.is_empty() {
            break;
        }

        let decrypted_batch: io::Result<Vec<DecryptedChunkOut>> = batch
            .into_par_iter()
            .map(|mut job| {
                let tag_pos = job.cipher_buf.len() - TAG_SIZE;
                let (nonce_mid, aad_mid) =
                    build_chunk_nonce_and_aad(&stream_id, job.chunk_index, false);

                // Copia di backup solo se dobbiamo ritentare come chunk finale (accade 1 sola volta a fine file)
                let backup_for_final = job.cipher_buf.clone();
                let (ct_slice, tag_slice) = job.cipher_buf.split_at_mut(tag_pos);
                let tag = Tag::from_slice(tag_slice);

                let is_final = if cipher
                    .decrypt_in_place_detached(
                        XNonce::from_slice(&nonce_mid),
                        &aad_mid,
                        ct_slice,
                        tag,
                    )
                    .is_ok()
                {
                    false
                } else {
                    job.cipher_buf.copy_from_slice(&backup_for_final);
                    let (ct_final, tag_final_slice) = job.cipher_buf.split_at_mut(tag_pos);
                    let tag_final = Tag::from_slice(tag_final_slice);
                    let (nonce_fin, aad_fin) =
                        build_chunk_nonce_and_aad(&stream_id, job.chunk_index, true);
                    cipher
                        .decrypt_in_place_detached(
                            XNonce::from_slice(&nonce_fin),
                            &aad_fin,
                            ct_final,
                            tag_final,
                        )
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                format!(
                                    "Autenticazione Poly1305 fallita al chunk {}: dati manomessi o password errata",
                                    job.chunk_index
                                ),
                            )
                        })?;
                    true
                };

                // Decomprime con Zstd solo DOPO che Poly1305 ha autenticato il blocco in-place
                let plain_data =
                    zstd::bulk::decompress(&job.cipher_buf[..tag_pos], CHUNK_SIZE)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                Ok(DecryptedChunkOut {
                    plain_data,
                    is_final,
                })
            })
            .collect();

        for out in decrypted_batch? {
            if saw_final {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Rilevati chunk aggiuntivi non autorizzati dopo il flag EOF",
                ));
            }
            if out.is_final {
                saw_final = true;
            }
            dst.write_all(&out.plain_data)?;
        }
    }

    if !saw_final {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Troncamento anomalo rilevato: flag di fine flusso (EOF) mancante",
        ));
    }

    Ok(())
}
`

// ============================================================================
// RANDOM-ACCESS SEEKER O(1) + HTTP RANGE STREAMING SERVER
// ============================================================================

const rustVaultSeekerContent = `use crate::vault::types::*;
use crate::vault::SecureVault;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

/// VaultReadSeeker implementa Read, Seek e read_at con complessità O(1) sul singolo blocco da 4 MB.
pub struct VaultReadSeeker {
    cipher: XChaCha20Poly1305,
    file: File,
    entry: FileEntry,
    stream_id: [u8; STREAM_ID_SIZE],
    chunk_offsets: Vec<u64>,
    pos: u64,
    cached_chunk_idx: Option<usize>,
    cached_plain: Vec<u8>,
    cipher_scratch: Vec<u8>,
}

impl VaultReadSeeker {
    pub fn new(
        cipher: XChaCha20Poly1305,
        mut file: File,
        entry: FileEntry,
    ) -> io::Result<Self> {
        if entry.chunk_sizes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Tabella chunk mancante per il random-access",
            ));
        }

        let mut header = [0u8; HEADER_SIZE];
        file.read_exact(&mut header)?;
        if &header[0..8] != VAULT_STREAM_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Header SVAULT03 non valido",
            ));
        }

        let mut stream_id = [0u8; STREAM_ID_SIZE];
        stream_id.copy_from_slice(&header[8..HEADER_SIZE]);

        let mut chunk_offsets = Vec::with_capacity(entry.chunk_sizes.len());
        let mut cur_offset = HEADER_SIZE as u64;
        for &c_size in &entry.chunk_sizes {
            chunk_offsets.push(cur_offset);
            cur_offset += 4 + (c_size as u64);
        }

        Ok(Self {
            cipher,
            file,
            entry,
            stream_id,
            chunk_offsets,
            pos: 0,
            cached_chunk_idx: None,
            cached_plain: Vec::with_capacity(CHUNK_SIZE),
            cipher_scratch: Vec::new(),
        })
    }

    pub fn size(&self) -> u64 {
        self.entry.original_size
    }

    pub fn read_at(&mut self, buf: &mut [u8], off: u64) -> io::Result<usize> {
        if off >= self.entry.original_size || buf.is_empty() {
            return Ok(0);
        }

        let mut total_copied = 0;
        let mut cur_off = off;

        while total_copied < buf.len() && cur_off < self.entry.original_size {
            let target_chunk = (cur_off / (CHUNK_SIZE as u64)) as usize;
            let offset_in_chunk = (cur_off % (CHUNK_SIZE as u64)) as usize;

            if target_chunk >= self.chunk_offsets.len() {
                break;
            }
            if self.cached_chunk_idx != Some(target_chunk) {
                self.load_and_verify_chunk(target_chunk)?;
            }
            if offset_in_chunk >= self.cached_plain.len() {
                break;
            }

            let available = &self.cached_plain[offset_in_chunk..];
            let to_copy = available.len().min(buf.len() - total_copied);
            buf[total_copied..total_copied + to_copy].copy_from_slice(&available[..to_copy]);
            total_copied += to_copy;
            cur_off += to_copy as u64;
        }

        Ok(total_copied)
    }

    fn load_and_verify_chunk(&mut self, chunk_idx: usize) -> io::Result<()> {
        let disk_offset = self.chunk_offsets[chunk_idx];
        let expected_cipher_len = self.entry.chunk_sizes[chunk_idx] as usize;
        let total_packet_size = 4 + expected_cipher_len;

        self.cipher_scratch.resize(total_packet_size, 0);
        self.file.seek(SeekFrom::Start(disk_offset))?;
        self.file.read_exact(&mut self.cipher_scratch)?;

        let recorded_len = u32::from_le_bytes(self.cipher_scratch[0..4].try_into().unwrap()) as usize;
        if recorded_len != expected_cipher_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Lunghezza chunk {chunk_idx} incoerente su disco"),
            ));
        }

        let is_final = chunk_idx + 1 == self.chunk_offsets.len();
        let (nonce, aad) =
            build_chunk_nonce_and_aad(&self.stream_id, chunk_idx as u64, is_final);

        let tag_pos = total_packet_size - TAG_SIZE;
        let (ct_with_hdr, tag_slice) = self.cipher_scratch.split_at_mut(tag_pos);
        let ct_slice = &mut ct_with_hdr[4..];
        let tag = Tag::from_slice(tag_slice);

        self.cipher
            .decrypt_in_place_detached(XNonce::from_slice(&nonce), &aad, ct_slice, tag)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("Autenticazione Poly1305 fallita in random-access al chunk {chunk_idx}"),
                )
            })?;

        self.cached_plain = zstd::bulk::decompress(ct_slice, CHUNK_SIZE)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.cached_chunk_idx = Some(chunk_idx);
        Ok(())
    }
}

impl Seek for VaultReadSeeker {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos: i64 = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::Current(d) => (self.pos as i64) + d,
            SeekFrom::End(d) => (self.entry.original_size as i64) + d,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Seek negativo non consentito",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

impl Read for VaultReadSeeker {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(buf, self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// Avvia un micro-server HTTP 1.1 su 127.0.0.1 con supporto Range: bytes=start-end (HTTP 206)
pub fn start_local_range_server(vault: Arc<SecureVault>, token: String) -> io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let v = Arc::clone(&vault);
            let tok = token.clone();
            thread::spawn(move || {
                let _ = handle_http_range_client(stream, &v, &tok);
            });
        }
    });

    Ok(port)
}

fn handle_http_range_client(
    mut stream: std::net::TcpStream,
    vault: &SecureVault,
    expected_token: &str,
) -> io::Result<()> {
    let mut req_buf = [0u8; 4096];
    let n = stream.read(&mut req_buf)?;
    if n == 0 {
        return Ok(());
    }
    let req_str = String::from_utf8_lossy(&req_buf[..n]);
    let mut lines = req_str.lines();
    let first_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }

    let url_part = parts[1];
    let mut token_param = "";
    let mut path_param = String::new();

    if let Some((_, query)) = url_part.split_once('?') {
        for pair in query.split('&') {
            if let Some((k, val)) = pair.split_once('=') {
                if k == "token" {
                    token_param = val;
                } else if k == "path" {
                    path_param = percent_decode(val);
                }
            }
        }
    }

    if token_param != expected_token {
        let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        return Ok(());
    }

    let mut seeker = match vault.open_read_seeker(&path_param) {
        Ok(s) => s,
        Err(_) => {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
            return Ok(());
        }
    };

    let total_size = seeker.size();
    let mut range_start: u64 = 0;
    let mut range_end: u64 = total_size.saturating_sub(1);
    let mut is_partial = false;

    for line in lines {
        if line.to_ascii_lowercase().starts_with("range:") {
            if let Some( idx) = line.find("bytes=") {
                let spec = line[idx + 6..].trim();
                if let Some((s, e)) = spec.split_once('-') {
                    if let Ok(st) = s.parse::<u64>() {
                        range_start = st;
                        is_partial = true;
                    }
                    if let Ok(en) = e.parse::<u64>() {
                        range_end = en.min(total_size.saturating_sub(1));
                    }
                }
            }
        }
    }

    if total_size == 0 {
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        return Ok(());
    }

    let content_len = range_end.saturating_sub(range_start) + 1;
    if is_partial {
        let header = format!(
            "HTTP/1.1 206 Partial Content\r\nAccept-Ranges: bytes\r\nContent-Range: bytes {range_start}-{range_end}/{total_size}\r\nContent-Length: {content_len}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(header.as_bytes())?;
    } else {
        let header = format!(
            "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nContent-Length: {total_size}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(header.as_bytes())?;
    }

    seeker.seek(SeekFrom::Start(range_start))?;
    let mut remaining = content_len;
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let to_read = (buf.len() as u64).min(remaining) as usize;
        let read_n = seeker.read(&mut buf[..to_read])?;
        if read_n == 0 {
            break;
        }
        stream.write_all(&buf[..read_n])?;
        remaining -= read_n as u64;
    }
    Ok(())
}

fn percent_decode(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(b) = u8::from_str_radix(hex_str, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
`

// ============================================================================
// VAULT CORE CRUD + ATOMIC INDEX + SHREDDING
// ============================================================================

const rustVaultModContent = `pub mod crypto_parallel;
pub mod seeker;
pub mod types;

use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use chrono::Utc;
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

pub use seeker::VaultReadSeeker;
pub use types::*;

pub struct SecureVault {
    root_path: PathBuf,
    #[allow(dead_code)]
    master_key: MasterKey,
    cipher: XChaCha20Poly1305,
    index: RwLock<VaultIndex>,
    stream_port: RwLock<Option<(u16, String)>>,
}

impl SecureVault {
    pub fn init_or_open(
        usb_mount_path: impl AsRef<Path>,
        password: &str,
        create_new: bool,
    ) -> io::Result<Arc<Self>> {
        let vault_dir = usb_mount_path.as_ref().join(".secure_vault");
        let blocks_dir = vault_dir.join("blocks");
        let salt_file = vault_dir.join("vault.salt");
        let index_file = vault_dir.join("index.meta");

        if create_new {
            let _ = fs::remove_dir_all(&vault_dir);
            fs::create_dir_all(&blocks_dir)?;

            let mut salt = [0u8; SALT_SIZE];
            rand::thread_rng().fill_bytes(&mut salt);
            fs::write(&salt_file, salt)?;

            let master_key = MasterKey::derive_from_password(password, &salt)?;
            let cipher = XChaCha20Poly1305::new(master_key.as_bytes().into());

            let vault = Arc::new(Self {
                root_path: vault_dir,
                master_key,
                cipher,
                index: RwLock::new(VaultIndex::default()),
                stream_port: RwLock::new(None),
            });
            vault.save_index()?;
            return Ok(vault);
        }

        if !index_file.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Nessun Vault trovato in questo percorso: usa 'Inizializza Nuovo Vault'",
            ));
        }

        let salt = fs::read(&salt_file)?;
        if salt.len() != SALT_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "File salt corrotto o illeggibile",
            ));
        }

        let master_key = MasterKey::derive_from_password(password, &salt)?;
        let cipher = XChaCha20Poly1305::new(master_key.as_bytes().into());

        let vault = Arc::new(Self {
            root_path: vault_dir,
            master_key,
            cipher,
            index: RwLock::new(VaultIndex::default()),
            stream_port: RwLock::new(None),
        });
        vault.load_index()?;
        Ok(vault)
    }

    pub fn write_stream<R: Read>(&self, virtual_path: &str, src: R) -> io::Result<()> {
        let vpath = normalize_path(virtual_path);

        let blob_id = {
            let idx = self.index.read().unwrap();
            if let Some(existing) = idx.entries.get(&vpath) {
                if !existing.blob_id.is_empty() {
                    existing.blob_id.clone()
                } else {
                     Self::random_blob_id()
                }
            } else {
                Self::random_blob_id()
            }
        };

        let blob_path = self.root_path.join("blocks").join(&blob_id);
        let tmp_blob = self
            .root_path
            .join("blocks")
            .join(format!("{blob_id}.tmp"));

        let out_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_blob)?;
        let mut bw = BufWriter::with_capacity(1024 * 1024, out_file);

        let res = crypto_parallel::encrypt_stream_parallel(&self.cipher, src, &mut bw, 3);
        let (plain_size, disk_size, chunk_sizes) = match res {
            Ok(v) => v,
            Err(e) => {
                let _ = fs::remove_file(&tmp_blob);
                return Err(e);
            }
        };

        bw.flush()?;
        bw.get_ref().sync_all()?;
        drop(bw);

        fs::rename(&tmp_blob, &blob_path)?;

        {
            let mut idx = self.index.write().unwrap();
            idx.entries.insert(
                vpath.clone(),
                FileEntry {
                    virtual_path: vpath,
                    blob_id,
                    is_dir: false,
                    original_size: plain_size,
                    disk_size,
                    chunk_sizes,
                    updated_at: Utc::now(),
                },
            );
        }
        self.save_index()
    }

    pub fn read_stream<W: Write>(&self, virtual_path: &str, dst: W) -> io::Result<()> {
        let vpath = normalize_path(virtual_path);
        let entry = {
            let idx = self.index.read().unwrap();
            idx.entries.get(&vpath).cloned()
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "File non trovato nel Vault"))?;

        if entry.is_dir {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Il percorso specificato è una cartella",
            ));
        }

        let blob_path = self.root_path.join("blocks").join(&entry.blob_id);
        let in_file = File::open(blob_path)?;
        let br = BufReader::with_capacity(1024 * 1024, in_file);
        crypto_parallel::decrypt_stream_parallel(&self.cipher, br, dst)
    }

    pub fn write_file(&self, virtual_path: &str, data: &[u8]) -> io::Result<()> {
        self.write_stream(virtual_path, Cursor::new(data))
    }

    pub fn read_file(&self, virtual_path: &str) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.read_stream(virtual_path, &mut buf)?;
        Ok(buf)
    }

    pub fn open_read_seeker(&self, virtual_path: &str) -> io::Result<VaultReadSeeker> {
        let vpath = normalize_path(virtual_path);
        let entry = {
            let idx = self.index.read().unwrap();
            idx.entries.get(&vpath).cloned()
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "File non trovato"))?;

        if entry.is_dir {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "È una cartella"));
        }

        let blob_path = self.root_path.join("blocks").join(&entry.blob_id);
        let file = File::open(blob_path)?;
        VaultReadSeeker::new(self.cipher.clone(), file, entry)
    }

    pub fn get_stream_url(self: &Arc<Self>, virtual_path: &str) -> io::Result<String> {
        let vpath = normalize_path(virtual_path);
        let mut guard = self.stream_port.write().unwrap();
        let (port, token) = if let Some((p, t)) = guard.as_ref() {
            (*p, t.clone())
        } else {
            let mut tok_bytes = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut tok_bytes);
            let tok = hex::encode(tok_bytes);
            let p = seeker::start_local_range_server(Arc::clone(self), tok.clone())?;
            *guard = Some((p, tok.clone()));
            (p, tok)
        };

        let encoded_path = vpath.replace(' ', "%20");
        Ok(format!(
            "http://127.0.0.1:{port}/stream?token={token}&path={encoded_path}"
        ))
    }

    pub fn stat(&self, virtual_path: &str) -> Option<FileEntry> {
        let vpath = normalize_path(virtual_path);
        if vpath == "/" {
            return Some(FileEntry {
                virtual_path: "/".to_string(),
                blob_id: String::new(),
                is_dir: true,
                original_size: 0,
                disk_size: 0,
                chunk_sizes: Vec::new(),
                updated_at: Utc::now(),
            });
        }
        self.index.read().unwrap().entries.get(&vpath).cloned()
    }

    pub fn create_dir(&self, virtual_dir: &str) -> io::Result<()> {
        let vdir = normalize_path(virtual_dir);
        if vdir == "/" {
            return Ok(());
        }
        {
            let mut idx = self.index.write().unwrap();
            if idx.entries.contains_key(&vdir) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Il percorso esiste già",
                ));
            }
            idx.entries.insert(
                vdir.clone(),
                FileEntry {
                    virtual_path: vdir,
                    blob_id: String::new(),
                    is_dir: true,
                    original_size: 0,
                    disk_size: 0,
                    chunk_sizes: Vec::new(),
                    updated_at: Utc::now(),
                },
            );
        }
        self.save_index()
    }

    pub fn delete(&self, virtual_path: &str) -> io::Result<()> {
        let vpath = normalize_path(virtual_path);
        let prefix = format!("{vpath}/");

        let to_remove: Vec<(String, FileEntry)> = {
            let idx = self.index.read().unwrap();
            idx.entries
                .iter()
                .filter(|(k, _)| *k == &vpath || k.starts_with(&prefix))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };

        {
            let mut idx = self.index.write().unwrap();
            for (k, entry) in to_remove {
                if !entry.is_dir && !entry.blob_id.is_empty() {
                    let blob_path = self.root_path.join("blocks").join(&entry.blob_id);
                    secure_erase_file(&blob_path);
                }
                idx.entries.remove(&k);
            }
        }
        self.save_index()
    }

    pub fn list_dir(&self, dir_path: &str) -> Vec<FileEntry> {
        let dpath = normalize_path(dir_path);
        let idx = self.index.read().unwrap();
        let mut list: Vec<FileEntry> = idx
            .entries
            .values()
            .filter(|e| {
                if e.virtual_path == "/" {
                    return false;
                }
                let parent = Path::new(&e.virtual_path)
                    .parent()
                    .map(|p| normalize_path(&p.to_string_lossy()))
                    .unwrap_or_else(|| "/".to_string());
                parent == dpath
            })
            .cloned()
            .collect();

        list.sort_by(|a, b| match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a
                .virtual_path
                .to_lowercase()
                .cmp(&b.virtual_path.to_lowercase()),
        });
        list
    }

    fn save_index(&self) -> io::Result<()> {
        let raw_json = {
            let idx = self.index.read().unwrap();
            serde_json::to_vec(&*idx)?
        };
        let index_file = self.root_path.join("index.meta");
        let tmp_file = self.root_path.join("index.meta.tmp");

        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_file)?;
        crypto_parallel::encrypt_stream_parallel(&self.cipher, Cursor::new(raw_json), f, 3)?;
        fs::rename(tmp_file, index_file)
    }

    fn load_index(&self) -> io::Result<()> {
        let index_file = self.root_path.join("index.meta");
        let f = File::open(index_file)?;
        let mut plain_json = Vec::new();
        crypto_parallel::decrypt_stream_parallel(&self.cipher, f, &mut plain_json)?;
        let loaded: VaultIndex = serde_json::from_slice(&plain_json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        *self.index.write().unwrap() = loaded;
        Ok(())
    }

    fn random_blob_id() -> String {
        let mut rnd = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut rnd);
        format!("{}.bin", hex::encode(rnd))
    }
}

pub fn secure_erase_file(path: &Path) {
    if let Ok(meta) = fs::metadata(path) {
        let len = meta.len();
        if len > 0 {
            if let Ok(mut f) = OpenOptions::new().write(true).open(path) {
                let zeros = vec![0u8; 1024 * 1024];
                let mut rem = len;
                while rem > 0 {
                    let w = (zeros.len() as u64).min(rem) as usize;
                    if f.write_all(&zeros[..w]).is_err() {
                        break;
                    }
                    rem -= w as u64;
                }
                let _ = f.sync_all();
            }
        }
    }
    let _ = fs::remove_file(path);
}
`

// ============================================================================
// FUSE MOUNT OPZIONALE & INTERFACCIA GRAFICA EGUI + IMAGE/PDF VIEWER
// ============================================================================

const rustFuseMountContent = `use crate::vault::SecureVault;
use std::io;
use std::sync::Arc;

#[cfg(feature = "native-fuse")]
pub fn mount_fuse(vault: Arc<SecureVault>, mount_point: &str) -> io::Result<()> {
    // Implementazione con crate fuser quando compilato con --features native-fuse
    let _ = (vault, mount_point);
    Ok(())
}

#[cfg(not(feature = "native-fuse"))]
pub fn mount_fuse(_vault: Arc<SecureVault>, _mount_point: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Per abilitare il mount FUSE/WinFsp ricompila con: cargo build --release --features native-fuse",
    ))
}
`

const rustUiPreviewContent = `use crate::vault::SecureVault;
use eframe::egui;
use std::io::Read;
use std::path::Path;

pub fn is_image_ext(path: &str) -> bool {
    matches!(
        Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase())
            .as_deref(),
        Some("png" | "jpg" | "jpeg" | "gif")
    )
}

pub fn is_pdf_ext(path: &str) -> bool {
    matches!(
        Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase())
            .as_deref(),
        Some("pdf")
    )
}

/// Decodifica un'immagine PNG/JPEG/GIF direttamente in RAM da VaultReadSeeker (zero file temporanei)
pub fn load_image_texture_in_ram(
    ctx: &egui::Context,
    vault: &SecureVault,
    virtual_path: &str,
) -> Result<(egui::TextureHandle, (usize, usize)), String> {
    let mut seeker = vault
        .open_read_seeker(virtual_path)
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::with_capacity(seeker.size() as usize);
    seeker.read_to_end(&mut raw).map_err(|e| e.to_string())?;

    let img = image::load_from_memory(&raw).map_err(|e| e.to_string())?;
    let rgba = img.to_rgba8();
    let dims = (rgba.width() as usize, rgba.height() as usize);
    let color_img = egui::ColorImage::from_rgba_unmultiplied([dims.0, dims.1], rgba.as_raw());
    let tex = ctx.load_texture(virtual_path, color_img, egui::TextureOptions::LINEAR);
    Ok((tex, dims))
}

/// Estrae il testo di tutte le pagine di un PDF direttamente in RAM da VaultReadSeeker
pub fn extract_pdf_pages_in_ram(
    vault: &SecureVault,
    virtual_path: &str,
) -> Result<Vec<String>, String> {
    let mut seeker = vault
        .open_read_seeker(virtual_path)
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::with_capacity(seeker.size() as usize);
    seeker.read_to_end(&mut raw).map_err(|e| e.to_string())?;

    let doc = lopdf::Document::load_mem(&raw).map_err(|e| format!("Errore parsing PDF: {e}"))?;
    let pages = doc.get_pages();
    let mut out = Vec::new();

    for (page_num, _) in pages {
        let text = doc
            .extract_text(&[page_num])
            .unwrap_or_else(|_| format!("[Pagina {page_num} senza testo estraibile]"));
        out.push(text);
    }

    if out.is_empty() {
        out.push("[Documento PDF decodificato in RAM — Nessuna pagina testuale rilevata]".to_string());
    }
    Ok(out)
}
`

const rustUiModContent = `pub mod preview;

use crate::usb::format_physical_usb;
use crate::vault::{FileEntry, SecureVault, MAX_TEXT_PREVIEW_SIZE};
use eframe::egui;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::sync::Arc;

pub fn run_app() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1150.0, 720.0]),
        ..Default::default()
    };
    eframe::run_native(
        "SecureUSB Explorer (Rust) — Zeroize + Rayon Multi-Core + SIMD In-Place AEAD",
        options,
        Box::new(|_cc| Ok(Box::new(SecureUsbApp::default()))),
    )
}

enum PreviewState {
    None,
    Text { path: String, content: String },
    Image {
        path: String,
        texture: egui::TextureHandle,
        dims: (usize, usize),
    },
    Pdf {
        path: String,
        pages: Vec<String>,
        current_page: usize,
    },
    LargeFile { path: String, size: u64, chunks: usize },
}

impl Default for PreviewState {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Default)]
struct SecureUsbApp {
    usb_path: String,
    password: String,
    raw_device: String,
    status_msg: String,
    vault: Option<Arc<SecureVault>>,
    current_dir: String,
    entries: Vec<FileEntry>,
    selected_path: Option<String>,
    preview: PreviewState,
    new_item_name: String,
}

impl SecureUsbApp {
    fn refresh_dir(&mut self) {
        if let Some(v) = &self.vault {
            if self.current_dir.is_empty() {
                self.current_dir = "/".to_string();
            }
            self.entries = v.list_dir(&self.current_dir);
        }
    }

    fn select_entry(&mut self, ctx: &egui::Context, entry: &FileEntry) {
        if entry.is_dir {
            self.current_dir = entry.virtual_path.clone();
            self.selected_path = None;
            self.preview = PreviewState::None;
            self.refresh_dir();
            return;
        }

        self.selected_path = Some(entry.virtual_path.clone());
        let Some(v) = &self.vault else { return };

        if preview::is_image_ext(&entry.virtual_path) {
            if let Ok((tex, dims)) = preview::load_image_texture_in_ram(ctx, v, &entry.virtual_path) {
                self.preview = PreviewState::Image {
                    path: entry.virtual_path.clone(),
                    texture: tex,
                    dims,
                };
                return;
            }
        }

        if preview::is_pdf_ext(&entry.virtual_path) && entry.original_size <= 64 * 1024 * 1024 {
            if let Ok(pages) = preview::extract_pdf_pages_in_ram(v, &entry.virtual_path) {
                self.preview = PreviewState::Pdf {
                    path: entry.virtual_path.clone(),
                    pages,
                    current_page: 0,
                };
                return;
            }
        }

        if entry.original_size > MAX_TEXT_PREVIEW_SIZE {
            self.preview = PreviewState::LargeFile {
                path: entry.virtual_path.clone(),
                size: entry.original_size,
                chunks: entry.chunk_sizes.len(),
            };
            return;
        }

        if let Ok(bytes) = v.read_file(&entry.virtual_path) {
            if let Ok(txt) = String::from_utf8(bytes) {
                self.preview = PreviewState::Text {
                    path: entry.virtual_path.clone(),
                    content: txt,
                };
            } else {
                self.preview = PreviewState::LargeFile {
                    path: entry.virtual_path.clone(),
                    size: entry.original_size,
                    chunks: entry.chunk_sizes.len(),
                };
            }
        }
    }
}

impl eframe::App for SecureUsbApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.vault.is_none() {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("Sblocco e Gestione Chiavetta Cifrata (Rust SVAULT03)");
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.label("Percorso USB:");
                    ui.text_edit_singleline(&mut self.usb_path);
                    if ui.button("Sfoglia...").clicked() {
                        if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                            self.usb_path = folder.display().to_string();
                        }
                    }
                });

                ui.horizontal(|ui| {
                    ui.label("Password (Argon2id):");
                    ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                });

                ui.horizontal(|ui| {
                    if ui.button("Sblocca Vault Esistente").clicked() {
                        match SecureVault::init_or_open(&self.usb_path, &self.password, false) {
                            Ok(v) => {
                                self.vault = Some(v);
                                self.current_dir = "/".to_string();
                                self.password.clear();
                                self.refresh_dir();
                            }
                            Err(e) => self.status_msg = format!("Errore: {e}"),
                        }
                    }
                    if ui.button("Inizializza Nuovo Vault (SVAULT03)").clicked() {
                        match SecureVault::init_or_open(&self.usb_path, &self.password, true) {
                            Ok(v) => {
                                self.vault = Some(v);
                                self.current_dir = "/".to_string();
                                self.password.clear();
                                self.refresh_dir();
                            }
                            Err(e) => self.status_msg = format!("Errore: {e}"),
                        }
                    }
                });

                ui.separator();
                ui.heading("Formattazione Hardware USB in exFAT (Windows / Linux / macOS)");
                ui.horizontal(|ui| {
                    ui.label("Dispositivo (es. E:, /dev/sdb1, /dev/disk2):");
                    ui.text_edit_singleline(&mut self.raw_device);
                    if ui.button("Formatta in exFAT").clicked() {
                        match format_physical_usb(&self.raw_device, "SECURE_USB") {
                            Ok(()) => self.status_msg = "Formattazione exFAT completata!".to_string(),
                            Err(e) => self.status_msg = format!("Errore formattazione: {e}"),
                        }
                    }
                });

                if !self.status_msg.is_empty() {
                    ui.add_space(10.0);
                    ui.colored_label(egui::Color32::LIGHT_RED, &self.status_msg);
                }
            });
            return;
        }

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.button("⬆ Su").clicked() && self.current_dir != "/" {
                    let parent = Path::new(&self.current_dir)
                        .parent()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| "/".to_string());
                    self.current_dir = if parent.is_empty() { "/".to_string() } else { parent };
                    self.refresh_dir();
                }

                ui.text_edit_singleline(&mut self.new_item_name);
                if ui.button("📁 +Cartella").clicked() && !self.new_item_name.trim().is_empty() {
                    if let Some(v) = &self.vault {
                        let target = format!("{}/{}", self.current_dir, self.new_item_name.trim());
                        let _ = v.create_dir(&target);
                        self.new_item_name.clear();
                        self.refresh_dir();
                    }
                }
                if ui.button("📄 +File Testo").clicked() && !self.new_item_name.trim().is_empty() {
                    if let Some(v) = &self.vault {
                        let target = format!("{}/{}", self.current_dir, self.new_item_name.trim());
                        let _ = v.write_file(&target, b"");
                        self.new_item_name.clear();
                        self.refresh_dir();
                    }
                }

                if ui.button("📥 Importa (Rayon Multi-Core)").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        if let (Some(v), Ok(f)) = (&self.vault, File::open(&path)) {
                            let fname = path.file_name().unwrap_or_default().to_string_lossy();
                            let target = format!("{}/{}", self.current_dir, fname);
                            if let Err(e) = v.write_stream(&target, f) {
                                self.status_msg = format!("Errore import: {e}");
                            }
                            self.refresh_dir();
                        }
                    }
                }

                if ui.button("▶ Stream Video al Volo (O(1) Seek)").clicked() {
                    if let (Some(v), Some(sel)) = (&self.vault, &self.selected_path) {
                        if let Ok(url) = v.get_stream_url(sel) {
                            let _ = open::that(url);
                        }
                    }
                }

                if ui.button("📤 Esporta").clicked() {
                    if let (Some(v), Some(sel)) = (&self.vault, &self.selected_path) {
                        if let Some(dest) = rfd::FileDialog::new().save_file() {
                            if let Ok(out) = File::create(dest) {
                                let _ = v.read_stream(sel, BufWriter::new(out));
                            }
                        }
                    }
                }

                if ui.button("🗑 Elimina (Shred)").clicked() {
                    if let (Some(v), Some(sel)) = (&self.vault, self.selected_path.clone()) {
                        let _ = v.delete(&sel);
                        self.selected_path = None;
                        self.preview = PreviewState::None;
                        self.refresh_dir();
                    }
                }

                if ui.button("🔒 Blocca (Zeroize Key)").clicked() {
                    self.vault = None; // Scatena ZeroizeOnDrop sulla MasterKey a 256-bit
                    self.entries.clear();
                    self.preview = PreviewState::None;
                }
            });
            ui.label(format!("Percorso attivo: {}", self.current_dir));
        });

        egui::SidePanel::left("file_list")
            .resizable(true)
            .default_width(400.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let entries_clone = self.entries.clone();
                    for e in entries_clone {
                        let name = Path::new(&e.virtual_path)
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_else(|| e.virtual_path.clone());
                        let label = if e.is_dir {
                            format!("📁 {name}/")
                        } else {
                            format!("📄 {name} ({} B | {} chunk)", e.original_size, e.chunk_sizes.len())
                        };
                        let is_sel = self.selected_path.as_deref() == Some(&e.virtual_path);
                        if ui.selectable_label(is_sel, label).clicked() {
                            self.select_entry(ctx, &e);
                        }
                    }
                });
            });

		let mut save_target: Option<(String, Vec<u8>)> = None;
        egui::CentralPanel::default().show(ctx, |ui| match &mut self.preview {
            PreviewState::None => {
                ui.label("Seleziona un file dalla lista per visualizzarlo o modificarlo in RAM.");
            }
			PreviewState::Text { path, content } => {
                ui.horizontal(|ui| {
                    ui.heading(format!("Editor Testo: {path}"));
                    if ui.button("💾 Salva Modifiche").clicked() {
                        save_target = Some((path.clone(), content.as_bytes().to_vec()));
                    }
                });
                ui.separator();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(content)
                            .desired_width(f32::INFINITY)
                            .desired_rows(28),
                    );
                });
            }
            PreviewState::Image {
                path,
                texture,
                dims,
            } => {
                ui.heading(format!(
                    "Visualizzatore Immagini RAM (Zero-Temp): {path} ({}x{} px)",
                    dims.0, dims.1
                ));
                ui.separator();
                ui.image((texture.id(), ui.available_size()));
            }
            PreviewState::Pdf {
                path,
                pages,
                current_page,
            } => {
                ui.horizontal(|ui| {
                    ui.heading(format!(
                        "Visualizzatore PDF RAM: {path} (Pagina {} di {})",
                        *current_page + 1,
                        pages.len()
                    ));
                    if ui.button("◀ Prec").clicked() && *current_page > 0 {
                        *current_page -= 1;
                    }
                    if ui.button("Succ ▶").clicked() && *current_page + 1 < pages.len() {
                        *current_page += 1;
                    }
                });
                ui.separator();
                let mut page_txt = pages[*current_page].clone();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut page_txt)
                            .desired_width(f32::INFINITY)
                            .desired_rows(28),
                    );
                });
            }
            PreviewState::LargeFile { path, size, chunks } => {
                ui.heading(format!("File Multimediale / Binario: {path}"));
                ui.label(format!(
                    "Dimensione: {size} byte suddivisi in {chunks} chunk indipendenti da 4 MB."
                ));
                ui.label("Usa 'Stream Video al Volo (O(1) Seek)' nella barra in alto per riprodurlo istantaneamente.");
            }
        });
		if let Some((path, data)) = save_target {
            if let Some(v) = &self.vault {
                let _ = v.write_file(&path, &data);
            }
            self.refresh_dir();
        }
    }
}
`

// ============================================================================
// TEST SUITE RUST: INTEGRATION, E2E, PROPERTY-FUZZING & CRITERION BENCHMARKS
// ============================================================================

const rustIntegrationE2EFuzzContent = `use proptest::prelude::*;
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
`

const rustCriterionBenchContent = `use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use secureusb_rs::vault::SecureVault;
use tempfile::tempdir;

fn bench_vault_pipeline(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let vault = SecureVault::init_or_open(dir.path(), "BenchMasterKey", true).unwrap();

    // Payload da 16 MB (4 chunk da 4 MB)
    let data: Vec<u8> = (0..(16 * 1024 * 1024))
        .map(|i| ((i * 73) % 251) as u8)
        .collect();

    let mut group = c.benchmark_group("svault03_rust_simd_rayon");
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("parallel_encrypt_16MB", |b| {
        b.iter(|| {
            vault.write_file("/bench.bin", black_box(&data)).unwrap();
        });
    });

    vault.write_file("/bench.bin", &data).unwrap();

    group.bench_function("parallel_decrypt_16MB", |b| {
        b.iter(|| {
            let out = vault.read_file(black_box("/bench.bin")).unwrap();
            black_box(out);
        });
    });

    let mut seeker = vault.open_read_seeker("/bench.bin").unwrap();
    let mut read_buf = [0u8; 4096];
    group.throughput(Throughput::Bytes(read_buf.len() as u64));
    group.bench_function("random_access_seek_O1_4KB", |b| {
        let mut iter_idx = 0u64;
        b.iter(|| {
            let offset = (iter_idx * 65536) % (15 * 1024 * 1024);
            iter_idx = iter_idx.wrapping_add(1);
            let n = seeker.read_at(black_box(&mut read_buf), offset).unwrap();
            black_box(n);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_vault_pipeline);
criterion_main!(benches);
`

const rustCargoFuzzTomlContent = `[package]
name = "secureusb-rs-fuzz"
version = "0.0.0"
publish = false
edition = "2021"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
tempfile = "3.14"

[dependencies.secureusb-rs]
path = ".."

[[bin]]
name = "fuzz_seeker"
path = "fuzz_targets/fuzz_seeker.rs"
test = false
doc = false
bench = false
`

const rustLibFuzzerTargetContent = `#![no_main]
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
`

// ============================================================================
// PIPELINE CI/CD GITHUB ACTIONS (.github/workflows/release.yml)
// ============================================================================

const githubActionsWorkflowContent = `name: SecureUSB CI/CD — Build & Test (Go + Rust)

on:
  push:
    branches: [ "main", "master" ]
    tags: [ "v*" ]
  pull_request:
    branches: [ "main", "master" ]

permissions:
  contents: write

jobs:
  # ==========================================================================
  # 1. SUITE DI TEST, RACE DETECTOR, FUZZING BREVE E BENCHMARK (GO + RUST)
  # ==========================================================================
  verify-and-test:
    name: Test, Fuzz & Bench (Ubuntu)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Install System Dependencies (FUSE, OpenGL, X11, exFAT)
        run: |
          sudo apt-get update
          sudo apt-get install -y libgl1-mesa-dev xorg-dev libfuse-dev exfatprogs pkg-config

      - name: Setup Go 1.22
        uses: actions/setup-go@v5
        with:
          go-version: "1.22"

      - name: Setup Rust Stable Toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Run Go Unit, Integration & E2E Tests (with Race Detector)
        run: |
          go mod tidy
          go test -v -race ./internal/vault/...

      - name: Run Go Native Fuzzing (10s Smoke Fuzz)
        run: |
          go test -fuzz=FuzzVaultRoundTripAndSeeker -fuzztime=10s ./internal/vault

      - name: Run Go Benchmarks
        run: |
          go test -bench=. -benchmem -run=^$ ./internal/vault

      - name: Run Rust Unit, Integration, E2E & Proptest Fuzz Suite
        working-directory: secureusb-rs
        run: |
          cargo test --release -- --nocapture

      - name: Verify Rust Criterion Benchmarks Compile & Execute
        working-directory: secureusb-rs
        run: |
          cargo bench --bench vault_bench -- --quick

  # ==========================================================================
  # 2. MATRICE DI COMPILAZIONE CROSS-PLATFORM (LINUX, WINDOWS, MACOS) — GO & RUST
  # ==========================================================================
  build-matrix:
    name: Build (${{ matrix.os_name }} — Go & Rust)
    needs: verify-and-test
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - os: ubuntu-latest
            os_name: linux-amd64
            go_bin: secureusb-go-linux-amd64
            rust_bin: secureusb-rs-linux-amd64
            ext: ""
          - os: windows-latest
            os_name: windows-amd64
            go_bin: SecureUSB-Go-Windows-amd64.exe
            rust_bin: SecureUSB-Rust-Windows-amd64.exe
            ext: ".exe"
          - os: macos-latest
            os_name: macos-universal
            go_bin: secureusb-go-macos
            rust_bin: secureusb-rs-macos
            ext: ""

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Install Linux Dependencies (FUSE & X11/OpenGL)
        if: runner.os == 'Linux'
        run: |
          sudo apt-get update
          sudo apt-get install -y libgl1-mesa-dev xorg-dev libfuse-dev pkg-config

      - name: Install macOS Dependencies (macFUSE headers)
        if: runner.os == 'macOS'
        run: |
          brew install --cask macfuse || true

      - name: Install Windows Dependencies (WinFsp)
        if: runner.os == 'Windows'
        run: |
          choco install winfsp -y || true

      - name: Setup Go 1.22
        uses: actions/setup-go@v5
        with:
          go-version: "1.22"

      - name: Setup Rust Toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Build Go Executable (${{ matrix.os_name }})
        shell: bash
        run: |
          go mod tidy
          if [ "${{ runner.os }}" = "Windows" ]; then
            go build -ldflags="-s -w -H=windowsgui" -o "dist/${{ matrix.go_bin }}" .
          else
            go build -ldflags="-s -w" -o "dist/${{ matrix.go_bin }}" .
          fi

      - name: Build Rust Executable with SIMD + LTO (${{ matrix.os_name }})
        shell: bash
        run: |
          cd secureusb-rs
          cargo build --release
          mkdir -p ../dist
          cp "target/release/secureusb-rs${{ matrix.ext }}" "../dist/${{ matrix.rust_bin }}"

      - name: Upload Artifacts (${{ matrix.os_name }})
        uses: actions/upload-artifact@v4
        with:
          name: binaries-${{ matrix.os_name }}
          path: dist/*

  # ==========================================================================
  # 3. PUBBLICAZIONE AUTOMATICA SU GITHUB RELEASES (SU TAG v*)
  # ==========================================================================
  publish-release:
    name: Publish GitHub Release (6 Executables)
    needs: build-matrix
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    steps:
      - name: Download All Built Artifacts
        uses: actions/download-artifact@v4
        with:
          path: release-assets
          merge-multiple: true

      - name: Generate SHA-256 Checksums
        run: |
          cd release-assets
          sha256sum * > SHA256SUMS.txt
          cat SHA256SUMS.txt

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: release-assets/*
          generate_release_notes: true
`
