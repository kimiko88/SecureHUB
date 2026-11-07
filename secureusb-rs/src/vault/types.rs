use argon2::{Algorithm, Argon2, Params, Version};
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
