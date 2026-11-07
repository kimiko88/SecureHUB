use crate::vault::ecc_rs::{verify_and_heal_with_ecc, write_ecc_sidecar};
use crate::vault::types::*;
use crate::vault::{crypto_parallel, SecureVault};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use chrono::Utc;
use rand::RngCore;
use std::fs::{self, File};
use std::io::{self, Cursor, Read};
use std::path::Path;

fn encode_key_slot(password: &str, dek: &[u8; KEY_SIZE]) -> io::Result<[u8; DUAL_SLOT_SIZE]> {
    let mut slot = [0u8; DUAL_SLOT_SIZE];
    rand::thread_rng().fill_bytes(&mut slot[0..40]); // 16B Salt + 24B Nonce
    rand::thread_rng().fill_bytes(&mut slot[88..96]); // 8B Random Pad

    let kek = MasterKey::derive_from_password(password, &slot[0..16])?;
    let aead = XChaCha20Poly1305::new(kek.as_bytes().into());
    let sealed = aead
        .encrypt(
            XNonce::from_slice(&slot[16..40]),
            Payload {
                msg: dek,
                aad: VAULT_KEY_DUAL_MAGIC,
            },
        )
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Errore cifratura slot"))?;

    slot[40..88].copy_from_slice(&sealed);
    Ok(slot)
}

fn decode_key_slot(password: &str, slot: &[u8]) -> io::Result<MasterKey> {
    if slot.len() < DUAL_SLOT_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Slot corto"));
    }
    let kek = MasterKey::derive_from_password(password, &slot[0..16])?;
    let aead = XChaCha20Poly1305::new(kek.as_bytes().into());
    let plain = aead
        .decrypt(
            XNonce::from_slice(&slot[16..40]),
            Payload {
                msg: &slot[40..88],
                aad: VAULT_KEY_DUAL_MAGIC,
            },
        )
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "Slot non corrispondente"))?;

    let mut raw = [0u8; KEY_SIZE];
    raw.copy_from_slice(&plain);
    Ok(MasterKey::from_raw_bytes(raw))
}

/// Inizializza 'vault.key' a doppio slot (Slot 0 = Primario, Slot 1 = CSPRNG indistinguibile)
/// e crea sempre 'index.shadow' (+ '.ecc') per garantire la Plausible Deniability.
pub fn init_dual_slot_and_shadow(
    vault_dir: &Path,
    primary_password: &str,
    _salt: &[u8],
    dek: &[u8; KEY_SIZE],
) -> io::Result<()> {
    let slot0 = encode_key_slot(primary_password, dek)?;
    let mut slot1 = [0u8; DUAL_SLOT_SIZE];
    rand::thread_rng().fill_bytes(&mut slot1);

    let mut packet = Vec::with_capacity(VAULT_KEY_DUAL_MAGIC.len() + 2 * DUAL_SLOT_SIZE);
    packet.extend_from_slice(VAULT_KEY_DUAL_MAGIC);
    packet.extend_from_slice(&slot0);
    packet.extend_from_slice(&slot1);

    let key_file = vault_dir.join("vault.key");
    fs::write(&key_file, &packet)?;
    write_ecc_sidecar(&key_file)?;

    // Crea index.shadow cifrato con chiave effimera usa-e-getta
    let eph_key = MasterKey::generate_random();
    let eph_cipher = XChaCha20Poly1305::new(eph_key.as_bytes().into());
    let empty_json = serde_json::to_vec(&VaultIndex::default())?;
    let shadow_path = vault_dir.join("index.shadow");
    let sf = File::create(&shadow_path)?;
    crypto_parallel::encrypt_stream_parallel(&eph_cipher, Cursor::new(empty_json), sf, 6)?;
    write_ecc_sidecar(&shadow_path)
}

pub fn unwrap_dual_or_legacy(
    vault_dir: &Path,
    password: &str,
    legacy_salt: &[u8],
) -> io::Result<(MasterKey, bool, String)> {
    let key_file = vault_dir.join("vault.key");
    let _ = verify_and_heal_with_ecc(&key_file);
    let packet = fs::read(&key_file)?;

    let m_len = VAULT_KEY_DUAL_MAGIC.len();
    if packet.len() == m_len + (2 * DUAL_SLOT_SIZE) && &packet[..m_len] == VAULT_KEY_DUAL_MAGIC {
        let slot0 = &packet[m_len..m_len + DUAL_SLOT_SIZE];
        if let Ok(k) = decode_key_slot(password, slot0) {
            return Ok((k, false, "index.meta".to_string()));
        }
        let slot1 = &packet[m_len + DUAL_SLOT_SIZE..m_len + (2 * DUAL_SLOT_SIZE)];
        if let Ok(k) = decode_key_slot(password, slot1) {
            return Ok((k, true, "index.shadow".to_string()));
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Password errata per entrambi gli slot (Primario / Shadow)",
        ));
    }

    let k = SecureVault::unwrap_dek(&key_file, password, legacy_salt)?;
    Ok((k, false, "index.meta".to_string()))
}

impl SecureVault {
    pub fn is_shadow_session(&self) -> bool {
        self.is_shadow
    }

    /// Configura o aggiorna il secondo Vault Nascosto (Slot 1 + index.shadow)
    pub fn configure_shadow_vault(&self, shadow_password: &str) -> io::Result<()> {
        if shadow_password.len() < 6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "La password Shadow deve contenere almeno 6 caratteri",
            ));
        }

        let key_file = self.root_path.join("vault.key");
        let mut packet = fs::read(&key_file)?;
        let m_len = VAULT_KEY_DUAL_MAGIC.len();
        if packet.len() != m_len + (2 * DUAL_SLOT_SIZE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vault.key non è in formato Dual-Slot SVKEY04",
            ));
        }

        let shadow_dek = MasterKey::generate_random();
        let slot1 = encode_key_slot(shadow_password, shadow_dek.as_bytes())?;
        packet[m_len + DUAL_SLOT_SIZE..].copy_from_slice(&slot1);
        fs::write(&key_file, &packet)?;
        write_ecc_sidecar(&key_file)?;

        let shadow_cipher = XChaCha20Poly1305::new(shadow_dek.as_bytes().into());
        let empty_json = serde_json::to_vec(&VaultIndex::default())?;
        let shadow_path = self.root_path.join("index.shadow");
        let sf = File::create(&shadow_path)?;
        crypto_parallel::encrypt_stream_parallel(&shadow_cipher, Cursor::new(empty_json), sf, 6)?;
        write_ecc_sidecar(&shadow_path)
    }

    pub fn change_dual_or_legacy_password(
        &self,
        old_password: &str,
        new_password: &str,
    ) -> io::Result<()> {
        let key_file = self.root_path.join("vault.key");
        let _ = verify_and_heal_with_ecc(&key_file);
        let mut packet = fs::read(&key_file)?;
        let m_len = VAULT_KEY_DUAL_MAGIC.len();

        if packet.len() == m_len + (2 * DUAL_SLOT_SIZE) && &packet[..m_len] == VAULT_KEY_DUAL_MAGIC {
            if self.is_shadow {
                let slot1 = &packet[m_len + DUAL_SLOT_SIZE..m_len + (2 * DUAL_SLOT_SIZE)];
                let _ = decode_key_slot(old_password, slot1)?;
                let new_slot1 = encode_key_slot(new_password, self.master_key.as_bytes())?;
                packet[m_len + DUAL_SLOT_SIZE..m_len + (2 * DUAL_SLOT_SIZE)].copy_from_slice(&new_slot1);
            } else {
                let slot0 = &packet[m_len..m_len + DUAL_SLOT_SIZE];
                let _ = decode_key_slot(old_password, slot0)?;
                let new_slot0 = encode_key_slot(new_password, self.master_key.as_bytes())?;
                packet[m_len..m_len + DUAL_SLOT_SIZE].copy_from_slice(&new_slot0);
            }
            let tmp_key = key_file.with_extension("key.tmp");
            fs::write(&tmp_key, &packet)?;
            fs::rename(&tmp_key, &key_file)?;
            write_ecc_sidecar(&key_file)?;
            return Ok(());
        }

        let salt_file = self.root_path.join("vault.salt");
        let cur_salt = fs::read(&salt_file)?;
        let _ = Self::unwrap_dek(&key_file, old_password, &cur_salt)?;
        let mut new_salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut new_salt);
        Self::wrap_and_save_dek(&key_file, new_password, &new_salt, self.master_key.as_bytes())?;
        fs::write(&salt_file, new_salt)
    }

    /// Scrittura con Deduplicazione Content-Addressed BLAKE3 (Keyed con la DEK a 256-bit).
    /// Restituisce il numero di chunk da 4 MB già esistenti riutilizzati in O(1).
    pub fn write_stream_dedup<R: Read>(
        &self,
        virtual_path: &str,
        mut src: R,
    ) -> io::Result<usize> {
        let vpath = normalize_path(virtual_path);
        let mut chunk_refs = Vec::new();
        let mut chunk_sizes = Vec::new();
        let mut total_plain = 0u64;
        let mut total_disk = 0u64;
        let mut dedup_hits = 0usize;

        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            let mut read_bytes = 0;
            while read_bytes < CHUNK_SIZE {
                let n = src.read(&mut buf[read_bytes..])?;
                if n == 0 {
                    break;
                }
                read_bytes += n;
            }
            if read_bytes == 0 && !chunk_refs.is_empty() {
                break;
            }
            let slice = &buf[..read_bytes];
            total_plain += read_bytes as u64;

            // 1. Hash crittografico BLAKE3-Keyed(DEK, slice)
            let b3_hash = blake3::keyed_hash(self.master_key.as_bytes(), slice);
            let cid = format!("{}.chk", b3_hash.to_hex());
            let chk_path = self.root_path.join("blocks").join(&cid);

            if let Ok(meta) = fs::metadata(&chk_path) {
                if meta.len() > 0 {
                    dedup_hits += 1;
                    chunk_refs.push(cid);
                    chunk_sizes.push(meta.len() as u32);
                    if read_bytes < CHUNK_SIZE {
                        break;
                    }
                    continue;
                }
            }

            // Cache Miss: comprime con Zstd e cifra legando l'hash BLAKE3 nell'AAD
            let comp = zstd::bulk::compress(slice, 6)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            let mut nonce = [0u8; NONCE_SIZE];
            rand::thread_rng().fill_bytes(&mut nonce);

            let sealed = self
                .cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &comp,
                        aad: b3_hash.as_bytes(),
                    },
                )
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Errore AEAD dedup"))?;

            let mut packet = Vec::with_capacity(NONCE_SIZE + sealed.len());
            packet.extend_from_slice(&nonce);
            packet.extend_from_slice(&sealed);

            let tmp_chk = chk_path.with_extension("chk.tmp");
            fs::write(&tmp_chk, &packet)?;
            fs::rename(&tmp_chk, &chk_path)?;

            total_disk += packet.len() as u64;
            chunk_sizes.push(packet.len() as u32);
            chunk_refs.push(cid);

            if read_bytes < CHUNK_SIZE {
                break;
            }
        }

        {
            let mut idx = self.index.write().unwrap();
            if let Some(old) = idx.entries.get(&vpath).cloned() {
                for old_cid in old.chunk_refs {
                    if let Some(cnt) = idx.chunk_ref_counts.get_mut(&old_cid) {
                        *cnt = cnt.saturating_sub(1);
                    }
                }
            }
            for cid in &chunk_refs {
                *idx.chunk_ref_counts.entry(cid.clone()).or_insert(0) += 1;
            }
            idx.entries.insert(
                vpath.clone(),
                FileEntry {
                    virtual_path: vpath,
                    blob_id: chunk_refs.first().cloned().unwrap_or_default(),
                    is_dir: false,
                    original_size: total_plain,
                    disk_size: total_disk,
                    deduplicated_chunks: dedup_hits,
                    is_shadow_vault: self.is_shadow,
                    chunk_sizes,
                    chunk_refs,
                    updated_at: Utc::now(),
                },
            );
        }
        self.save_index()?;
        Ok(dedup_hits)
    }

    pub fn read_dedup_file(&self, virtual_path: &str) -> io::Result<Vec<u8>> {
        let vpath = normalize_path(virtual_path);
        let entry = {
            let idx = self.index.read().unwrap();
            idx.entries.get(&vpath).cloned()
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "File non trovato"))?;

        if entry.chunk_refs.is_empty() {
            return self.read_file(&vpath);
        }

        let mut out = Vec::with_capacity(entry.original_size as usize);
        for cid in &entry.chunk_refs {
            let chk_path = self.root_path.join("blocks").join(cid);
            let packet = fs::read(chk_path)?;
            if packet.len() < NONCE_SIZE + TAG_SIZE {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Chunk corrotto"));
            }
            let hex_part = cid.strip_suffix(".chk").unwrap_or(cid);
            let aad_bytes = hex::decode(hex_part)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            let comp = self
                .cipher
                .decrypt(
                    XNonce::from_slice(&packet[..NONCE_SIZE]),
                    Payload {
                        msg: &packet[NONCE_SIZE..],
                        aad: &aad_bytes,
                    },
                )
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Tag Poly1305 non valido sul chunk deduplicato",
                    )
                })?;

            let plain = zstd::bulk::decompress(&comp, CHUNK_SIZE)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            out.extend_from_slice(&plain);
        }
        Ok(out)
    }
}
