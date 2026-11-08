pub mod crypto_parallel;
pub mod dedup_deniability;
pub mod ecc_rs;
pub mod seeker;
pub mod types;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
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
    master_key: MasterKey,
    cipher: XChaCha20Poly1305,
    index: RwLock<VaultIndex>,
    stream_port: RwLock<Option<(u16, String)>>,
    active_index: String,
    is_shadow: bool,
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
        let key_file = vault_dir.join("vault.key");

        if create_new {
            let _ = fs::remove_dir_all(&vault_dir);
            fs::create_dir_all(&blocks_dir)?;

            let mut salt = [0u8; SALT_SIZE];
            rand::thread_rng().fill_bytes(&mut salt);
            fs::write(&salt_file, salt)?;

            let dek = MasterKey::generate_random();
            dedup_deniability::init_dual_slot_and_shadow(&vault_dir, password, &salt, dek.as_bytes())?;
            let cipher = XChaCha20Poly1305::new(dek.as_bytes().into());

            let vault = Arc::new(Self {
                root_path: vault_dir,
                master_key: dek,
                cipher,
                index: RwLock::new(VaultIndex::default()),
                stream_port: RwLock::new(None),
                active_index: "index.meta".to_string(),
                is_shadow: false,
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

        let (dek, is_shadow, active_index) = if key_file.exists() {
            dedup_deniability::unwrap_dual_or_legacy(&vault_dir, password, &salt)?
        } else {
            (MasterKey::derive_from_password(password, &salt)?, false, "index.meta".to_string())
        };
        let cipher = XChaCha20Poly1305::new(dek.as_bytes().into());

        let vault = Arc::new(Self {
            root_path: vault_dir,
            master_key: dek,
            cipher,
            index: RwLock::new(VaultIndex::default()),
            stream_port: RwLock::new(None),
            active_index,
            is_shadow,
        });
        vault.load_index()?;

        if !key_file.exists() {
            let _ = Self::wrap_and_save_dek(
                &key_file,
                password,
                &salt,
                vault.master_key.as_bytes(),
            );
        }
        Ok(vault)
    }

    pub fn is_mount_alive(&self) -> bool {
        self.root_path.join("index.meta").is_file()
    }

    fn wrap_and_save_dek(
        key_file: &Path,
        password: &str,
        salt: &[u8],
        dek_bytes: &[u8; KEY_SIZE],
    ) -> io::Result<()> {
        let kek = MasterKey::derive_from_password(password, salt)?;
        let kek_cipher = XChaCha20Poly1305::new(kek.as_bytes().into());

        let mut nonce = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);

        let wrapped = kek_cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: dek_bytes,
                    aad: VAULT_KEY_MAGIC,
                },
            )
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Errore Key Wrapping"))?;

        let mut packet = Vec::with_capacity(VAULT_KEY_MAGIC.len() + NONCE_SIZE + wrapped.len());
        packet.extend_from_slice(VAULT_KEY_MAGIC);
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&wrapped);

        let tmp_file = key_file.with_extension("key.tmp");
        fs::write(&tmp_file, &packet)?;
        fs::rename(tmp_file, key_file)
    }

    fn unwrap_dek(key_file: &Path, password: &str, salt: &[u8]) -> io::Result<MasterKey> {
        let packet = fs::read(key_file)?;
        let magic_len = VAULT_KEY_MAGIC.len();
        if packet.len() != magic_len + NONCE_SIZE + KEY_SIZE + TAG_SIZE
            || &packet[..magic_len] != VAULT_KEY_MAGIC
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Formato vault.key non valido",
            ));
        }

        let kek = MasterKey::derive_from_password(password, salt)?;
        let kek_cipher = XChaCha20Poly1305::new(kek.as_bytes().into());

        let nonce = &packet[magic_len..magic_len + NONCE_SIZE];
        let cipher_dek = &packet[magic_len + NONCE_SIZE..];

        let plain_vec = kek_cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: cipher_dek,
                    aad: VAULT_KEY_MAGIC,
                },
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Password errata o vault.key manomesso",
                )
            })?;

        let mut raw = [0u8; KEY_SIZE];
        raw.copy_from_slice(&plain_vec);
        Ok(MasterKey::from_raw_bytes(raw))
    }

    /// Cambia istantaneamente la password del Vault ri-avvolgendo la DEK (0 byte di file ricifrati)
    pub fn change_password(&self, old_password: &str, new_password: &str) -> io::Result<()> {
        if new_password.len() < 6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "La nuova password deve contenere almeno 6 caratteri",
            ));
        }
        self.change_dual_or_legacy_password(old_password, new_password)
    }

    /// Ricerca istantanea in RAM su tutti i file e le sottocartelle del Vault
    pub fn search(&self, query: &str) -> Vec<FileEntry> {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return self.list_dir("/");
        }
        let idx = self.index.read().unwrap();
        let mut results: Vec<FileEntry> = idx
            .entries
            .values()
            .filter(|e| e.virtual_path != "/" && e.virtual_path.to_lowercase().contains(&q))
            .cloned()
            .collect();

        results.sort_by(|a, b| match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a
                .virtual_path
                .to_lowercase()
                .cmp(&b.virtual_path.to_lowercase()),
        });
        results
    }

    /// Statistiche di compressione Zstd e conteggio chunk per la barra telemetrica
    pub fn stats(&self) -> VaultStats {
        let idx = self.index.read().unwrap();
        let mut st = VaultStats::default();
        for e in idx.entries.values() {
            if e.virtual_path == "/" {
                continue;
            }
            if e.is_dir {
                st.total_folders += 1;
            } else {
                st.total_files += 1;
                st.total_chunks += e.chunk_sizes.len();
                st.original_size += e.original_size;
                st.disk_size += e.disk_size;
            }
        }
        st
    }

    /// Verifica globale di integrità Poly1305 + Zstd su tutti i blocchi della chiavetta
    pub fn scrub_integrity(&self) -> ScrubReport {
        let files: Vec<FileEntry> = {
            let idx = self.index.read().unwrap();
            idx.entries.values().filter(|e| !e.is_dir).cloned().collect()
        };

        let mut report = ScrubReport {
            total_files: files.len(),
            ..Default::default()
        };

        for f_entry in files {
            match self.read_stream(&f_entry.virtual_path, io::sink()) {
                Ok(()) => {
                    report.verified_chunks += f_entry.chunk_sizes.len();
                    report.verified_bytes += f_entry.original_size;
                }
                Err(_) => {
                    report.corrupted_files.push(f_entry.virtual_path);
                }
            }
        }
        report
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

        let res = crypto_parallel::encrypt_stream_parallel(&self.cipher, src, &mut bw, 6);
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
                    deduplicated_chunks: 0,
                    is_shadow_vault: self.is_shadow,
                    chunk_sizes,
                    chunk_refs: Vec::new(),
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

    pub fn import_dir(
        &self,
        local_dir_path: impl AsRef<Path>,
        target_parent_virtual_dir: &str,
    ) -> io::Result<usize> {
        let local_root = local_dir_path.as_ref();
        if !local_root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Il percorso selezionato non è una cartella",
            ));
        }
        if should_ignore_entry(local_root) {
            return Ok(0);
        }

        let folder_name = local_root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Imported_Folder".to_string());

        let root_virtual = normalize_path(&format!("{target_parent_virtual_dir}/{folder_name}"));
        let _ = self.create_dir(&root_virtual);

        let mut imported_files = 0usize;
        self.import_dir_recursive(local_root, local_root, &root_virtual, &mut imported_files)?;
        self.save_index()?;
        Ok(imported_files)
    }

    fn import_dir_recursive(
        &self,
        base_local: &Path,
        current_local: &Path,
        root_virtual: &str,
        imported_files: &mut usize,
    ) -> io::Result<()> {
        for entry_res in fs::read_dir(current_local)? {
            let entry = entry_res?;
            let path = entry.path();
            if should_ignore_entry(&path) {
                continue;
            }

            let file_type = entry.file_type()?;
            let rel = path
                .strip_prefix(base_local)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            let rel_slash = rel.to_string_lossy().replace('\\', "/");
            let target_virtual = normalize_path(&format!("{root_virtual}/{rel_slash}"));

            if file_type.is_dir() {
                let _ = self.create_dir(&target_virtual);
                self.import_dir_recursive(base_local, &path, root_virtual, imported_files)?;
            } else if file_type.is_file() {
                let f = File::open(&path)?;
                self.write_stream(&target_virtual, f)?;
                *imported_files += 1;
            }
        }
        Ok(())
    }

    pub fn export_dir(
        &self,
        virtual_dir_path: &str,
        local_dest_parent: impl AsRef<Path>,
    ) -> io::Result<usize> {
        let vdir = normalize_path(virtual_dir_path);
        let folder_name = if vdir == "/" {
            "Vault_Export".to_string()
        } else {
            Path::new(&vdir)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "Vault_Export".to_string())
        };

        let target_root_local = local_dest_parent.as_ref().join(folder_name);
        fs::create_dir_all(&target_root_local)?;

        let prefix = if vdir == "/" {
            "/".to_string()
        } else {
            format!("{vdir}/")
        };

        let items: Vec<FileEntry> = {
            let idx = self.index.read().unwrap();
            idx.entries
                .values()
                .filter(|e| e.virtual_path == vdir || e.virtual_path.starts_with(&prefix))
                .cloned()
                .collect()
        };

        for item in &items {
            if !item.is_dir {
                continue;
            }
            let rel = item
                .virtual_path
                .strip_prefix(&vdir)
                .unwrap_or(&item.virtual_path)
                .trim_start_matches('/');
            if !rel.is_empty() {
                fs::create_dir_all(target_root_local.join(rel))?;
            }
        }

        let mut exported_files = 0usize;
        for item in &items {
            if item.is_dir {
                continue;
            }
            let rel = item
                .virtual_path
                .strip_prefix(&vdir)
                .unwrap_or(&item.virtual_path)
                .trim_start_matches('/');
            let dest_file_path = target_root_local.join(rel);
            if let Some(parent) = dest_file_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let out_file = File::create(&dest_file_path)?;
            self.read_stream(
                &item.virtual_path,
                BufWriter::with_capacity(1024 * 1024, out_file),
            )?;
            exported_files += 1;
        }

        Ok(exported_files)
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
                deduplicated_chunks: 0,
                is_shadow_vault: self.is_shadow,
                chunk_sizes: Vec::new(),
                chunk_refs: Vec::new(),
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
                    deduplicated_chunks: 0,
                    is_shadow_vault: self.is_shadow,
                    chunk_sizes: Vec::new(),
                    chunk_refs: Vec::new(),
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

    /// Restituisce tutti i file contenuti nel sotto-albero `dir_prefix` ordinati per dimensione decrescente.
    pub fn all_files(&self, dir_prefix: &str) -> Vec<FileEntry> {
        let dpath = normalize_path(dir_prefix);
        let prefix = if dpath == "/" {
            "/".to_string()
        } else {
            format!("{dpath}/")
        };
        let idx = self.index.read().unwrap();
        let mut files: Vec<FileEntry> = idx
            .entries
            .values()
            .filter(|e| {
                !e.is_dir
                    && e.virtual_path != "/"
                    && (dpath == "/" || e.virtual_path.starts_with(&prefix))
            })
            .cloned()
            .collect();

        files.sort_by(|a, b| {
            b.original_size
                .cmp(&a.original_size)
                .then_with(|| a.virtual_path.cmp(&b.virtual_path))
        });
        files
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
        let index_file = self.root_path.join(&self.active_index);
        let tmp_file = self.root_path.join("index.meta.tmp");

        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_file)?;
        crypto_parallel::encrypt_stream_parallel(&self.cipher, Cursor::new(raw_json), f, 6)?;
        fs::rename(&tmp_file, &index_file)?;
        ecc_rs::write_ecc_sidecar(&index_file)
    }

    fn load_index(&self) -> io::Result<()> {
        let index_file = self.root_path.join(&self.active_index);
        let _ = ecc_rs::verify_and_heal_with_ecc(&index_file);
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
