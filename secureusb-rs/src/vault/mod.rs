pub mod crypto_parallel;
pub mod seeker;
pub mod types;

use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305};
use chrono::Utc;
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

pub use seeker::VaultReadSeeker;
pub use types::*;

use chacha20poly1305::aead::{Aead, AeadInPlace, Payload};
use chacha20poly1305::XNonce;
use rayon::prelude::*;

pub struct SecureVault {
    root_path: PathBuf,
    master_key: MasterKey, // DEK a 256-bit ancorata in RAM con mlock + ZeroizeOnDrop
    salt: RwLock<[u8; SALT_SIZE]>,
    cipher: XChaCha20Poly1305,
    index: RwLock<VaultIndex>,
    stream_port: RwLock<Option<(u16, String)>>,
}

fn wrap_dek(kek: &MasterKey, dek: &MasterKey) -> io::Result<Vec<u8>> {
    let kek_cipher = XChaCha20Poly1305::new(kek.as_bytes().into());
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ct = kek_cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: dek.as_bytes(),
                aad: KEY_WRAP_AAD,
            },
        )
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Errore Key Wrapping"))?;

    let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn unwrap_dek(kek: &MasterKey, packet: &[u8]) -> io::Result<MasterKey> {
    if packet.len() != NONCE_SIZE + KEY_SIZE + TAG_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "File vault.key corrotto",
        ));
    }
    let kek_cipher = XChaCha20Poly1305::new(kek.as_bytes().into());
    let mut plain = kek_cipher
        .decrypt(
            XNonce::from_slice(&packet[..NONCE_SIZE]),
            Payload {
                msg: &packet[NONCE_SIZE..],
                aad: KEY_WRAP_AAD,
            },
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Password errata o vault.key manomesso",
            )
        })?;

    let mut raw = [0u8; KEY_SIZE];
    raw.copy_from_slice(&plain);
    zeroize::Zeroize::zeroize(&mut plain);
    Ok(MasterKey::from_raw(raw))
}

impl SecureVault {
    pub fn search(&self, query: &str) -> Vec<FileEntry> {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return Vec::new();
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
            _ => a.virtual_path.to_lowercase().cmp(&b.virtual_path.to_lowercase()),
        });
        results
    }
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

            let kek = MasterKey::derive_from_password(password, &salt)?;
            let dek = MasterKey::generate_random();
            let wrapped = wrap_dek(&kek, &dek)?;
            fs::write(&key_file, wrapped)?;

            let cipher = XChaCha20Poly1305::new(dek.as_bytes().into());
            let vault = Arc::new(Self {
                root_path: vault_dir,
                master_key: dek,
                salt: RwLock::new(salt),
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

        let salt_vec = fs::read(&salt_file)?;
        if salt_vec.len() != SALT_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "File salt corrotto"));
        }
        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&salt_vec);

        let kek = MasterKey::derive_from_password(password, &salt)?;
        let (dek, needs_migration) = if key_file.exists() {
            let pkt = fs::read(&key_file)?;
            (unwrap_dek(&kek, &pkt)?, false)
        } else {
            (MasterKey::from_raw(*kek.as_bytes()), true)
        };

        let cipher = XChaCha20Poly1305::new(dek.as_bytes().into());
        let vault = Arc::new(Self {
            root_path: vault_dir,
            master_key: dek,
            salt: RwLock::new(salt),
            cipher,
            index: RwLock::new(VaultIndex::default()),
            stream_port: RwLock::new(None),
        });
        vault.load_index()?;

        if needs_migration {
            if let Ok(wrapped) = wrap_dek(&kek, &vault.master_key) {
                let _ = fs::write(&key_file, wrapped);
            }
        }
        Ok(vault)
    }

    pub fn change_password(&self, old_password: &str, new_password: &str) -> io::Result<()> {
        if new_password.len() < 6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "La nuova password deve contenere almeno 6 caratteri",
            ));
        }

        let mut salt_guard = self.salt.write().unwrap();
        let old_kek = MasterKey::derive_from_password(old_password, &*salt_guard)?;

        let key_file = self.root_path.join("vault.key");
        if key_file.exists() {
            let wrapped_bytes = fs::read(&key_file)?;
            let unwrapped_dek = unwrap_dek(&old_kek, &wrapped_bytes)?;
            if unwrapped_dek.as_bytes() != self.master_key.as_bytes() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "La password attuale inserita non è corretta",
                ));
            }
        } else if old_kek.as_bytes() != self.master_key.as_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "La password attuale inserita non è corretta",
            ));
        }

        let mut new_salt = [0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut new_salt);

        let new_kek = MasterKey::derive_from_password(new_password, &new_salt)?;
        let new_wrapped = wrap_dek(&new_kek, &self.master_key)?;

        let salt_file = self.root_path.join("vault.salt");
        let key_tmp = self.root_path.join("vault.key.tmp");
        let salt_tmp = self.root_path.join("vault.salt.tmp");

        fs::write(&key_tmp, &new_wrapped)?;
        if let Err(e) = fs::write(&salt_tmp, &new_salt) {
            let _ = fs::remove_file(&key_tmp);
            return Err(e);
        }

        if fs::rename(&key_tmp, &key_file).is_err() {
            let _ = fs::remove_file(&key_file);
            fs::rename(&key_tmp, &key_file)?;
        }

        if fs::rename(&salt_tmp, &salt_file).is_err() {
            let _ = fs::remove_file(&salt_file);
            fs::rename(&salt_tmp, &salt_file)?;
        }

        *salt_guard = new_salt;
        Ok(())
    }

    pub fn verify_integrity(&self) -> IntegrityReport {
        let files: Vec<FileEntry> = {
            let idx = self.index.read().unwrap();
            idx.entries
                .values()
                .filter(|e| !e.is_dir)
                .cloned()
                .collect()
        };

        let files_checked = files.len();

        let results: Vec<(Option<String>, usize, u64)> = files
            .into_par_iter()
            .map(|entry| match self.verify_single_file_poly1305(&entry) {
                Ok(chunks) => (None, chunks, entry.disk_size),
                Err(err) => (
                    Some(format!("{} ({})", entry.virtual_path, err)),
                    0,
                    0,
                ),
            })
            .collect();

        let mut report = IntegrityReport {
            files_checked,
            chunks_verified: 0,
            bytes_verified: 0,
            corrupted_files: Vec::new(),
        };

        for (corrupted, chunks, bytes) in results {
            if let Some(err_msg) = corrupted {
                report.corrupted_files.push(err_msg);
            } else {
                report.chunks_verified += chunks;
                report.bytes_verified += bytes;
            }
        }
        report.corrupted_files.sort();
        report
    }

    fn verify_single_file_poly1305(&self, entry: &FileEntry) -> io::Result<usize> {
        if entry.blob_id.is_empty() {
            return Ok(0);
        }
        let blob_path = self.root_path.join("blocks").join(&entry.blob_id);
        let mut file = File::open(&blob_path)
            .map_err(|e| io::Error::new(e.kind(), "Blocco mancante su disco"))?;

        let mut header = [0u8; HEADER_SIZE];
        file.read_exact(&mut header)
            .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "Header troncato"))?;

        if &header[..8] != VAULT_STREAM_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Magic SVAULT03 non valido",
            ));
        }

        let mut stream_id = [0u8; STREAM_ID_SIZE];
        stream_id.copy_from_slice(&header[8..HEADER_SIZE]);

        let mut len_buf = [0u8; 4];
        let mut cipher_buf = Vec::new();

        for (idx, &expected_len) in entry.chunk_sizes.iter().enumerate() {
            file.read_exact(&mut len_buf)
                .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, format!("Chunk {idx} mancante")))?;

            let got_len = u32::from_le_bytes(len_buf);
            if got_len != expected_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Lunghezza chunk {idx} alterata"),
                ));
            }

            let got_len_usize = got_len as usize;
            if got_len_usize < TAG_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Chunk {idx} troppo corto"),
                ));
            }

            cipher_buf.resize(got_len_usize, 0);
            file.read_exact(&mut cipher_buf)
                .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, format!("Chunk {idx} troncato")))?;

            let is_final = idx + 1 == entry.chunk_sizes.len();
            let (nonce, aad) = build_chunk_nonce_and_aad(&stream_id, idx as u64, is_final);

            let tag_pos = got_len_usize - TAG_SIZE;
            let (ct_slice, tag_slice) = cipher_buf.split_at_mut(tag_pos);
            let tag = Tag::from_slice(tag_slice);

            self.cipher
                .decrypt_in_place_detached(XNonce::from_slice(&nonce), &aad, ct_slice, tag)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("Tag Poly1305 invalido al chunk {idx}"),
                    )
                })?;
        }

        Ok(entry.chunk_sizes.len())
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

    /// Importa ricorsivamente una cartella dal PC dentro 'target_parent_virtual_dir',
    /// escludendo automaticamente '.DS_Store', 'Thumbs.db', 'desktop.ini', '._*', '~$*', '*.tmp', ecc.
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

    /// Esporta ricorsivamente una cartella virtuale dal Vault verso 'local_dest_parent' sul PC.
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
