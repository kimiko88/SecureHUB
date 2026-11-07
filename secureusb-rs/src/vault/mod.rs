pub mod crypto_parallel;
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
