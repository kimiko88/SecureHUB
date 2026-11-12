use crate::vault::types::*;
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
        let new_pos = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
            SeekFrom::End(delta) => self.entry.original_size.checked_add_signed(delta),
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Posizione di seek fuori dall'intervallo u64",
            )
        })?;
        self.pos = new_pos;
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
    let is_head = parts[0] == "HEAD";

    if parts[0] != "GET" && !is_head {
        stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }

    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("range") {
                let Some(spec) = value.trim().strip_prefix("bytes=") else {
                    stream.write_all(b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
                    return Ok(());
                };
                // Multi-range e suffix-range non sono supportati: rifiutali invece
                // di restituire una risposta 206 incoerente.
                if spec.contains(',') {
                    stream.write_all(b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
                    return Ok(());
                }
                let Some((start, end)) = spec.split_once('-') else {
                    stream.write_all(b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
                    return Ok(());
                };
                if start.is_empty() {
                    stream.write_all(b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
                    return Ok(());
                }
                range_start = match start.parse::<u64>() {
                    Ok(value) => value,
                    Err(_) => {
                        stream.write_all(b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
                        return Ok(());
                    }
                };
                range_end = if end.is_empty() {
                    total_size.saturating_sub(1)
                } else {
                    match end.parse::<u64>() {
                        Ok(value) => value.min(total_size.saturating_sub(1)),
                        Err(_) => {
                            stream.write_all(b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
                            return Ok(());
                        }
                    }
                };
                is_partial = true;
            }
        }
    }

    if total_size == 0 {
        stream.write_all(b"HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }
    if range_start >= total_size || range_start > range_end {
        stream.write_all(b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */")?;
        stream.write_all(total_size.to_string().as_bytes())?;
        stream.write_all(b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }

    let content_len = range_end - range_start + 1;
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

    if is_head {
        return Ok(());
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
