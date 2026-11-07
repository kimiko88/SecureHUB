use crate::vault::types::*;
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

/// Seleziona dinamicamente il livello di compressione Zstd campionando l'entropia sui primi 16 KB:
/// - Dati ad alta entropia (> 7.85 bit/byte, es. video MP4/MKV o archivi): livello 1 (massima velocità)
/// - Dati comprimibili (testo, PDF, DB, binari, immagini raw): livello 6 (massima compressione senza perdere velocità in lettura)
#[inline]
fn adaptive_zstd_level(data: &[u8], default_level: i32) -> i32 {
    let sample = &data[..data.len().min(16 * 1024)];
    if sample.len() < 512 {
        return default_level;
    }
    let mut counts = [0u32; 256];
    for &b in sample {
        counts[b as usize] += 1;
    }
    let inv_len = 1.0f32 / (sample.len() as f32);
    let mut entropy = 0.0f32;
    for &c in &counts {
        if c > 0 {
            let p = (c as f32) * inv_len;
            entropy -= p * p.log2();
        }
    }
    if entropy > 7.85 {
        1
    } else {
        6
    }
}

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

        let encrypted_batch: io::Result<Vec<EncryptedChunkOut>> = batch
            .into_par_iter()
            .map(|job| {
                let plain_len = job.plain_data.len() as u64;
                let max_comp = zstd::zstd_safe::compress_bound(job.plain_data.len());
                let level = adaptive_zstd_level(&job.plain_data, zstd_level);

                let mut packet = vec![0u8; 4 + max_comp];
                let comp_size = zstd::bulk::compress_to_buffer(
                    &job.plain_data,
                    &mut packet[4..],
                    level,
                )
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                packet.truncate(4 + comp_size);

                let (nonce, aad) =
                    build_chunk_nonce_and_aad(&stream_id, job.chunk_index, job.is_final);

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
