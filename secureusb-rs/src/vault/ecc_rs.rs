use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::OnceLock;

const RS_DATA_SHARDS: usize = 8;
const RS_PARITY_SHARDS: usize = 4;
const RS_TOTAL_SHARDS: usize = RS_DATA_SHARDS + RS_PARITY_SHARDS;
const ECC_MAGIC: &[u8; 8] = b"RSECC01\0";

struct GfTables {
    exp: [u8; 512],
    log: [u8; 256],
    matrix: [[u8; RS_DATA_SHARDS]; RS_TOTAL_SHARDS],
}

static GF_TABLES: OnceLock<GfTables> = OnceLock::new();

fn gf() -> &'static GfTables {
    GF_TABLES.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: usize = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            exp[i + 255] = x as u8;
            log[x] = i as u8;
            x <<= 1;
            if (x & 0x100) != 0 {
                x ^= 0x11d;
            }
        }
        let mut matrix = [[0u8; RS_DATA_SHARDS]; RS_TOTAL_SHARDS];
        for i in 0..RS_DATA_SHARDS {
            matrix[i][i] = 1;
        }
        for r in 0..RS_PARITY_SHARDS {
            for c in 0..RS_DATA_SHARDS {
                let a = ((RS_DATA_SHARDS + r) ^ c) as u8;
                matrix[RS_DATA_SHARDS + r][c] = exp[255 - (log[a as usize] as usize)];
            }
        }
        GfTables { exp, log, matrix }
    })
}

#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = gf();
    t.exp[(t.log[a as usize] as usize) + (t.log[b as usize] as usize)]
}

#[inline]
fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let t = gf();
    t.exp[255 - (t.log[a as usize] as usize)]
}

/// Genera il file sidecar '<target_path>.ecc' con 4 shard di parità Reed-Solomon GF(2^8).
pub fn write_ecc_sidecar(target_path: &Path) -> io::Result<()> {
    let data = fs::read(target_path)?;
    let shard_size = ((data.len() + RS_DATA_SHARDS - 1) / RS_DATA_SHARDS).max(1);

    let mut shards = vec![vec![0u8; shard_size]; RS_TOTAL_SHARDS];
    for i in 0..RS_DATA_SHARDS {
        let start = i * shard_size;
        if start < data.len() {
            let end = (start + shard_size).min(data.len());
            shards[i][..end - start].copy_from_slice(&data[start..end]);
        }
    }

    let t = gf();
    for p in 0..RS_PARITY_SHARDS {
        let row = t.matrix[RS_DATA_SHARDS + p];
        let mut p_shard = vec![0u8; shard_size];
        for c in 0..RS_DATA_SHARDS {
            let coeff = row[c];
            let d_shard = &shards[c];
            for b_idx in 0..shard_size {
                p_shard[b_idx] ^= gf_mul(coeff, d_shard[b_idx]);
            }
        }
        shards[RS_DATA_SHARDS + p] = p_shard;
    }

    let mut out = Vec::with_capacity(8 + 12 + (RS_TOTAL_SHARDS * 32) + (RS_PARITY_SHARDS * shard_size));
    out.extend_from_slice(ECC_MAGIC);
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&(shard_size as u32).to_le_bytes());

    for s in &shards {
        let digest = Sha256::digest(s);
        out.extend_from_slice(&digest);
    }
    for p in 0..RS_PARITY_SHARDS {
        out.extend_from_slice(&shards[RS_DATA_SHARDS + p]);
    }

    let ecc_path = Path::new(&format!("{}.ecc", target_path.display())).to_path_buf();
    let tmp_ecc = Path::new(&format!("{}.ecc.tmp", target_path.display())).to_path_buf();
    fs::write(&tmp_ecc, &out)?;
    fs::rename(tmp_ecc, ecc_path)
}

/// Verifica 'target_path' contro i checksum SHA-256 in '<target_path>.ecc' e ripara automaticamente
/// fino a 4 shard danneggiati da bit-rot su 12 prima della decifratura Poly1305.
pub fn verify_and_heal_with_ecc(target_path: &Path) -> io::Result<(bool, usize)> {
    let ecc_path = Path::new(&format!("{}.ecc", target_path.display())).to_path_buf();
    let ecc_raw = match fs::read(&ecc_path) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok((false, 0)),
        Err(err) => return Err(err),
    };

    let fixed_hdr = 8 + 12 + (RS_TOTAL_SHARDS * 32);
    if ecc_raw.len() < fixed_hdr || &ecc_raw[..8] != ECC_MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "File .ecc corrotto"));
    }

    let orig_size = u64::from_le_bytes(ecc_raw[8..16].try_into().unwrap()) as usize;
    let shard_size = u32::from_le_bytes(ecc_raw[16..20].try_into().unwrap()) as usize;
    if shard_size == 0 || ecc_raw.len() != fixed_hdr + (RS_PARITY_SHARDS * shard_size) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Dimensione .ecc non valida"));
    }

    let mut expected_hashes = [[0u8; 32]; RS_TOTAL_SHARDS];
    let mut off = 20;
    for i in 0..RS_TOTAL_SHARDS {
        expected_hashes[i].copy_from_slice(&ecc_raw[off..off + 32]);
        off += 32;
    }

    let raw_data = match fs::read(target_path) {
        Ok(data) => data,
        // Un file mancante può essere ricostruito dai quattro shard di parità;
        // gli altri errori devono invece interrompere la riparazione.
        Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(err),
    };
    let mut shards = vec![vec![0u8; shard_size]; RS_TOTAL_SHARDS];
    let mut valid = [false; RS_TOTAL_SHARDS];
    let mut damaged_count = 0usize;

    for i in 0..RS_DATA_SHARDS {
        let start = i * shard_size;
        if start < raw_data.len() {
            let end = (start + shard_size).min(raw_data.len());
            shards[i][..end - start].copy_from_slice(&raw_data[start..end]);
        }
        let digest = Sha256::digest(&shards[i]);
        if digest.as_slice() == expected_hashes[i] {
            valid[i] = true;
        } else {
            damaged_count += 1;
        }
    }

    if damaged_count == 0 && raw_data.len() == orig_size {
        return Ok((false, 0));
    }

    for p in 0..RS_PARITY_SHARDS {
        let idx = RS_DATA_SHARDS + p;
        shards[idx].copy_from_slice(&ecc_raw[off..off + shard_size]);
        off += shard_size;
        let digest = Sha256::digest(&shards[idx]);
        if digest.as_slice() == expected_hashes[idx] {
            valid[idx] = true;
        }
    }

    let t = gf();
    let mut sub_matrix = [[0u8; RS_DATA_SHARDS]; RS_DATA_SHARDS];
    let mut sub_shards: Vec<&[u8]> = Vec::with_capacity(RS_DATA_SHARDS);
    for i in 0..RS_TOTAL_SHARDS {
        if valid[i] && sub_shards.len() < RS_DATA_SHARDS {
            sub_matrix[sub_shards.len()] = t.matrix[i];
            sub_shards.push(&shards[i]);
        }
    }

    if sub_shards.len() < RS_DATA_SHARDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Troppi settori NAND danneggiati (> 4 shard su 12)",
        ));
    }

    let inv_matrix = invert_gf256_matrix(sub_matrix)?;
    let mut reconstructed_data = Vec::with_capacity(RS_DATA_SHARDS * shard_size);

    for d in 0..RS_DATA_SHARDS {
        if valid[d] {
            reconstructed_data.extend_from_slice(&shards[d]);
        } else {
            let mut rec = vec![0u8; shard_size];
            let row = inv_matrix[d];
            for c in 0..RS_DATA_SHARDS {
                let coeff = row[c];
                let src_s = sub_shards[c];
                for b_idx in 0..shard_size {
                    rec[b_idx] ^= gf_mul(coeff, src_s[b_idx]);
                }
            }
            reconstructed_data.extend_from_slice(&rec);
        }
    }

    reconstructed_data.truncate(orig_size);
    fs::write(target_path, &reconstructed_data)?;
    Ok((true, damaged_count))
}

fn invert_gf256_matrix(
    mut m: [[u8; RS_DATA_SHARDS]; RS_DATA_SHARDS],
) -> io::Result<[[u8; RS_DATA_SHARDS]; RS_DATA_SHARDS]> {
    let mut inv = [[0u8; RS_DATA_SHARDS]; RS_DATA_SHARDS];
    for i in 0..RS_DATA_SHARDS {
        inv[i][i] = 1;
    }

    for col in 0..RS_DATA_SHARDS {
        if m[col][col] == 0 {
            let Some(swap_r) = ((col + 1)..RS_DATA_SHARDS).find(|&r| m[r][col] != 0) else {
                return Err(io::Error::new(io::ErrorKind::Other, "Matrice singolare GF(256)"));
            };
            m.swap(col, swap_r);
            inv.swap(col, swap_r);
        }

        let pivot_inv = gf_inv(m[col][col]);
        for j in 0..RS_DATA_SHARDS {
            m[col][j] = gf_mul(m[col][j], pivot_inv);
            inv[col][j] = gf_mul(inv[col][j], pivot_inv);
        }

        for r in 0..RS_DATA_SHARDS {
            if r == col || m[r][col] == 0 {
                continue;
            }
            let factor = m[r][col];
            for j in 0..RS_DATA_SHARDS {
                m[r][j] ^= gf_mul(factor, m[col][j]);
                inv[r][j] ^= gf_mul(factor, inv[col][j]);
            }
        }
    }
    Ok(inv)
}
