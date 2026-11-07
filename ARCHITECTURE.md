# Architecture & Engineering Specification (v0.4.0)

## 1. Dual-Slot Key Wrapping & Plausible Deniability (`SVKEY04`)

Instead of encrypting files directly with the password-derived key, **SecureHUB** uses a two-tier key hierarchy:
1. **DEK (Data Encryption Key):** A 256-bit CSPRNG master key used for `XChaCha20-Poly1305` and `BLAKE3` keyed deduplication.
2. **KEK (Key Encryption Key):** Derived from the user password via `Argon2id` (`64 MiB, t=3, p=4`) using a per-slot 16-byte salt.

`vault.key` (`SVKEY04`) has a strict 199-byte layout:
* `Bytes 0..7`: Magic tag `"SVKEY04"` (authenticated as AAD).
* `Bytes 7..103` (**Slot 0 — 96 Bytes**): `Salt_0 (16B) || Nonce_0 (24B) || Seal_KEK0(DEK_Primary) (48B) || Pad_0 (8B)`.
* `Bytes 103..199` (**Slot 1 — 96 Bytes**): `Salt_1 (16B) || Nonce_1 (24B) || Seal_KEK1(DEK_Shadow) (48B) || Pad_1 (8B)`.

When unlocking:
* If the password authenticates **Slot 0**, the engine loads `DEK_Primary` and mounts `index.meta`.
* If the password authenticates **Slot 1**, the engine loads `DEK_Shadow` and mounts `index.shadow`.

---

## 2. Content-Addressed Deduplication (`BLAKE3` Keyed)

When importing files via `WriteStreamDedup` / `write_stream_dedup`:
1. The input stream is split into chunks $M_i$ of at most $4\text{ MiB}$.
2. For each chunk, the engine computes a keyed cryptographic Content ID:
   $$\text{CID}_i = \text{Hex}\Big(\text{BLAKE3\_Keyed}(\text{DEK}, M_i)\Big) \mathbin{\Vert} \text{".chk"}$$
3. **Fast-Path ($O(1)$ Hit):** If '.secure_vault/blocks/' 'CID_i' already exists on disk, compression, encryption, and disk I/O are bypassed completely, and 'ChunkRefCounts[CID_i]' is incremented.
4. **Cache Miss:** The chunk is compressed with `Zstd` and sealed with `XChaCha20-Poly1305` using the raw 32-byte `BLAKE3` digest as Associated Data (AAD).

---

## 3. Systematic Reed-Solomon $\text{GF}(2^8)$ Anti Bit-Rot Engine (`RSECC01`)

USB flash drives use TLC/QLC NAND memory prone to charge leakage (*bit-rot*). To prevent a single flipped bit in `index.meta` or `vault.key` from locking out the entire vault:

1. **Galois Field Arithmetic:** Operations are performed in $\text{GF}(2^8)$ with primitive polynomial $x^8 + x^4 + x^3 + x^2 + 1$ (`0x11d`).
2. **Cauchy Encoding Matrix ($12 \times 8$):** The target file is split into $K = 8$ data shards $D_0, \dots, D_7$. The encoder generates $M = 4$ parity shards $P_0, \dots, P_3$ using a Cauchy matrix $C_{r,c} = ((8+r) \oplus c)^{-1}$ in $\text{GF}(2^8)$, and records the `SHA-256` hash of all 12 shards inside '<file>.ecc'.
3. **Automatic Gauss-Jordan Healing:** Before reading `index.meta`, `index.shadow`, or `vault.key`, `VerifyAndHealWithECC` checks the `SHA-256` of the 8 data shards. If up to **4 shards** are corrupted, it selects 8 intact shards, inverts the $8 \times 8$ submatrix in $\text{GF}(2^8)$, reconstructs the missing data shards, and heals the file on disk before `Poly1305` verification.

---

## 4. Entropy-Adaptive Zstd Compression & $O(1)$ Seeker

* **4 MiB Window Alignment:** `Zstd` is configured with a $4\text{ MiB}$ window matching the exact chunk boundary.
* **Shannon Entropy Fast-Path:** The engine computes the Shannon entropy $H(X) = -\sum p(x)\log_2 p(x)$ over the first $16\text{ KiB}$ of each chunk. If $H(X) > 7.85\text{ bits/byte}$ (already compressed video/archive), it switches to Level 1 (`SpeedFastest`); otherwise it uses Level 6 (`SpeedBetterCompression`), maximizing compression ratios while keeping decompression speed above $1,000\text{ MB/s}$.
* **$O(1)$ Random-Access Seeking:** Using `ChunkSizes []uint32`, any byte offset $P$ maps in $O(1)$ to chunk $k = \lfloor P / 4\text{ MiB} \rfloor$ and intra-chunk offset $\delta = P \bmod 4\text{ MiB}$.
