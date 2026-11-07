# Security Policy & Threat Model (v0.4.0)

## Cryptographic & Resilience Primitives

| Component | Algorithm / Specification | Security Role |
| :--- | :--- | :--- |
| **Key Derivation (KDF)** | `Argon2id (v0x13)` — 64 MiB RAM, $t=3$, $p=4$, 16B CSPRNG Salt | Protects user passwords against GPU/ASIC brute-force attacks |
| **Key Wrapping & Deniability** | `SVKEY04` Dual-Slot Envelope (2 $\times$ 96B slots + `XChaCha20-Poly1305`) | Instant password rotation & Plausible Deniability (`index.meta` vs `index.shadow`) |
| **Symmetric Chunk AEAD** | `XChaCha20-Poly1305` (256-bit DEK, 192-bit Nonce, 128-bit Tag) | Authenticated encryption per 4 MiB chunk |
| **Stream Integrity** | Rogaway `STREAM` construction (64-bit Counter + EOF Flag in Nonce & AAD) | Prevents chunk reordering, truncation, and splice attacks |
| **Content-Addressed Dedup** | `BLAKE3 Keyed Hash` (`BLAKE3_Keyed(DEK, PlainChunk)`) | Prevents cross-vault hash leakage while deduplicating identical 4 MiB blocks |
| **Anti Bit-Rot ECC** | Systematic `Reed-Solomon GF(2^8)` ($8+4$ Cauchy shards + `SHA-256`) | Self-heals up to 33.3% damaged NAND flash sectors prior to `Poly1305` auth |
| **RAM & Unplug Hygiene** | `ZeroizeOnDrop` + `libc::mlock` + 2s USB Hot-Plug Watchdog | Locks keys in physical RAM and zeroes DEK immediately if USB is unplugged |

---

## Threat Model

### 1. Lost or Stolen USB Drive (At-Rest Confidentiality)
* All filenames, directory structures, file sizes, and chunk tables are encrypted inside `index.meta` / `index.shadow`.
* Only obfuscated '<128-bit-hex>.bin' and '<256-bit-blake3-keyed>.chk' blobs exist on the `exFAT` partition.
* Because `BLAKE3` deduplication uses the vault's secret 256-bit **DEK** as its key (`keyed_hash`), an attacker cannot perform known-file confirmation attacks by comparing chunk hashes against public datasets.

### 2. Coercion & Rubber-Hose Cryptanalysis (Plausible Deniability)
* Every initialized vault always creates a 199-byte `vault.key` with **two 96-byte slots** and both `index.meta` and `index.shadow` (plus their '.ecc' sidecars).
* Even if the user has never configured a Shadow Vault, **Slot 1** is filled with 96 bytes of CSPRNG noise and `index.shadow` is encrypted with a discarded ephemeral 256-bit key.
* Under coercion, the user can disclose the **Primary Password** (unlocking Slot 0 and revealing innocuous decoy files), while there is no cryptographic distinguisher proving that Slot 1 holds a valid second key rather than random initialization bytes.
* *Operational Note:* Plausible deniability holds against an adversary who inspects the USB drive at a single point in time. If an adversary captures forensic images of the USB drive *before* and *after* you modify files in the Shadow Vault, they could observe new '.bin'/'.chk' files or changes to `index.shadow`.

### 3. Active Tampering, Decompression Bombs & NAND Bit-Rot
* **Authenticate-Before-Decompress:** No byte is ever passed to the `Zstd` decompressor until `Poly1305` has verified the integrity of the encrypted chunk.
* **Bit-Rot vs. Tampering:** If NAND flash degradation corrupts up to 4 out of 12 shards in `index.meta`, `index.shadow`, or `vault.key`, the `Reed-Solomon GF(2^8)` healer reconstructs the original ciphertext and verifies it with `Poly1305`.

---

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for suspected security vulnerabilities. Use GitHub's [**Private Vulnerability Reporting**](https://github.com/kimiko88/SecureHUB/security/advisories/new) tab so we can release a coordinated fix.
