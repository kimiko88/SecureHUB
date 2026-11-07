# Security Policy & Threat Model

## Cryptographic Specifications (SVAULT03)

| Primitive | Algorithm / Parameter | Purpose |
| :--- | :--- | :--- |
| **Key Derivation (KDF)** | `Argon2id (v0x13)` — 64 MiB RAM, $t=3$, $p=4$, 16B Salt | Protects master password against GPU/ASIC cracking |
| **Symmetric AEAD** | `XChaCha20-Poly1305` (256-bit key, 192-bit nonce, 128-bit tag) | Authenticated encryption per 4 MB chunk |
| **Stream Integrity** | Rogaway `STREAM` construction (Chunk Counter + EOF Flag in Nonce & AAD) | Prevents chunk reordering, truncation, and splice attacks |
| **Compression** | `Zstandard (Zstd)` applied per-chunk *before* encryption | Eliminates plaintext redundancy; verified by Poly1305 *before* decompression |
| **Memory Hygiene (Rust)** | `zeroize::ZeroizeOnDrop` + `libc::mlock` | Prevents master key swapping to disk and zeroes RAM on lock |

---

## Threat Model

### What SecureHUB Protects Against
1. **Lost or Stolen USB Drive (At-Rest Confidentiality):**
   * File contents, filenames, directory trees, and original file sizes are completely encrypted.
   * Only obfuscated '<128-bit-hex>.bin' files exist on the physical `exFAT` partition.
2. **Active Offline Tampering (At-Rest Integrity):**
   * Modifying a single bit inside any '.bin' file or `index.meta` causes immediate `Poly1305` authentication failure prior to Zstd decompression (preventing decompression bomb exploits).
   * Reordering two 4 MB chunks or truncating the end of a file is detected via the 64-bit chunk index and `FinalEOF` byte bound into both the Nonce and AAD.
3. **Forensic Remnants on Host Disk during Media Playback:**
   * Images, PDFs, and text files are decoded strictly in RAM.
   * Large videos are streamed over loopback `127.0.0.1` with a random 128-bit per-session token using $O(1)$ chunk seeking, leaving zero temporary files in '/tmp' or '%TEMP%'.

### Out of Scope
* **Compromised Host OS:** If the host computer is infected with a kernel keylogger or screen scraper while the vault is unlocked, the attacker can capture the password or read unlocked data.
* **Traffic Analysis on Total Vault Size:** While individual file names and directory hierarchies are hidden inside `index.meta`, an observer inspecting the raw `exFAT` partition can see the number of '.bin' blobs and their compressed sizes.

---

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for suspected cryptographic or security vulnerabilities.
Instead, use GitHub's [**Private Vulnerability Reporting**](https://github.com/kimiko88/SecureHUB/security/advisories/new) tab on this repository so we can coordinate a fix and release a patch prior to disclosure.
