# Changelog

All notable changes to **SecureHUB** are documented in this file.

## [v0.4.0] — 2026-11-07
### Added
- **Plausible Deniability (`SVKEY04` Dual-Slot + `index.shadow`):** Added hidden second vault unlocked with a separate secret password; unconfigured slots are filled with CSPRNG noise for mathematical indistinguishability.
- **Content-Addressed Deduplication (`BLAKE3` Keyed):** Added 4 MB chunk deduplication (`WriteStreamDedup` / `write_stream_dedup`) using `BLAKE3_Keyed(DEK, chunk)` and per-chunk reference counting.
- **Anti Bit-Rot Self-Healing (`RSECC01` Reed-Solomon $\text{GF}(2^8)$):** Added '.ecc' parity sidecars (8 data + 4 Cauchy parity shards + `SHA-256`) with automatic Gauss-Jordan healing for `index.meta`, `index.shadow`, and `vault.key`.
- **Instant Password Change (Key Wrapping) & Global `Poly1305` Scrubbing:** Added millisecond password rotation and full-drive multi-core integrity scrubbing.
- **Cross-Platform USB Auto-Detection & Emergency Unplug Panic Lock:** Added automatic USB volume discovery, hot-plug polling, and immediate RAM key zeroization upon physical USB removal.
- **Recursive Folder Import/Export, Drag & Drop & OS Junk Filter:** Added folder tree import/export, native GUI Drag & Drop, and automatic filtering of '.DS_Store', `Thumbs.db`, `desktop.ini`, `._*`, `~$*`, and `*.tmp`.
- **Cyber-Dark UI, Instant RAM Search, Breadcrumbs & Async Loading Spinners:** Added `SecureCyberTheme`, sub-millisecond RAM search bar, interactive breadcrumb navigation, compression telemetry bar, and animated busy modals.

## [v0.3.0] — 2026-11-07
### Added
- **Protocol `SVAULT03`:** Added `ChunkSizes []uint32` metadata table for $O(1)$ random-access video streaming (`HTTP 206 Range`), FUSE/WinFsp virtual disk mounting, zero-temp RAM viewers for images/PDFs, and the **Rust** (`rayon` + `SIMD` + `Zeroize`) edition.

## [v0.2.0] — 2026-11-07
### Added
- **Protocol `SVAULT02`:** Introduced 4 MB streaming chunked AEAD construction (`STREAM`).

## [v0.1.0] — 2026-11-07
### Added
- Initial cross-platform USB `exFAT` formatter and `SVAULT01` encrypted VFS in Go.
