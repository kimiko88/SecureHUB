# Changelog

All notable changes to this project are documented in this file.

## [v0.3.0] — 2026-11-07
### Added
- **Protocol `SVAULT03`:** Added `ChunkSizes []uint32` metadata table enabling $O(1)$ random-access seeking across compressed & encrypted 4 MB chunks.
- **Multi-Core Parallel Pipeline:** Implemented parallel chunk compression (`Zstd`) and encryption (`XChaCha20-Poly1305`) across all CPU cores in both Go and Rust (`rayon`).
- **Rust High-Performance Edition (`secureusb-rs`):** Added complete Rust implementation with `ZeroizeOnDrop`, `mlock`, `AeadInPlace` zero-copy encryption, `AVX2/BMI2/NEON` SIMD flags, and `egui` native GUI.
- **Instant Video Streaming Server:** Added local `127.0.0.1` HTTP 1.1 `Range` (`206 Partial Content`) server for zero-temp media playback.
- **Native Virtual Drive Mount:** Added FUSE / macFUSE / WinFsp filesystem bridge (`internal/fuse`).
- **Zero-Temp RAM Viewers:** Added built-in image (`PNG/JPEG/GIF`) and `PDF` viewers operating strictly in memory.
- **CI/CD & Test Suite:** Added Unit, Integration, E2E, Fuzz (`testing.F`, `proptest`, `cargo-fuzz`), and Benchmark (`testing.B`, `Criterion`) suites plus GitHub Actions 6-binary release matrix.

## [v0.2.0] — 2026-11-07
### Added
- **Protocol `SVAULT02`:** Introduced 4 MB streaming chunked AEAD construction (`STREAM`) for constant-RAM multi-GB file handling.

## [v0.1.0] — 2026-11-07
### Added
- Initial cross-platform USB `exFAT` formatter and `SVAULT01` in-memory encrypted virtual filesystem with Fyne GUI.
