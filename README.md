<div align="center">

# 🔐 SecureHUB (v0.5.0 — SVAULT03 / SVKEY04)

**High-Performance Cross-Platform Encrypted, Deduplicated & Self-Healing USB Virtual Filesystem**  
*Dual Implementation in **Go** (Fyne) & **Rust** (egui + Rayon + SIMD + Zeroize)*

[![CI/CD Auto-Release](https://github.com/kimiko88/SecureHUB/actions/workflows/release.yml/badge.svg)](https://github.com/kimiko88/SecureHUB/actions/workflows/release.yml)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go)](https://go.dev/)
[![Rust Edition](https://img.shields.io/badge/Rust-2021%20(SIMD%20%2B%20LTO)-DEA584?logo=rust)](https://www.rust-lang.org/)
[![Protocol](https://img.shields.io/badge/Protocol-SVAULT03%20%7C%20SVKEY04-6f42c1)](ARCHITECTURE.md)
[![ECC](https://img.shields.io/badge/Anti%20Bit--Rot-Reed--Solomon%20GF(256)-059669)](ARCHITECTURE.md)
[![Dedup](https://img.shields.io/badge/Deduplication-BLAKE3%20Keyed-d97706)](ARCHITECTURE.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-success.svg)](LICENSE)

[English](#-overview) • [Italiano](#-panoramica-italiano) • [Developer Guide](DEVELOPERS.md) • [Architecture](ARCHITECTURE.md) • [Security Policy](SECURITY.md)

</div>

---

## 🚀 Overview

**SecureHUB** transforms any standard USB flash drive or external SSD into a zero-trust, self-healing, hardware-agnostic encrypted vault that runs natively across **Windows, Linux, and macOS** without requiring kernel drivers for proprietary filesystems (such as LUKS, BitLocker, or APFS).

### Key Capabilities in v0.5.0
* **📤 Bidirectional Drag & Drop (Drag-In & Outbound Drag-to-Export):** Drag files or entire folder trees from your OS directly into the window to encrypt them (automatically excluding '.DS_Store', `Thumbs.db`, `desktop.ini`, `*.tmp`), or **drag any file/folder out of the window** (or onto the Desktop/OS Clipboard Dock) to decrypt and export it to your Desktop or `Ctrl+V` (`CF_HDROP` / `POSIX file` / `text/uri-list`) into any open folder.
* **🗺️ Interactive Disk Space Treemap:** Built-in *WinDirStat / DaisyDisk*-style Binary Space Partitioning (BSP) Treemap calculated in RAM. Hover to inspect compression ratios and click any block to open the file in RAM.
* **🕵️ Plausible Deniability (`SVKEY04` Dual-Slot Hidden Shadow Vault):** Fixed 199-byte `vault.key` with two indistinguishable 96-byte slots (`index.meta` vs `index.shadow`).
* **🧬 Content-Addressed Deduplication (`BLAKE3` Keyed Hash):** Identical 4 MB chunks across files or VM snapshots are stored on disk only once ($O(1)$ skip).
* **🛡️ Self-Healing Anti Bit-Rot (`Reed-Solomon GF(2^8)`):** '.ecc' sidecar files (`RSECC01`: 8 data + 4 Cauchy parity shards) automatically heal up to **33.3% damaged NAND sectors** before `Poly1305` verification.
* **🎬 $O(1)$ Random-Access Video Streaming & Zero-Temp RAM Viewers:** Built-in text editor, image viewer (`PNG/JPEG/GIF`), `PDF` reader in RAM, loopback `HTTP 206 Partial Content` (`Range`) media server, and native **FUSE / macFUSE / WinFsp** virtual drive mounting.
* **🚀 Automated Per-Commit Semantic Versioning & Release Matrix:** Every commit pushed to `main`/`master` automatically runs the test/fuzz suites, increments the semantic version tag (`v0.5.X`), and publishes all **6 cross-platform executables** to GitHub Releases.

---

## 🇮🇹 Panoramica (Italiano)

**SecureHUB** consente di formattare qualsiasi chiavetta USB in **exFAT** e di gestirvi un **Virtual Filesystem (VFS) cifrato, deduplicato e auto-riparante** su **Windows, Linux e macOS**:

1. **Trascinamento Bidirezionale (Drag-In & Drag-Out Export):** Trascina file e cartelle dentro il programma per cifrarli, oppure **trascina un file o una cartella fuori dai bordi della finestra** (o sulla Dock inferiore) per esportarlo direttamente sul Desktop o copiarlo negli appunti di sistema (`Ctrl+V` in qualsiasi cartella).
2. **Treemap Interattivo dello Spazio Disco:** Mappa a rettangoli proporzionali colorati per categoria con apertura immediata al clic.
3. **Plausible Deniability, Deduplicazione `BLAKE3` e Parità `Reed-Solomon GF(2^8)`:** Doppio vault nascosto (`index.shadow`), deduplicazione dei blocchi da 4 MB e riparazione automatica del bit-rot NAND.
4. **Rilascio Continuo Automatico (CI/CD):** Ogni commit su `main`/`master` genera automaticamente un nuovo tag semantico e pubblica una GitHub Release con i 6 eseguibili compilati.

---

## 🛠️ Quick Start

### Rust Edition (Full-Window `egui` + `Rayon` + `SIMD`)
```bash
cd secureusb-rs
cargo run --release
cargo test --release
```

### Go Edition (`Fyne v2` + Multi-Core Goroutines)
```bash
go mod tidy
go test -v -race ./internal/vault/...
go run .
```

---

## 📚 Documentation Index

* [**DEVELOPERS.md**](DEVELOPERS.md) — **Developer & Contributor Handbook** (Internals, Memory Layout, Threading, CGO/FUSE SDK setup, Outbound Drag Bridge, CI/CD Pipeline).
* [**ARCHITECTURE.md**](ARCHITECTURE.md) — Mathematical & binary specification of `SVAULT03`, `SVKEY04`, `BLAKE3`, and `Reed-Solomon GF(2^8)`.
* [**SECURITY.md**](SECURITY.md) — Threat model, Plausible Deniability guarantees, and vulnerability disclosure.
* [**CONTRIBUTING.md**](CONTRIBUTING.md) — Code formatting and PR checklist.
* [**CHANGELOG.md**](CHANGELOG.md) — Full version history.

---

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full details.
