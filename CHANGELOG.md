# Changelog

All notable changes to **SecureHUB** are documented in this file.

## [v0.5.0] — 2026-11-08
### Added
- **Outbound Drag-to-Export (Files & Folders):** Added ability to drag files and folders out of the GUI (via outer-border drop or the interactive 3-slot Export Dock) directly to the OS `Desktop`, a chosen folder, or the native OS File Clipboard (`CF_HDROP` on Windows, `POSIX file` on macOS, `text/uri-list` on Linux) for instant `Ctrl+V` pasting in File Explorer.
- **Interactive Disk Space Treemap:** Added *WinDirStat / DaisyDisk*-style BSP Treemap view in both Go (`Fyne`) and Rust (`egui`) with color-coded file categories, hover compression tooltips, and click-to-open in RAM.
- **Full-Bleed Responsive `egui` Layout:** Redesigned the Rust GUI to occupy 100% of the window viewport (`auto_shrink([false, false])` and 2-column full-height unlock dashboard).
- **Automated Per-Commit Semantic Versioning CI/CD:** Updated GitHub Actions (`release.yml`) to automatically bump semantic version tags (`v0.5.X`) and publish all 6 executables on every push to `main`/`master`.
- **Developer Handbook (`DEVELOPERS.md`):** Added deep technical documentation for contributors covering internals, wire compatibility, CGO/FUSE headers, and the outbound drag bridge.

## [v0.4.0] — 2026-11-07
### Added
- **Plausible Deniability (`SVKEY04` Dual-Slot + `index.shadow`)**, **Content-Addressed Deduplication (`BLAKE3` Keyed)**, **Anti Bit-Rot Self-Healing (`RSECC01` Reed-Solomon $\text{GF}(2^8)$)**, **Key Wrapping**, **Global `Poly1305` Scrubbing**, **USB Auto-Detection**, and **Inbound Drag & Drop**.
