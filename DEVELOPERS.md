# 👨‍💻 Developer & Internals Guide (SecureHUB)

This document provides low-level engineering details for programmers working on either the **Go** (`/`) or **Rust** (`/secureusb-rs`) implementation of **SecureHUB**.

---

## 1. Repository Layout & Module Responsibilities

```text
SecureHUB/
├── main.go                             # Go entrypoint
├── go.mod / go.sum                     # Go module definitions
├── internal/
│   ├── usb/
│   │   └── format.go                   # OS-native USB auto-discovery + exFAT formatting
│   ├── fuse/
│   │   └── mount.go                    # cgofuse bridge (FUSE2/3 Linux, macFUSE, WinFsp)
│   ├── vault/
│   │   ├── types.go                    # SVAULT03/SVKEY04 constants, structs, Nonce/AAD builder
│   │   ├── crypto_parallel.go          # Multi-core channel-of-channels FIFO encrypt/decrypt
│   │   ├── seeker.go                   # O(1) io.ReadSeeker/ReaderAt + loopback HTTP 206 server
│   │   ├── ecc_rs.go                   # Systematic Reed-Solomon GF(2^8) 8+4 Cauchy healer
│   │   ├── dedup_deniability.go        # Native RFC BLAKE3 keyed hash + SVKEY04 Dual-Slot Shadow
│   │   ├── vault.go                    # Thread-safe VFS CRUD, recursive ImportDir/ExportDir, Scrub
│   │   ├── vault_test.go               # Unit, Integration, E2E, Native Fuzz & Benchmark suite
│   │   └── v4_features_test.go         # Plausible Deniability, BLAKE3 Dedup & ECC Bit-Rot tests
│   └── ui/
│       ├── theme.go                    # SecureCyberTheme (Slate/Emerald dark palette + entropy math)
│       ├── preview.go                  # Zero-temp in-RAM image (PNG/JPG/GIF) & PDF stream parser
│       ├── treemap.go                  # Interactive BSP Treemap widget (hover + click-to-open)
│       ├── drag_export.go              # Outbound Drag-to-Export & OS Clipboard File Object bridge
│       └── app.go                      # Main Fyne v2 GUI, hot-plug poller & unplug panic watchdog
└── secureusb-rs/                       # Rust High-Performance Workspace
    ├── Cargo.toml                      # Dependencies & release LTO/codegen-units=1 profile
    ├── .cargo/config.toml              # Explicit AVX2 / BMI2 / SSE4.1 / NEON target-feature flags
    ├── src/
    │   ├── lib.rs / main.rs            # Rust crate root & GUI binary entrypoint
    │   ├── usb.rs                      # Cross-platform USB volume scanner & exFAT formatter
    │   ├── fuse_mount.rs               # Optional fuser integration (--features native-fuse)
    │   ├── vault/
    │   │   ├── types.rs                # MasterKey (ZeroizeOnDrop + libc::mlock), SVAULT03 types
    │   │   ├── crypto_parallel.rs      # Rayon work-stealing + AeadInPlace zero-copy + adaptive Zstd
    │   │   ├── seeker.rs               # O(1) VaultReadSeeker + raw TCP HTTP 1.1 Range server
    │   │   ├── ecc_rs.rs               # Reed-Solomon GF(2^8) encoder & Gauss-Jordan matrix healer
    │   │   ├── dedup_deniability.rs    # blake3::keyed_hash dedup + SVKEY04 Dual-Slot Shadow Vault
    │   │   └── mod.rs                  # Arc<SecureVault> RwLock CRUD, search, stats, scrub
    │   └── ui/
    │       ├── preview.rs              # In-RAM egui texture loader & lopdf text extractor
    │       ├── treemap.rs              # Full-canvas egui Painter BSP Treemap
    │       ├── drag_export.rs          # Outbound Drag-to-Export + CF_HDROP / AppleScript / xclip
    │       └── mod.rs                  # Full-bleed egui state machine + mpsc async worker threads
    ├── tests/
    │   ├── integration_e2e_fuzz.rs     # Multi-chunk tamper tests, E2E HTTP 206, Proptest suite
    │   └── v4_features_test.rs         # Rust Shadow Vault, BLAKE3 Dedup & Reed-Solomon ECC tests
    ├── benches/
    │   └── vault_bench.rs              # Criterion statistical throughput benchmarks
    └── fuzz/
        └── fuzz_targets/fuzz_seeker.rs # libFuzzer continuous fuzz target
```

---

## 2. Binary Compatibility Rules Between Go and Rust

Both implementations read and write the exact same '.secure_vault/' directory structure. When modifying any storage structure, you **must** preserve these invariants across both languages:

1. **Chunk Size (`ChunkSize = 4,194,304` bytes):** Every uncompressed chunk (except the final chunk) must be exactly $4\text{ MiB}$ so that integer division `targetChunk = offset / ChunkSize` yields the exact chunk index in $O(1)$ without scanning cumulative sizes.
2. **Nonce & AAD Construction (`buildChunkNonceAndAAD` / `build_chunk_nonce_and_aad`):**
   * `Nonce (24B)` = `StreamID (15B) || BigEndianUint64(ChunkIndex) (8B) || FinalFlag (1B: 0x00 or 0x01)`
   * `AAD (17B)` = `"SVAULT03" (8B) || BigEndianUint64(ChunkIndex) (8B) || FinalFlag (1B)`
3. **JSON Field Names in `index.meta` / `index.shadow`:**
   * All JSON keys use `snake_case` (`virtual_path`, `blob_id`, `is_dir`, `original_size`, `disk_size`, `chunk_sizes`, `chunk_refs`, `updated_at`, `chunk_ref_counts`).
   * Paths inside `Entries`` are always normalized to POSIX forward slashes starting with `/` (e.g., ``/Documents/report.pdf`).

---

## 3. Outbound Drag-to-Export Architecture (`drag_export`)

Because cross-platform windowing backends (`GLFW` in Fyne and `winit` in egui) trap mouse capture inside the OpenGL/Vulkan surface during internal widget drags, **SecureHUB** implements a hybrid **Outbound Drag & OS File Clipboard Bridge**:

1. **Gesture Initiation:**
   * In **Rust (`egui`)**: File and folder rows in `SidePanel` allocate `Sense::click_and_drag()`. When `resp.drag_started()` fires, `self.dragging_entry` stores the `FileEntry`, displays a floating ghost badge (`Order::Tooltip`), and expands the 3-slot **Export Drop Dock** at the bottom of the window.
   * In **Go (`Fyne`)**: List items use `DraggableFileRow` (implementing `fyne.Draggable` and `fyne.Tappable`).
2. **Drop Resolution:**
   * **Outer-Border / Desktop Drop:** Releasing the mouse button near or outside the window viewport border (`!screen_rect.shrink(18.0).contains(pos)`) or on the `🖥️ Desktop` slot spawns a background worker that decrypts the file or recursive folder tree directly to `~/Desktop` and invokes `explorer.exe /select,` (Windows), `open -R` (macOS), or `xdg-open` (Linux).
   * **OS File Clipboard (`CF_HDROP` / `POSIX file` / `text/uri-list`):** Dropping onto the `📋 OS Clipboard` slot extracts the decrypted item to a protected staging directory and registers the file handle in the OS shell clipboard so the user can press `Ctrl+V` (`Cmd+V`) inside any open File Explorer or Finder window.

---

## 4. Building C/CGO Dependencies Locally & in CI

The **Go** edition uses `Fyne v2` (OpenGL/GLFW) and `cgofuse` (FUSE/WinFsp), both of which require `CGO_ENABLED=1` and a C compiler:

* **Linux (Ubuntu/Debian):**
  ```bash
  sudo apt-get install -y build-essential libgl1-mesa-dev xorg-dev libfuse-dev exfatprogs pkg-config
  ```
* **Windows (MinGW-w64 + WinFsp Headers):**
  ```powershell
  # Ensure GCC (MinGW-w64) is in PATH and WinFsp headers are reachable:
  git clone --depth 1 [https://github.com/winfsp/winfsp.git](https://github.com/winfsp/winfsp.git) C:\winfsp_sdk
  $env:CGO_ENABLED = "1"
  $env:CGO_CFLAGS = "-IC:/winfsp_sdk/inc/fuse -IC:/winfsp_sdk/inc"
  go build -ldflags="-s -w -H=windowsgui" -o SecureUSB.exe .
  ```
* **macOS (Xcode Command Line Tools + Darwin FUSE Headers):**
  ```bash
  git clone --depth 1 [https://github.com/osxfuse/fuse.git](https://github.com/osxfuse/fuse.git) /tmp/macfuse_sdk
  mkdir -p /tmp/macfuse_sdk/include/fuse && cp -r /tmp/macfuse_sdk/include/*.h /tmp/macfuse_sdk/include/fuse/
  export CGO_CFLAGS="-I/tmp/macfuse_sdk/include/fuse -I/tmp/macfuse_sdk/include -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26"
  go build -ldflags="-s -w" -o secureusb-macos .
  ```

---

## 5. CI/CD Auto-Versioning & Per-Commit Release Pipeline

The workflow in ['.github/workflows/release.yml'](.github/workflows/release.yml) is designed so that **every push to `main` or `master` produces a versioned GitHub Release with all 6 executables**:

1. **`verify-and-test`:** Runs Go unit/integration/E2E tests with '-race', a 10-second Go fuzz smoke test, Go benchmarks, Rust release tests, and Criterion quick benchmarks.
2. **`build-matrix`:** Compiles `linux-amd64`, `windows-amd64`, and `macos-universal` for both Go and Rust in parallel.
3. **`publish-release`:**
   * Inspects the latest `vMAJOR.MINOR.PATCH` git tag.
   * Automatically increments `PATCH` by default (or `MINOR` if the commit message contains `[minor]`, or `MAJOR` if it contains `[major]`).
   * Generates `SHA256SUMS.txt`, creates the new Git tag on `GITHUB_SHA`, and publishes the GitHub Release with all 6 binaries attached.
