# Architecture & Protocol Specification (SVAULT03)

## 1. Two-Layer Filesystem Design

To achieve plug-and-play portability across Windows, Linux, and macOS without requiring administrator privileges to install filesystem drivers on every host machine, **SecureHUB** separates physical storage from logical cryptography:

1. **Physical Layer (`exFAT`):** Chosen because it is natively supported in read/write mode by Windows, Linux (`exfatprogs` / kernel 5.7+), and macOS, and supports files larger than 4 GiB.
2. **Logical VFS Layer (`SVAULT03`):** Stores an encrypted JSON metadata tree (`index.meta`) and a flat pool of chunked encrypted blobs (`.secure_vault/blocks/<UUID>.bin`).

---

## 2. $O(1)$ Random-Access Seeker Mathematics

Traditional compressed & encrypted streams require sequential decryption from byte 0 to reach an arbitrary offset $P$.
In `SVAULT03`, every file is split into fixed **uncompressed** chunks of size $C = 4\text{ MiB}$ ($4,194,304\text{ bytes}$). Because compressed chunks have variable sizes on disk, `FileEntry` records a compact array `ChunkSizes []uint32` inside the encrypted `index.meta`.

When `OpenReadSeeker` opens a file:
1. It precomputes the physical disk offset $O_k$ of chunk $k$ in $O(N)$ memory (only 8 KB of RAM for a 4 GB file):
   $$O_0 = 23 \quad (\text{8B Magic} + \text{15B StreamID})$$
   $$O_k = O_{k-1} + 4 + \text{ChunkSizes}[k-1]$$
2. When `Seek(P)` + `Read()` or `ReadAt(buf, P)` is called at virtual byte offset $P$:
   $$k = \left\lfloor \frac{P}{4,194,304} \right\rfloor, \qquad \delta = P \bmod 4,194,304$$
3. The seeker jumps directly to disk offset $O_k$, reads `4 + ChunkSizes[k]` bytes, verifies the `Poly1305` tag for chunk $k$, decompresses the 4 MiB block into its active cache slot, and slices from $\delta$.

---

## 3. Multi-Core Compression & Encryption Pipeline

* **Go Engine (`internal/vault/crypto_parallel.go`):** Uses a bounded **Channel-of-Channels** (`orderCh chan chan encResult`). The reader goroutine enqueues a result channel into `orderCh` *before* dispatching the 4 MiB job to the worker pool, guaranteeing that the writer goroutine drains completed chunks in strict `0, 1, 2, ...` order regardless of which CPU core finishes first.
* **Rust Engine (`secureusb-rs/src/vault/crypto_parallel.rs`):** Reads batches of chunks proportional to `rayon::current_num_threads()` and executes `into_par_iter()`, performing Zstd compression directly into the target packet slice followed by `AeadInPlace::encrypt_in_place_detached` to eliminate intermediate buffer copies.
