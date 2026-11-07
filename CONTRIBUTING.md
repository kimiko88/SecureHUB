# Contributing to SecureHUB

Thank you for contributing to **SecureHUB**! Because this repository maintains two 100% binary-compatible engines (**Go** and **Rust**) implementing the `SVAULT03` (stream), `SVKEY04` (dual-slot key envelope), and `RSECC01` (Reed-Solomon parity) formats, any protocol change must be reflected and tested in both languages.

## Pre-Submission Verification Checklist

### 1. Go Suite
```bash
gofmt -s -w .
go vet ./...
go test -v -race ./internal/vault/...
```

### 2. Rust Suite
```bash
cd secureusb-rs
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --release
```

## Architectural Invariants
1. **Authenticate-Before-Decompress:** Never pass unauthenticated bytes to `Zstd`.
2. **Plausible Deniability Indistinguishability:** Never write plaintext markers or flags indicating whether Slot 1 (`index.shadow`) has been configured by the user.
3. **OS Junk Exclusion:** Ensure `ShouldIgnoreFile` (Go) and `should_ignore_entry` (Rust) stay synchronized.
