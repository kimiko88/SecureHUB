# Contributing to SecureHUB

Thank you for your interest in contributing to **SecureHUB**! Because this project maintains two binary-compatible engines (**Go** and **Rust**) implementing the `SVAULT03` specification, any change to the wire format must be reflected and tested in both implementations.

## Pre-Submission Checklist

Before opening a Pull Request, please verify that all checks pass locally:

### 1. Go Verification
```bash
gofmt -s -w .
go vet ./...
go test -v -race ./internal/vault/...
```

### 2. Rust Verification
```bash
cd secureusb-rs
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --release
```

## Adding Features to SVAULT03
* Never modify the 24-byte Nonce or 17-byte AAD layout without bumping the magic header (`SVAULT03` -> `SVAULT04`) and adding backward-compatibility tests.
* Every new I/O path must preserve the **Authenticate-before-Decompress** invariant.
