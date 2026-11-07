## Summary of Changes
- 

## Verification Checklist
- [ ] Preserves `SVAULT03` binary compatibility between Go and Rust
- [ ] `go test -v -race ./internal/vault/...` passes
- [ ] `cargo test --release` passes inside `secureusb-rs/`
- [ ] No sensitive keys or unencrypted temporary files are written to disk
