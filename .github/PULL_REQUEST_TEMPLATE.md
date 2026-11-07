## Summary of Changes
- 

## Verification Checklist
- [ ] Preserves `SVAULT03`, `SVKEY04`, and `RSECC01` binary compatibility between Go and Rust
- [ ] `go test -v -race ./internal/vault/...` passes (including `TestV4_*`)
- [ ] `cargo test --release` passes inside `secureusb-rs/` (including `v4_features_test`)
- [ ] No sensitive keys or unencrypted temporary files are written to disk
