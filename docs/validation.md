# Validation report — 2026-10-17

Development host: Linux x86_64, Rust 1.99.1, sevenz-rust2 0.24.0.

Passed locally:

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --locked`: 29 module tests + 3 CLI integration tests
- `cargo build --release --locked`
- Generate a synthetic 7z, inspect it with the release CLI, read JSON bytes correctly

Coverage includes encrypted headers, Unicode passwords, wrong passwords, later solid-member reads under a small request cap, CRC failures, block-only CRC verification, unsupported stream layout rejection, traversal/collision/link rejection, resource limits, Upper locking, durable rename/tombstones, reopened process state, each partial rename-record prefix, corrupt records, and byte-identical source archives after CLI activity.

Fixtures are generated in tests from synthetic byte strings. Block-only CRC and unsupported stream-layout regressions additionally mutate parsed metadata to exercise the exact dependency integration edge cases. These are not claims that every third-party archive encoder has been covered.

Official 7-Zip 26.04 interoperability subsequently passed 12 format/encryption combinations and 60 byte comparisons; see [the reproducible report](7zip-interoperability.md).

Not tested: arbitrary power-loss sector damage, disk-full/fsync-failure injection, NAS disconnection, FUSE mounts, NW.js gameplay, macOS/Windows behavior, or production performance. CI configuration is included but no remote CI run has occurred yet.

## Byte-operation slice

The subsequent Overlay slice passed partial-write/copy-up, zero-filled holes, grow/shrink/zero truncation, overflow and malicious-path rejection, lower deletion/reopen, lower rename overwrite/recovery at every incomplete frame prefix, and near-limit rename failure tests. A separate CLI integration test verifies these across independent processes with the archive byte-identical. Independent source review found and verified a fix for the longer-destination near-limit rename case. The full 12-combination/60-comparison official 7-Zip matrix was rerun successfully after these changes.
