# Architecture and validation scope

The core stays separate from platform mounts and runtimes:

- `archive`: index validation, encrypted 7z decode, bounded resource policy, memory cache.
- `save`: a local append-only checksummed transaction log, single-writer lock, durable acknowledgement, tombstones and transactional rename.
- `runtime`: metadata-only MV/MZ candidate detection.
- `vfs`: file-level Overlay byte operations with bounded whole-file buffers, copy-up on actual mutation, zero-filled growth, and atomic source tombstone + target data for lower renames.
- CLI: inspection, stdout reads and explicit local-save operations. Linux address-space limit applies before archive parsing.

Stable game identity is now separate from the accepted archive revision: the WAL stores a random 128-bit ID and a SHA-256 source revision. Overlay construction verifies that binding before serving contents. There is still no automatic game library or cross-device identity service.

Resource files never map directly to host filesystem paths. This avoids extraction traversal, but archive names still require validation to ensure later mount safety. Unknown and ambiguous layouts should be rejected rather than guessed.

A full VFS must eventually implement lookup, read_at, write_at, truncate, rename, unlink and fsync with independent Linux/macOS/Windows adapters. Merely opening read/write must not trigger copy-up. This prototype implements the file-level byte operations independently of platform APIs; directory operations, open handles and adapters remain unimplemented.

## Upstream references checked during implementation

- [sevenz-rust2 upstream](https://github.com/hasenbanck/sevenz-rust2), API and downloaded 0.24.0 crate sources: archive readers/writers and solid-block behavior.
- [ArchiveReader API](https://docs.rs/sevenz-rust2/0.24.0/sevenz_rust2/struct.ArchiveReader.html): `read_file` has solid decoding costs; no assumption of direct random seeks.
- [NW.js getting started](https://docs.nwjs.io/en/latest/For%20Users/Getting%20Started/): directory/package execution is the intended future integration boundary.
- [Rust File sync_all](https://doc.rust-lang.org/std/fs/struct.File.html#method.sync_all): durable save acknowledgement depends on filesystem/OS semantics, not just a successful buffered write.

## Validation labels

“Unit/integration tests pass” means only the tested synthetic operations on the development Linux filesystem. It does not mean power-cut durability, SMB semantics, official 7-Zip interoperability, mounted filesystem correctness, platform sandboxing or actual game compatibility. Those require independent acceptance tests.

## Recovery precision

The save log recovers an incomplete final record by truncating it to the last complete valid transaction. A complete-length frame with bad checksum or corrupt framing fails closed; this prototype has no salvage UI and does not silently discard potentially acknowledged records. Prefix-truncation tests are not a substitute for arbitrary torn-sector or real power-failure tests. Keep independent backups before using important saves.

## Initial independent review

Review identified two upstream-reader integration traps: stopping early in a solid block may omit block-only CRC validation, and streamless entries interleaved in a solid block do not match the dependency's iteration assumptions. The reader now drains and verifies the full block when a target lacks an individual CRC, rejects entries without either integrity source, and rejects the unsupported interleaved layout. Regression tests cover both policies. See code/tests for the current policy rather than treating crate support as a platform compatibility guarantee.

## Overlay mutation semantics

`read_at` never persists resource contents. Opening its Upper store can create an empty WAL or recover a truncated tail; this is distinct from copying resource payloads up. `write_at` with nonempty bytes creates missing/deleted files or replaces the requested range of a bounded full-file copy. Holes are zero-filled. Empty writes are no-ops. Truncation requires an existing file; truncating to zero requires no lower decode. Mutations return only after the Store has fsynced their complete transaction.

A lower-file rename records both destination contents and the source tombstone in one WAL frame, including replacement of an existing destination. The Store remains single-writer. Whole-file buffering imposes a conservative per-file cap below 16 MiB, plus the Store's aggregate live-state and 256 MiB log limits. This is intended to prove semantics before introducing paged copy-up, handles and mounted filesystem behavior.

## Archive binding policy

A new empty WAL receives a random 128-bit game ID and the source archive's SHA-256 revision in one fsynced metadata transaction. This metadata has no file path or password. The first Overlay open binds even when the subsequent requested read/write fails; this metadata initialization is distinct from resource copy-up. Reopening the same revision retains the ID; any different revision is rejected before Overlay reads/writes. The digest streams through the same open archive descriptor, restoring its position and checking metadata around hashing. Concurrent mutation of that source is unsupported: callers must provide an exclusively immutable archive. Metadata checks detect some changes but are not a proof against all in-place-write races.

Every Overlay open reads the full compressed archive, including over NAS. This initial correctness design can be expensive for large libraries and remains subject to the CLI CPU budget. Source-path replacement is detected on the next open because the newly opened file is fully hashed.

Use `overlay-bind ARCHIVE WAL` before standalone save commands when creating a game store. Populated unbound legacy WALs fail closed: no automatic migration, identity reassignment or revision acceptance exists. Preserve the legacy WAL and its backup; a future explicit migration/export workflow must validate the intended source and retain the stable ID across legitimate archive revision updates.

Existing WALs exposing group/world permissions are rejected instead of silently changing access settings. Plaintext Upper remains distinct from source encryption. After an I/O failure a poisoned Store refuses reads as well as writes until reopened for recovery.

## Library resource-isolation limitation

`Archive::open` checks the packed next-header size before parsing, but the upstream metadata parser can expand encrypted metadata or perform key derivation before payload limits are available. The CLI establishes Linux address-space and CPU limits first. Direct library callers must supply equivalent process isolation for untrusted archives; the library API does not itself guarantee metadata/KDF resource bounds. This remains an explicit unresolved prototype limitation.
