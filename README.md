# rpg-archive-launcher

> This branch adds an experimental supervised decoder, read-only FUSE adapter,
> independent save-prefix Upper API, and explicit NW.js directory launch.
> See [macOS probe and acceptance limits](docs/macos-playability.md).
> Real macOS mounts, NW.js gameplay, and mounted saves are not yet accepted.
> The core-command description below remains applicable to the original CLI.

An experimental Rust core for reading encrypted 7z RPG Maker resources in memory and keeping user changes in a durable, separate local Upper store.

**Status: first CLI/core prototype, not a playable launcher.** There is no filesystem mount or NW.js execution yet. Linux tests do not establish macOS FSKit or Windows WinFsp compatibility.

## What works in this slice

- Inspect single 7z archives and identify MV/MZ runtime candidates from metadata.
- Read an entry to memory/stdout, with bounded resource policies and no extraction directory.
- Persist local save data, tombstones and atomic save renames in a single-writer log.
- Read Upper first, then immutable archive contents with `overlay-read`.
- Bounded byte-range reads, partial writes with copy-up, zero-filled holes, truncate, unlink and atomic lower-file rename. Read operations never copy resource payloads into Upper.
- Synthetic archive tests and save-store recovery tests; no commercial game data required.
- [Official 7-Zip 26.04 interoperability](docs/7zip-interoperability.md): 12 combinations and 60 byte comparisons passed.

Original archives are opened read-only. There is no automatic archive update, NAS sync, full-extraction fallback, runtime download or game execution.

## Build and use

Install a current stable Rust toolchain from [rustup.rs](https://rustup.rs), then:

```sh
cargo test --locked
cargo build --release --locked
cargo run --example make_demo -- demo.7z
cargo run -- inspect demo.7z
cargo run -- read demo.7z data/System.json
cargo run -- overlay-bind demo.7z /private/local/path/game.wal
cargo run -- save-put /private/local/path/game.wal save/file1.rpgsave ./new-save
cargo run -- overlay-read demo.7z /private/local/path/game.wal save/file1.rpgsave
cargo run -- save-rename /private/local/path/game.wal save/file1.rpgsave save/file2.rpgsave
cargo run -- save-delete /private/local/path/game.wal data/System.json
cargo run -- overlay-read-at demo.7z /private/local/path/game.wal data/System.json 0 16
cargo run -- overlay-write-at demo.7z /private/local/path/game.wal save/file1.rpgsave 4 ./patch-bytes
cargo run -- overlay-truncate demo.7z /private/local/path/game.wal save/file1.rpgsave 0
cargo run -- overlay-rename demo.7z /private/local/path/game.wal save/file1.rpgsave save/file2.rpgsave
```

Encrypted archives accept a single UTF-8 password line via stdin with `--password-stdin`. Feed it using your own secure password input or secret manager; do not put secrets in shell command arguments or history. The prototype does not save passwords. It does not promise locked or zeroized memory.

`read` and `save-get` explicitly output plaintext bytes to stdout. Redirecting stdout creates a plaintext file at your direction. The launcher itself does not create unpacked resource files. OS swap, crash dumps, runtime caches and future game writes are separate concerns.

## Safety and boundaries

- Public archive library access and CLI are currently Linux-only: a 512 MiB process virtual-address-space ceiling is applied before parsing untrusted headers. This is not an RSS guarantee or sandbox. Allocation exhaustion can terminate the process. A 120-second CPU-time ceiling also applies, including malicious header key derivation; large solid reads may hit it. `Archive::open` fails before opening/parsing unless both hard ceilings are already installed. The CLI opts in explicitly; embedding applications must use a dedicated limited host rather than silently limiting their GUI/server. CPU accounting is cumulative across all host threads and requests. Existing allocations are not removed by lowering limits. See [the library resource contract](docs/architecture.md#library-resource-contract).
- Entry, dictionary and cache limits are reported by `inspect`; unsupported layouts/codecs are rejected, not silently extracted.
- Large solid blocks can require decoding preceding files repeatedly. This prototype is not the final block-coalescing scheduler and does not claim acceptable game latency.
- Each Overlay WAL binds a random stable game ID to the SHA-256 of its accepted immutable archive revision. Different archives/revisions fail closed; binding requires a new empty WAL. Existing populated legacy WALs are not automatically migrated. Opening an Overlay reads the entire source archive to verify its digest, including across NAS; see the [binding policy](docs/architecture.md#archive-binding-policy).
- Upper is **plaintext**. Keep its log in a private, trusted directory on a local filesystem. Source archive encryption does not encrypt saves.
- Save persistence is separate from “synced to NAS” and “merged into archive.” Neither latter operation exists yet.
- Upper currently requires Unix filesystem semantics and fails closed on other systems. Upper WAL must not be shared over SMB/NAS between active devices. One writer is enforced locally; cross-device coordination is not implemented.
- COW is not a sandbox. Future NW.js games can execute code with user privileges.
- The runtime detector is a heuristic only, with reports capped at 512 candidates and 64 native modules per candidate. Native `.node`/DLL dependencies are reported and not repaired.
- Only file-level Upper operations are implemented. General POSIX directory/rename semantics and open-handle behavior remain future VFS work. Byte operations commit a bounded full-file replacement per mutation, rather than journaling individual ranges. `read_at` also buffers the whole file and currently rejects files around 16 MiB even for a small slice; it is a correctness prototype, not the final streaming data path.

## Planned acceptance gates

1. Benchmark cold/warm solid block reads, decode amplification and peak RSS against official 7-Zip fixtures.
2. Linux FUSE adapter, with ordinary file operations and runtime lifecycle tests.
3. macOS Apple Silicon FSKit/macFUSE probe and actual MV/MZ play/save/reopen tests.
4. Persistent save snapshots, conflict branches, interrupted-operation recovery and opt-in validated archive commit.
5. Independent Windows WinFsp semantics and playability tests.
6. Tauri management UI, isolated from game content.

This environment has no `/dev/fuse`, NW.js install or macOS/Windows host. Mounting and playability have not been tested. See [design notes](docs/architecture.md).

## License

Apache-2.0 for this project's code. Third-party dependencies have their own licenses. No macFUSE, WinFsp or NW.js binaries are bundled. Packaging and redistribution require a separate dependency/license review.
