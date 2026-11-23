# Experimental macOS playability probe

This branch restores the missing implementation from the staged PR as a coherent,
limited probe. It does **not** establish real-game playability. Existing core
commands still have their strict Linux hard-limit contract. The new `probe-read`
and `mount-ro` paths use a dedicated decoder child instead of weakening that API.

## Backend decision (sources checked 2026-10-18)

| Aspect | macFUSE FSKit | macFUSE kernel |
| --- | --- | --- |
| macFUSE 5.5 package | Apple Silicon and Intel, macOS 12+ package | Same |
| API/platform floor | FSKit itself: macOS 15.4+; this **read-only** probe: macOS 26.4+ and macFUSE 5.5+ | This probe: macOS 12+, macFUSE 5.5+ |
| Installation/security | Separately installed/activated FSKit extension, entirely user space; no Recovery security downgrade | Separately installed/approved kernel extension; Apple Silicon normally needs Reduced Security and user-managed identified-developer extensions; approvals and restart |
| Mount location | macFUSE documents `/Volumes`; probe restricts to a direct child | Existing empty directory, owned by invoking user, not group/other writable |
| Important limitations | Backend option support and performance differ. Read-only support is new; credentials/open flags require real-host validation | More complete/mature filesystem support; recent macOS VMs and external boot configurations may not load third-party kexts |
| Save acceptance | Not accepted; read-only only | Also read-only in this milestone; Upper tested separately |

The 5.5 announcement adds read-only mounting on 26.4+ and fixes spaces/non-ASCII
mount paths. It also states that FSKit lacks a per-file fsync callback; on macOS
27 close cannot report a flush failure. Therefore a writable mount cannot be
assumed to provide the existing WAL durability contract merely because it mounts.
The wiki predates this release by one day and still lists always-read/write opens;
the newer release establishes the read-only version floor, while actual callback
flags remain an explicit acceptance gate. No permissive fallback is implemented.

Sources:
- [macFUSE 5.5.0 release](https://macfuse.github.io/2026/10/17/macfuse-5.5.0.html)
- [macFUSE backend selection and restrictions](https://github.com/macfuse/macfuse/wiki/FUSE-Backends)
- [Installation and Apple Silicon security requirements](https://github.com/macfuse/macfuse/wiki/Getting-Started)
- [Apple FSKit](https://developer.apple.com/documentation/fskit/)

A native Apple FSKit implementation needs an app extension. This Rust adapter
instead delegates transport to separately installed macFUSE through its libfuse2
API. It is not a signed/notarized app bundle, installer, or independently shipped
FSKit extension. This project never installs/enables a kext, changes Recovery
policy, grants credentials, or bypasses platform prompts. CI does not prove that
an extension is installed or approved on a user's Mac.

## Security and resource boundaries

- Child parses the archive only after limits are installed. Password and path use
  a length-bounded private stdin pipe; password is not in argv, environment, or logs.
- Linux: hard address space <=512 MiB, cumulative CPU <=120 seconds, no core dumps,
  `no_new_privs`, and non-dumpable child. The embedding parent keeps its own limits.
- macOS: hard CPU <=120 seconds and no core dumps; parent samples libproc RSS every
  20 ms and kills on >512 MiB **or sampler failure**, including while idle. This is
  a sampled soft memory bound and may overshoot. It is **not equivalent to Linux's
  hard address-space ceiling**. Other operating systems fail closed.
- Every exchange, including nonblocking request writes, has a 30-second wall
  timeout. Timeout/protocol/worker errors poison the worker; the owner kills and
  reaps it. Destruction closes pipes, stops the watcher before reaping (avoiding
  PID-reuse signalling), and joins the bounded response reader.
- Requests <=16 KiB; initial metadata <=4 MiB and <=16,384 entries; responses <=16
  MiB plus a status byte. One response is queued and at most one additional frame
  is being read. The parent retains bounded metadata, at most 1,024 mount handles,
  and per-call file buffers. A file is decoded on demand, never a whole archive
  into a directory. Solid archives can still require decoding preceding members.
- Watchdog failure is fatal; there is no unsupervised macOS fallback. This is not
  filesystem/network syscall sandboxing or protection from malicious native game
  code. No secret-memory zeroization guarantee is made. Use only explicitly trusted
  NW.js runtimes and games. `noexec` is not a JavaScript sandbox.
- Archive source is opened read-only; inode/size/timestamp checks bracket hashing
  and reads, including cache hits. These checks detect ordinary changes; they are
  not a cryptographic immutable snapshot of a concurrently rewritten NAS file.
- The independent `Filesystem::with_upper` API binds an existing local Store to
  the archive hash. Only an explicit save subtree can be modified; writes sync
  through the existing WAL. Other resource paths cannot be overlaid or tombstoned.
  The caller must supply a trusted private **local** directory. No NAS type detection,
  synchronization, original-7z rewrite, or mounted-save support is implemented.

## Reproducible local probe

Generate only redistributable synthetic content (layout markers are not licensed
RPG Maker engine code):

```sh
cargo run --locked --example make_probe -- /tmp/synthetic-games.7z
cargo run --locked -- probe-read /tmp/synthetic-games.7z 'MV 遊戲/data/probe.json'
```

Build the optional adapter using separately installed libfuse2 development headers
on Linux or macFUSE headers/libraries on macOS:

```sh
# macOS may require: export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
cargo build --locked --features fuse
# Prepare an empty, private user-owned mountpoint yourself.
# FSKit must be a direct /Volumes child; provisioning it may need administrator action.
target/debug/rpg-archive-launcher mount-ro /tmp/synthetic-games.7z '/Volumes/RPG Probe' fskit
# Use `kernel` instead on an already authorized macFUSE kernel host, or Linux.
```

The mount stays in the foreground and is single-threaded. It exposes read-only
files and directories, rejects all mutations, disables normal file caching, and
bounds open handles. Unmount through the OS before stopping it. There is no
writable mount flag. The API's save-prefix methods are not connected to these
callbacks. Extended attributes, locks, native executables/modules and arbitrary
POSIX behaviors are not claimed supported.

In another terminal, with an already installed trusted NW.js and a separate local
profile directory owned by you with mode 0700:

```sh
target/debug/rpg-archive-launcher launch-directory '/Volumes/RPG Probe' 'MV 遊戲' '/Applications/nwjs.app' '/path/to/private-profile'
```

NW.js officially supports launching a directory containing `package.json`.
The launch plan validates containment, a local main file, external runtime,
and private profile; arguments are passed directly without a shell. The fixture
shows PASS only after both Node file reads and browser fetch load a mounted JSON
asset. Repeat with `MZ 遊戲`. A real-game title screen/save/reload remains a separate,
licensed-content acceptance test. Sources: [NW.js getting started](https://docs.nwjs.io/For%20Users/Getting%20Started/),
[manifest](https://docs.nwjs.io/References/Manifest%20Format/).

## Validation ledger

Run `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`,
`cargo test --locked`, and repeat clippy/tests with `--features fuse` where headers
are available. `tests/probe.rs` uses actual encrypted 7z subprocess decoding for
MV/MZ-shaped fixtures, verifies unchanged source bytes and no extracted files,
round-trips a separate Upper WAL, invalidates mutated sources, and exercises a
nonreading child through its full 30-second timeout plus EOF failure.

The workflow runs Linux default/FUSE builds, 7-Zip interoperability, and a conditional
real Linux mount smoke. Missing `/dev/fuse` is explicitly **SKIP**, not acceptance.
The macOS job runs native worker/library tests without installing a kernel component;
it does not compile the macFUSE C adapter. Local Apple Silicon cross-check compiles
Rust only, not Apple linking or execution.

Still unverified until explicitly recorded on a real host:
- macFUSE C adapter on macOS, extension activation and successful FSKit/kernel mount
- Same-UID callback credentials and readonly open flags under FSKit 5.5/26.4+
- Actual NW.js GUI fixture result, Intel/Apple Silicon runtime compatibility
- Actual MV/MZ gameplay, latency, native module compatibility, save/reload
- Writable-mounted POSIX semantics and reliable application-observed save errors

Do not call this branch production-ready or weaken these gates to make CI green.
