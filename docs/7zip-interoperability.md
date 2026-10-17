# Official 7-Zip interoperability — 2026-10-17

Tested with the official Linux x86-64 **7-Zip 26.04 (2026-10-05)** distribution, linked by [7-zip.org/download.html](https://www.7-zip.org/download.html):

- Distribution: https://github.com/ip7z/7zip/releases/download/26.04/7z2604-linux-x64.tar.xz
- Observed distribution SHA-256: `fc0327ba27e89bd086cf426dff17d77de582953cdbbc10a6576540a06853ffcd`
- The checksum records the downloaded artifact; it is not an independent authenticity signature.
- No official 7-Zip binary is bundled in this repository or source archive.

## Reproduce

Obtain an official 7-Zip console executable separately, then:

```sh
cargo build --release --locked
python3 scripts/test_7zip_interop.py /path/to/7zz
```

The script creates and removes its own temporary synthetic files. It never opens a game library or NAS. Its fixed Unicode password is explicitly public test data and is passed to official 7-Zip as a fixture-generation argument. The launcher itself receives passwords through stdin. Do not adapt this argument pattern for real passwords.

## Results

All 12 combinations passed:

- LZMA and LZMA2, 1 MiB dictionary, single-threaded official encoder
- Solid and non-solid
- No encryption, content encryption with visible header, content plus header encryption

For each combination, all five fixture entries were read by both the launcher and `7zz x -so`, then compared with the original bytes: **60 byte comparisons passed**. Fixtures include an empty file, Unicode paths and text, JSON, synthetic save bytes, and a 256 KiB binary resource. `7zz t` also accepted every generated archive.

The launcher rejected incorrect passwords in all eight encrypted combinations. SHA-256 checks confirmed that archive reads did not modify source files. Both readers rejected a deliberately corrupted COPY payload; the launcher also rejected a truncated next-header archive.

In the reverse direction, official `7zz t` accepted the three-entry LZMA2 archive produced by `cargo run --example make_demo`; `7zz x -so ... data/System.json` returned the expected JSON. This reverse check covers the demo writer only, not encrypted archive commit (which is not implemented).

## Limits of this result

This is a concrete compatibility matrix, not support for every 7z feature. Filters such as BCJ, split archives, SFX, alternative codecs, ambiguous filenames and unsupported interleaved streamless layouts remain unsupported. The matrix does not establish production latency, memory RSS bounds, NAS behavior or actual game playability.
