#!/usr/bin/env python3
"""Optional official 7-Zip cross-implementation test; synthetic public data only.

Usage: python3 scripts/test_7zip_interop.py /path/to/7zz [launcher-binary]
Does not download software, read games, or extract user archives.
The fixed fixture password below is public test data, NOT a real credential.
"""
import hashlib
import pathlib
import subprocess
import sys
import tempfile

SEVENZIP = str(pathlib.Path(sys.argv[1]).resolve())
LAUNCHER = str(pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "target/release/rpg-archive-launcher").resolve())
PASSWORD = "public-fixture-秘密🔑"


def command(args, *, cwd=None, data=None, success=True):
    result = subprocess.run(args, cwd=cwd, input=data, capture_output=True, timeout=45)
    if (result.returncode == 0) != success:
        raise AssertionError(f"unexpected exit {result.returncode}: {args[0:2]}\n{result.stderr.decode(errors='replace')}\n{result.stdout[:1000]!r}")
    return result


def launcher(verb, archive, entry=None, password=None, success=True):
    args = [LAUNCHER, verb, str(archive)]
    if entry is not None:
        args.append(entry)
    if password is not None:
        args.append("--password-stdin")
    return command(args, data=(password + "\n").encode() if password else None, success=success)


with tempfile.TemporaryDirectory(prefix="rpg-official-interop-") as root:
    root = pathlib.Path(root)
    source = root / "source"
    source.mkdir()
    fixtures = {
        "data/System.json": b'{"gameTitle":"Synthetic interoperability fixture"}',
        "data/empty.json": b"",
        "遊戲/地圖.json": '{"name":"テスト地圖"}'.encode(),
        "resources/large.bin": bytes(range(256)) * 1024,
        "save/original.rpgsave": b"synthetic original save",
    }
    for name, data in fixtures.items():
        destination = source / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    checked = 0
    for codec in ("LZMA", "LZMA2"):
        for solid in (False, True):
            for encryption in ("none", "content", "header"):
                archive = root / f"{codec}-{solid}-{encryption}.7z"
                args = [SEVENZIP, "a", "-t7z", f"-m0={codec}", "-md=1m", "-mmt=1", "-ms=on" if solid else "-ms=off"]
                password = None if encryption == "none" else PASSWORD
                if password:
                    # Public synthetic fixture string; never use this pattern for real secrets.
                    args += [f"-p{PASSWORD}", "-mhe=on" if encryption == "header" else "-mhe=off"]
                command(args + [str(archive), "."], cwd=source)
                command([SEVENZIP, "t", str(archive)] + ([f"-p{PASSWORD}"] if password else []))
                before = hashlib.sha256(archive.read_bytes()).digest()
                report = launcher("inspect", archive, password=password).stdout.decode()
                assert f"Solid: {str(solid).lower()}" in report, report
                for name, expected in fixtures.items():
                    actual = launcher("read", archive, name, password).stdout
                    official = command([SEVENZIP, "x", "-so", str(archive), name] + ([f"-p{PASSWORD}"] if password else [])).stdout
                    assert actual == official == expected, (codec, solid, encryption, name)
                    checked += 1
                if password:
                    launcher("read", archive, "data/System.json", "incorrect-test-password", success=False)
                assert hashlib.sha256(archive.read_bytes()).digest() == before
                print(f"PASS {codec} solid={solid} encryption={encryption}: {len(fixtures)} entries")

    # COPY gives an unambiguous byte-level payload corruption (first byte after the 7z signature).
    original = root / "copy.7z"
    command([SEVENZIP, "a", "-t7z", "-m0=Copy", "-ms=off", str(original), "data/System.json"], cwd=source)
    damaged = bytearray(original.read_bytes())
    damaged[32] ^= 0x80
    corrupt = root / "corrupt.7z"
    corrupt.write_bytes(damaged)
    command([SEVENZIP, "t", str(corrupt)], success=False)
    launcher("read", corrupt, "data/System.json", success=False)
    truncated = root / "truncated.7z"
    truncated.write_bytes(original.read_bytes()[:-8])
    launcher("inspect", truncated, success=False)
    print(f"PASS {checked} byte comparisons, wrong passwords, immutable archives, payload corruption and truncated header")
