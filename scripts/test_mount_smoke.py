#!/usr/bin/env python3
"""Conditional real Linux read-only FUSE smoke; never reports skipped as passed."""
import errno
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

if not Path('/dev/fuse').exists():
    print('SKIP: /dev/fuse unavailable; real mount remains unverified')
    raise SystemExit(0)
unmount = shutil.which('fusermount')
if unmount is None:
    raise SystemExit('FAIL: /dev/fuse exists but fusermount is missing')
exe = Path('target/debug/rpg-archive-launcher').resolve()
with tempfile.TemporaryDirectory(prefix='rpg-mount-') as temporary:
    root = Path(temporary)
    archive = root / 'synthetic.7z'
    subprocess.run(['cargo','run','--locked','--example','make_probe','--',str(archive)], check=True)
    original = archive.read_bytes()
    mount = root / 'mount space'
    mount.mkdir(mode=0o700)
    log = root / 'mount.log'
    with log.open('w') as output:
        process = subprocess.Popen([str(exe),'mount-ro',str(archive),str(mount),'kernel'],stdout=output,stderr=output)
        try:
            deadline = time.monotonic()+15
            while not os.path.ismount(mount):
                if process.poll() is not None or time.monotonic()>=deadline:
                    raise RuntimeError('Mount failed: '+log.read_text())
                time.sleep(.1)
            for game in ['MV 遊戲','MZ 遊戲']:
                assert (mount/game/'data/probe.json').read_bytes() == b'{"fixture":"synthetic"}'
                try:
                    (mount/game/'save/new').write_bytes(b'blocked')
                except OSError as error:
                    assert error.errno in (errno.EROFS,errno.EACCES), error
                else:
                    raise AssertionError('Read-only mount allowed a write')
            assert archive.read_bytes() == original
            print('PASS: real Linux read-only mount, MV/MZ fixture reads, rejected write, unchanged source')
        finally:
            if os.path.ismount(mount):
                subprocess.run([unmount,'-u',str(mount)],check=True)
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
