#![cfg(any(target_os = "linux", target_os = "macos"))]
use rpg_archive_launcher::{
    archive::ArchiveSource, filesystem::Filesystem, save::Store, worker::DecoderWorker,
};
use sevenz_rust2::{
    ArchiveEntry, ArchiveWriter, Password,
    encoder_options::{AesEncoderOptions, Lzma2Options},
};
use std::{fs, path::Path};
fn worker(path: &Path, password: &str) -> Result<DecoderWorker, String> {
    DecoderWorker::spawn(
        Path::new(env!("CARGO_BIN_EXE_rpg-archive-launcher")),
        path,
        password,
    )
}
fn fixture(path: &Path, engine: &str) {
    let mut writer = ArchiveWriter::create(path).unwrap();
    writer.set_content_methods(vec![
        AesEncoderOptions::new(Password::new("秘密🔑")).into(),
        Lzma2Options::default().into(),
    ]);
    writer.set_encrypt_header(true);
    for (name, bytes) in [
        (
            "遊戲/package.json".to_string(),
            br#"{"main":"index.html"}"#.as_slice(),
        ),
        ("遊戲/index.html".into(), b"synthetic only"),
        (format!("遊戲/js/{engine}.js"), b"fixture"),
        ("遊戲/save/file1".into(), b"lower"),
    ] {
        writer
            .push_archive_entry(ArchiveEntry::new_file(&name), Some(bytes))
            .unwrap();
    }
    writer.finish().unwrap();
}
#[test]
fn encrypted_mv_mz_worker_reads_and_isolated_upper() {
    for engine in ["rpg_core", "rmmz_core"] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("遊戲 space.7z");
        fixture(&archive, engine);
        let before = fs::read(&archive).unwrap();
        let original_count = fs::read_dir(dir.path()).unwrap().count();
        assert!(worker(&archive, "wrong").is_err());
        let mut fs = Filesystem::readonly(worker(&archive, "秘密🔑").unwrap()).unwrap();
        assert_eq!(fs.read_at("遊戲/index.html", 2, 4).unwrap(), b"nthe");
        assert!(fs.metadata(&format!("遊戲/js/{engine}.js")).is_ok());
        assert!(fs.put_save("遊戲/save/file1", b"new").is_err());
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            original_count,
            "read must not extract files"
        );
        let wal = dir.path().join("upper.wal");
        let mut fs = fs
            .with_upper(Store::open(&wal).unwrap(), "遊戲/save")
            .unwrap();
        fs.put_save("遊戲/save/file1", b"new").unwrap();
        assert_eq!(fs.read_at("遊戲/save/file1", 0, 100).unwrap(), b"new");
        drop(fs);
        let mut reopened = Filesystem::readonly(worker(&archive, "秘密🔑").unwrap())
            .unwrap()
            .with_upper(Store::open(&wal).unwrap(), "遊戲/save")
            .unwrap();
        assert_eq!(reopened.read_at("遊戲/save/file1", 0, 100).unwrap(), b"new");
        assert_eq!(std::fs::read(&archive).unwrap(), before);
    }
}
#[test]
fn worker_range_reads_are_sliced_in_the_child() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("range.7z");
    fixture(&archive, "rpg_core");
    let mut source = worker(&archive, "秘密🔑").unwrap();
    assert_eq!(source.read_range("遊戲/index.html", 2, 4).unwrap(), b"nthe");
    assert_eq!(
        source.read_range("遊戲/index.html", 10, 1 << 20).unwrap(),
        b"only"
    );
    assert!(
        source
            .read_range("遊戲/index.html", 14, 4)
            .unwrap()
            .is_empty()
    );
    assert!(
        source
            .read_range("遊戲/index.html", u64::MAX, 4)
            .unwrap()
            .is_empty()
    );
    assert!(source.read_range("遊戲/missing", 0, 4).is_err());
    // A logical error leaves the worker usable.
    assert_eq!(source.read("遊戲/index.html").unwrap(), b"synthetic only");
}
#[test]
fn source_mutation_invalidates_cached_read() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("game.7z");
    fixture(&archive, "rmmz_core");
    let mut source = worker(&archive, "秘密🔑").unwrap();
    source.read("遊戲/index.html").unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&archive)
        .unwrap()
        .write_all(b"changed")
        .unwrap();
    assert!(source.read("遊戲/index.html").is_err());
    assert!(source.revision_sha256().is_err());
}
#[test]
fn worker_eof_and_stalled_input_are_bounded() {
    use std::{
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };
    let dir = tempfile::tempdir().unwrap();
    let fake = dir.path().join("fake-worker");
    fs::write(&fake, b"#!/bin/sh\nexec /bin/sleep 60\n").unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
    let start = Instant::now();
    // Larger than a minimal pipe buffer: the timeout must cover writes too.
    let result = DecoderWorker::spawn(&fake, Path::new(&"a".repeat(10000)), &"p".repeat(4096));
    assert!(result.is_err());
    assert!(start.elapsed() < Duration::from_secs(36));
    assert!(start.elapsed() >= Duration::from_secs(29));
    assert!(DecoderWorker::spawn(Path::new("/usr/bin/true"), Path::new("ignored"), "").is_err());
}

#[test]
fn worker_exit_with_descendant_holding_stdout_does_not_hang() {
    use std::{
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };
    let dir = tempfile::tempdir().unwrap();
    let fake = dir.path().join("fake-worker");
    let marker = dir.path().join("descendant.pid");
    // The child exits at once; a descendant keeps the stdout pipe open.
    fs::write(
        &fake,
        format!(
            "#!/bin/sh\n/bin/sleep 60 &\necho $! > '{}'\nexit 0\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
    // Orphans of the exited shell are reparented here, which is what leaves
    // a killed descendant as a zombie if stop() only waits for the leader.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    }
    let start = Instant::now();
    let result = DecoderWorker::spawn(&fake, Path::new("ignored"), "");
    let elapsed = start.elapsed();
    assert!(result.is_err());
    // Neither the 30 s exchange timeout nor the 60 s descendant is waited on.
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    let pid: i32 = fs::read_to_string(&marker).unwrap().trim().parse().unwrap();
    // The descendant shared the worker's process group and was killed with it.
    let deadline = Instant::now() + Duration::from_secs(5);
    while unsafe { libc::kill(pid, 0) } == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    // A zombie still answers kill(pid, 0). ESRCH means it was collected.
    assert_ne!(
        unsafe { libc::kill(pid, 0) },
        0,
        "descendant {pid} survived"
    );
}

#[test]
fn worker_rejects_oversize_entry_before_payload_response() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("large.7z");
    let mut writer = ArchiveWriter::create(&archive).unwrap();
    writer
        .push_archive_entry(
            ArchiveEntry::new_file("small.txt"),
            Some(b"still-readable".as_slice()),
        )
        .unwrap();
    let data = vec![b'x'; 17 * 1024 * 1024];
    writer
        .push_archive_entry(ArchiveEntry::new_file("large.bin"), Some(data.as_slice()))
        .unwrap();
    writer.finish().unwrap();
    drop(data);
    let mut fs = Filesystem::readonly(worker(&archive, "").unwrap()).unwrap();
    let error = fs.read_at("large.bin", 0, 16).unwrap_err();
    assert!(error.contains("over request limit"), "{error}");
    assert!(!error.contains("unavailable"), "{error}");
    assert_eq!(fs.read_at("small.txt", 0, 100).unwrap(), b"still-readable");
    assert!(
        fs.read_at("large.bin", 100, 16)
            .unwrap_err()
            .contains("over request limit")
    );
    assert_eq!(fs.read_at("small.txt", 6, 8).unwrap(), b"readable");
}

#[test]
fn oversized_range_reply_retires_the_worker() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let fake = dir.path().join("wide-worker");
    fs::write(
        &fake,
        r#"#!/usr/bin/python3
import json, struct, sys
def read_frame():
    header = sys.stdin.buffer.read(4)
    if len(header) < 4:
        return b""
    n = struct.unpack("<I", header)[0]
    return sys.stdin.buffer.read(n)
def write_frame(payload: bytes):
    sys.stdout.buffer.write(struct.pack("<I", len(payload)) + payload)
    sys.stdout.buffer.flush()
read_frame()
body = json.dumps([[["a.txt", 4]], [0] * 32]).encode()
write_frame(b"\x00" + body)
read_frame()
write_frame(b"\x00" + b"x" * 32)
read_frame()
write_frame(b"\x00ok")
"#,
    )
    .unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
    let mut source = DecoderWorker::spawn(&fake, Path::new("ignored"), "").unwrap();
    let error = source.read_range("a.txt", 0, 4).unwrap_err();
    assert!(error.contains("more than the requested range"), "{error}");
    let again = source.read_range("a.txt", 0, 4).unwrap_err();
    assert!(again.contains("unavailable"), "{again}");
}
