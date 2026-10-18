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
fn worker_rejects_oversize_entry_before_payload_response() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("large.7z");
    let mut writer = ArchiveWriter::create(&archive).unwrap();
    let data = vec![b'x'; 17 * 1024 * 1024];
    writer
        .push_archive_entry(ArchiveEntry::new_file("large.bin"), Some(data.as_slice()))
        .unwrap();
    writer.finish().unwrap();
    drop(data);
    let mut source = worker(&archive, "").unwrap();
    assert!(
        source
            .read("large.bin")
            .unwrap_err()
            .contains("over request limit")
    );
}
