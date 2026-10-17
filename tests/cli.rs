#![cfg(target_os = "linux")]
use sevenz_rust2::{
    ArchiveEntry, ArchiveWriter, Password,
    encoder_options::{AesEncoderOptions, Lzma2Options},
};
use std::{
    io::Write,
    process::{Command, Stdio},
};
fn cli(args: &[&str], password: Option<&str>) -> std::process::Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_rpg-archive-launcher"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(password) = password {
        process
            .stdin
            .take()
            .unwrap()
            .write_all(password.as_bytes())
            .unwrap();
    }
    process.wait_with_output().unwrap()
}
#[test]
fn encrypted_archive_and_upper_survive_separate_processes() {
    let temp = tempfile::tempdir().unwrap();
    let archive = temp.path().join("game.7z");
    let wal = temp.path().join("upper.wal");
    let input = temp.path().join("save-input");
    let mut writer = ArchiveWriter::create(&archive).unwrap();
    writer.set_content_methods(vec![
        AesEncoderOptions::new(Password::new("秘密🔑")).into(),
        Lzma2Options::default().into(),
    ]);
    writer.set_encrypt_header(true);
    for (name, bytes) in [
        ("package.json", b"{}".as_slice()),
        ("js/rmmz_core.js", b"// fixture".as_slice()),
        ("save/file1", b"old".as_slice()),
    ] {
        writer
            .push_archive_entry(ArchiveEntry::new_file(name), Some(bytes))
            .unwrap();
    }
    writer.finish().unwrap();
    let original = std::fs::read(&archive).unwrap();
    let a = archive.to_str().unwrap();
    let w = wal.to_str().unwrap();
    let inspected = cli(&["inspect", a, "--password-stdin"], Some("秘密🔑\n"));
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    assert!(String::from_utf8_lossy(&inspected.stdout).contains("RPG Maker MZ"));
    assert!(!String::from_utf8_lossy(&inspected.stdout).contains("秘密"));
    assert!(
        !cli(
            &["read", a, "save/file1", "--password-stdin"],
            Some("wrong\n")
        )
        .status
        .success()
    );
    assert_eq!(
        cli(
            &["read", a, "save/file1", "--password-stdin"],
            Some("秘密🔑\n")
        )
        .stdout,
        b"old"
    );
    std::fs::write(&input, b"new save").unwrap();
    assert!(
        cli(
            &["save-put", w, "save/file1", input.to_str().unwrap()],
            None
        )
        .status
        .success()
    );
    assert_eq!(
        cli(
            &["overlay-read", a, w, "save/file1", "--password-stdin"],
            Some("秘密🔑\n")
        )
        .stdout,
        b"new save"
    );
    assert!(
        cli(&["save-rename", w, "save/file1", "save/file2"], None)
            .status
            .success()
    );
    assert_eq!(
        cli(&["save-get", w, "save/file2"], None).stdout,
        b"new save"
    );
    assert!(
        !cli(
            &["overlay-read", a, w, "save/file1", "--password-stdin"],
            Some("秘密🔑\n")
        )
        .status
        .success()
    );
    assert_eq!(
        std::fs::read(archive).unwrap(),
        original,
        "archive must remain byte-identical"
    );
    assert_eq!(
        std::fs::read_dir(temp.path()).unwrap().count(),
        3,
        "no unpacked resource directory"
    );
}
#[test]
fn malformed_invocations_fail_cleanly() {
    assert!(cli(&["--help"], None).status.success());
    assert!(!cli(&["mount"], None).status.success());
    assert!(!cli(&["inspect"], None).status.success());
}

#[test]
fn overlay_byte_operations_persist_across_commands() {
    let temp = tempfile::tempdir().unwrap();
    let archive = temp.path().join("game.7z");
    let wal = temp.path().join("upper.wal");
    let input = temp.path().join("patch");
    let mut writer = ArchiveWriter::create(&archive).unwrap();
    writer
        .push_archive_entry(
            ArchiveEntry::new_file("save/file1"),
            Some(b"abcdef".as_slice()),
        )
        .unwrap();
    writer.finish().unwrap();
    let original = std::fs::read(&archive).unwrap();
    let a = archive.to_str().unwrap();
    let w = wal.to_str().unwrap();
    assert_eq!(
        cli(&["overlay-read-at", a, w, "save/file1", "2", "3"], None).stdout,
        b"cde"
    );
    let readonly_wal = std::fs::read(&wal).unwrap();
    assert!(
        !cli(
            &["overlay-write-at", a, w, "save/file1", "-1", "missing"],
            None
        )
        .status
        .success()
    );
    std::fs::write(&input, b"XY").unwrap();
    assert!(
        !cli(
            &[
                "overlay-write-at",
                a,
                w,
                "save/file1",
                "18446744073709551615",
                input.to_str().unwrap()
            ],
            None
        )
        .status
        .success()
    );
    assert_eq!(std::fs::read(&wal).unwrap(), readonly_wal);
    assert!(
        cli(
            &[
                "overlay-write-at",
                a,
                w,
                "save/file1",
                "8",
                input.to_str().unwrap()
            ],
            None
        )
        .status
        .success()
    );
    assert_eq!(
        cli(&["overlay-read", a, w, "save/file1"], None).stdout,
        b"abcdef\0\0XY"
    );
    assert!(
        cli(&["overlay-truncate", a, w, "save/file1", "3"], None)
            .status
            .success()
    );
    assert_eq!(
        cli(&["overlay-read", a, w, "save/file1"], None).stdout,
        b"abc"
    );
    assert!(
        cli(&["overlay-truncate", a, w, "save/file1", "0"], None)
            .status
            .success()
    );
    assert_eq!(cli(&["overlay-read", a, w, "save/file1"], None).stdout, b"");
    assert!(
        cli(&["overlay-unlink", a, w, "save/file1"], None)
            .status
            .success()
    );
    assert!(
        !cli(&["overlay-read", a, w, "save/file1"], None)
            .status
            .success()
    );
    assert_eq!(std::fs::read(&archive).unwrap(), original);
}
