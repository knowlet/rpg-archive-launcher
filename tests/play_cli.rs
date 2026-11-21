#![cfg(target_os = "linux")]
use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Stdio};

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rpg-archive-launcher"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn assert_no_directory_writes(directory: &Path, run: impl FnOnce()) {
    let path = CString::new(directory.as_os_str().as_bytes()).unwrap();
    // SAFETY: inotify_init1 returns a new descriptor on success, which File
    // takes ownership of; the path is a live, NUL-terminated string.
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    assert!(fd >= 0, "inotify_init1: {}", io::Error::last_os_error());
    let mut watcher = unsafe { File::from_raw_fd(fd) };
    let watch = unsafe {
        libc::inotify_add_watch(
            watcher.as_raw_fd(),
            path.as_ptr(),
            libc::IN_CREATE | libc::IN_DELETE,
        )
    };
    assert!(
        watch >= 0,
        "inotify_add_watch: {}",
        io::Error::last_os_error()
    );
    run();
    // A create/delete probe leaves no file behind but does leave events.
    let mut events = [0; 4096];
    let result = watcher.read(&mut events);
    assert!(
        matches!(&result, Err(error) if error.kind() == io::ErrorKind::WouldBlock),
        "unexpected source directory activity: {result:?}"
    );
}

#[test]
fn path_first_play_command_succeeds() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let archive = source.join("game.7z");
    let wal = temp.path().join("custom.wal");
    let mut writer = ArchiveWriter::create(&archive).unwrap();
    for (name, bytes) in [
        ("Game/package.json", br#"{"name":""}"#.as_slice()),
        ("Game/www/js/rpg_core.js", b"// mv"),
        (
            "Game/www/js/plugins.js",
            br#"{ "name":"OrangeGreenworks", "status":true }"#,
        ),
    ] {
        writer
            .push_archive_entry(ArchiveEntry::new_file(name), Some(bytes))
            .unwrap();
    }
    writer.finish().unwrap();
    let a = archive.to_str().unwrap();
    let w = wal.to_str().unwrap();
    assert_no_directory_writes(&source, || {
        let explicit = cli(&["play", a, "--wal", w]);
        assert!(
            explicit.status.success(),
            "{}",
            String::from_utf8_lossy(&explicit.stderr)
        );
        let stdout = String::from_utf8_lossy(&explicit.stdout);
        assert!(stdout.contains("runtime: RPG Maker MV"));
        assert!(stdout.contains("repair:"));
        let implicit = cli(&[a, "--wal", w]);
        assert!(implicit.status.success());
        assert!(String::from_utf8_lossy(&implicit.stdout).contains("runtime: RPG Maker MV"));
    });
    assert!(wal.is_file());
}

#[test]
fn invalid_play_flags_do_not_probe_source_directory() {
    let source = tempfile::tempdir().unwrap();
    let archive = source.path().join("game.7z");
    let a = archive.to_str().unwrap();
    assert_no_directory_writes(source.path(), || {
        for (flag, expected) in [
            ("--unknown", "unknown play flag: --unknown"),
            ("--wal", "--wal requires a path"),
        ] {
            let result = cli(&["play", a, flag]);
            assert!(!result.status.success());
            assert!(String::from_utf8_lossy(&result.stderr).contains(expected));
        }
    });
}
