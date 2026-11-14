#![cfg(target_os = "linux")]
use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
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

#[test]
fn path_first_play_command_succeeds() {
    let temp = tempfile::tempdir().unwrap();
    let archive = temp.path().join("game.7z");
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
}
