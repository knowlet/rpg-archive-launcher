#![cfg(target_os = "linux")]
use rpg_archive_launcher::archive::{Archive, Limits};
use rpg_archive_launcher::isolation;
use std::process::Command;

#[test]
fn official_split_archive_opens_via_volume_chain() {
    if Command::new("/tmp/7zz").arg("--help").status().is_err() {
        eprintln!("split volume decode test skipped: /tmp/7zz missing");
        return;
    }
    isolation::install_process_limits().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let payload = vec![b'x'; 6 * 1024];
    std::fs::write(temp.path().join("payload.bin"), &payload).unwrap();
    let base = temp.path().join("split.7z");
    assert!(
        Command::new("/tmp/7zz")
            .current_dir(temp.path())
            .args([
                "a",
                "-v5k",
                "-y",
                "-mx=0",
                base.file_name().unwrap().to_str().unwrap(),
                "payload.bin",
            ])
            .status()
            .unwrap()
            .success()
    );
    let first = temp.path().join("split.7z.001");
    if !first.is_file() {
        eprintln!("split volume decode test skipped: 7zz did not create .7z.001");
        return;
    }
    let mut archive = Archive::open(&first, "", Limits::default()).unwrap();
    assert!(
        archive.volume_paths().len() > 1,
        "expected multiple volumes, got {}",
        archive.volume_paths().len()
    );
    let data = archive
        .read("payload.bin")
        .expect("decode split volume member");
    assert_eq!(data, payload);
}
