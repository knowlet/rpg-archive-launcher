#![cfg(target_os = "linux")]
use rpg_archive_launcher::{
    archive::{Archive, Limits},
    isolation,
};
use sevenz_rust2::{
    ArchiveEntry, ArchiveWriter, Password,
    encoder_options::{AesEncoderOptions, Lzma2Options},
};
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn get(resource: libc::c_int) -> libc::rlimit {
    let mut value = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(unsafe { libc::getrlimit(resource as _, &mut value) }, 0);
    value
}
fn set(resource: libc::c_int, soft: libc::rlim_t, hard: libc::rlim_t) {
    assert!(
        get(resource).rlim_max >= hard,
        "test requires inherited hard ceiling at least {hard}"
    );
    let value = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    assert_eq!(unsafe { libc::setrlimit(resource as _, &value) }, 0);
}

#[test]
fn production_library_process_guard() {
    if let Ok(mode) = std::env::var("RPG_ISOLATION_TEST_CHILD") {
        child(&mode);
        return;
    }
    // Changes affect exec children only, never cargo/the parallel parent harness.
    for mode in [
        "unlimited",
        "soft_only",
        "as_high",
        "cpu_high",
        "valid",
        "stricter",
    ] {
        let mut process = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "production_library_process_guard",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("RPG_ISOLATION_TEST_CHILD", mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if process.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                process.kill().unwrap();
                let output = process.wait_with_output().unwrap();
                panic!("guard child {mode} timed out: {output:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = process.wait_with_output().unwrap();
        assert!(output.status.success(), "guard child {mode}: {output:?}");
    }
}

fn child(mode: &str) {
    const AS: libc::rlim_t = isolation::MAX_ADDRESS_SPACE_BYTES as libc::rlim_t;
    const CPU: libc::rlim_t = isolation::MAX_CPU_SECONDS as libc::rlim_t;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("encrypted.7z");
    // Public synthetic password only. Build the fixture before lowering limits.
    let mut writer = ArchiveWriter::create(&path).unwrap();
    writer.set_content_methods(vec![
        AesEncoderOptions::new(Password::new("fixture秘密")).into(),
        Lzma2Options::default().into(),
    ]);
    writer.set_encrypt_header(true);
    writer
        .push_archive_entry(
            ArchiveEntry::new_file("data/test"),
            Some(b"correct bytes".as_slice()),
        )
        .unwrap();
    writer.finish().unwrap();
    match mode {
        "unlimited" => {
            assert_eq!(get(libc::RLIMIT_AS as _).rlim_max, libc::RLIM_INFINITY);
            assert_eq!(get(libc::RLIMIT_CPU as _).rlim_max, libc::RLIM_INFINITY);
        }
        "soft_only" => {
            set(libc::RLIMIT_AS as _, AS, libc::RLIM_INFINITY);
            set(libc::RLIMIT_CPU as _, CPU, libc::RLIM_INFINITY);
        }
        "as_high" => {
            set(libc::RLIMIT_AS as _, AS, AS + 1);
            set(libc::RLIMIT_CPU as _, CPU, CPU);
        }
        "cpu_high" => {
            set(libc::RLIMIT_AS as _, AS, AS);
            set(libc::RLIMIT_CPU as _, CPU, CPU + 1);
        }
        "valid" => {
            isolation::install_process_limits().unwrap();
            assert_eq!(
                (
                    get(libc::RLIMIT_AS as _).rlim_cur,
                    get(libc::RLIMIT_AS as _).rlim_max
                ),
                (AS, AS)
            );
            assert_eq!(
                (
                    get(libc::RLIMIT_CPU as _).rlim_cur,
                    get(libc::RLIMIT_CPU as _).rlim_max
                ),
                (CPU, CPU)
            );
        }
        "stricter" => {
            set(libc::RLIMIT_AS as _, AS - (32 << 20), AS - (16 << 20));
            set(libc::RLIMIT_CPU as _, CPU - 20, CPU - 10);
            isolation::install_process_limits().unwrap();
            assert_eq!(get(libc::RLIMIT_AS as _).rlim_cur, AS - (32 << 20));
            assert_eq!(get(libc::RLIMIT_AS as _).rlim_max, AS - (16 << 20));
            assert_eq!(get(libc::RLIMIT_CPU as _).rlim_cur, CPU - 20);
            assert_eq!(get(libc::RLIMIT_CPU as _).rlim_max, CPU - 10);
        }
        _ => unreachable!(),
    }
    let before_as = get(libc::RLIMIT_AS as _);
    let before_cpu = get(libc::RLIMIT_CPU as _);
    if matches!(mode, "valid" | "stricter") {
        let mut archive = Archive::open(&path, "fixture秘密", Limits::default()).unwrap();
        assert_eq!(archive.read("data/test").unwrap(), b"correct bytes");
    } else {
        // Same policy error for valid encrypted, malformed and nonexistent inputs:
        // rejection must occur before path I/O, header allocation or header KDF.
        let malformed = temp.path().join("malformed.7z");
        std::fs::write(&malformed, b"invalid").unwrap();
        for input in [&path, &malformed, &temp.path().join("does-not-exist")] {
            let error = Archive::open(input, "fixture秘密", Limits::default())
                .err()
                .unwrap();
            assert!(
                error.contains("archive requires Linux hard process limits"),
                "{error}"
            );
        }
    }
    // Checking/opening never silently changes any process limit.
    for (resource, before) in [(libc::RLIMIT_AS, before_as), (libc::RLIMIT_CPU, before_cpu)] {
        let after = get(resource as _);
        assert_eq!(
            (after.rlim_cur, after.rlim_max),
            (before.rlim_cur, before.rlim_max)
        );
    }
}
