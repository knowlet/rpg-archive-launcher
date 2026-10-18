//! Explicit NW.js directory launch. No archive extraction, runtime download, or
//! shell command construction. The profile is separate from the mounted game.
//! NW.js executes trusted game code with the user's privileges; it is not sandboxed.
use std::{
    fs::{self, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};

const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

#[derive(Debug)]
pub struct LaunchPlan {
    pub executable: PathBuf,
    pub game_directory: PathBuf,
    pub profile_directory: PathBuf,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn regular_read(path: &Path) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("package.json must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(invalid("package.json exceeds the 64 KiB launch policy"));
    }
    Ok(bytes)
}

impl LaunchPlan {
    pub fn new(
        mountpoint: &Path,
        game_root: &str,
        executable: &Path,
        profile: &Path,
    ) -> io::Result<Self> {
        if !game_root.is_empty() {
            crate::archive::validate_archive_path(game_root).map_err(|e| invalid(&e))?;
        }
        let mountpoint = fs::canonicalize(mountpoint)?;
        if !mountpoint.is_dir() {
            return Err(invalid("mountpoint must be a directory"));
        }
        let game_directory = fs::canonicalize(mountpoint.join(game_root))?;
        if !game_directory.is_dir() || !game_directory.starts_with(&mountpoint) {
            return Err(invalid(
                "game root must remain inside the mounted directory",
            ));
        }
        let manifest: serde_json::Value =
            serde_json::from_slice(&regular_read(&game_directory.join("package.json"))?)
                .map_err(|_| invalid("package.json must be valid JSON"))?;
        let main = manifest
            .get("main")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid("package.json requires a local main path"))?;
        crate::archive::validate_archive_path(main).map_err(|e| invalid(&e))?;
        let entry = fs::canonicalize(game_directory.join(main))?;
        if !entry.starts_with(&game_directory) || !entry.is_file() {
            return Err(invalid("package main must be a file inside the game root"));
        }
        let executable =
            if executable.is_dir() && executable.extension().is_some_and(|e| e == "app") {
                executable.join("Contents/MacOS/nwjs")
            } else {
                executable.to_owned()
            };
        let executable = fs::canonicalize(executable)?;
        let metadata = fs::metadata(&executable)?;
        if !metadata.is_file() || executable.starts_with(&mountpoint) {
            return Err(invalid("NW.js must be installed outside the game mount"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(invalid("NW.js path is not executable"));
            }
        }
        let profile_meta = fs::symlink_metadata(profile)?;
        if !profile_meta.is_dir() || profile_meta.file_type().is_symlink() {
            return Err(invalid(
                "profile must be an existing non-symlink local directory",
            ));
        }
        let profile_directory = fs::canonicalize(profile)?;
        if profile_directory.starts_with(&mountpoint) || mountpoint.starts_with(&profile_directory)
        {
            return Err(invalid(
                "profile and mounted game directories must not overlap",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if profile_meta.uid() != unsafe { libc::geteuid() } || profile_meta.mode() & 0o077 != 0
            {
                return Err(invalid(
                    "profile directory must be owned by this user with mode 0700",
                ));
            }
        }
        Ok(Self {
            executable,
            game_directory,
            profile_directory,
        })
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        let mut profile_argument = std::ffi::OsString::from("--user-data-dir=");
        profile_argument.push(&self.profile_directory);
        command
            .arg(profile_argument)
            .arg(&self.game_directory)
            .current_dir(&self.game_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        command
    }

    pub fn run(&self) -> io::Result<ExitStatus> {
        self.command().status()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let game = temp.path().join("RPG 測試 with space");
        let profile = temp.path().join("profile");
        fs::create_dir(&game).unwrap();
        fs::create_dir(&profile).unwrap();
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            game.join("package.json"),
            br#"{"name":"fixture","main":"index.html"}"#,
        )
        .unwrap();
        fs::write(game.join("index.html"), "synthetic fixture").unwrap();
        let runtime = temp.path().join("fake nwjs");
        fs::write(&runtime, "#!/bin/sh\nexit 7\n").unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        (temp, game, profile, runtime)
    }

    #[test]
    fn directory_arguments_preserve_unicode_spaces_and_exit_status() {
        let (_temp, game, profile, runtime) = setup();
        let plan = LaunchPlan::new(&game, "", &runtime, &profile).unwrap();
        let cmd = plan.command();
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args.len(), 2);
        assert_eq!(args[1], fs::canonicalize(&game).unwrap().as_os_str());
        assert_eq!(
            cmd.get_current_dir().unwrap(),
            fs::canonicalize(&game).unwrap()
        );
        assert_eq!(plan.run().unwrap().code(), Some(7));
    }

    #[test]
    fn rejects_escape_and_profile_inside_mount_before_execution() {
        let (_temp, game, profile, runtime) = setup();
        assert!(LaunchPlan::new(&game, "../profile", &runtime, &profile).is_err());
        fs::write(
            game.join("package.json"),
            br#"{"main":"../profile/out.html"}"#,
        )
        .unwrap();
        assert!(LaunchPlan::new(&game, "", &runtime, &profile).is_err());
        fs::write(
            game.join("package.json"),
            br#"{"main":"https://example.com"}"#,
        )
        .unwrap();
        assert!(LaunchPlan::new(&game, "", &runtime, &profile).is_err());
        fs::write(game.join("package.json"), br#"{"main":"index.html"}"#).unwrap();
        assert!(LaunchPlan::new(&game, "", &runtime, &game).is_err());
        symlink(&profile, game.join("escape")).unwrap();
        assert!(LaunchPlan::new(&game, "escape", &runtime, &profile).is_err());
    }

    #[test]
    fn rejects_manifest_fifo_symlink_and_oversize_without_running() {
        let (_temp, game, profile, runtime) = setup();
        fs::remove_file(game.join("package.json")).unwrap();
        symlink(game.join("index.html"), game.join("package.json")).unwrap();
        assert!(LaunchPlan::new(&game, "", &runtime, &profile).is_err());
        fs::remove_file(game.join("package.json")).unwrap();
        let path = std::ffi::CString::new(game.join("package.json").as_os_str().as_encoded_bytes())
            .unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(LaunchPlan::new(&game, "", &runtime, &profile).is_err());
        fs::remove_file(game.join("package.json")).unwrap();
        fs::write(
            game.join("package.json"),
            vec![b' '; MAX_MANIFEST_BYTES as usize + 1],
        )
        .unwrap();
        assert!(LaunchPlan::new(&game, "", &runtime, &profile).is_err());
    }
}
