//! Conservative mount preflight. Version checks are eligibility, never proof
//! of a successfully installed/enabled FSKit extension or kernel extension.
use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub fn macos_version_supported(version: &str, fskit: bool) -> bool {
    let mut components = version.trim().split('.');
    let Some(major) = components.next().and_then(|n| n.parse::<u32>().ok()) else {
        return false;
    };
    let minor = match components.next() {
        Some(n) => match n.parse::<u32>() {
            Ok(n) => n,
            Err(_) => return false,
        },
        None => 0,
    };
    if fskit { (major, minor) >= (26, 4) } else { major >= 12 }
}

pub fn macfuse_version_supported(version: &str) -> bool {
    let numbers = version
        .trim()
        .split('.')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>();
    matches!(numbers.as_deref(), Ok([major, minor, patch]) if (*major, *minor, *patch) >= (5, 5, 0))
}

#[cfg(target_os = "macos")]
pub fn require_macfuse_55() -> io::Result<()> {
    let output = std::process::Command::new("/usr/bin/plutil")
        .args([
            "-extract",
            "CFBundleShortVersionString",
            "raw",
            "-o",
            "-",
            "/Library/Filesystems/macfuse.fs/Contents/Info.plist",
        ])
        .output()?;
    if !output.status.success()
        || !macfuse_version_supported(&String::from_utf8_lossy(&output.stdout))
    {
        return Err(io::Error::other(
            "FSKit probe requires separately installed macFUSE 5.5.0 or later; this does not establish extension activation",
        ));
    }
    Ok(())
}

pub fn validate_mountpoint(path: &Path, fskit: bool) -> io::Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::other(
            "mountpoint must be an existing non-symlink directory",
        ));
    }
    let canonical = fs::canonicalize(path)?;
    if canonical == Path::new("/") || fs::read_dir(&canonical)?.next().is_some() {
        return Err(io::Error::other("mountpoint must be an empty directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err(io::Error::other(
                "mountpoint must be owned by this user and not writable by group/others",
            ));
        }
    }
    if fskit && canonical.parent() != Some(Path::new("/Volumes")) {
        return Err(io::Error::other(
            "this macFUSE FSKit probe requires a direct /Volumes mountpoint",
        ));
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distinct_version_floors_do_not_claim_mount_acceptance() {
        assert!(!macos_version_supported("26.3.9", true));
        assert!(macos_version_supported("26.4", true));
        assert!(macos_version_supported("27.0.1", true));
        assert!(!macos_version_supported("15.7", true));
        assert!(macos_version_supported("12.0", false));
        assert!(!macos_version_supported("11.7", false));
        assert!(!macos_version_supported("unknown", true));
        assert!(!macfuse_version_supported("5.4.0"));
        assert!(macfuse_version_supported("5.5.0\n"));
        assert!(macfuse_version_supported("5.5.1"));
        assert!(!macfuse_version_supported("2.1"));
    }
    #[test]
    fn refuses_nonempty_or_ineligible_mountpoint() {
        let temp = tempfile::tempdir().unwrap();
        assert!(validate_mountpoint(temp.path(), false).is_ok());
        assert!(validate_mountpoint(temp.path(), true).is_err());
        fs::write(temp.path().join("keep"), b"existing data").unwrap();
        assert!(validate_mountpoint(temp.path(), false).is_err());
        assert_eq!(fs::read(temp.path().join("keep")).unwrap(), b"existing data");
    }
}
