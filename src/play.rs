//! High-level `play` preparation: open archive/volumes, bind Upper, apply RPG Maker repairs.
use crate::{
    archive::{Archive, Limits},
    repair::{
        RepairReport, archive_relative_name, fix_mpp_color_index, fix_package_name, fix_plugins_js,
        is_apple_double, remove_pixi_sourcemap, strip_achievement_calls_json,
    },
    runtime,
    save::Store,
    vfs::Overlay,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;

#[derive(Debug)]
pub struct PlaySummary {
    pub archive_display: String,
    pub wal_path: PathBuf,
    pub engine: Option<String>,
    pub game_root: Option<String>,
    pub repairs: RepairReport,
    pub mount_ready: bool,
}

fn archive_identity_token(archive: &Path) -> String {
    let paths =
        crate::volumes::resolve_archive(archive).unwrap_or_else(|_| vec![archive.to_path_buf()]);
    let mut hash = Sha256::new();
    for path in paths {
        hash.update(path.as_os_str().as_encoded_bytes());
        hash.update([0u8]);
    }
    hash.finalize()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sanitize_wal_label(label: &str) -> String {
    let mut safe: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() {
        safe.push_str("archive");
    }
    safe
}

fn user_local_wal_dir() -> PathBuf {
    if let Ok(data_home) = std::env::var("XDG_DATA_HOME")
        && !data_home.is_empty()
    {
        return PathBuf::from(data_home).join("rpg-archive-launcher");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("rpg-archive-launcher");
    }
    PathBuf::from(".rpg-archive-launcher")
}

fn parent_allows_wal_dir(parent: &Path) -> bool {
    if parent.as_os_str().is_empty() {
        return true;
    }
    if !parent.exists() {
        return parent.parent().is_none_or(parent_allows_wal_dir);
    }
    if std::fs::symlink_metadata(parent)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(true)
    {
        return false;
    }
    if !parent.is_dir() {
        return false;
    }
    directory_is_writable(parent)
}

/// Probe create/delete in the directory — opening a directory with `O_WRONLY` returns `EISDIR`.
fn directory_is_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(
        ".rpg-archive-launcher-write-probe-{}",
        std::process::id()
    ));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .and_then(|_| std::fs::remove_file(probe))
        .is_ok()
}

fn beside_archive_wal_usable(archive: &Path) -> bool {
    let archive_parent = archive.parent().unwrap_or_else(|| Path::new("."));
    if !parent_allows_wal_dir(archive_parent) {
        return false;
    }
    let launcher_dir = archive_parent.join(".rpg-archive-launcher");
    if !launcher_dir.exists() {
        return true;
    }
    if std::fs::symlink_metadata(&launcher_dir)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(true)
    {
        return false;
    }
    if !launcher_dir.is_dir() {
        return false;
    }
    directory_is_writable(&launcher_dir)
}

/// Default WAL path: archive-adjacent when writable, otherwise a per-user local directory.
pub fn default_wal_path(archive: &Path) -> PathBuf {
    let label = crate::volumes::volume_set_label(archive);
    let filename = format!(
        "{}-{}.wal",
        sanitize_wal_label(&label),
        archive_identity_token(archive)
    );
    let beside_parent = archive
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".rpg-archive-launcher");
    if beside_archive_wal_usable(archive) {
        beside_parent.join(filename)
    } else {
        user_local_wal_dir().join(filename)
    }
}

pub fn ensure_wal_parent(dir: &Path) -> Result<()> {
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    if dir.is_dir() {
        let meta = std::fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!("refusing symlink WAL directory: {}", dir.display()));
        }
    } else if dir.exists() {
        return Err(format!("WAL parent is not a directory: {}", dir.display()));
    } else {
        if let Some(parent) = dir.parent()
            && !parent.as_os_str().is_empty()
        {
            ensure_wal_parent(parent)?;
        }
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let meta = std::fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!("refusing symlink WAL directory: {}", dir.display()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

pub fn prepare(
    archive_path: &Path,
    wal: &Path,
    password: &str,
    limits: Limits,
) -> Result<PlaySummary> {
    if let Some(parent) = wal.parent()
        && !parent.as_os_str().is_empty()
    {
        ensure_wal_parent(parent)?;
    }
    let archive = Archive::open(archive_path, password, limits).map_err(|e| e.to_string())?;
    let names = archive.names();
    let candidates = runtime::detect(&names);
    if candidates.len() > 1 {
        let roots: BTreeSet<String> = candidates
            .iter()
            .map(|c| c.root.trim_end_matches('/').to_owned())
            .collect();
        if roots.len() > 1 {
            return Err(
                "multiple distinct RPG Maker game roots detected; inspect the archive and pass --wal for a single game"
                    .into(),
            );
        }
    }
    let store = Store::open(wal).map_err(|e| e.to_string())?;
    let mut overlay = Overlay::new(archive, store).map_err(|e| e.to_string())?;
    let (engine, game_root, package_root) = candidates.first().map_or((None, None, None), |c| {
        let package_root = c.root.trim_end_matches('/').to_string();
        let root = effective_root(&c.root, &names);
        (Some(c.engine.to_string()), Some(root), Some(package_root))
    });
    let repairs = apply_repairs(
        &mut overlay,
        game_root.as_deref(),
        package_root.as_deref(),
        &names,
    )?;
    let archive_display = crate::volumes::resolve_archive(archive_path)
        .map(|v| {
            v.iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(" + ")
        })
        .unwrap_or_else(|_| archive_path.display().to_string());
    Ok(PlaySummary {
        archive_display,
        wal_path: wal.to_path_buf(),
        engine,
        game_root,
        repairs,
        mount_ready: false,
    })
}

fn effective_root(candidate_root: &str, names: &[String]) -> String {
    let root = candidate_root.trim_end_matches('/');
    let has_engine_under = |prefix: &str| {
        let prefix = prefix.trim_end_matches('/');
        let (mv, mz) = if prefix.is_empty() {
            ("js/rpg_core.js".to_owned(), "js/rmmz_core.js".to_owned())
        } else {
            (
                format!("{prefix}/js/rpg_core.js"),
                format!("{prefix}/js/rmmz_core.js"),
            )
        };
        names.iter().any(|n| n == &mv || n == &mz)
    };
    if has_engine_under(root) {
        return root.to_owned();
    }
    let www = if root.is_empty() {
        "www".to_owned()
    } else {
        format!("{root}/www")
    };
    if has_engine_under(&www) {
        return www;
    }
    root.to_owned()
}

pub fn apply_repairs(
    overlay: &mut Overlay,
    game_root: Option<&str>,
    package_root: Option<&str>,
    names: &[String],
) -> Result<RepairReport> {
    let Some(game_root) = game_root else {
        return Ok(RepairReport::default());
    };
    let mut report = RepairReport::default();
    if let Some(pkg_root) = package_root {
        let path = archive_relative_name(pkg_root, "package.json");
        if names.iter().any(|n| n == &path)
            && let Some(original) = read_repair_source(overlay, &path)
            && let Ok(text) = std::str::from_utf8(&original)
            && let Some(patched) = fix_package_name(text)
        {
            report.package_name_set_www = true;
            let bytes = patched.into_bytes();
            if bytes != original {
                overlay.replace_file(&path, &bytes)?;
            }
        }
    }
    let rel_targets = [
        ("js/plugins.js", RepairKind::Plugins),
        ("js/plugins/MPP_MessageEX.js", RepairKind::Mpp),
        ("js/libs/pixi.js", RepairKind::Pixi),
    ];
    for (rel, kind) in rel_targets {
        let path = archive_relative_name(game_root, rel);
        if !names.iter().any(|n| n == &path) {
            continue;
        }
        let Some(original) = read_repair_source(overlay, &path) else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&original) else {
            continue;
        };
        let (patched, count) = match kind {
            RepairKind::Plugins => fix_plugins_js(text),
            RepairKind::Mpp => fix_mpp_color_index(text),
            RepairKind::Pixi => remove_pixi_sourcemap(text),
        };
        match kind {
            RepairKind::Plugins => report.plugins_greenworks_disabled += count,
            RepairKind::Mpp => report.mpp_color_index_moves += count,
            RepairKind::Pixi => report.pixi_sourcemap_strips += count,
        }
        if patched.as_bytes() != original.as_slice() {
            overlay.replace_file(&path, patched.as_bytes())?;
        }
    }
    let data_prefix = archive_relative_name(game_root, "data/");
    for name in names {
        if !name.starts_with(&data_prefix) || !name.ends_with(".json") || is_apple_double(name) {
            continue;
        }
        let Some(original) = read_repair_source(overlay, name) else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&original) else {
            continue;
        };
        let (patched, count) = strip_achievement_calls_json(text);
        report.data_achievement_strips += count;
        if patched.as_bytes() != original.as_slice() {
            overlay.replace_file(name, patched.as_bytes())?;
        }
    }
    Ok(report)
}

fn read_repair_source(overlay: &mut Overlay, path: &str) -> Option<Vec<u8>> {
    match overlay.try_read_file(path) {
        Ok(Some(bytes)) => Some(bytes),
        Ok(None) | Err(_) => None,
    }
}

enum RepairKind {
    Plugins,
    Mpp,
    Pixi,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::Limits;
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
    use std::path::Path;

    fn fixture_archive(dir: &Path) -> PathBuf {
        let path = dir.join("game.7z");
        let mut writer = ArchiveWriter::create(&path).unwrap();
        let files: &[(&str, &[u8])] = &[
            (
                "Game/package.json",
                br#"{"name":"","main":"www/index.html"}"#,
            ),
            ("Game/www/js/rpg_core.js", b"// mv core"),
            (
                "Game/www/js/plugins.js",
                br#"{ "name":"OrangeGreenworks", "status":true }"#,
            ),
            (
                "Game/www/js/plugins/MPP_MessageEX.js",
                b"Window_Base.prototype.initialize.call(this);\nthis._colorIndex = 0;\n",
            ),
            (
                "Game/www/js/libs/pixi.js",
                b"//game\n//# sourceMappingURL=pixi.js.map\n",
            ),
            (
                "Game/www/data/Map001.json",
                br#"{"list":[{"parameters":["OrangeGreenworks.activateAchievement('a');"]}]}"#,
            ),
            (
                "Game/www/data/._Map002.json",
                br#"{"parameters":["OrangeGreenworks.activateAchievement('b');"]}"#,
            ),
        ];
        for (name, body) in files {
            writer
                .push_archive_entry(ArchiveEntry::new_file(name), Some(*body))
                .unwrap();
        }
        writer.finish().unwrap();
        path
    }

    #[test]
    fn play_applies_repairs_into_upper() {
        let temp = tempfile::tempdir().unwrap();
        let archive = fixture_archive(temp.path());
        let wal = temp.path().join("play.wal");
        let opened = Archive::open_fixture(&archive, "", Limits::default()).unwrap();
        let names = opened.names();
        let candidates = runtime::detect(&names);
        let candidate = candidates.first().unwrap();
        let game_root = effective_root(&candidate.root, &names);
        let package_root = candidate.root.trim_end_matches('/').to_string();
        let mut overlay = Overlay::new(opened, Store::open(&wal).unwrap()).unwrap();
        let report =
            apply_repairs(&mut overlay, Some(&game_root), Some(&package_root), &names).unwrap();
        assert!(report.plugins_greenworks_disabled >= 1);
        assert!(report.mpp_color_index_moves >= 1);
        assert!(report.pixi_sourcemap_strips >= 1);
        assert!(report.data_achievement_strips >= 1);
        assert!(report.package_name_set_www);
        let plugins = overlay.read_file("Game/www/js/plugins.js").unwrap();
        assert!(std::str::from_utf8(&plugins).unwrap().contains("false"));
        let map = overlay.read_file("Game/www/data/Map001.json").unwrap();
        assert!(
            !std::str::from_utf8(&map)
                .unwrap()
                .contains("activateAchievement")
        );
        let apple = overlay.read_file("Game/www/data/._Map002.json").unwrap();
        assert!(
            std::str::from_utf8(&apple)
                .unwrap()
                .contains("activateAchievement('b')")
        );
    }

    #[test]
    fn default_wal_paths_differ_for_distinct_archives() {
        let temp = tempfile::tempdir().unwrap();
        let one = temp.path().join("Game One.7z");
        let two = temp.path().join("Game_One.7z");
        std::fs::write(&one, b"a").unwrap();
        std::fs::write(&two, b"b").unwrap();
        assert_ne!(default_wal_path(&one), default_wal_path(&two));
    }

    #[test]
    fn effective_root_prefers_runtime_js_location() {
        let names = [
            "Game/package.json",
            "Game/js/rpg_core.js",
            "Game/www/readme.txt",
        ]
        .map(str::to_owned);
        assert_eq!(effective_root("Game/", &names), "Game");
    }

    #[test]
    fn effective_root_uses_www_for_rootless_mv_layout() {
        let names = ["package.json", "www/js/rpg_core.js", "www/js/plugins.js"].map(str::to_owned);
        assert_eq!(effective_root("", &names), "www");
    }

    #[test]
    fn default_wal_stays_beside_writable_archive() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("game.7z");
        std::fs::write(&archive, b"x").unwrap();
        let wal = default_wal_path(&archive);
        assert!(wal.starts_with(temp.path()));
        assert!(wal.to_string_lossy().contains(".rpg-archive-launcher"));
    }

    #[cfg(unix)]
    #[test]
    fn default_wal_falls_back_when_launcher_subdir_not_writable() {
        // Effective root can write through 0o555; the probe would not trigger fallback.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("game.7z");
        std::fs::write(&archive, b"x").unwrap();
        let launcher = temp.path().join(".rpg-archive-launcher");
        std::fs::create_dir(&launcher).unwrap();
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o555)).unwrap();
        let wal = default_wal_path(&archive);
        assert!(
            !wal.starts_with(&launcher),
            "expected per-user fallback, got {}",
            wal.display()
        );
    }
}
