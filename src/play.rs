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
use std::path::{Path, PathBuf};

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

pub fn default_wal_path(archive: &Path) -> PathBuf {
    let parent = archive.parent().unwrap_or_else(|| Path::new("."));
    let label = crate::volumes::volume_set_label(archive);
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
    parent
        .join(".rpg-archive-launcher")
        .join(format!("{safe}.wal"))
}

pub fn prepare(
    archive_path: &Path,
    wal: &Path,
    password: &str,
    limits: Limits,
) -> Result<PlaySummary> {
    if let Some(parent) = wal.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let archive = Archive::open(archive_path, password, limits).map_err(|e| e.to_string())?;
    let names = archive.names();
    let store = Store::open(wal).map_err(|e| e.to_string())?;
    let mut overlay = Overlay::new(archive, store).map_err(|e| e.to_string())?;
    let candidates = runtime::detect(&names);
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
    let www_prefix = format!("{root}/www/");
    if names.iter().any(|n| n.starts_with(&www_prefix)) {
        format!("{root}/www")
    } else if root.is_empty() {
        if names.iter().any(|n| n.starts_with("www/")) {
            "www".to_owned()
        } else {
            String::new()
        }
    } else {
        root.to_owned()
    }
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
            && let Ok(original) = overlay.read_file(&path)
            && let Ok(text) = std::str::from_utf8(&original)
            && let Some(patched) = fix_package_name(text)
        {
            report.package_name_set_www = true;
            overlay.replace_file(&path, patched.as_bytes())?;
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
        let original = overlay.read_file(&path)?;
        let (patched, count) = match kind {
            RepairKind::Plugins => {
                fix_plugins_js(std::str::from_utf8(&original).map_err(|e| e.to_string())?)
            }
            RepairKind::Mpp => {
                fix_mpp_color_index(std::str::from_utf8(&original).map_err(|e| e.to_string())?)
            }
            RepairKind::Pixi => {
                remove_pixi_sourcemap(std::str::from_utf8(&original).map_err(|e| e.to_string())?)
            }
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
        let original = overlay.read_file(name)?;
        let text = std::str::from_utf8(&original).map_err(|e| e.to_string())?;
        let (patched, count) = strip_achievement_calls_json(text);
        report.data_achievement_strips += count;
        if patched.as_bytes() != original.as_slice() {
            overlay.replace_file(name, patched.as_bytes())?;
        }
    }
    Ok(report)
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
            ("Game/www/data/._Map002.json", br#"{"skip":true}"#),
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
    }
}
