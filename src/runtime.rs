//! Metadata-only runtime detection. Never executes archive code.
//! Index once; cap report growth to 512 candidates and 64 native modules each.
use std::collections::BTreeSet;
#[derive(Debug, PartialEq, Eq)]
pub struct Candidate {
    pub root: String,
    pub engine: &'static str,
    pub native_modules: Vec<String>,
}
pub fn detect(names: &[String]) -> Vec<Candidate> {
    let index: BTreeSet<&str> = names.iter().map(String::as_str).collect();
    let native: BTreeSet<&str> = index
        .iter()
        .copied()
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            [".node", ".dll", ".so", ".dylib"]
                .iter()
                .any(|suffix| lower.ends_with(suffix))
        })
        .collect();
    index
        .iter()
        .filter_map(|name| {
            let root = name.strip_suffix("package.json")?;
            if !root.is_empty() && !root.ends_with('/') {
                return None;
            }
            let has = |suffix: &str| index.contains(format!("{root}{suffix}").as_str());
            let engine = if has("js/rmmz_core.js") || has("www/js/rmmz_core.js") {
                "RPG Maker MZ"
            } else if has("js/rpg_core.js") || has("www/js/rpg_core.js") {
                "RPG Maker MV"
            } else {
                return None;
            };
            let native_modules = native
                .range(root..)
                .take_while(|name| name.starts_with(root))
                .take(64)
                .map(|name| (*name).to_owned())
                .collect();
            Some(Candidate {
                root: root.to_owned(),
                engine,
                native_modules,
            })
        })
        .take(512)
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_without_executing() {
        let names = [
            "Game/package.json",
            "Game/www/js/rpg_core.js",
            "Game/plugin.dll",
        ]
        .map(str::to_owned);
        let found = detect(&names);
        assert_eq!(found[0].engine, "RPG Maker MV");
        assert_eq!(found[0].native_modules, ["Game/plugin.dll"]);
        assert!(detect(&["Game.exe".into()]).is_empty());
    }
    #[test]
    fn detects_mz_www_and_bounds_indexed_report() {
        let mut names = Vec::new();
        for i in 0..20_000 {
            names.push(format!("candidate{i}/package.json"));
        }
        names.extend(["Game/package.json", "Game/www/js/rmmz_core.js"].map(str::to_owned));
        names.extend((0..100).map(|i| format!("Game/module{i}.node")));
        let found = detect(&names);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].engine, "RPG Maker MZ");
        assert_eq!(found[0].native_modules.len(), 64);
        assert!(detect(&["notpackage.json".into(), "notjs/rmmz_core.js".into()]).is_empty());
    }
}
