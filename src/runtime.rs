//! Metadata-only runtime detection. Never executes archive code.
#[derive(Debug, PartialEq, Eq)]
pub struct Candidate {
    pub root: String,
    pub engine: &'static str,
    pub native_modules: Vec<String>,
}
pub fn detect(names: &[String]) -> Vec<Candidate> {
    names
        .iter()
        .filter_map(|n| {
            let root = n.strip_suffix("package.json")?;
            let has = |p: &str| names.iter().any(|n| n == &format!("{root}{p}"));
            let engine = if has("js/rmmz_core.js") {
                "RPG Maker MZ"
            } else if has("www/js/rpg_core.js") || has("js/rpg_core.js") {
                "RPG Maker MV"
            } else {
                return None;
            };
            Some(Candidate {
                root: root.to_owned(),
                engine,
                native_modules: names
                    .iter()
                    .filter(|n| {
                        n.starts_with(root)
                            && [".node", ".dll", ".so", ".dylib"]
                                .iter()
                                .any(|e| n.to_ascii_lowercase().ends_with(e))
                    })
                    .cloned()
                    .collect(),
            })
        })
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
}
