//! RPG Maker overlay repairs ported from the Python autofix script.
//! Mutations go into Upper only; the archive stays read-only.
use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepairReport {
    pub plugins_greenworks_disabled: usize,
    pub data_achievement_strips: usize,
    pub mpp_color_index_moves: usize,
    pub pixi_sourcemap_strips: usize,
    pub package_name_set_www: bool,
}

static GREENWORKS_STATUS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"("name"\s*:\s*['"]OrangeGreenworks['"][^}]*?"status"\s*:\s*)true"#).unwrap()
});
static ACHIEVEMENT_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"OrangeGreenworks\.activateAchievement\(['"].+?['"]\);?"#).unwrap()
});
static WINDOW_INIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Window_Base\.prototype\.initialize\.call\s*\(.*\)").unwrap());
static COLOR_INDEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"this\._colorIndex\s*=\s*0\s*;").unwrap());
static PIXI_MAP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"//# sourceMappingURL=pixi\.js\.map\s*\n?").unwrap());

pub fn is_apple_double(name: &str) -> bool {
    name.split('/')
        .any(|part| part.starts_with("._") || part == ".DS_Store")
}

pub fn fix_plugins_js(content: &str) -> (String, usize) {
    let count = GREENWORKS_STATUS.find_iter(content).count();
    if count == 0 {
        return (content.to_owned(), 0);
    }
    let out = GREENWORKS_STATUS
        .replace_all(content, "${1}false")
        .into_owned();
    (out, count)
}

pub fn strip_achievement_calls_json(content: &str) -> (String, usize) {
    let mut value: Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return (content.to_owned(), 0),
    };
    let mut changes = 0usize;
    fn walk(value: &mut Value, changes: &mut usize) {
        match value {
            Value::Object(map) => {
                for (key, child) in map.iter_mut() {
                    if key == "parameters"
                        && let Value::Array(params) = child
                    {
                        for entry in params.iter_mut() {
                            if let Value::String(text) = entry {
                                let stripped = ACHIEVEMENT_CALL.replace_all(text, "void 0;");
                                if stripped.len() != text.len() {
                                    *changes += 1;
                                    *text = stripped.into_owned();
                                }
                            }
                        }
                    }
                    walk(child, changes);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, changes);
                }
            }
            _ => {}
        }
    }
    walk(&mut value, &mut changes);
    if changes == 0 {
        return (content.to_owned(), 0);
    }
    let out = serde_json::to_string(&value).unwrap_or_else(|_| content.to_owned());
    (out, changes)
}

pub fn fix_mpp_color_index(content: &str) -> (String, usize) {
    let mut lines: Vec<String> = content.lines().map(str::to_owned).collect();
    let mut moves = 0usize;
    let mut index = 0usize;
    while index < lines.len() {
        if WINDOW_INIT.is_match(&lines[index]) {
            for offset in 1..=5 {
                let target = index + offset;
                if target < lines.len() && COLOR_INDEX.is_match(&lines[target]) {
                    if index > 0 && COLOR_INDEX.is_match(&lines[index - 1]) {
                        break;
                    }
                    let line = lines.remove(target);
                    lines.insert(index, line);
                    moves += 1;
                    break;
                }
            }
        }
        index += 1;
    }
    if moves == 0 {
        return (content.to_owned(), 0);
    }
    let trailing_newline = content.ends_with('\n');
    let mut out = lines.join("\n");
    if trailing_newline {
        out.push('\n');
    }
    (out, moves)
}

pub fn remove_pixi_sourcemap(content: &str) -> (String, usize) {
    let count = PIXI_MAP.find_iter(content).count();
    if count == 0 {
        return (content.to_owned(), 0);
    }
    (PIXI_MAP.replace_all(content, "").into_owned(), count)
}

pub fn fix_package_name(content: &str) -> Option<String> {
    let mut value: Value = serde_json::from_str(content).ok()?;
    let Value::Object(ref mut map) = value else {
        return None;
    };
    let Some(Value::String(name)) = map.get("name") else {
        return None;
    };
    if !name.is_empty() {
        return None;
    }
    map.insert("name".to_owned(), Value::String("www".to_owned()));
    serde_json::to_string(&value).ok()
}

pub fn archive_relative_name(game_root: &str, rel: &str) -> String {
    let root = game_root.trim_end_matches('/');
    if root.is_empty() {
        rel.to_owned()
    } else {
        format!("{root}/{rel}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disables_greenworks_status() {
        let input = r#"{ "plugins": [ { "name":"OrangeGreenworks", "status":true } ] }"#;
        let (out, n) = fix_plugins_js(input);
        assert!(n >= 1);
        assert!(out.contains("\"status\":false"));
        assert!(!out.contains("\"status\":true"));
    }

    #[test]
    fn strips_achievement_parameters() {
        let input = r#"{"events":[{"parameters":["OrangeGreenworks.activateAchievement('x');"]}]}"#;
        let (out, n) = strip_achievement_calls_json(input);
        assert_eq!(n, 1);
        assert!(!out.contains("activateAchievement"));
        assert!(out.contains("void 0;"));
    }

    #[test]
    fn moves_color_index_line() {
        let input = "a\nWindow_Base.prototype.initialize.call(this);\nb\nthis._colorIndex = 0;\n";
        let (out, n) = fix_mpp_color_index(input);
        assert_eq!(n, 1);
        let lines: Vec<_> = out.lines().collect();
        assert!(COLOR_INDEX.is_match(lines[1]));
        assert!(WINDOW_INIT.is_match(lines[2]));
    }

    #[test]
    fn removes_pixi_map_comment() {
        let input = "console.log(1);\n//# sourceMappingURL=pixi.js.map\n";
        let (out, n) = remove_pixi_sourcemap(input);
        assert_eq!(n, 1);
        assert!(!out.contains("sourceMappingURL"));
    }

    #[test]
    fn sets_empty_package_name() {
        let Some(out) = fix_package_name(r#"{"name":""}"#) else {
            panic!("expected change");
        };
        assert!(out.contains("\"name\":\"www\"") || out.contains("\"name\": \"www\""));
    }
}
