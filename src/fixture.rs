//! Synthetic MV/MZ-shaped archive used by the playability probe.
//! The bytes are redistributable test content, not a licensed engine or game.
use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
use std::{fs::OpenOptions, path::Path};

pub fn write_synthetic_probe(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // create_new leaves an existing file untouched. ArchiveWriter::create truncates.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?;
    let mut writer = ArchiveWriter::new(file)?;
    for (root, engine) in [("MV 遊戲", "rpg_core"), ("MZ 遊戲", "rmmz_core")] {
        let html = br#"<!doctype html><meta charset="utf-8"><title>Archive read probe</title><h1 id="result">Reading mounted assets...</h1><script>
(async () => { try {
 const fs = require('fs'); const path = require('path');
 const data = fs.readFileSync(path.join(process.cwd(),'data','probe.json'),'utf8');
 if (JSON.parse(data).fixture !== 'synthetic') throw new Error('Unexpected resource');
 const response = await fetch('data/probe.json');
 if ((await response.json()).fixture !== 'synthetic') throw new Error('Fetch failed');
 document.getElementById('result').textContent = 'PASS: Node and browser resource reads; NW.js '+process.versions.nw;
} catch (e) { document.getElementById('result').textContent='FAIL: '+e.message; } })();
</script>"#;
        for (name, data) in [
            (
                "package.json".to_string(),
                br#"{"name":"synthetic-archive-probe","main":"index.html","window":{"width":700,"height":300}}"#
                    .as_slice(),
            ),
            ("index.html".into(), html.as_slice()),
            ("data/probe.json".into(), br#"{"fixture":"synthetic"}"#.as_slice()),
            (
                format!("js/{engine}.js"),
                b"// Synthetic layout marker, not RPG Maker engine code.\n".as_slice(),
            ),
            ("save/fixture.txt".into(), b"lower-save".as_slice()),
        ] {
            writer.push_archive_entry(
                ArchiveEntry::new_file(&format!("{root}/{name}")),
                Some(data),
            )?;
        }
    }
    writer.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_truncate_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("already.7z");
        std::fs::write(&path, b"keep-these-bytes").unwrap();
        assert!(write_synthetic_probe(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep-these-bytes");
        let fresh = dir.path().join("fresh.7z");
        write_synthetic_probe(&fresh).unwrap();
        assert!(std::fs::metadata(&fresh).unwrap().len() > 0);
    }
}
