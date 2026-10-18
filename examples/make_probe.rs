//! Creates only synthetic, redistributable MV/MZ-shaped test content.
//! Not a licensed RPG Maker engine or a real game acceptance test.
use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: make_probe OUTPUT.7z")?;
    let mut writer = ArchiveWriter::create(path)?;
    for (root, engine) in [("MV 遊戲", "rpg_core"), ("MZ 遊戲", "rmmz_core")] {
        let html=br#"<!doctype html><meta charset="utf-8"><title>Archive read probe</title><h1 id="result">Reading mounted assets...</h1><script>
(async () => { try {
 const fs = require('fs'); const path = require('path');
 const data = fs.readFileSync(path.join(process.cwd(),'data','probe.json'),'utf8');
 if (JSON.parse(data).fixture !== 'synthetic') throw new Error('Unexpected resource');
 const response = await fetch('data/probe.json');
 if ((await response.json()).fixture !== 'synthetic') throw new Error('Fetch failed');
 document.getElementById('result').textContent = 'PASS: Node and browser resource reads; NW.js '+process.versions.nw;
} catch (e) { document.getElementById('result').textContent='FAIL: '+e.message; } })();
</script>"#;
        for (path,data) in [("package.json".into(),br#"{"name":"synthetic-archive-probe","main":"index.html","window":{"width":700,"height":300}}"#.as_slice()),("index.html".into(),html.as_slice()),("data/probe.json".into(),br#"{"fixture":"synthetic"}"#.as_slice()),(format!("js/{engine}.js"),b"// Synthetic layout marker, not RPG Maker engine code.\n".as_slice()),("save/fixture.txt".into(),b"lower-save".as_slice())] {
            writer.push_archive_entry(ArchiveEntry::new_file(&format!("{root}/{path}")),Some(data))?;
        }
    }
    writer.finish()?;
    Ok(())
}
