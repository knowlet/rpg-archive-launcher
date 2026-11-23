//! Creates only synthetic, redistributable MV/MZ-shaped test content.
//! Not a licensed RPG Maker engine or a real game acceptance test.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: make_probe OUTPUT.7z")?;
    rpg_archive_launcher::fixture::write_synthetic_probe(std::path::Path::new(&path))
}
