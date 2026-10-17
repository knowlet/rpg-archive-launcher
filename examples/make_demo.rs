//! Makes a small, unencrypted synthetic archive; contains no commercial game code.
use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let destination = std::env::args()
        .nth(1)
        .ok_or("usage: cargo run --example make_demo -- OUTPUT.7z")?;
    // Never overwrite an existing file, including a user's archive.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .open(&destination)?;
    let mut writer = ArchiveWriter::new(file)?;
    for (name, bytes) in [
        (
            "data/System.json",
            b"{\"gameTitle\":\"Synthetic demo\"}".as_slice(),
        ),
        ("save/file1.rpgsave", b"synthetic original save".as_slice()),
        (
            "README.txt",
            b"Test data only; not a playable RPG.".as_slice(),
        ),
    ] {
        writer.push_archive_entry(ArchiveEntry::new_file(name), Some(bytes))?;
    }
    writer.finish()?.sync_all()?;
    println!("Created synthetic archive: {destination}");
    Ok(())
}
