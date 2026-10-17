use rpg_archive_launcher::vfs::Overlay;
use rpg_archive_launcher::{
    archive::{Archive, Limits},
    runtime,
    save::Store,
};
use std::{
    env,
    io::{self, BufRead, Read, Write},
    path::Path,
};

const HELP: &str = "RPG Archive Launcher 0.1 (experimental core, no mount backend yet)\n\nCommands:\n  inspect ARCHIVE [--password-stdin]\n  read ARCHIVE ENTRY [--password-stdin]\n  overlay-bind ARCHIVE WAL [--password-stdin]\n  overlay-read ARCHIVE WAL ENTRY [--password-stdin]\n  overlay-read-at ARCHIVE WAL ENTRY OFFSET LENGTH [--password-stdin]\n  overlay-write-at ARCHIVE WAL ENTRY OFFSET INPUT_FILE [--password-stdin]\n  overlay-truncate ARCHIVE WAL ENTRY SIZE [--password-stdin]\n  overlay-unlink ARCHIVE WAL ENTRY [--password-stdin]\n  overlay-rename ARCHIVE WAL OLD NEW [--password-stdin]\n  save-put WAL ENTRY INPUT_FILE\n  save-get WAL ENTRY\n  save-delete WAL ENTRY\n  save-rename WAL OLD NEW\n\nPasswords: one UTF-8 line on stdin, never command-line arguments.\nread / save-get emit bytes to stdout; redirect only if you want a plaintext file.\nWAL is persistent PLAINTEXT local storage; keep it in a private local directory.\nNo archive overwrite, full extraction, NAS sync, mount or game execution.\n";
fn fail(s: impl Into<String>) -> Box<dyn std::error::Error> {
    io::Error::other(s.into()).into()
}
fn input_file(path: &str) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("input must be a regular file"));
    }
    Ok(file)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let encrypted = args.iter().any(|s| s == "--password-stdin");
    args.retain(|s| s != "--password-stdin");
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print!("{HELP}");
        return Ok(());
    }
    let expected = match args[0].as_str() {
        "inspect" => 2,
        "read" | "overlay-bind" | "save-get" | "save-delete" => 3,
        "overlay-read" | "overlay-unlink" | "save-put" | "save-rename" => 4,
        "overlay-truncate" | "overlay-rename" => 5,
        "overlay-read-at" | "overlay-write-at" => 6,
        _ => return Err(fail("unknown command; use --help")),
    };
    if args.len() != expected {
        return Err(fail("wrong argument count; use --help"));
    }
    match args[0].as_str() {
        "inspect" | "read" | "overlay-bind" | "overlay-read" | "overlay-read-at"
        | "overlay-write-at" | "overlay-truncate" | "overlay-unlink" | "overlay-rename" => {
            rpg_archive_launcher::isolation::install_process_limits()?;
            let mut password = String::new();
            if encrypted {
                let mut line = Vec::new();
                io::stdin().lock().take(4097).read_until(b'\n', &mut line)?;
                password = String::from_utf8(line)?;
                if password.len() > 4096 {
                    return Err(fail("password input exceeds 4096 bytes"));
                }
                if password.ends_with('\n') {
                    password.pop();
                    if password.ends_with('\r') {
                        password.pop();
                    }
                }
                if password.contains('\n') {
                    return Err(fail("password input must be a single line"));
                }
            }
            let mut archive =
                Archive::open(Path::new(&args[1]), &password, Limits::default()).map_err(fail)?;
            if args[0] == "inspect" {
                println!("{}", archive.inspect());
                for c in runtime::detect(&archive.names()) {
                    println!(
                        "runtime candidate: {} root={:?} native_modules={:?}",
                        c.engine, c.root, c.native_modules
                    );
                }
                println!("runtime report limits: 512 candidates, 64 native modules per candidate");
                println!(
                    "mount: not implemented; playability: not tested; Linux CLI address-space ceiling: 512 MiB"
                );
            } else if args[0].starts_with("overlay-") {
                let store = Store::open(&args[2])?;
                let mut overlay = Overlay::new(archive, store).map_err(fail)?;
                match args[0].as_str() {
                    "overlay-bind" => eprintln!("Upper identity verified and bound locally"),
                    "overlay-read" => {
                        io::stdout()
                            .lock()
                            .write_all(&overlay.read_file(&args[3]).map_err(fail)?)?;
                    }
                    "overlay-read-at" => {
                        let bytes = overlay
                            .read_at(&args[3], args[4].parse()?, args[5].parse()?)
                            .map_err(fail)?;
                        io::stdout().lock().write_all(&bytes)?;
                    }
                    "overlay-write-at" => {
                        let offset: u64 = args[4].parse()?;
                        let mut bytes = Vec::new();
                        let file = input_file(&args[5])?;
                        if !file.metadata()?.is_file() {
                            return Err(fail("input must be a regular file"));
                        }
                        file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
                        overlay.write_at(&args[3], offset, &bytes).map_err(fail)?;
                        eprintln!("local write persisted; not synced or merged");
                    }
                    "overlay-truncate" => {
                        overlay.truncate(&args[3], args[4].parse()?).map_err(fail)?
                    }
                    "overlay-unlink" => overlay.unlink(&args[3]).map_err(fail)?,
                    "overlay-rename" => overlay.rename(&args[3], &args[4]).map_err(fail)?,
                    _ => unreachable!(),
                }
            } else {
                let data = archive.read(&args[2]).map_err(fail)?;
                io::stdout().lock().write_all(&data)?;
            }
        }
        "save-put" => {
            let mut data = Vec::new();
            input_file(&args[3])?
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut data)?;
            if data.len() > 16 * 1024 * 1024 {
                return Err(fail("save exceeds 16 MiB"));
            }
            Store::open(&args[1])?.put(&args[2], &data)?;
            eprintln!("saved locally; not synced; not merged into archive");
        }
        "save-get" => {
            let data = Store::open(&args[1])?
                .get(&args[2])?
                .ok_or_else(|| fail("save missing or deleted"))?;
            io::stdout().lock().write_all(&data)?;
        }
        "save-delete" => {
            Store::open(&args[1])?.delete(&args[2])?;
            eprintln!("local tombstone persisted");
        }
        "save-rename" => {
            Store::open(&args[1])?.rename(&args[2], &args[3])?;
            eprintln!("local rename persisted");
        }
        _ => unreachable!(),
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
