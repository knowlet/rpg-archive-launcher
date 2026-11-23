//! Split 7z volume discovery and sequential read/seek across sibling `.7z.NNN` parts.
//!
//! The decoder sees one logical byte stream; this does not unpack archive members to disk.
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::SystemTime,
};

type Result<T> = std::result::Result<T, String>;

/// User-supplied path to the volumes that form one logical 7z container (sorted).
pub fn resolve_archive(path: &Path) -> Result<Vec<PathBuf>> {
    if !path.is_file() {
        return Err(format!(
            "archive not found or not a regular file: {}",
            path.display()
        ));
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("archive path has no file name: {}", path.display()))?;
    let (stem_os, vol) = parse_volume_suffix_os(file_name);
    if vol.is_some() {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut volumes = Vec::new();
        for index in 1..=999 {
            let name = volume_part_name(&stem_os, index);
            let candidate = parent.join(&name);
            if !candidate.is_file() {
                if index == 1 {
                    return Err(format!(
                        "split volume {} missing in {}",
                        name.to_string_lossy(),
                        parent.display()
                    ));
                }
                if has_later_split_part_os(parent, &stem_os, index) {
                    return Err(format!(
                        "split volume gap: missing {}",
                        name.to_string_lossy()
                    ));
                }
                break;
            }
            volumes.push(candidate);
        }
        if volumes.is_empty() {
            return Err("no split volumes resolved".into());
        }
        return Ok(volumes);
    }
    Ok(vec![path.to_path_buf()])
}

fn volume_part_name(stem: &OsStr, index: u32) -> OsString {
    let mut name = stem.to_os_string();
    name.push(format!(".{index:03}"));
    name
}

fn has_later_split_part_os(parent: &Path, stem: &OsStr, after: u32) -> bool {
    (after + 1..=999).any(|index| parent.join(volume_part_name(stem, index)).is_file())
}

fn parse_volume_suffix_os(file_name: &OsStr) -> (OsString, Option<u32>) {
    let bytes = file_name.as_encoded_bytes();
    let Some(dot) = bytes.iter().rposition(|&b| b == b'.') else {
        return (file_name.to_os_string(), None);
    };
    if dot == 0 {
        return (file_name.to_os_string(), None);
    }
    let suffix = &bytes[dot + 1..];
    if suffix.len() != 3 || !suffix.iter().all(|b| b.is_ascii_digit()) {
        return (file_name.to_os_string(), None);
    }
    let Ok(suffix_str) = std::str::from_utf8(suffix) else {
        return (file_name.to_os_string(), None);
    };
    let Ok(num) = suffix_str.parse::<u32>() else {
        return (file_name.to_os_string(), None);
    };
    if num < 1 {
        return (file_name.to_os_string(), None);
    }
    let stem_bytes = &bytes[..dot];
    if stem_bytes.ends_with(b".7z") || stem_bytes.ends_with(b".zip") {
        #[cfg(unix)]
        let stem = OsStr::from_bytes(stem_bytes).to_os_string();
        #[cfg(not(unix))]
        let stem = match file_name.to_str() {
            Some(text) => {
                let (stem_str, detected) = parse_volume_suffix(text);
                if detected != Some(num) {
                    return (file_name.to_os_string(), None);
                }
                OsString::from(stem_str)
            }
            None => return (file_name.to_os_string(), None),
        };
        return (stem, Some(num));
    }
    (file_name.to_os_string(), None)
}

/// Strip `.7z.NNN` or `.zip.NNN` style extensions for stable WAL naming.
pub fn volume_set_label(path: &Path) -> String {
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive".into());
    let (stem, vol) = parse_volume_suffix(&file_name);
    if vol.is_some() {
        stem.to_string()
    } else {
        file_name
    }
}

fn parse_volume_suffix(file_name: &str) -> (&str, Option<u32>) {
    if let Some(dot) = file_name.rfind('.')
        && dot > 0
    {
        let suffix = &file_name[dot + 1..];
        if suffix.len() == 3
            && suffix.chars().all(|c| c.is_ascii_digit())
            && let Ok(num) = suffix.parse::<u32>()
            && num >= 1
        {
            let stem = &file_name[..dot];
            if stem.ends_with(".7z") || stem.ends_with(".zip") {
                return (stem, Some(num));
            }
        }
    }
    (file_name, None)
}

#[derive(Debug)]
struct VolumeSnapshot {
    len: u64,
    modified: Option<SystemTime>,
}

#[derive(Debug)]
pub struct VolumeChain {
    files: Vec<File>,
    lengths: Vec<u64>,
    snapshots: Vec<VolumeSnapshot>,
    total: u64,
    position: u64,
}

impl VolumeChain {
    pub fn open(paths: &[PathBuf]) -> Result<Self> {
        if paths.is_empty() {
            return Err("no volume paths".into());
        }
        if paths.len() > 1 {
            let first_name = paths[0]
                .file_name()
                .ok_or_else(|| "split volume path has no file name".to_string())?;
            let (stem_os, vol) = parse_volume_suffix_os(first_name);
            if vol.is_none() {
                return Err("split volume path missing part suffix".into());
            }
            for (index, path) in paths.iter().enumerate() {
                let expected = volume_part_name(&stem_os, index as u32 + 1);
                let actual = path
                    .file_name()
                    .ok_or_else(|| format!("volume path has no file name: {}", path.display()))?;
                if actual != expected.as_os_str() {
                    return Err(format!(
                        "split volumes out of order: expected {}, got {}",
                        expected.to_string_lossy(),
                        actual.to_string_lossy()
                    ));
                }
            }
        }
        let mut files = Vec::with_capacity(paths.len());
        let mut lengths = Vec::with_capacity(paths.len());
        let mut snapshots = Vec::with_capacity(paths.len());
        let mut total = 0u64;
        for path in paths {
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NONBLOCK);
            }
            let file = options
                .open(path)
                .map_err(|e| format!("open volume {}: {e}", path.display()))?;
            let meta = file.metadata().map_err(|e| e.to_string())?;
            if !meta.is_file() {
                return Err(format!("volume must be a regular file: {}", path.display()));
            }
            let len = meta.len();
            total = total
                .checked_add(len)
                .ok_or_else(|| "volume set size overflow".to_string())?;
            lengths.push(len);
            snapshots.push(VolumeSnapshot {
                len,
                modified: meta.modified().ok(),
            });
            files.push(file);
        }
        Ok(Self {
            files,
            lengths,
            snapshots,
            total,
            position: 0,
        })
    }

    pub fn total_len(&self) -> u64 {
        self.total
    }

    pub fn logical_position(&self) -> u64 {
        self.position
    }

    pub fn volume_metadata_unchanged(&self) -> io::Result<()> {
        for (file, snap) in self.files.iter().zip(&self.snapshots) {
            let meta = file.metadata()?;
            if !meta.is_file() || meta.len() != snap.len || meta.modified().ok() != snap.modified {
                return Err(io::Error::other("split volume set changed on disk"));
            }
        }
        Ok(())
    }

    fn locate(&self, pos: u64) -> (usize, u64) {
        let mut offset = 0u64;
        for (index, &len) in self.lengths.iter().enumerate() {
            if pos < offset + len {
                return (index, pos - offset);
            }
            offset += len;
        }
        (
            self.files.len().saturating_sub(1),
            self.lengths.last().copied().unwrap_or(0),
        )
    }
}

impl Read for VolumeChain {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.total {
            return Ok(0);
        }
        let (mut volume, mut local) = self.locate(self.position);
        let mut written = 0usize;
        while written < buf.len() && self.position < self.total {
            let file = &mut self.files[volume];
            file.seek(SeekFrom::Start(local))?;
            let remaining_in_volume = self.lengths[volume].saturating_sub(local);
            let chunk = (buf.len() - written).min(remaining_in_volume as usize);
            let count = file.read(&mut buf[written..written + chunk])?;
            if count == 0 {
                break;
            }
            written += count;
            self.position += count as u64;
            local += count as u64;
            if local >= self.lengths[volume] {
                volume += 1;
                local = 0;
            }
        }
        Ok(written)
    }
}

impl Seek for VolumeChain {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(delta) => {
                if delta >= 0 {
                    self.total.checked_add(delta as u64).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "seek overflow")
                    })?
                } else {
                    let magnitude = delta.unsigned_abs();
                    self.total.checked_sub(magnitude).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "seek before start")
                    })?
                }
            }
            SeekFrom::Current(delta) => {
                if delta >= 0 {
                    self.position.checked_add(delta as u64).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "seek overflow")
                    })?
                } else {
                    let magnitude = delta.unsigned_abs();
                    self.position.checked_sub(magnitude).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "seek before start")
                    })?
                }
            }
        };
        if new_pos > self.total {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek past end of volume set",
            ));
        }
        self.position = new_pos;
        Ok(new_pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_volume_suffix_os_strips_part_index_from_stem() {
        let (stem, vol) = parse_volume_suffix_os(OsStr::new("Game.7z.001"));
        assert_eq!(vol, Some(1));
        assert_eq!(stem, OsString::from("Game.7z"));
    }

    #[test]
    fn parses_split_suffix_and_discovers_siblings() {
        let temp = tempfile::tempdir().unwrap();
        for (name, body) in [
            ("Game.7z.001", b"part1"),
            ("Game.7z.002", b"part2"),
            ("Game.7z.003", b"part3"),
        ] {
            std::fs::write(temp.path().join(name), body).unwrap();
        }
        let resolved = resolve_archive(&temp.path().join("Game.7z.001")).unwrap();
        assert_eq!(resolved.len(), 3);
        assert!(
            resolved[0]
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with(".001")
        );
        assert_eq!(volume_set_label(&resolved[0]), "Game.7z");
    }

    #[test]
    fn resolving_from_later_part_starts_at_first_volume() {
        let temp = tempfile::tempdir().unwrap();
        for (name, body) in [
            ("Game.7z.001", b"part1"),
            ("Game.7z.002", b"part2"),
            ("Game.7z.003", b"part3"),
        ] {
            std::fs::write(temp.path().join(name), body).unwrap();
        }
        let resolved = resolve_archive(&temp.path().join("Game.7z.002")).unwrap();
        assert_eq!(resolved.len(), 3);
        assert_eq!(
            resolved[0].file_name().unwrap().to_str().unwrap(),
            "Game.7z.001"
        );
    }

    #[test]
    fn detects_gap_in_split_numbering() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("Game.7z.001"), b"a").unwrap();
        std::fs::write(temp.path().join("Game.7z.003"), b"c").unwrap();
        assert!(
            resolve_archive(&temp.path().join("Game.7z.001"))
                .unwrap_err()
                .contains("gap")
        );
    }

    #[test]
    fn single_seven_z_path_is_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("solo.7z");
        std::fs::write(&path, b"7z").unwrap();
        assert_eq!(resolve_archive(&path).unwrap(), vec![path]);
    }

    #[test]
    fn volume_chain_reads_across_parts() {
        let temp = tempfile::tempdir().unwrap();
        let paths: Vec<_> = (1..=3)
            .map(|i| {
                let p = temp.path().join(format!("chunk.7z.{i:03}"));
                std::fs::write(&p, format!("vol{i}").as_bytes()).unwrap();
                p
            })
            .collect();
        let mut chain = VolumeChain::open(&paths).unwrap();
        let mut out = String::new();
        std::io::Read::read_to_string(&mut chain, &mut out).unwrap();
        assert_eq!(out, "vol1vol2vol3");
        chain.seek(SeekFrom::Start(4)).unwrap();
        let mut slice = [0u8; 3];
        chain.read_exact(&mut slice).unwrap();
        assert_eq!(&slice, b"vol");
    }

    #[test]
    fn seek_before_start_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("solo.7z");
        std::fs::write(&path, b"abcdef").unwrap();
        let mut chain = VolumeChain::open(&[path]).unwrap();
        chain.seek(SeekFrom::Start(3)).unwrap();
        assert!(
            chain.seek(SeekFrom::Current(-10)).unwrap_err().kind() == io::ErrorKind::InvalidInput
        );
    }

    #[cfg(unix)]
    #[test]
    fn discovers_split_volumes_with_non_utf8_stem_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let stem = OsStr::from_bytes(b"G\xe9me.7z");
        let first_name = volume_part_name(stem, 1);
        let (parsed, vol) = parse_volume_suffix_os(&first_name);
        assert_eq!(vol, Some(1));
        assert_eq!(parsed.as_bytes(), b"G\xe9me.7z");
        let temp = tempfile::tempdir().unwrap();
        for index in 1..=2 {
            let name = volume_part_name(stem, index);
            if let Err(error) = std::fs::write(temp.path().join(&name), format!("p{index}")) {
                // APFS rejects names that are not Unicode. The byte parser above
                // still runs; a volume with this stem cannot exist on that host.
                assert_eq!(error.raw_os_error(), Some(libc::EILSEQ), "{error}");
                return;
            }
        }
        let first = temp.path().join(first_name);
        assert_eq!(resolve_archive(&first).unwrap().len(), 2);
    }

    #[test]
    fn rejects_out_of_order_chain_paths() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("Game.7z.001");
        let second = temp.path().join("Game.7z.002");
        std::fs::write(&first, b"a").unwrap();
        std::fs::write(&second, b"b").unwrap();
        assert!(
            VolumeChain::open(&[second, first])
                .unwrap_err()
                .contains("out of order")
        );
    }
}
