//! Split 7z volume discovery and sequential read/seek across sibling `.7z.NNN` parts.
//!
//! The decoder sees one logical byte stream; this does not unpack archive members to disk.
use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
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
        .and_then(OsStr::to_str)
        .ok_or_else(|| format!("non-UTF-8 archive name: {}", path.display()))?;
    let (stem, vol) = parse_volume_suffix(file_name);
    if let Some(start) = vol {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut volumes = Vec::new();
        for index in start..=999 {
            let name = format!("{stem}.{index:03}");
            let candidate = parent.join(&name);
            if !candidate.is_file() {
                if index == start {
                    return Err(format!(
                        "split volume {name} missing in {}",
                        parent.display()
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

/// Strip `.7z.NNN` or `.zip.NNN` style extensions for stable WAL naming.
pub fn volume_set_label(path: &Path) -> String {
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("archive");
    let (stem, vol) = parse_volume_suffix(file_name);
    if vol.is_some() {
        stem.to_string()
    } else {
        file_name.to_string()
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
pub struct VolumeChain {
    files: Vec<File>,
    lengths: Vec<u64>,
    total: u64,
    position: u64,
}

impl VolumeChain {
    pub fn open(paths: &[PathBuf]) -> Result<Self> {
        if paths.is_empty() {
            return Err("no volume paths".into());
        }
        let mut files = Vec::with_capacity(paths.len());
        let mut lengths = Vec::with_capacity(paths.len());
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
            files.push(file);
        }
        Ok(Self {
            files,
            lengths,
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
        for (file, &expected_len) in self.files.iter().zip(&self.lengths) {
            let meta = file.metadata()?;
            if !meta.is_file() || meta.len() != expected_len {
                return Err(io::Error::other("split volume set changed size"));
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
                    self.total.saturating_add(delta as u64)
                } else {
                    self.total.saturating_sub(delta.unsigned_abs())
                }
            }
            SeekFrom::Current(delta) => {
                if delta >= 0 {
                    self.position.saturating_add(delta as u64)
                } else {
                    self.position.saturating_sub(delta.unsigned_abs())
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
}
