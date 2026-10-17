//! Platform-neutral file operations over an immutable archive and durable Upper.
//!
//! Each mutation commits a complete replacement file (or one atomic rename), not
//! a POSIX handle/inode operation. There are no open handles, directory mutation,
//! mmap, permissions, or concurrent writers. Paths are exact, case-sensitive
//! logical keys. File/directory collisions are rejected against live lower and
//! Upper names. This core alone is not a mount-ready filesystem. Reads never copy up. Holes and truncate growth are zero-filled.
//! Per-file buffers are bounded below the Store limit; aggregate Store capacity
//! can still reject a commit without changing either visible file.
use crate::archive::{Archive, validate_archive_path};
use crate::save::{Entry, MAX_BYTES, Store};

type Result<T> = std::result::Result<T, String>;

pub struct Overlay {
    archive: Archive,
    upper: Store,
}

// Include transaction framing plus conservative Store map-entry accounting.
// Rename needs two keys and two entries, so use that bound for every operation.
fn file_limit(path: &str, other: Option<&str>) -> usize {
    MAX_BYTES.saturating_sub(12 + 1 + 8 + 512 + path.len() + other.unwrap_or(path).len())
}

impl Overlay {
    pub fn new(archive: Archive, upper: Store) -> Result<Self> {
        let mut overlay = Self { archive, upper };
        // Raw save commands and externally supplied WALs may contain keys that
        // are valid individually but inconsistent with this lower namespace.
        for name in overlay.upper.live_names().map_err(|e| e.to_string())? {
            Self::validate(name)?;
            overlay.validate_destination(name)?;
        }
        let revision = overlay.archive.revision_sha256()?;
        overlay
            .upper
            .bind_archive(revision)
            .map_err(|e| e.to_string())?;
        Ok(overlay)
    }

    fn validate(path: &str) -> Result<()> {
        validate_archive_path(path)
    }

    fn exists(&self, path: &str) -> Result<bool> {
        Self::validate(path)?;
        match self.upper.lookup(path).map_err(|e| e.to_string())? {
            Some(Entry::Data(_)) => Ok(true),
            Some(Entry::Deleted) => Ok(false),
            None => Ok(self.archive.file_size(path).is_some()),
        }
    }

    fn validate_destination(&self, path: &str) -> Result<()> {
        if self.archive.is_explicit_directory(path) {
            return Err("destination is an explicit archive directory".into());
        }
        for (index, _) in path.match_indices('/') {
            if self.exists(&path[..index])? {
                return Err("destination ancestor is a file".into());
            }
        }
        if self
            .upper
            .has_live_descendant(path)
            .map_err(|e| e.to_string())?
        {
            return Err("destination is an implicit directory".into());
        }
        for name in self.archive.descendant_names(path) {
            if self.exists(name)? {
                return Err("destination is an implicit directory".into());
            }
        }
        Ok(())
    }

    fn contents(&mut self, path: &str, limit: usize) -> Result<Option<Vec<u8>>> {
        Self::validate(path)?;
        let data = match self.upper.lookup(path).map_err(|e| e.to_string())? {
            Some(Entry::Data(data)) => Some(data),
            Some(Entry::Deleted) => None,
            None => match self.archive.file_size(path) {
                Some(size) => {
                    if size > limit as u64 {
                        return Err("file exceeds bounded Overlay buffer limit".into());
                    }
                    Some(self.archive.read(path)?)
                }
                None => None,
            },
        };
        if data.as_ref().is_some_and(|bytes| bytes.len() > limit) {
            return Err("file exceeds bounded Overlay buffer limit".into());
        }
        Ok(data)
    }

    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        self.contents(path, file_limit(path, None))?
            .ok_or_else(|| "file not found".into())
    }

    pub fn read_at(&mut self, path: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
        Self::validate(path)?;
        let limit = file_limit(path, None);
        if length > limit {
            return Err("read request exceeds Overlay buffer limit".into());
        }
        let data = self.contents(path, limit)?.ok_or("file not found")?;
        if offset >= data.len() as u64 {
            return Ok(Vec::new());
        }
        let start = offset as usize; // bounded by the existing Vec length
        let count = length.min(data.len() - start);
        let mut result = Vec::new();
        result.try_reserve_exact(count).map_err(|e| e.to_string())?;
        result.extend_from_slice(&data[start..start + count]);
        Ok(result)
    }

    pub fn write_at(&mut self, path: &str, offset: u64, bytes: &[u8]) -> Result<()> {
        Self::validate(path)?;
        let limit = file_limit(path, None);
        self.validate_destination(path)?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or("write offset overflow")?;
        if end > limit as u64 {
            return Err("write exceeds Overlay file limit".into());
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let mut data = self.contents(path, limit)?.unwrap_or_default();
        // Empty writes are no-ops; nonempty writes create missing files.
        if !bytes.is_empty() {
            let end = end as usize;
            if end > data.len() {
                data.try_reserve_exact(end - data.len())
                    .map_err(|e| e.to_string())?;
                data.resize(end, 0);
            }
            data[offset as usize..end].copy_from_slice(bytes);
        }
        self.upper.put(path, &data).map_err(|e| e.to_string())
    }

    pub fn truncate(&mut self, path: &str, size: u64) -> Result<()> {
        Self::validate(path)?;
        let limit = file_limit(path, None);
        if size > limit as u64 {
            return Err("truncate exceeds Overlay file limit".into());
        }
        if !self.exists(path)? {
            return Err("file not found".into());
        }
        // Truncate-to-zero does not need to decompress the lower contents.
        let mut data = if size == 0 {
            Vec::new()
        } else {
            self.contents(path, limit)?.ok_or("file not found")?
        };
        let size = size as usize;
        if size > data.len() {
            data.try_reserve_exact(size - data.len())
                .map_err(|e| e.to_string())?;
        }
        data.resize(size, 0);
        self.upper.put(path, &data).map_err(|e| e.to_string())
    }

    pub fn unlink(&mut self, path: &str) -> Result<()> {
        if !self.exists(path)? {
            return Err("file not found".into());
        }
        self.upper.delete(path).map_err(|e| e.to_string())
    }

    pub fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        Self::validate(from)?;
        Self::validate(to)?;
        self.validate_destination(to)?;
        if from == to {
            return if self.exists(from)? {
                Ok(())
            } else {
                Err("file not found".into())
            };
        }
        match self.upper.lookup(from).map_err(|e| e.to_string())? {
            Some(Entry::Data(data)) => {
                if data.len() > file_limit(to, None) {
                    return Err("rename destination exceeds Overlay file limit".into());
                }
                self.upper.rename(from, to).map_err(|e| e.to_string())
            }
            Some(Entry::Deleted) => Err("file not found".into()),
            None => {
                let data = self
                    .contents(from, file_limit(from, Some(to)).min(file_limit(to, None)))?
                    .ok_or("file not found")?;
                self.upper
                    .move_data(from, to, &data)
                    .map_err(|e| e.to_string())
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::archive::Limits;
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
    use std::{fs, path::Path};

    fn fixture(dir: &Path) {
        let mut writer = ArchiveWriter::create(dir.join("game.7z")).unwrap();
        for (name, bytes) in [
            ("data/a", b"abcdef".as_slice()),
            ("save/b", b"old".as_slice()),
        ] {
            writer
                .push_archive_entry(ArchiveEntry::new_file(name), Some(bytes))
                .unwrap();
        }
        writer.finish().unwrap();
    }
    fn open(dir: &Path) -> Overlay {
        Overlay::new(
            Archive::open(dir.join("game.7z"), "", Limits::default()).unwrap(),
            Store::open(dir.join("upper.wal")).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn explicit_empty_directories_and_ancestors_cannot_be_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("game.7z");
        let mut writer = ArchiveWriter::create(&path).unwrap();
        let mut directory = ArchiveEntry::new_file("empty/nested/");
        directory.is_directory = true;
        writer.push_archive_entry(directory, None::<&[u8]>).unwrap();
        writer
            .push_archive_entry(ArchiveEntry::new_file("source"), Some(b"x".as_slice()))
            .unwrap();
        writer.finish().unwrap();
        let mut overlay = open(temp.path());
        let before = fs::read(temp.path().join("upper.wal")).unwrap();
        for destination in ["empty", "empty/nested"] {
            assert!(overlay.write_at(destination, 0, b"x").is_err());
            assert!(overlay.rename("source", destination).is_err());
        }
        assert_eq!(fs::read(temp.path().join("upper.wal")).unwrap(), before);
        overlay.write_at("empty/nested/new", 0, b"x").unwrap();
        drop(overlay);
        let mut overlay = open(temp.path());
        assert_eq!(overlay.read_at("empty/nested/new", 0, 1).unwrap(), b"x");
    }

    #[test]
    fn persisted_upper_conflicting_with_lower_is_rejected_at_open() {
        for key in ["data", "data/a/child"] {
            let temp = tempfile::tempdir().unwrap();
            fixture(temp.path());
            let wal = temp.path().join("upper.wal");
            let mut store = Store::open(&wal).unwrap();
            let revision = Archive::open(temp.path().join("game.7z"), "", Limits::default())
                .unwrap()
                .revision_sha256()
                .unwrap();
            store.bind_archive(revision).unwrap();
            store.put(key, b"raw save").unwrap();
            drop(store);
            let before = fs::read(&wal).unwrap();
            assert!(
                Overlay::new(
                    Archive::open(temp.path().join("game.7z"), "", Limits::default()).unwrap(),
                    Store::open(&wal).unwrap(),
                )
                .is_err()
            );
            assert_eq!(fs::read(&wal).unwrap(), before);
        }
    }

    #[test]
    fn persisted_upper_cannot_replace_explicit_directory_or_ancestor() {
        for key in ["empty", "empty/nested"] {
            let temp = tempfile::tempdir().unwrap();
            let mut writer = ArchiveWriter::create(temp.path().join("game.7z")).unwrap();
            let mut entry = ArchiveEntry::new_file("empty/nested");
            entry.is_directory = true;
            writer.push_archive_entry(entry, None::<&[u8]>).unwrap();
            writer.finish().unwrap();
            let mut upper = Store::open(temp.path().join("upper.wal")).unwrap();
            let revision = Archive::open(temp.path().join("game.7z"), "", Limits::default())
                .unwrap()
                .revision_sha256()
                .unwrap();
            upper.bind_archive(revision).unwrap();
            upper.put(key, b"raw save").unwrap();
            assert!(
                Overlay::new(
                    Archive::open(temp.path().join("game.7z"), "", Limits::default()).unwrap(),
                    upper,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn upper_cannot_reopen_against_a_different_archive_revision() {
        for replacement_name in ["game.7z", "other-game.7z"] {
            let temp = tempfile::tempdir().unwrap();
            fixture(temp.path());
            let mut overlay = open(temp.path());
            overlay.write_at("save/b", 0, b"progress").unwrap();
            drop(overlay);
            let before = fs::read(temp.path().join("upper.wal")).unwrap();
            let replacement = temp.path().join(replacement_name);
            let mut writer = ArchiveWriter::create(&replacement).unwrap();
            // Identical keys and member sizes, but different payload bytes.
            for (name, bytes) in [
                ("data/a", b"ABCDEF".as_slice()),
                ("save/b", b"old".as_slice()),
            ] {
                writer
                    .push_archive_entry(ArchiveEntry::new_file(name), Some(bytes))
                    .unwrap();
            }
            writer.finish().unwrap();
            let error = Overlay::new(
                Archive::open(replacement, "", Limits::default()).unwrap(),
                Store::open(temp.path().join("upper.wal")).unwrap(),
            )
            .err()
            .unwrap();
            assert!(error.contains("different archive"));
            assert_eq!(fs::read(temp.path().join("upper.wal")).unwrap(), before);
        }
    }

    #[test]
    fn empty_upper_binds_once_and_reopens_without_wal_changes() {
        let temp = tempfile::tempdir().unwrap();
        fixture(temp.path());
        drop(Store::open(temp.path().join("upper.wal")).unwrap());
        let before = fs::read(temp.path().join("upper.wal")).unwrap();
        drop(open(temp.path()));
        let bound = fs::read(temp.path().join("upper.wal")).unwrap();
        assert!(bound.len() > before.len());
        let mut overlay = open(temp.path());
        assert_eq!(overlay.read_file("data/a").unwrap(), b"abcdef");
        assert_eq!(fs::read(temp.path().join("upper.wal")).unwrap(), bound);
    }

    #[test]
    fn legacy_upper_with_nonconflicting_data_cannot_bind_implicitly() {
        let temp = tempfile::tempdir().unwrap();
        fixture(temp.path());
        let mut upper = Store::open(temp.path().join("upper.wal")).unwrap();
        upper.put("save/b", b"progress").unwrap();
        let before = fs::read(temp.path().join("upper.wal")).unwrap();
        let error = Overlay::new(
            Archive::open(temp.path().join("game.7z"), "", Limits::default()).unwrap(),
            upper,
        )
        .err()
        .unwrap();
        assert!(error.contains("legacy nonempty"));
        assert_eq!(fs::read(temp.path().join("upper.wal")).unwrap(), before);
    }

    #[test]
    fn readonly_reads_never_copy_up_or_mutate_archive() {
        let temp = tempfile::tempdir().unwrap();
        fixture(temp.path());
        let archive_before = fs::read(temp.path().join("game.7z")).unwrap();
        let mut overlay = open(temp.path());
        let upper_before = fs::read(temp.path().join("upper.wal")).unwrap();
        assert_eq!(overlay.read_at("data/a", 2, 3).unwrap(), b"cde");
        assert_eq!(overlay.read_at("data/a", 5, 10).unwrap(), b"f");
        assert_eq!(overlay.read_at("data/a", u64::MAX, 1).unwrap(), b"");
        assert!(overlay.read_at("missing", 0, 0).is_err());
        assert_eq!(overlay.upper.lookup("data/a").unwrap(), None);
        assert_eq!(
            fs::read(temp.path().join("upper.wal")).unwrap(),
            upper_before
        );
        assert_eq!(
            fs::read(temp.path().join("game.7z")).unwrap(),
            archive_before
        );
    }
    #[test]
    fn writes_holes_truncate_zero_and_reopen() {
        let temp = tempfile::tempdir().unwrap();
        fixture(temp.path());
        let before = fs::read(temp.path().join("game.7z")).unwrap();
        let mut overlay = open(temp.path());
        overlay.write_at("data/a", 2, b"XY").unwrap();
        assert_eq!(overlay.read_at("data/a", 0, 100).unwrap(), b"abXYef");
        overlay.write_at("data/a", 8, b"!").unwrap();
        assert_eq!(overlay.read_at("data/a", 0, 100).unwrap(), b"abXYef\0\0!");
        overlay.truncate("data/a", 3).unwrap();
        overlay.truncate("data/a", 5).unwrap();
        assert_eq!(overlay.read_at("data/a", 0, 100).unwrap(), b"abX\0\0");
        overlay.truncate("save/b", 0).unwrap();
        overlay.write_at("new", 3, b"x").unwrap();
        drop(overlay);
        let mut overlay = open(temp.path());
        assert_eq!(overlay.read_at("data/a", 0, 100).unwrap(), b"abX\0\0");
        assert_eq!(overlay.read_at("save/b", 0, 100).unwrap(), b"");
        assert_eq!(overlay.read_at("new", 0, 100).unwrap(), b"\0\0\0x");
        assert_eq!(fs::read(temp.path().join("game.7z")).unwrap(), before);
    }
    #[test]
    fn zero_truncate_and_empty_write_do_not_decode_lower() {
        let temp = tempfile::tempdir().unwrap();
        fixture(temp.path());
        let mut overlay = Overlay::new(
            Archive::open(
                temp.path().join("game.7z"),
                "",
                Limits {
                    max_file_bytes: 0,
                    ..Limits::default()
                },
            )
            .unwrap(),
            Store::open(temp.path().join("upper.wal")).unwrap(),
        )
        .unwrap();
        let wal = temp.path().join("upper.wal");
        let before = fs::read(&wal).unwrap();
        overlay.write_at("data/a", 0, b"").unwrap();
        assert_eq!(fs::read(&wal).unwrap(), before);
        assert_eq!(overlay.upper.lookup("data/a").unwrap(), None);
        assert!(overlay.write_at("data/a", u64::MAX, b"").is_err());
        assert!(overlay.write_at("data/a", 0, b"x").is_err());
        overlay.truncate("data/a", 0).unwrap();
        assert_eq!(overlay.read_at("data/a", 0, 10).unwrap(), b"");
    }

    #[test]
    fn unlink_masks_lower_and_write_recreates_without_old_bytes() {
        let temp = tempfile::tempdir().unwrap();
        fixture(temp.path());
        let mut overlay = open(temp.path());
        overlay.unlink("data/a").unwrap();
        assert!(overlay.read_at("data/a", 0, 10).is_err());
        assert!(overlay.unlink("data/a").is_err());
        assert!(overlay.truncate("data/a", 0).is_err());
        overlay.write_at("data/a", 2, b"x").unwrap();
        assert_eq!(overlay.read_at("data/a", 0, 10).unwrap(), b"\0\0x");
        overlay.rename("data/a", "save/b").unwrap();
        drop(overlay);
        let mut overlay = open(temp.path());
        assert!(overlay.read_at("data/a", 0, 10).is_err());
        assert_eq!(overlay.read_at("save/b", 0, 10).unwrap(), b"\0\0x");
    }
    #[test]
    fn lower_rename_is_one_recoverable_transaction() {
        let temp = tempfile::tempdir().unwrap();
        fixture(temp.path());
        let mut overlay = open(temp.path());
        let wal = temp.path().join("upper.wal");
        let before = fs::read(&wal).unwrap();
        overlay.rename("data/a", "save/b").unwrap();
        let after = fs::read(&wal).unwrap();
        let payload_size =
            u32::from_le_bytes(after[before.len()..before.len() + 4].try_into().unwrap()) as usize;
        assert_eq!(after.len() - before.len(), 12 + payload_size);
        drop(overlay);
        for cut in before.len()..after.len() {
            fs::write(&wal, &after[..cut]).unwrap();
            let mut overlay = open(temp.path());
            assert_eq!(overlay.read_at("data/a", 0, 100).unwrap(), b"abcdef");
            assert_eq!(overlay.read_at("save/b", 0, 100).unwrap(), b"old");
        }
        fs::write(&wal, after).unwrap();
        let mut overlay = open(temp.path());
        assert!(overlay.read_at("data/a", 0, 100).is_err());
        assert_eq!(overlay.read_at("save/b", 0, 100).unwrap(), b"abcdef");
    }
    #[test]
    fn live_descendants_block_replacement_but_tombstones_do_not() {
        let temp = tempfile::tempdir().unwrap();
        fixture(temp.path());
        let mut overlay = open(temp.path());
        overlay.write_at("new/child", 0, b"x").unwrap();
        assert!(overlay.write_at("new", 0, b"y").is_err());
        assert!(overlay.rename("data/a", "new").is_err());
        overlay.unlink("new/child").unwrap();
        overlay.write_at("new", 0, b"y").unwrap();
        overlay.unlink("data/a").unwrap();
        overlay.write_at("data", 0, b"z").unwrap();
        assert_eq!(overlay.read_at("data", 0, 10).unwrap(), b"z");
    }

    #[test]
    fn longer_rename_limit_preserves_source_target_and_wal() {
        let temp = tempfile::tempdir().unwrap();
        fixture(temp.path());
        let mut overlay = open(temp.path());
        let target = "t".repeat(255);
        overlay
            .upper
            .put("s", &vec![b'x'; file_limit(&target, None) + 1])
            .unwrap();
        overlay.upper.put(&target, b"old").unwrap();
        let wal = temp.path().join("upper.wal");
        let before = fs::metadata(&wal).unwrap().len();
        assert!(overlay.rename("s", &target).is_err());
        assert_eq!(overlay.read_at("s", 0, 1).unwrap(), b"x");
        assert_eq!(overlay.read_at(&target, 0, 3).unwrap(), b"old");
        assert_eq!(fs::metadata(wal).unwrap().len(), before);
    }

    #[test]
    fn unsafe_paths_and_oversized_offsets_leave_wal_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        fixture(temp.path());
        let mut overlay = open(temp.path());
        let wal = temp.path().join("upper.wal");
        let before = fs::read(&wal).unwrap();
        for path in [
            "../escape",
            "/tmp/escape",
            "C:/escape",
            "a\\b",
            "a//b",
            "NUL.txt",
            "a\0b",
        ] {
            assert!(overlay.read_at(path, 0, 1).is_err());
            assert!(overlay.write_at(path, 0, b"x").is_err());
            assert!(overlay.truncate(path, 0).is_err());
            assert!(overlay.unlink(path).is_err());
            assert!(overlay.rename("data/a", path).is_err());
            assert!(overlay.rename(path, "data/a").is_err());
        }
        assert!(overlay.write_at("data/a", u64::MAX, b"x").is_err());
        assert!(overlay.write_at("data/a", MAX_BYTES as u64, b"x").is_err());
        assert!(overlay.truncate("data/a", u64::MAX).is_err());
        assert!(overlay.read_at("data/a", 0, usize::MAX).is_err());
        assert!(overlay.rename("data/a", "save/b/child").is_err());
        assert!(overlay.write_at("data/a/child", 0, b"x").is_err());
        assert!(overlay.write_at("data", 0, b"x").is_err());
        assert!(overlay.rename("save/b", "data").is_err());
        overlay.write_at("new-empty", 0, b"").unwrap();
        assert!(overlay.read_at("new-empty", 0, 1).is_err());
        assert!(overlay.rename("missing", "data/a").is_err());
        assert!(overlay.rename("missing", "missing").is_err());
        overlay.rename("data/a", "data/a").unwrap();
        assert_eq!(fs::read(wal).unwrap(), before);
        assert_eq!(overlay.read_at("data/a", 0, 100).unwrap(), b"abcdef");
    }
}
