//! Path-based probe interface. No extraction; lower reads never copy up.
//! Upper writes are explicit, durable file replacements under one save prefix.
//! This is not a complete POSIX inode/handle or writable mount implementation.
use crate::{
    archive::{ArchiveSource, validate_archive_path},
    save::{Entry, MAX_BYTES, Occupancy, Store},
};
#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
type Result<T> = std::result::Result<T, String>;

/// Lower names. `Clone` counts a full copy so lookups can be checked for one.
struct Names {
    map: BTreeMap<String, Option<u64>>,
    #[cfg(test)]
    clones: Cell<usize>,
}
impl Names {
    fn new(map: BTreeMap<String, Option<u64>>) -> Self {
        Self {
            map,
            #[cfg(test)]
            clones: Cell::new(0),
        }
    }
    fn get(&self, key: &str) -> Option<&Option<u64>> {
        self.map.get(key)
    }
}
impl Clone for Names {
    fn clone(&self) -> Self {
        #[cfg(test)]
        self.clones.set(self.clones.get() + 1);
        Self {
            map: self.map.clone(),
            #[cfg(test)]
            clones: Cell::new(0),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub size: u64,
    pub directory: bool,
}
pub struct Filesystem<S: ArchiveSource> {
    source: S,
    lower: Names,
    upper: Option<(Store, String)>,
    revision: [u8; 32],
}
impl<S: ArchiveSource> Filesystem<S> {
    pub fn readonly(mut source: S) -> Result<Self> {
        let entries = source.entries();
        if entries.len() > 16384
            || entries.iter().map(|(n, _)| n.len() + 64).sum::<usize>() > 4 * 1024 * 1024
        {
            return Err("filesystem namespace limit exceeded".into());
        }
        let mut lower = BTreeMap::new();
        for (path, size) in entries {
            validate_archive_path(&path)?;
            if lower.insert(path, size).is_some() {
                return Err("duplicate archive entry".into());
            }
        }
        for path in lower.keys() {
            for (i, _) in path.match_indices('/') {
                if matches!(lower.get(&path[..i]), Some(Some(_))) {
                    return Err("file/directory collision".into());
                }
            }
        }
        let revision = source.revision_sha256()?;
        Ok(Self {
            source,
            lower: Names::new(lower),
            upper: None,
            revision,
        })
    }
    /// Explicitly enable only a save subtree, with a separate local WAL.
    /// The caller must choose an existing game save directory; mounts remain RO.
    pub fn with_upper(mut self, mut store: Store, save_prefix: &str) -> Result<Self> {
        validate_archive_path(save_prefix)?;
        if self.lower.get(save_prefix).is_some_and(Option::is_some) {
            return Err("save prefix is a lower file".into());
        }
        let prefix = format!("{save_prefix}/");
        for name in store.names().map_err(|e| e.to_string())? {
            validate_archive_path(name)?;
            if !name.starts_with(&prefix) {
                return Err("Upper contains a key outside the save prefix".into());
            }
        }
        for (i, _) in save_prefix.match_indices('/') {
            if matches!(self.lower.get(&save_prefix[..i]), Some(Some(_))) {
                return Err("save prefix ancestor is a lower file".into());
            }
        }
        // Exact explicit directories must never be shadowed. Other namespace
        // collisions must be checked after applying persisted tombstones, just
        // as they are for live mutations (a deleted lower file may gain children).
        for name in store.live_names().map_err(|e| e.to_string())? {
            if matches!(self.lower.get(name), Some(None)) {
                return Err("destination is an explicit lower directory".into());
            }
        }
        store
            .bind_archive(self.revision)
            .map_err(|e| e.to_string())?;
        self.upper = Some((store, save_prefix.into()));
        let live: Vec<String> = self
            .upper
            .as_ref()
            .unwrap()
            .0
            .live_names()
            .map_err(|e| e.to_string())?
            .map(str::to_owned)
            .collect();
        for name in &live {
            self.destination(name)?;
        }
        Ok(self)
    }
    fn key(path: &str) -> Result<&str> {
        if path == "/" || path.is_empty() {
            return Ok("");
        }
        let key = path.strip_prefix('/').unwrap_or(path);
        validate_archive_path(key)?;
        Ok(key)
    }
    fn check_revision(&mut self) -> Result<()> {
        if self.source.revision_sha256()? != self.revision {
            return Err("archive revision changed".into());
        }
        Ok(())
    }
    fn under_save(&self, key: &str) -> Option<(&Store, &str)> {
        let (upper, prefix) = self.upper.as_ref()?;
        if key == prefix || key.starts_with(&format!("{prefix}/")) {
            Some((upper, prefix))
        } else {
            None
        }
    }
    fn file_len(&self, key: &str) -> Result<Option<u64>> {
        if let Some((upper, _)) = self.under_save(key) {
            match upper.occupancy(key).map_err(|e| e.to_string())? {
                Some(Occupancy::Data(len)) => return Ok(Some(len)),
                Some(Occupancy::Deleted) => return Ok(None),
                None => {}
            }
        }
        Ok(match self.lower.get(key) {
            Some(Some(len)) => Some(*len),
            _ => None,
        })
    }
    fn explicit_dir(&self, key: &str) -> bool {
        matches!(self.lower.get(key), Some(None))
            || self.upper.as_ref().is_some_and(|(_, prefix)| prefix == key)
    }
    fn has_visible_descendant(&self, key: &str) -> Result<bool> {
        let prefix = format!("{key}/");
        let (upper, save_prefix) = self
            .upper
            .as_ref()
            .map(|(store, prefix)| (Some(store), prefix.as_str()))
            .unwrap_or((None, ""));
        for (path, size) in self.lower.map.range(prefix.clone()..) {
            if !path.starts_with(&prefix) {
                break;
            }
            if size.is_none() {
                return Ok(true);
            }
            let tombstoned = upper.is_some_and(|_| path.starts_with(&format!("{save_prefix}/")))
                && matches!(
                    upper.unwrap().occupancy(path).map_err(|e| e.to_string())?,
                    Some(Occupancy::Deleted)
                );
            if !tombstoned {
                return Ok(true);
            }
        }
        if let Some(store) = upper
            && store.has_live_descendant(key).map_err(|e| e.to_string())?
        {
            return Ok(true);
        }
        Ok(false)
    }
    pub fn metadata(&mut self, path: &str) -> Result<Metadata> {
        let key = Self::key(path)?;
        self.check_revision()?;
        if key.is_empty() {
            return Ok(Metadata {
                size: 0,
                directory: true,
            });
        }
        if let Some(size) = self.file_len(key)? {
            return Ok(Metadata {
                size,
                directory: false,
            });
        }
        if self.explicit_dir(key) || self.has_visible_descendant(key)? {
            return Ok(Metadata {
                size: 0,
                directory: true,
            });
        }
        Err("file not found".into())
    }
    fn child_name<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
        let suffix = if prefix.is_empty() {
            path
        } else {
            path.strip_prefix(prefix)?
        };
        let name = suffix.split('/').next().unwrap_or("");
        (!name.is_empty()).then_some(name)
    }
    pub fn readdir(&mut self, path: &str) -> Result<Vec<String>> {
        if !self.metadata(path)?.directory {
            return Err("not a directory".into());
        }
        let key = Self::key(path)?;
        let prefix = if key.is_empty() {
            String::new()
        } else {
            format!("{key}/")
        };
        let mut children = BTreeSet::new();
        let upper = self.upper.as_ref();
        let save_prefix = upper.map(|(_, prefix)| prefix.as_str()).unwrap_or("");
        let start = if prefix.is_empty() {
            String::new()
        } else {
            prefix.clone()
        };
        for (path, size) in self.lower.map.range(start..) {
            if !prefix.is_empty() && !path.starts_with(&prefix) {
                break;
            }
            let tombstoned = size.is_some()
                && upper.is_some()
                && path.starts_with(&format!("{save_prefix}/"))
                && matches!(
                    upper
                        .unwrap()
                        .0
                        .occupancy(path)
                        .map_err(|e| e.to_string())?,
                    Some(Occupancy::Deleted)
                );
            if tombstoned {
                continue;
            }
            if let Some(name) = Self::child_name(path, &prefix) {
                children.insert(name.to_owned());
            }
        }
        if let Some((store, save_prefix)) = upper {
            for name in store.live_names().map_err(|e| e.to_string())? {
                if let Some(child) = Self::child_name(name, &prefix) {
                    children.insert(child.to_owned());
                }
            }
            if key != save_prefix
                && (prefix.is_empty() || save_prefix.starts_with(&prefix))
                && let Some(child) = Self::child_name(save_prefix, &prefix)
            {
                children.insert(child.to_owned());
            }
        }
        Ok(children.into_iter().collect())
    }
    pub fn read_at(&mut self, path: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
        let key = Self::key(path)?;
        if length > 16 * 1024 * 1024 {
            return Err("read request exceeds limit".into());
        }
        if self.metadata(key)?.directory {
            return Err("is a directory".into());
        }
        let data = if let Some((upper, prefix)) = &self.upper
            && key.starts_with(&format!("{prefix}/"))
        {
            match upper.lookup(key).map_err(|e| e.to_string())? {
                Some(Entry::Data(data)) => data,
                Some(Entry::Deleted) => return Err("file not found".into()),
                None => return self.source.read_range(key, offset, length),
            }
        } else {
            return self.source.read_range(key, offset, length);
        };
        if data.len() > 16 * 1024 * 1024 {
            return Err("source response exceeds limit".into());
        }
        Ok(crate::archive::slice_range(data, offset, length))
    }
    fn writable(&self, path: &str) -> Result<()> {
        let (_, prefix) = self.upper.as_ref().ok_or("read-only filesystem")?;
        if !path.starts_with(&format!("{prefix}/")) {
            return Err("writes are restricted to the explicit save prefix".into());
        }
        Ok(())
    }
    fn destination(&self, path: &str) -> Result<()> {
        if self.explicit_dir(path) || self.has_visible_descendant(path)? {
            return Err("destination is a directory".into());
        }
        for (i, _) in path.match_indices('/') {
            if self.file_len(&path[..i])?.is_some() {
                return Err("destination ancestor is a file".into());
            }
        }
        Ok(())
    }
    pub fn put_save(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let key = Self::key(path)?;
        self.writable(key)?;
        self.check_revision()?;
        self.destination(key)?;
        if data.len() > MAX_BYTES.saturating_sub(4096 + 2 * key.len()) {
            return Err("save exceeds file limit".into());
        }
        self.upper
            .as_mut()
            .unwrap()
            .0
            .put(key, data)
            .map_err(|e| e.to_string())
    }
    pub fn rename_save(&mut self, from: &str, to: &str) -> Result<()> {
        let from = Self::key(from)?;
        let to = Self::key(to)?;
        self.writable(from)?;
        self.writable(to)?;
        self.check_revision()?;
        self.destination(to)?;
        let data = self.read_at(from, 0, MAX_BYTES)?;
        self.upper
            .as_mut()
            .unwrap()
            .0
            .move_data(from, to, &data)
            .map_err(|e| e.to_string())
    }
    pub fn delete_save(&mut self, path: &str) -> Result<()> {
        let key = Self::key(path)?;
        self.writable(key)?;
        if self.metadata(key)?.directory {
            return Err("is a directory".into());
        }
        self.upper
            .as_mut()
            .unwrap()
            .0
            .delete(key)
            .map_err(|e| e.to_string())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lower_reads_request_only_the_range_from_the_source() {
        struct Counting {
            data: Vec<u8>,
            full_reads: usize,
            served: usize,
        }
        impl ArchiveSource for Counting {
            fn entries(&self) -> Vec<(String, Option<u64>)> {
                vec![("big.bin".into(), Some(self.data.len() as u64))]
            }
            fn read(&mut self, _: &str) -> Result<Vec<u8>> {
                self.full_reads += 1;
                self.served += self.data.len();
                Ok(self.data.clone())
            }
            fn read_range(&mut self, _: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
                let part = crate::archive::slice_range(self.data.clone(), offset, length);
                self.served += part.len();
                Ok(part)
            }
            fn revision_sha256(&mut self) -> Result<[u8; 32]> {
                Ok([7; 32])
            }
        }
        let data: Vec<u8> = (0..4 << 20).map(|i| (i % 251) as u8).collect();
        let mut fs = Filesystem::readonly(Counting {
            data: data.clone(),
            full_reads: 0,
            served: 0,
        })
        .unwrap();
        for chunk in 0..16u64 {
            let offset = chunk * 4096;
            assert_eq!(
                fs.read_at("big.bin", offset, 4096).unwrap(),
                &data[offset as usize..offset as usize + 4096]
            );
        }
        assert!(
            fs.read_at("big.bin", data.len() as u64, 4096)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            fs.read_at("big.bin", data.len() as u64 - 3, 4096)
                .unwrap()
                .len(),
            3
        );
        // 16 reads of 4 KiB move 64 KiB, not 16 copies of the 4 MiB entry.
        assert_eq!(fs.source.full_reads, 0);
        assert_eq!(fs.source.served, 16 * 4096 + 3);
    }
    struct Synthetic(BTreeMap<String, Vec<u8>>);
    impl ArchiveSource for Synthetic {
        fn entries(&self) -> Vec<(String, Option<u64>)> {
            self.0
                .iter()
                .map(|(n, v)| (n.clone(), Some(v.len() as u64)))
                .collect()
        }
        fn read(&mut self, p: &str) -> Result<Vec<u8>> {
            self.0.get(p).cloned().ok_or("file not found".into())
        }
        fn revision_sha256(&mut self) -> Result<[u8; 32]> {
            Ok([42; 32])
        }
    }
    fn fixture(engine: &str) -> Synthetic {
        Synthetic(
            [
                (
                    String::from("遊戲/package.json"),
                    br#"{"main":"index.html"}"#.to_vec(),
                ),
                ("遊戲/index.html".into(), b"synthetic fixture only".to_vec()),
                (format!("遊戲/js/{engine}.js"), b"fixture".to_vec()),
                ("遊戲/save/file1.rmmzsave".into(), b"lower".to_vec()),
            ]
            .into(),
        )
    }
    #[test]
    fn mv_mz_readonly_namespace_and_bounds() {
        for engine in ["rpg_core", "rmmz_core"] {
            let mut fs = Filesystem::readonly(fixture(engine)).unwrap();
            assert_eq!(fs.readdir("/").unwrap(), ["遊戲"]);
            assert_eq!(fs.read_at("/遊戲/index.html", 0, 9).unwrap(), b"synthetic");
            assert!(fs.metadata("/遊戲/js").unwrap().directory);
            assert!(fs.read_at("/遊戲/index.html", 0, usize::MAX).is_err());
            assert!(fs.put_save("遊戲/save/new", b"x").is_err());
            assert!(fs.metadata("/../escape").is_err());
        }
    }
    #[test]
    fn upper_tombstones_outside_save_prefix_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut upper = Store::open(dir.path().join("upper.wal")).unwrap();
        upper.bind_archive([42; 32]).unwrap();
        upper.delete("遊戲/index.html").unwrap();
        let result = Filesystem::readonly(fixture("rmmz_core"))
            .unwrap()
            .with_upper(upper, "遊戲/save");
        assert!(matches!(result,Err(error) if error.contains("outside the save prefix")));
    }
    #[test]
    fn persisted_upper_cannot_replace_explicit_lower_directory() {
        struct Directory;
        impl ArchiveSource for Directory {
            fn entries(&self) -> Vec<(String, Option<u64>)> {
                vec![("game/save/empty".into(), None)]
            }
            fn read(&mut self, _: &str) -> Result<Vec<u8>> {
                Err("is a directory".into())
            }
            fn revision_sha256(&mut self) -> Result<[u8; 32]> {
                Ok([42; 32])
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut upper = Store::open(dir.path().join("upper.wal")).unwrap();
        upper.bind_archive([42; 32]).unwrap();
        upper.put("game/save/empty", b"shadow").unwrap();
        let result = Filesystem::readonly(Directory)
            .unwrap()
            .with_upper(upper, "game/save");
        assert!(matches!(result,Err(error) if error.contains("directory")));
    }
    #[test]
    fn deleted_lower_file_can_gain_a_child_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let wal = dir.path().join("upper.wal");
        {
            let mut fs = Filesystem::readonly(fixture("rmmz_core"))
                .unwrap()
                .with_upper(Store::open(&wal).unwrap(), "遊戲/save")
                .unwrap();
            fs.delete_save("遊戲/save/file1.rmmzsave").unwrap();
            fs.put_save("遊戲/save/file1.rmmzsave/child", b"new")
                .unwrap();
            assert_eq!(
                fs.read_at("遊戲/save/file1.rmmzsave/child", 0, 100)
                    .unwrap(),
                b"new"
            );
        }
        let mut reopened = Filesystem::readonly(fixture("rmmz_core"))
            .unwrap()
            .with_upper(Store::open(&wal).unwrap(), "遊戲/save")
            .unwrap();
        assert_eq!(
            reopened
                .read_at("遊戲/save/file1.rmmzsave/child", 0, 100)
                .unwrap(),
            b"new"
        );
        assert!(
            reopened
                .metadata("遊戲/save/file1.rmmzsave")
                .unwrap()
                .directory
        );
    }
    #[test]
    fn independent_upper_persists_without_changing_lower() {
        let dir = tempfile::tempdir().unwrap();
        let wal = dir.path().join("save.wal");
        {
            let mut fs = Filesystem::readonly(fixture("rmmz_core"))
                .unwrap()
                .with_upper(Store::open(&wal).unwrap(), "遊戲/save")
                .unwrap();
            assert!(fs.put_save("遊戲/js/rmmz_core.js", b"overwrite").is_err());
            fs.put_save("遊戲/save/temp", b"saved").unwrap();
            fs.rename_save("遊戲/save/temp", "遊戲/save/file1.rmmzsave")
                .unwrap();
            assert_eq!(
                fs.read_at("遊戲/save/file1.rmmzsave", 0, 100).unwrap(),
                b"saved"
            );
        }
        let mut fs = Filesystem::readonly(fixture("rmmz_core"))
            .unwrap()
            .with_upper(Store::open(&wal).unwrap(), "遊戲/save")
            .unwrap();
        assert_eq!(
            fs.read_at("遊戲/save/file1.rmmzsave", 0, 100).unwrap(),
            b"saved"
        );
        let mut lower = Filesystem::readonly(fixture("rmmz_core")).unwrap();
        assert_eq!(
            lower.read_at("遊戲/save/file1.rmmzsave", 0, 100).unwrap(),
            b"lower"
        );
    }
    #[test]
    fn reopening_populated_store_copies_each_payload_once() {
        let dir = tempfile::tempdir().unwrap();
        let wal = dir.path().join("upper.wal");
        let count = 48usize;
        let size = 4096usize;
        let payload = vec![7u8; size];
        {
            let mut store = Store::open(&wal).unwrap();
            store.bind_archive([42; 32]).unwrap();
            store.delete("game/save/old").unwrap();
            for i in 0..count {
                store
                    .put(&format!("game/save/slot-{i:04}"), &payload)
                    .unwrap();
            }
        }
        let wal_payload_bytes = count * size;
        let mut lower = BTreeMap::new();
        lower.insert("game/save/old".into(), b"old-lower".to_vec());
        lower.insert("game/save/slot-0000".into(), b"lower".to_vec());
        lower.insert("game/readme.txt".into(), b"readme".to_vec());
        let mut fs = Filesystem::readonly(Synthetic(lower))
            .unwrap()
            .with_upper(Store::open(&wal).unwrap(), "game/save")
            .unwrap();
        let copied = fs.upper.as_ref().unwrap().0.payload_bytes_copied();
        assert_eq!(
            copied, wal_payload_bytes,
            "reopen copied {copied} payload bytes for {wal_payload_bytes} WAL payload bytes"
        );
        assert_eq!(fs.read_at("game/save/slot-0001", 0, size).unwrap(), payload);
        assert_eq!(fs.read_at("game/save/slot-0000", 0, size).unwrap(), payload);
        assert!(fs.read_at("game/save/old", 0, 100).is_err());
        assert_eq!(fs.read_at("game/readme.txt", 0, 100).unwrap(), b"readme");
    }
    #[test]
    fn lookups_do_not_clone_the_namespace() {
        let mut lower = BTreeMap::new();
        for i in 0..64 {
            lower.insert(format!("game/save/slot-{i:04}"), b"x".to_vec());
            lower.insert(format!("game/data/map-{i:04}"), b"y".to_vec());
        }
        let dir = tempfile::tempdir().unwrap();
        let wal = dir.path().join("upper.wal");
        {
            let mut store = Store::open(&wal).unwrap();
            store.bind_archive([42; 32]).unwrap();
            store.put("game/save/slot-0000", b"replaced").unwrap();
            store.delete("game/save/slot-0001").unwrap();
        }
        let mut fs = Filesystem::readonly(Synthetic(lower))
            .unwrap()
            .with_upper(Store::open(&wal).unwrap(), "game/save")
            .unwrap();
        assert_eq!(fs.lower.clones.get(), 0);
        for _ in 0..32 {
            assert!(fs.metadata("game/save/slot-0000").unwrap().size > 0);
            assert!(fs.metadata("game/data/map-0003").is_ok());
            assert!(fs.metadata("game/save").unwrap().directory);
            assert!(fs.metadata("game/missing").is_err());
            assert!(fs.readdir("game").unwrap().contains(&"save".to_string()));
            assert!(fs.readdir("/").unwrap().contains(&"game".to_string()));
        }
        assert_eq!(fs.lower.clones.get(), 0, "lookup cloned the namespace");
    }
}
