//! Path-based probe interface. No extraction; lower reads never copy up.
//! Upper writes are explicit, durable file replacements under one save prefix.
//! This is not a complete POSIX inode/handle or writable mount implementation.
use crate::{
    archive::{ArchiveSource, validate_archive_path},
    save::{Entry, MAX_BYTES, Occupancy, Store},
};
use std::collections::{BTreeMap, BTreeSet};
type Result<T> = std::result::Result<T, String>;

fn has_descendant(names: &BTreeMap<String, Option<u64>>, path: &str) -> bool {
    let prefix = format!("{path}/");
    names
        .range(prefix.clone()..)
        .next()
        .is_some_and(|(name, _)| name.starts_with(&prefix))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub size: u64,
    pub directory: bool,
}
pub struct Filesystem<S: ArchiveSource> {
    source: S,
    lower: BTreeMap<String, Option<u64>>,
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
            lower,
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
        // One namespace walk. Per-key `destination` rebuilt it, and each rebuild
        // cloned every live payload, so reopen copied bytes roughly n times.
        let visible = self.visible()?;
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
            Self::reject_directory_collision(&self.lower, &visible, name)?;
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
    fn visible(&self) -> Result<BTreeMap<String, Option<u64>>> {
        let mut result = self.lower.clone();
        if let Some((upper, prefix)) = &self.upper {
            // Lower tombstones may hide files, but explicit directories survive.
            for (path, size) in &self.lower {
                if size.is_some() && path.starts_with(&format!("{prefix}/")) {
                    match upper.occupancy(path).map_err(|e| e.to_string())? {
                        Some(Occupancy::Deleted) => {
                            result.remove(path);
                        }
                        Some(Occupancy::Data(len)) => {
                            result.insert(path.clone(), Some(len));
                        }
                        None => {}
                    }
                }
            }
            for path in upper.live_names().map_err(|e| e.to_string())? {
                if let Some(Occupancy::Data(len)) =
                    upper.occupancy(path).map_err(|e| e.to_string())?
                {
                    result.insert(path.to_owned(), Some(len));
                }
            }
            result.entry(prefix.clone()).or_insert(None);
        }
        Ok(result)
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
        let names = self.visible()?;
        if let Some(size) = names.get(key) {
            return Ok(Metadata {
                size: size.unwrap_or(0),
                directory: size.is_none(),
            });
        }
        let prefix = format!("{key}/");
        if names.keys().any(|p| p.starts_with(&prefix)) {
            return Ok(Metadata {
                size: 0,
                directory: true,
            });
        }
        Err("file not found".into())
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
        for path in self.visible()?.keys() {
            if let Some(suffix) = path.strip_prefix(&prefix)
                && let Some(name) = suffix.split('/').next()
                && !name.is_empty()
            {
                children.insert(name.into());
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
        Self::reject_directory_collision(&self.lower, &self.visible()?, path)
    }
    fn reject_directory_collision(
        lower: &BTreeMap<String, Option<u64>>,
        names: &BTreeMap<String, Option<u64>>,
        path: &str,
    ) -> Result<()> {
        if matches!(lower.get(path), Some(None))
            || matches!(names.get(path), Some(None))
            || has_descendant(names, path)
        {
            return Err("destination is a directory".into());
        }
        for (i, _) in path.match_indices('/') {
            if matches!(names.get(&path[..i]), Some(Some(_))) {
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
}
