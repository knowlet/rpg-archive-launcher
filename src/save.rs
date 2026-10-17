//! Crash-recoverable Upper save layer. Keys are archive-relative logical names;
//! they are never joined to a filesystem path. Rename is one WAL transaction.
//!
//! Successful mutations call `sync_all` before becoming visible. This assumes a
//! local filesystem/device that honors fsync; network filesystems and faulty
//! storage may not provide that guarantee. Locks are advisory: every writer must
//! cooperate. The store's parent directory must be trusted (not writable by an
//! attacker); O_NOFOLLOW protects the final component, not ancestor replacement.
//! The WAL is intentionally not compacted and capped at 256 MiB on disk.
//! Once full, mutations fail without changing state; export/migration is required.
//! Accounted live state and each record are limited to 16 MiB. Transient
//! serialization/recovery buffers can consume additional bounded memory. Deleted-key markers
//! count against that limit. A failed write poisons this handle: reopen to recover.
//! Unix creation syncs the parent directory. On other platforms this implementation
//! fails closed rather than claiming equivalent symlink/directory durability.

use fs2::FileExt;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const MAX_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_WAL_BYTES: u64 = 256 * 1024 * 1024;
const FRAME_HEADER: usize = 12;
const MAGIC: &[u8; 8] = b"RPGSAVE1";
const MAX_KEY: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    Data(Vec<u8>),
    Deleted,
}

pub struct Store {
    file: File,
    entries: BTreeMap<String, Entry>,
    live_bytes: usize,
    poisoned: bool,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Reject ambiguous or traversal-capable names, including Windows spellings.
pub fn validate_key(key: &str) -> io::Result<()> {
    if key.is_empty()
        || key.len() > MAX_KEY
        || key.contains(['\\', ':', '<', '>', '"', '|', '?', '*'])
        || key.chars().any(char::is_control)
    {
        return Err(invalid("invalid save key"));
    }
    for component in key.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > 255
            || component.ends_with(['.', ' '])
        {
            return Err(invalid("invalid save path component"));
        }
        let stem = component
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'));
        if reserved {
            return Err(invalid("reserved save path component"));
        }
    }
    Ok(())
}

fn cost(key: &str, value: &Entry) -> usize {
    // Conservative per-entry allowance bounds tiny-key map/allocator overhead.
    key.len()
        + 256
        + match value {
            Entry::Data(bytes) => bytes.len(),
            Entry::Deleted => 0,
        }
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "durable save store currently requires Unix",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            let (mut file, created) = match options.create_new(true).open(path) {
                Ok(file) => (file, true),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    options.create_new(false);
                    (options.open(path)?, false)
                }
                Err(e) => return Err(e),
            };
            let meta = file.metadata()?;
            if !meta.is_file() || meta.nlink() != 1 {
                return Err(invalid("save store must be a regular file with one link"));
            }
            FileExt::try_lock_exclusive(&file)?;
            if file.metadata()?.len() > MAX_WAL_BYTES {
                return Err(invalid("save WAL exceeds 256 MiB limit"));
            }
            if meta.len() == 0 {
                file.write_all(MAGIC)?;
                file.sync_all()?;
            }
            if created {
                let parent = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                File::open(parent)?.sync_all()?;
            }
            file.seek(SeekFrom::Start(0))?;
            let mut magic = [0; 8];
            file.read_exact(&mut magic)?;
            if magic != *MAGIC {
                return Err(invalid("unrecognized save store format"));
            }
            let mut store = Self {
                file,
                entries: BTreeMap::new(),
                live_bytes: 0,
                poisoned: false,
            };
            store.recover()?;
            Ok(store)
        }
    }

    pub fn live_names(&self) -> impl Iterator<Item = &str> {
        self.entries
            .iter()
            .filter_map(|(name, entry)| matches!(entry, Entry::Data(_)).then_some(name.as_str()))
    }

    pub fn lookup(&self, key: &str) -> io::Result<Option<Entry>> {
        validate_key(key)?;
        Ok(self.entries.get(key).cloned())
    }

    pub fn get(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
        Ok(match self.lookup(key)? {
            Some(Entry::Data(bytes)) => Some(bytes),
            _ => None,
        })
    }

    pub fn put(&mut self, key: &str, bytes: &[u8]) -> io::Result<()> {
        validate_key(key)?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid("save exceeds 16 MiB limit"));
        }
        let mut payload = vec![1];
        encode_key(&mut payload, key);
        payload.extend_from_slice(bytes);
        self.commit(payload)
    }

    pub fn delete(&mut self, key: &str) -> io::Result<()> {
        validate_key(key)?;
        let mut payload = vec![2];
        encode_key(&mut payload, key);
        self.commit(payload)
    }

    /// Replace `to` with `from` and tombstone `from`, atomically. Source must be
    /// present in this Upper layer; archive-backed sources must first be copied up.
    pub fn rename(&mut self, from: &str, to: &str) -> io::Result<()> {
        validate_key(from)?;
        validate_key(to)?;
        if !matches!(self.entries.get(from), Some(Entry::Data(_))) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "rename source is not in Upper",
            ));
        }
        if from == to {
            return Ok(());
        }
        let mut payload = vec![3];
        encode_key(&mut payload, from);
        encode_key(&mut payload, to);
        self.commit(payload)
    }

    /// Persist a lower-layer rename in one transaction: target bytes and source
    /// tombstone are acknowledged together. Caller resolves the source contents.
    pub fn move_data(&mut self, from: &str, to: &str, bytes: &[u8]) -> io::Result<()> {
        validate_key(from)?;
        validate_key(to)?;
        if from == to {
            return Ok(());
        }
        let required = 9usize
            .checked_add(from.len())
            .and_then(|v| v.checked_add(to.len()))
            .and_then(|v| v.checked_add(bytes.len()))
            .ok_or_else(|| invalid("rename size overflow"))?;
        if required > MAX_BYTES {
            return Err(invalid("rename record exceeds 16 MiB limit"));
        }
        let mut payload = Vec::with_capacity(required);
        payload.push(4);
        encode_key(&mut payload, from);
        encode_key(&mut payload, to);
        payload.extend_from_slice(bytes);
        self.commit(payload)
    }

    fn commit(&mut self, payload: Vec<u8>) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "save handle needs reopening after failed write",
            ));
        }
        if payload.len() > MAX_BYTES {
            return Err(invalid("save record exceeds 16 MiB limit"));
        }
        if self.file.metadata()?.len() + FRAME_HEADER as u64 + payload.len() as u64 > MAX_WAL_BYTES
        {
            return Err(invalid("save WAL is full (256 MiB limit)"));
        }
        let changes = decode(&payload, &self.entries)?;
        let size = self.check_size(&changes)?;
        self.poisoned = true;
        self.file.write_all(&(payload.len() as u32).to_le_bytes())?;
        self.file
            .write_all(&(!(payload.len() as u32)).to_le_bytes())?;
        self.file.write_all(&checksum(&payload).to_le_bytes())?;
        self.file.write_all(&payload)?;
        self.file.sync_all()?;
        for (key, value) in changes {
            self.entries.insert(key, value);
        }
        self.live_bytes = size;
        self.poisoned = false;
        Ok(())
    }

    fn check_size(&self, changes: &[(String, Entry)]) -> io::Result<usize> {
        let mut size = self.live_bytes;
        for (key, value) in changes {
            if let Some(old) = self.entries.get(key) {
                size -= cost(key, old);
            }
            size = size
                .checked_add(cost(key, value))
                .ok_or_else(|| invalid("save size overflow"))?;
        }
        if size > MAX_BYTES {
            return Err(invalid("total save state exceeds 16 MiB limit"));
        }
        Ok(size)
    }

    fn recover(&mut self) -> io::Result<()> {
        let length = self.file.metadata()?.len();
        let mut offset = MAGIC.len() as u64;
        while offset < length {
            if length - offset < FRAME_HEADER as u64 {
                return self.truncate_tail(offset);
            }
            let mut header = [0; FRAME_HEADER];
            self.file.read_exact(&mut header)?;
            let size = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
            let inverse = u32::from_le_bytes(header[4..8].try_into().unwrap());
            if inverse != !(size as u32) {
                return Err(invalid("save frame length checksum mismatch"));
            }
            let crc = u32::from_le_bytes(header[8..12].try_into().unwrap());
            if size == 0 || size > MAX_BYTES {
                return Err(invalid("invalid save frame length"));
            }
            if length - offset - (FRAME_HEADER as u64) < size as u64 {
                return self.truncate_tail(offset);
            }
            let mut payload = vec![0; size];
            self.file.read_exact(&mut payload)?;
            if checksum(&payload) != crc {
                return Err(invalid("save frame checksum mismatch"));
            }
            let changes = decode(&payload, &self.entries)?;
            self.live_bytes = self.check_size(&changes)?;
            for (key, value) in changes {
                self.entries.insert(key, value);
            }
            offset += FRAME_HEADER as u64 + size as u64;
        }
        self.file.seek(SeekFrom::End(0))?;
        Ok(())
    }

    fn truncate_tail(&mut self, offset: u64) -> io::Result<()> {
        self.file.set_len(offset)?;
        self.file.sync_all()?;
        self.file.seek(SeekFrom::End(0))?;
        Ok(())
    }
}

fn encode_key(out: &mut Vec<u8>, key: &str) {
    out.extend_from_slice(&(key.len() as u32).to_le_bytes());
    out.extend_from_slice(key.as_bytes());
}

fn take_key<'a>(input: &mut &'a [u8]) -> io::Result<&'a str> {
    if input.len() < 4 {
        return Err(invalid("truncated save key length"));
    }
    let size = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
    *input = &input[4..];
    if size > MAX_KEY || size > input.len() {
        return Err(invalid("invalid save key length"));
    }
    let key = std::str::from_utf8(&input[..size]).map_err(|_| invalid("non UTF-8 save key"))?;
    validate_key(key)?;
    *input = &input[size..];
    Ok(key)
}

fn decode(payload: &[u8], entries: &BTreeMap<String, Entry>) -> io::Result<Vec<(String, Entry)>> {
    let (&opcode, mut rest) = payload
        .split_first()
        .ok_or_else(|| invalid("empty save record"))?;
    let key = take_key(&mut rest)?.to_owned();
    match opcode {
        1 => Ok(vec![(key, Entry::Data(rest.to_vec()))]),
        2 if rest.is_empty() => Ok(vec![(key, Entry::Deleted)]),
        3 => {
            let target = take_key(&mut rest)?.to_owned();
            if !rest.is_empty() || target == key {
                return Err(invalid("invalid rename record"));
            }
            let value = match entries.get(&key) {
                Some(value @ Entry::Data(_)) => value.clone(),
                _ => return Err(invalid("missing rename source")),
            };
            Ok(vec![(key, Entry::Deleted), (target, value)])
        }
        4 => {
            let target = take_key(&mut rest)?.to_owned();
            if target == key {
                return Err(invalid("invalid copy-up rename record"));
            }
            Ok(vec![
                (key, Entry::Deleted),
                (target, Entry::Data(rest.to_vec())),
            ])
        }
        _ => Err(invalid("invalid save opcode or trailing bytes")),
    }
}

// IEEE CRC-32 detects accidental damage; it is not an authentication mechanism.
fn checksum(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "rpg-save-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> PathBuf {
            self.0.join("upper.wal")
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn durable_operations_and_tombstones() {
        let temp = Temp::new();
        {
            let mut s = Store::open(temp.path()).unwrap();
            s.put("save/a", b"first").unwrap();
            s.put("save/b", b"second").unwrap();
            s.rename("save/a", "save/b").unwrap();
            assert_eq!(s.lookup("save/a").unwrap(), Some(Entry::Deleted));
            assert_eq!(s.get("save/b").unwrap(), Some(b"first".to_vec()));
            s.delete("archive-only").unwrap();
        }
        let s = Store::open(temp.path()).unwrap();
        assert_eq!(s.lookup("save/a").unwrap(), Some(Entry::Deleted));
        assert_eq!(s.get("save/b").unwrap(), Some(b"first".to_vec()));
        assert_eq!(s.lookup("archive-only").unwrap(), Some(Entry::Deleted));
        assert_eq!(s.lookup("absent").unwrap(), None);
    }

    #[test]
    fn every_partial_rename_tail_recovers_previous_state() {
        let temp = Temp::new();
        let mut s = Store::open(temp.path()).unwrap();
        s.put("a", b"content").unwrap();
        s.put("b", b"old").unwrap();
        let before = fs::read(temp.path()).unwrap();
        s.rename("a", "b").unwrap();
        let after = fs::read(temp.path()).unwrap();
        drop(s);
        for length in before.len()..after.len() {
            fs::write(temp.path(), &after[..length]).unwrap();
            let s = Store::open(temp.path()).unwrap();
            assert_eq!(s.get("a").unwrap(), Some(b"content".to_vec()));
            assert_eq!(s.get("b").unwrap(), Some(b"old".to_vec()));
            assert_eq!(
                fs::metadata(temp.path()).unwrap().len(),
                before.len() as u64
            );
        }
        fs::write(temp.path(), after).unwrap();
        let s = Store::open(temp.path()).unwrap();
        assert_eq!(s.lookup("a").unwrap(), Some(Entry::Deleted));
        assert_eq!(s.get("b").unwrap(), Some(b"content".to_vec()));
    }

    #[test]
    fn corruption_is_rejected_without_truncation() {
        let temp = Temp::new();
        let mut s = Store::open(temp.path()).unwrap();
        s.put("a", b"data").unwrap();
        drop(s);
        let mut bytes = fs::read(temp.path()).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(temp.path(), &bytes).unwrap();
        assert!(Store::open(temp.path()).is_err());
        assert_eq!(fs::read(temp.path()).unwrap(), bytes);
    }

    #[test]
    fn traversal_and_windows_aliases_rejected() {
        for key in [
            "", "/a", "../a", "a/../b", "a//b", "a/./b", "a/", "C:/a", "a\\b", "a\0b", "a\nb",
            "a.", "a ", "NUL", "con.txt", "LPT1.dat",
        ] {
            assert!(validate_key(key).is_err(), "accepted {key:?}");
        }
        assert!(validate_key("Save/進度.json").is_ok());
    }

    #[test]
    fn locks_symlinks_and_hardlinks_rejected() {
        use std::os::unix::fs::symlink;
        let temp = Temp::new();
        let s = Store::open(temp.path()).unwrap();
        assert!(Store::open(temp.path()).is_err());
        let alias = temp.0.join("alias");
        symlink(temp.path(), &alias).unwrap();
        assert!(Store::open(&alias).is_err());
        drop(s);
        let hard = temp.0.join("hard");
        fs::hard_link(temp.path(), &hard).unwrap();
        assert!(Store::open(&hard).is_err());
    }

    #[test]
    fn corrupt_length_header_is_not_mistaken_for_torn_payload() {
        let temp = Temp::new();
        let mut s = Store::open(temp.path()).unwrap();
        s.put("a", b"data").unwrap();
        drop(s);
        let mut bytes = fs::read(temp.path()).unwrap();
        bytes[8] ^= 64;
        fs::write(temp.path(), &bytes).unwrap();
        assert!(Store::open(temp.path()).is_err());
        assert_eq!(fs::read(temp.path()).unwrap(), bytes);
    }

    #[test]
    fn oversized_wal_is_rejected_before_scanning() {
        let temp = Temp::new();
        let s = Store::open(temp.path()).unwrap();
        drop(s);
        OpenOptions::new()
            .write(true)
            .open(temp.path())
            .unwrap()
            .set_len(MAX_WAL_BYTES + 1)
            .unwrap();
        assert!(Store::open(temp.path()).is_err());
    }

    #[test]
    fn malicious_key_in_checksummed_wal_is_rejected() {
        let temp = Temp::new();
        let s = Store::open(temp.path()).unwrap();
        drop(s);
        let mut payload = vec![1];
        encode_key(&mut payload, "../outside");
        payload.extend_from_slice(b"data");
        let mut file = OpenOptions::new().append(true).open(temp.path()).unwrap();
        file.write_all(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        file.write_all(&(!(payload.len() as u32)).to_le_bytes())
            .unwrap();
        file.write_all(&checksum(&payload).to_le_bytes()).unwrap();
        file.write_all(&payload).unwrap();
        drop(file);
        assert!(Store::open(temp.path()).is_err());
        assert!(!temp.0.parent().unwrap().join("outside").exists());
    }

    #[test]
    fn size_and_missing_rename_leave_state_unchanged() {
        let temp = Temp::new();
        let mut s = Store::open(temp.path()).unwrap();
        s.put("a", b"ok").unwrap();
        let length = fs::metadata(temp.path()).unwrap().len();
        assert!(s.put("huge", &vec![0; MAX_BYTES]).is_err());
        assert!(s.rename("missing", "a").is_err());
        assert_eq!(s.get("a").unwrap(), Some(b"ok".to_vec()));
        assert_eq!(fs::metadata(temp.path()).unwrap().len(), length);
    }
    #[test]
    fn lower_rename_record_recovers_atomically_at_every_prefix() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("original.wal");
        let mut store = Store::open(&original).unwrap();
        store.put("target", b"previous target").unwrap();
        let baseline = std::fs::read(&original).unwrap();
        store
            .move_data("lower-source", "target", b"lower content")
            .unwrap();
        let complete = std::fs::read(&original).unwrap();
        drop(store);
        for length in baseline.len()..=complete.len() {
            let candidate = temp.path().join(format!("cut-{length}.wal"));
            std::fs::write(&candidate, &complete[..length]).unwrap();
            let store = Store::open(candidate).unwrap();
            if length == complete.len() {
                assert_eq!(store.lookup("lower-source").unwrap(), Some(Entry::Deleted));
                assert_eq!(store.get("target").unwrap().unwrap(), b"lower content");
            } else {
                assert_eq!(store.lookup("lower-source").unwrap(), None);
                assert_eq!(store.get("target").unwrap().unwrap(), b"previous target");
            }
        }
    }
}
