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
//! Every Unix open syncs the parent directory. On other platforms this implementation
//! fails closed rather than claiming equivalent symlink/directory durability.

use fs2::FileExt;
use std::collections::{BTreeMap, BTreeSet};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Binding {
    game_id: [u8; 16],
    archive_sha256: [u8; 32],
}

type Changes = Vec<(String, Entry)>;

pub struct Store {
    file: File,
    entries: BTreeMap<String, Entry>,
    live_bytes: usize,
    live_keys: BTreeSet<String>,
    poisoned: bool,
    binding: Option<Binding>,
    has_records: bool,
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
    key.len() * 2
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
            let mut file = match options.create_new(true).open(path) {
                Ok(file) => file,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    options.create_new(false);
                    options.open(path)?
                }
                Err(e) => return Err(e),
            };
            let meta = file.metadata()?;
            if !meta.is_file() || meta.nlink() != 1 {
                return Err(invalid("save store must be a regular file with one link"));
            }
            if meta.mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "save store must not grant group or other permissions",
                ));
            }
            FileExt::try_lock_exclusive(&file)?;
            if file.metadata()?.len() > MAX_WAL_BYTES {
                return Err(invalid("save WAL exceeds 256 MiB limit"));
            }
            // A creator may have crashed after any prefix of the initial magic.
            // Inspect under the lock, because another opener may have initialized it.
            let length = file.metadata()?.len();
            if length < MAGIC.len() as u64 {
                let mut prefix = vec![0; length as usize];
                file.read_exact(&mut prefix)?;
                if prefix != MAGIC[..prefix.len()] {
                    return Err(invalid("unrecognized partial save store format"));
                }
                file.seek(SeekFrom::Start(0))?;
                file.write_all(MAGIC)?;
                file.sync_all()?;
            }
            // Also cover files created by an opener that crashed before syncing
            // its directory entry, even when the full magic was already written.
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            File::open(parent)?.sync_all()?;
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
                live_keys: BTreeSet::new(),
                poisoned: false,
                binding: None,
                has_records: false,
            };
            store.recover()?;
            Ok(store)
        }
    }

    /// Bind an empty WAL to exactly one archive. Legacy, unbound WALs with
    /// records are never attached implicitly to an archive.
    pub fn bind_archive(&mut self, archive_sha256: [u8; 32]) -> io::Result<[u8; 16]> {
        self.ensure_healthy()?;
        if let Some(binding) = self.binding {
            if binding.archive_sha256 != archive_sha256 {
                return Err(invalid("save store belongs to a different archive"));
            }
            return Ok(binding.game_id);
        }
        if self.has_records {
            return Err(invalid(
                "legacy nonempty save store cannot be bound automatically",
            ));
        }
        let mut game_id = [0; 16];
        getrandom::fill(&mut game_id)
            .map_err(|e| io::Error::other(format!("cannot generate game identity: {e}")))?;
        let mut payload = vec![5];
        payload.extend_from_slice(&game_id);
        payload.extend_from_slice(&archive_sha256);
        self.commit(payload)?;
        Ok(game_id)
    }

    fn decode_frame(&self, payload: &[u8]) -> io::Result<(Changes, Option<Binding>)> {
        if payload.first() == Some(&5) {
            if payload.len() != 49 || self.has_records || self.binding.is_some() {
                return Err(invalid("invalid, duplicate, or misplaced archive binding"));
            }
            return Ok((
                Vec::new(),
                Some(Binding {
                    game_id: payload[1..17].try_into().unwrap(),
                    archive_sha256: payload[17..49].try_into().unwrap(),
                }),
            ));
        }
        Ok((decode(payload, &self.entries)?, None))
    }

    fn ensure_healthy(&self) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "save handle needs reopening after failed write",
            ));
        }
        Ok(())
    }

    pub fn live_names(&self) -> io::Result<impl Iterator<Item = &str>> {
        self.ensure_healthy()?;
        Ok(self.live_keys.iter().map(String::as_str))
    }

    /// Check for a live file below this logical directory in logarithmic time.
    pub fn has_live_descendant(&self, path: &str) -> io::Result<bool> {
        self.ensure_healthy()?;
        validate_key(path)?;
        let prefix = format!("{path}/");
        Ok(self
            .live_keys
            .range(prefix.clone()..)
            .next()
            .is_some_and(|name| name.starts_with(&prefix)))
    }

    pub fn lookup(&self, key: &str) -> io::Result<Option<Entry>> {
        self.ensure_healthy()?;
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
        self.ensure_healthy()?;
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
        self.ensure_healthy()?;
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
        self.ensure_healthy()?;
        if payload.len() > MAX_BYTES {
            return Err(invalid("save record exceeds 16 MiB limit"));
        }
        if self.file.metadata()?.len() + FRAME_HEADER as u64 + payload.len() as u64 > MAX_WAL_BYTES
        {
            return Err(invalid("save WAL is full (256 MiB limit)"));
        }
        let (changes, binding) = self.decode_frame(&payload)?;
        let size = self.check_size(&changes)?;
        self.check_namespace(&changes)?;
        self.poisoned = true;
        self.file.write_all(&(payload.len() as u32).to_le_bytes())?;
        self.file
            .write_all(&(!(payload.len() as u32)).to_le_bytes())?;
        self.file.write_all(&checksum(&payload).to_le_bytes())?;
        self.file.write_all(&payload)?;
        self.file.sync_all()?;
        self.apply_changes(changes);
        self.binding = binding.or(self.binding);
        self.has_records = true;
        self.live_bytes = size;
        self.poisoned = false;
        Ok(())
    }

    fn apply_changes(&mut self, changes: Vec<(String, Entry)>) {
        for (key, value) in changes {
            if matches!(value, Entry::Data(_)) {
                self.live_keys.insert(key.clone());
            } else {
                self.live_keys.remove(&key);
            }
            self.entries.insert(key, value);
        }
    }

    /// Validate the prospective transaction, including removals, without cloning
    /// the map or scanning tombstones. Each transaction changes at most two keys.
    fn check_namespace(&self, changes: &[(String, Entry)]) -> io::Result<()> {
        let is_live = |key: &str| match changes.iter().find(|(name, _)| name == key) {
            Some((_, entry)) => matches!(entry, Entry::Data(_)),
            None => self.live_keys.contains(key),
        };
        for (key, entry) in changes {
            if !matches!(entry, Entry::Data(_)) {
                continue;
            }
            for (index, _) in key.match_indices('/') {
                if is_live(&key[..index]) {
                    return Err(invalid("save file conflicts with an ancestor file"));
                }
            }
            let prefix = format!("{key}/");
            for existing in self.live_keys.range(prefix.clone()..) {
                if !existing.starts_with(&prefix) {
                    break;
                }
                if is_live(existing) {
                    return Err(invalid("save file conflicts with a descendant file"));
                }
            }
            if changes
                .iter()
                .any(|(name, value)| matches!(value, Entry::Data(_)) && name.starts_with(&prefix))
            {
                return Err(invalid("save files conflict within transaction"));
            }
        }
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
            let (changes, binding) = self.decode_frame(&payload)?;
            self.live_bytes = self.check_size(&changes)?;
            self.check_namespace(&changes)?;
            self.apply_changes(changes);
            self.binding = binding.or(self.binding);
            self.has_records = true;
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

    fn write_private(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
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
        drop(s);
        let alias = temp.0.join("alias");
        symlink(temp.path(), &alias).unwrap();
        assert!(Store::open(&alias).is_err());
        assert!(Store::open(temp.path()).is_ok());
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
            write_private(&candidate, &complete[..length]);
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
    #[test]
    fn partial_magic_initialization_repairs_only_valid_prefixes() {
        let temp = Temp::new();
        for length in 0..MAGIC.len() {
            let path = temp.0.join(format!("prefix-{length}"));
            write_private(&path, &MAGIC[..length]);
            let mut store = Store::open(&path).unwrap();
            assert_eq!(fs::read(&path).unwrap(), MAGIC);
            store.put("save", b"ok").unwrap();
            drop(store);
            assert_eq!(
                Store::open(&path).unwrap().get("save").unwrap().unwrap(),
                b"ok"
            );
        }
        for length in 1..MAGIC.len() {
            let path = temp.0.join(format!("bad-{length}"));
            let mut bytes = MAGIC[..length].to_vec();
            bytes[length - 1] ^= 1;
            write_private(&path, &bytes);
            assert!(Store::open(&path).is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }

    #[test]
    fn group_or_world_permissions_rejected_without_changing_them() {
        use std::os::unix::fs::PermissionsExt;
        let temp = Temp::new();
        for mode in [0o640, 0o604, 0o620, 0o602, 0o610, 0o601, 0o666] {
            let path = temp.0.join(format!("mode-{mode}"));
            write_private(&path, MAGIC);
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                Store::open(&path).err().unwrap().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                mode
            );
        }
    }

    #[test]
    fn failed_write_poison_blocks_every_read_and_noop_mutation() {
        let temp = Temp::new();
        let mut store = Store::open(temp.path()).unwrap();
        store.put("save", b"old").unwrap();
        // A read-only descriptor deterministically injects an append failure.
        store.file = File::open(temp.path()).unwrap();
        assert!(store.put("save", b"new").is_err());
        assert!(store.poisoned);
        assert!(store.lookup("save").is_err());
        assert!(store.get("save").is_err());
        assert!(store.live_names().is_err());
        assert!(store.has_live_descendant("save").is_err());
        assert!(store.rename("save", "save").is_err());
        assert!(store.move_data("save", "save", b"new").is_err());
        assert!(store.bind_archive([1; 32]).is_err());
    }

    #[test]
    fn prospective_namespace_rejects_conflicts_and_allows_removed_source() {
        let temp = Temp::new();
        let mut store = Store::open(temp.path()).unwrap();
        store.put("a/b", b"b").unwrap();
        store.put("a-", b"neighbor").unwrap();
        assert!(store.put("a", b"bad").is_err());
        assert!(store.put("a/b/c", b"bad").is_err());
        store.put("other", b"other").unwrap();
        assert!(store.rename("other", "a").is_err());
        assert!(store.move_data("lower", "a", b"bad").is_err());
        assert!(store.move_data("lower", "a/b/c", b"bad").is_err());
        store.rename("a/b", "a").unwrap();
        store.rename("a", "a/c").unwrap();
        store.move_data("a/c", "a", b"replacement").unwrap();
        drop(store);
        let store = Store::open(temp.path()).unwrap();
        assert_eq!(store.get("a").unwrap().unwrap(), b"replacement");
        assert_eq!(
            store.live_names().unwrap().collect::<Vec<_>>(),
            vec!["a", "a-", "other"]
        );
    }

    fn append_frame(path: &Path, payload: &[u8]) {
        let mut file = OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        file.write_all(&(!(payload.len() as u32)).to_le_bytes())
            .unwrap();
        file.write_all(&checksum(payload).to_le_bytes()).unwrap();
        file.write_all(payload).unwrap();
    }

    #[test]
    fn recovery_rejects_checksummed_namespace_conflict() {
        let temp = Temp::new();
        let mut store = Store::open(temp.path()).unwrap();
        store.put("a/b", b"first").unwrap();
        drop(store);
        let mut payload = vec![1];
        encode_key(&mut payload, "a");
        payload.extend_from_slice(b"conflict");
        append_frame(&temp.path(), &payload);
        let before = fs::read(temp.path()).unwrap();
        assert!(Store::open(temp.path()).is_err());
        assert_eq!(fs::read(temp.path()).unwrap(), before);
    }

    #[test]
    fn archive_binding_is_durable_and_rejects_mismatch_and_legacy_records() {
        let temp = Temp::new();
        let mut store = Store::open(temp.path()).unwrap();
        let id = store.bind_archive([7; 32]).unwrap();
        assert_eq!(store.bind_archive([7; 32]).unwrap(), id);
        assert!(store.bind_archive([8; 32]).is_err());
        store.put("save", b"content").unwrap();
        drop(store);
        let mut store = Store::open(temp.path()).unwrap();
        assert_eq!(store.bind_archive([7; 32]).unwrap(), id);
        assert!(store.bind_archive([8; 32]).is_err());
        assert_eq!(store.get("save").unwrap().unwrap(), b"content");
        let mut legacy = Store::open(temp.0.join("legacy")).unwrap();
        legacy.delete("unused").unwrap();
        assert!(legacy.bind_archive([7; 32]).is_err());
    }

    #[test]
    fn recovery_rejects_duplicate_malformed_and_misplaced_bindings() {
        let temp = Temp::new();
        for kind in ["duplicate", "malformed", "misplaced"] {
            let path = temp.0.join(kind);
            let mut store = Store::open(&path).unwrap();
            if kind == "duplicate" {
                store.bind_archive([1; 32]).unwrap();
            } else if kind == "misplaced" {
                store.delete("gone").unwrap();
            }
            drop(store);
            let payload = if kind == "malformed" {
                vec![5; 48]
            } else {
                vec![5; 49]
            };
            append_frame(&path, &payload);
            assert!(Store::open(&path).is_err());
        }
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn failed_sync_poison_blocks_stale_reads() {
        let temp = Temp::new();
        let mut store = Store::open(temp.path()).unwrap();
        store.put("save", b"old").unwrap();
        // /dev/null accepts every write but rejects fsync on Linux. This drives
        // the precise post-write/pre-publication failure path without unsafe fd use.
        store.file = OpenOptions::new().write(true).open("/dev/null").unwrap();
        assert!(store.put("save", b"new").is_err());
        assert!(store.poisoned);
        assert!(store.lookup("save").is_err());
        assert!(store.get("save").is_err());
        assert!(store.live_names().is_err());
        assert!(store.has_live_descendant("save").is_err());
        drop(store);
        assert_eq!(
            Store::open(temp.path())
                .unwrap()
                .get("save")
                .unwrap()
                .unwrap(),
            b"old"
        );
    }

    #[test]
    fn binding_recovers_atomically_at_every_frame_prefix() {
        let temp = Temp::new();
        let mut store = Store::open(temp.path()).unwrap();
        let id = store.bind_archive([7; 32]).unwrap();
        drop(store);
        let complete = fs::read(temp.path()).unwrap();
        for length in MAGIC.len()..=complete.len() {
            let path = temp.0.join(format!("binding-cut-{length}"));
            write_private(&path, &complete[..length]);
            let mut recovered = Store::open(&path).unwrap();
            if length == complete.len() {
                assert_eq!(recovered.bind_archive([7; 32]).unwrap(), id);
                assert!(recovered.bind_archive([8; 32]).is_err());
            } else {
                assert_eq!(fs::metadata(&path).unwrap().len(), MAGIC.len() as u64);
                recovered.bind_archive([8; 32]).unwrap();
            }
        }
    }
    #[test]
    fn live_descendant_checks_component_boundaries_and_tombstones() {
        let temp = Temp::new();
        let mut store = Store::open(temp.path()).unwrap();
        store.put("a-/b", b"neighbor").unwrap();
        store.put("aa/b", b"neighbor").unwrap();
        assert!(!store.has_live_descendant("a").unwrap());
        store.put("a/b/c", b"nested").unwrap();
        assert!(store.has_live_descendant("a").unwrap());
        assert!(store.has_live_descendant("a/b").unwrap());
        assert!(!store.has_live_descendant("a/b/c").unwrap());
        store.delete("a/b/c").unwrap();
        assert!(!store.has_live_descendant("a").unwrap());
        assert!(store.has_live_descendant("../a").is_err());
    }
}
