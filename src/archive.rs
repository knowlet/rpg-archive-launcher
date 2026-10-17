//! Memory-only archive access. Never calls an extraction API.
//! Limits apply to payload dictionaries, returned files, and the one-entry cache.
//! Encoded headers are parsed by the dependency before their metadata is available:
//! callers must set a process address-space limit before `open` for untrusted input.
use sevenz_rust2::{Archive as Metadata, BlockDecoder, Password};
use std::{
    collections::{BTreeMap, HashSet},
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};
use unicode_normalization::UnicodeNormalization;

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_file_bytes: u64,
    pub max_cache_bytes: u64,
    pub max_dictionary_bytes: u64,
    pub max_entries: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: 64 << 20,
            max_cache_bytes: 32 << 20,
            max_dictionary_bytes: 64 << 20,
            max_entries: 100_000,
        }
    }
}

pub struct Archive {
    source: File,
    metadata: Metadata,
    password: Password,
    limits: Limits,
    index: BTreeMap<String, usize>,
    cache: Option<(String, Vec<u8>)>,
}

/// Strict portable relative path policy. No URL decoding is performed here.
pub fn validate_archive_path(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 4096
        || name.contains('\\')
        || name.contains(':')
        || name
            .chars()
            .any(|c| c.is_control() || matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return Err(format!("unsafe archive path: {name:?}"));
    }
    for component in name.split('/') {
        if component.is_empty()
            || component.len() > 255
            || component == "."
            || component == ".."
            || component.ends_with('.')
            || component.ends_with(' ')
        {
            return Err(format!("unsafe archive path: {name:?}"));
        }
        let stem = component
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        {
            return Err(format!("reserved device path: {name:?}"));
        }
    }
    Ok(())
}

fn header_preflight(file: &mut File) -> Result<()> {
    let len = file.metadata().map_err(|e| e.to_string())?.len();
    let mut header = [0; 32];
    file.read_exact(&mut header)
        .map_err(|e| format!("7z signature: {e}"))?;
    if &header[..6] != b"7z\xbc\xaf\x27\x1c" {
        return Err("not a 7z archive".into());
    }
    let offset = u64::from_le_bytes(header[12..20].try_into().unwrap());
    let size = u64::from_le_bytes(header[20..28].try_into().unwrap());
    if size == 0 || size > 8 << 20 {
        return Err(
            "7z next header must be between 1 byte and 8 MiB; recovery-mode archives unsupported"
                .into(),
        );
    }
    if 32u64
        .checked_add(offset)
        .and_then(|v| v.checked_add(size))
        .is_none_or(|end| end > len)
    {
        return Err("7z next header outside archive".into());
    }
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    Ok(())
}

fn dictionary_size(id: &[u8], properties: &[u8]) -> Result<u64> {
    match id {
        [0] => Ok(0), // COPY
        [6, 0xf1, 7, 1] => {
            // AES256: reject pathological KDF work factors.
            let power = properties.first().ok_or("missing AES properties")? & 0x3f;
            if power > 24 && power != 63 {
                return Err("AES work factor exceeds 2^24".into());
            }
            Ok(0)
        }
        [3, 1, 1] if properties.len() == 5 => {
            Ok(u32::from_le_bytes(properties[1..5].try_into().unwrap()).max(4096) as u64)
        }
        [0x21] if properties.len() == 1 && properties[0] <= 40 => {
            let p = properties[0] as u32;
            Ok(if p == 40 {
                u32::MAX as u64
            } else {
                ((2 | (p & 1)) as u64) << (p / 2 + 11)
            })
        }
        _ => Err(format!(
            "unsupported codec/properties {id:02x?}; only COPY, LZMA, LZMA2, AES256 supported"
        )),
    }
}

fn validate_stream_layout(metadata: &Metadata) -> Result<()> {
    if metadata.stream_map.file_block_index.len() != metadata.files.len() {
        return Err("invalid file/block mapping".into());
    }
    let mut totals = vec![0u64; metadata.blocks.len()];
    for (entry, block) in metadata
        .files
        .iter()
        .zip(&metadata.stream_map.file_block_index)
    {
        if let Some(block) = *block {
            if !entry.has_stream {
                return Err(
                    "unsupported archive layout: streamless entry interleaved in a solid block"
                        .into(),
                );
            }
            let total = totals.get_mut(block).ok_or("invalid block index")?;
            *total = total.checked_add(entry.size).ok_or("block size overflow")?;
        } else if entry.has_stream {
            return Err("streamed entry has no block".into());
        }
    }
    for (block, total) in metadata.blocks.iter().zip(totals) {
        if block.get_unpack_size() != total {
            return Err("block unpack size disagrees with member sizes".into());
        }
    }
    Ok(())
}

impl Archive {
    pub fn open(path: impl AsRef<Path>, password: &str, limits: Limits) -> Result<Self> {
        if limits.max_file_bytes > usize::MAX as u64 || limits.max_cache_bytes > usize::MAX as u64 {
            return Err("memory limits exceed platform address size".into());
        }
        let mut source = File::open(path).map_err(|e| e.to_string())?;
        header_preflight(&mut source)?;
        let password = Password::new(password);
        // Metadata::read uses one decoding thread, including encrypted headers.
        let metadata = Metadata::read(&mut source, &password)
            .map_err(|e| format!("archive metadata (password may be wrong): {e}"))?;
        if metadata.files.len() > limits.max_entries {
            return Err("archive entry-count limit exceeded".into());
        }
        validate_stream_layout(&metadata)?;
        let mut index = BTreeMap::new();
        let mut seen = HashSet::new();
        let mut file_keys = HashSet::new();
        for (i, entry) in metadata.files.iter().enumerate() {
            let name = if entry.is_directory {
                entry.name.strip_suffix('/').unwrap_or(&entry.name)
            } else {
                &entry.name
            };
            validate_archive_path(name)?;
            let key: String = name
                .nfc()
                .collect::<String>()
                .to_lowercase()
                .nfc()
                .collect();
            if !seen.insert(key.clone()) {
                return Err(format!("duplicate/case-colliding path: {name:?}"));
            }
            let mode = (entry.windows_attributes >> 16) & 0xf000;
            if entry.is_anti_item
                || (entry.has_windows_attributes
                    && (entry.windows_attributes & 0x400 != 0
                        || (mode != 0 && mode != 0x8000 && mode != 0x4000)))
            {
                return Err(format!(
                    "link, special file, reparse point, or anti-item rejected: {name:?}"
                ));
            }
            if entry.size > usize::MAX as u64 {
                return Err("archive file exceeds platform size".into());
            }
            if !entry.is_directory {
                file_keys.insert(key);
                index.insert(name.to_owned(), i);
            }
        }
        for name in &seen {
            for (pos, _) in name.match_indices('/') {
                if file_keys.contains(&name[..pos]) {
                    return Err(format!("file/directory path collision: {name:?}"));
                }
            }
        }
        for block in &metadata.blocks {
            if block.coders.len() > 4 {
                return Err("too many chained coders".into());
            }
            let mut dictionaries = 0u64;
            for coder in &block.coders {
                dictionaries = dictionaries
                    .checked_add(dictionary_size(
                        coder.encoder_method_id(),
                        coder.properties(),
                    )?)
                    .ok_or("dictionary size overflow")?;
            }
            if dictionaries > limits.max_dictionary_bytes {
                return Err(format!(
                    "decoder dictionaries need {dictionaries} bytes, over limit {}",
                    limits.max_dictionary_bytes
                ));
            }
        }
        Ok(Self {
            source,
            metadata,
            password,
            limits,
            index,
            cache: None,
        })
    }

    pub fn file_size(&self, name: &str) -> Option<u64> {
        self.index.get(name).map(|&i| self.metadata.files[i].size)
    }

    pub fn names(&self) -> Vec<String> {
        self.index.keys().cloned().collect()
    }

    pub fn inspect(&self) -> String {
        let mut report = format!(
            "Files: {}\nBlocks: {}\nSolid: {}\nLimits: request={} cache={} dictionary={} bytes; decoder threads=1\n",
            self.index.len(),
            self.metadata.blocks.len(),
            self.metadata.is_solid,
            self.limits.max_file_bytes,
            self.limits.max_cache_bytes,
            self.limits.max_dictionary_bytes
        );
        report.push_str("Solid blocks require decoding preceding bytes on cache misses; no whole-block RAM cache.\nEncoded-header allocation is guarded by the CLI process limit, not these payload limits.\n");
        for (i, block) in self.metadata.blocks.iter().enumerate() {
            let dictionary_bytes: u64 = block
                .coders
                .iter()
                .map(|coder| {
                    dictionary_size(coder.encoder_method_id(), coder.properties()).unwrap_or(0)
                })
                .sum();
            report.push_str(&format!(
                "Block {i}: unpacked={} bytes, dictionary={dictionary_bytes} bytes, codecs=",
                block.get_unpack_size()
            ));
            for coder in &block.coders {
                report.push_str(&format!("{:02x?} ", coder.encoder_method_id()));
            }
            report.push('\n');
        }
        for (name, &i) in &self.index {
            report.push_str(&format!(
                "{} bytes\tblock={:?}\t{name}\n",
                self.metadata.files[i].size, self.metadata.stream_map.file_block_index[i]
            ));
        }
        report
    }

    pub fn read(&mut self, name: &str) -> Result<Vec<u8>> {
        validate_archive_path(name)?;
        if let Some((key, bytes)) = &self.cache
            && key == name
        {
            return Ok(bytes.clone());
        }
        let i = *self
            .index
            .get(name)
            .ok_or_else(|| format!("archive file not found: {name:?}"))?;
        let size = self.metadata.files[i].size;
        if size > self.limits.max_file_bytes {
            return Err(format!(
                "file requires {size} bytes, over request limit {}",
                self.limits.max_file_bytes
            ));
        }
        self.cache = None;
        if !self.metadata.files[i].has_stream {
            return Ok(Vec::new());
        }
        let block = self.metadata.stream_map.file_block_index[i].ok_or("file has no data block")?;
        let target_has_crc = self.metadata.files[i].has_crc;
        if !target_has_crc && !self.metadata.blocks[block].has_crc {
            return Err(
                "entry has neither individual nor block checksum; integrity cannot be verified"
                    .into(),
            );
        }
        let mut output = None;
        BlockDecoder::new(1, block, &self.metadata, &self.password, &mut self.source)
            .for_each_entries(&mut |entry, reader| {
                if entry.name != name {
                    // Stream preceding solid members to a fixed-size discard buffer.
                    let discarded = std::io::copy(reader, &mut std::io::sink())?;
                    if discarded != entry.size {
                        return Err(sevenz_rust2::Error::Other("truncated solid member".into()));
                    }
                    return Ok(true);
                }
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(size as usize).map_err(|e| {
                    sevenz_rust2::Error::Other(format!("request allocation: {e}").into())
                })?;
                bytes.resize(size as usize, 0);
                reader.read_exact(&mut bytes)?;
                let mut extra = [0];
                if reader.read(&mut extra)? != 0 {
                    return Err(sevenz_rust2::Error::Other(
                        "entry exceeded declared size".into(),
                    ));
                }
                output = Some(bytes);
                // Without an entry CRC, consume every remaining block byte to
                // make the dependency verify the block CRC before returning.
                Ok(!target_has_crc)
            })
            .map_err(|e| format!("archive decode: {e}"))?;
        let output = output.ok_or("entry missing from block")?;
        if size <= self.limits.max_cache_bytes {
            self.cache = Some((name.to_owned(), output.clone()));
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sevenz_rust2::{
        ArchiveEntry, ArchiveWriter,
        encoder_options::{AesEncoderOptions, Lzma2Options},
    };
    fn fixture(path: &Path, names: &[&str], encrypted: bool) {
        let mut writer = ArchiveWriter::create(path).unwrap();
        if encrypted {
            writer.set_content_methods(vec![
                AesEncoderOptions::new(Password::new("秘密🔑")).into(),
                Lzma2Options::default().into(),
            ]);
            writer.set_encrypt_header(true);
        }
        for name in names {
            writer
                .push_archive_entry(
                    ArchiveEntry::new_file(name),
                    Some(b"hello archive".as_slice()),
                )
                .unwrap();
        }
        writer.finish().unwrap();
    }
    #[test]
    fn rejects_unsafe_paths() {
        for name in [
            "../a", "/a", "a/../b", "a\\b", "C:a", "a//b", "a/./b", "a\0b", "a.", "NUL.txt",
        ] {
            assert!(validate_archive_path(name).is_err(), "{name:?}");
        }
        assert!(validate_archive_path("遊戲/data/Map001.json").is_ok());
    }
    #[test]
    fn encrypted_header_unicode_and_wrong_password() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("game.7z");
        fixture(&path, &["遊戲/data.json"], true);
        assert!(Archive::open(&path, "wrong", Limits::default()).is_err());
        let mut archive = Archive::open(&path, "秘密🔑", Limits::default()).unwrap();
        assert_eq!(archive.read("遊戲/data.json").unwrap(), b"hello archive");
        assert_eq!(archive.read("遊戲/data.json").unwrap(), b"hello archive");
        assert!(archive.read("missing").is_err());
        assert_eq!(
            std::fs::read_dir(temp.path()).unwrap().count(),
            1,
            "no extraction files"
        );
    }
    #[test]
    fn request_dictionary_entry_limits() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("game.7z");
        fixture(&path, &["data.json"], false);
        let mut limits = Limits {
            max_file_bytes: 2,
            ..Limits::default()
        };
        assert!(
            Archive::open(&path, "", limits)
                .unwrap()
                .read("data.json")
                .is_err()
        );
        limits.max_dictionary_bytes = 1;
        assert!(Archive::open(&path, "", limits).is_err());
        limits = Limits::default();
        limits.max_entries = 0;
        assert!(Archive::open(&path, "", limits).is_err());
    }
    #[test]
    fn rejects_collisions_and_traversal_in_actual_archives() {
        let temp = tempfile::tempdir().unwrap();
        for (i, names) in [
            vec!["a", "A"],
            vec!["a", "a/b"],
            vec!["../escape"],
            vec!["caf\u{e9}", "cafe\u{301}"],
        ]
        .iter()
        .enumerate()
        {
            let path = temp.path().join(format!("{i}.7z"));
            fixture(&path, names, false);
            assert!(Archive::open(path, "", Limits::default()).is_err());
        }
    }
    #[test]
    fn solid_reads_late_member_without_caching_predecessor() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("solid.7z");
        let mut writer = ArchiveWriter::create(&path).unwrap();
        let big = vec![b'x'; 2 << 20];
        writer
            .push_archive_entries(
                vec![
                    ArchiveEntry::new_file("big.bin"),
                    ArchiveEntry::new_file("small.json"),
                ],
                vec![big.as_slice().into(), b"{}".as_slice().into()],
            )
            .unwrap();
        writer.finish().unwrap();
        let limits = Limits {
            max_file_bytes: 16,
            max_cache_bytes: 1,
            ..Limits::default()
        };
        let mut archive = Archive::open(&path, "", limits).unwrap();
        assert!(archive.metadata.is_solid);
        assert!(archive.read("big.bin").is_err());
        assert_eq!(archive.read("small.json").unwrap(), b"{}");
        assert!(archive.cache.is_none());
        assert_eq!(archive.read("small.json").unwrap(), b"{}");
    }
    #[test]
    fn rejects_unix_symlink_and_windows_reparse_entries() {
        let temp = tempfile::tempdir().unwrap();
        for attrs in [0xa000u32 << 16, 0x400] {
            let path = temp.path().join(format!("{attrs}.7z"));
            let mut writer = ArchiveWriter::create(&path).unwrap();
            let mut entry = ArchiveEntry::new_file("link");
            entry.has_windows_attributes = true;
            entry.windows_attributes = attrs;
            writer
                .push_archive_entry(entry, Some(b"target".as_slice()))
                .unwrap();
            writer.finish().unwrap();
            assert!(Archive::open(&path, "", Limits::default()).is_err());
        }
    }
    #[test]
    fn early_member_without_file_crc_verifies_whole_block() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("block-crc.7z");
        let mut writer = ArchiveWriter::create(&path).unwrap();
        writer
            .push_archive_entries(
                vec![
                    ArchiveEntry::new_file("first"),
                    ArchiveEntry::new_file("last"),
                ],
                vec![b"first".as_slice().into(), b"last".as_slice().into()],
            )
            .unwrap();
        writer.finish().unwrap();
        let mut archive = Archive::open(&path, "", Limits::default()).unwrap();
        // Simulate a legal block-only-CRC header while keeping real compressed
        // data. Corrupt the expected block checksum: returning early would miss it.
        for entry in &mut archive.metadata.files {
            entry.has_crc = false;
        }
        archive.metadata.blocks[0].has_crc = true;
        archive.metadata.blocks[0].crc ^= 0xffff_ffff;
        assert!(archive.read("first").is_err());
        assert!(archive.cache.is_none());
    }
    #[test]
    fn rejects_interleaved_streamless_layout() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("layout.7z");
        fixture(&path, &["data.json"], false);
        let mut archive = Archive::open(&path, "", Limits::default()).unwrap();
        archive.metadata.files[0].has_stream = false;
        assert!(
            validate_stream_layout(&archive.metadata)
                .unwrap_err()
                .contains("interleaved")
        );
    }
    #[test]
    fn rejects_corrupt_payload() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("corrupt.7z");
        fixture(&path, &["data.json"], false);
        let archive = Archive::open(&path, "", Limits::default()).unwrap();
        let offset = 32 + archive.metadata.pack_pos();
        drop(archive);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[offset as usize] ^= 0xff;
        std::fs::write(&path, bytes).unwrap();
        let mut archive = Archive::open(&path, "", Limits::default()).unwrap();
        assert!(archive.read("data.json").is_err());
    }
    #[test]
    fn refuses_oversized_header_before_parse() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bad.7z");
        let mut bytes = [0u8; 32];
        bytes[..6].copy_from_slice(b"7z\xbc\xaf\x27\x1c");
        bytes[20..28].copy_from_slice(&(9u64 << 20).to_le_bytes());
        std::fs::write(&path, bytes).unwrap();
        assert!(Archive::open(path, "", Limits::default()).is_err());
    }
}
