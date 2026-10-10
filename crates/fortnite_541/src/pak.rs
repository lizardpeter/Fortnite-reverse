//! Bounded, read-only UE4 PakFile index inspection. No archive content is executed
//! or extracted. Index contents must match the footer's SHA-1 before admission.
use aes::{Aes256, cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray}};
use sha1::{Digest, Sha1};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const MAGIC: u32 = 0x5A6F_12E1;
const MAX_INDEX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 1_000_000;
const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STRING_UNITS: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PakFooter {
    pub version: u32,
    pub index_offset: u64,
    pub index_size: u64,
    pub index_hash: [u8; 20],
    pub encrypted_index: bool,
    pub encryption_key_guid: Option<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PakEntry {
    pub path: String,
    pub offset: u64,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub compression_method: u32,
    pub content_hash: [u8; 20],
    pub encrypted: bool,
    pub compression_block_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexStatus {
    Encrypted,
    UnsupportedVersion(u32),
    Indexed { mount_point: String, entries: Vec<PakEntry> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PakReport {
    pub footer: PakFooter,
    pub status: IndexStatus,
    pub file_size: u64,
}

/// Inspect without keys. Encrypted indexes stay explicit, not guessed.
pub fn inspect(path: &Path) -> Result<PakReport, String> {
    inspect_inner(path, None)
}

/// Inspect an archive with an explicitly supplied historical/source AES-256
/// key. Index SHA-1 must match the source footer after decryption.
pub fn inspect_with_key(path: &Path, key: &[u8; 32]) -> Result<PakReport, String> {
    inspect_inner(path, Some(key))
}

fn inspect_inner(path: &Path, key: Option<&[u8; 32]>) -> Result<PakReport, String> {
    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let file_size = file.metadata().map_err(|e| format!("metadata {}: {e}", path.display()))?.len();
    let footer = read_footer(&mut file, file_size)?;
    if footer.encrypted_index && key.is_none() {
        return Ok(PakReport { footer, status: IndexStatus::Encrypted, file_size });
    }
    // Version 8+ changes compression method registration and eventually the
    // structure of the index. Do not claim that older records decode it.
    if footer.version > 7 {
        let version = footer.version;
        return Ok(PakReport { footer, status: IndexStatus::UnsupportedVersion(version), file_size });
    }
    if footer.index_size > MAX_INDEX_BYTES {
        return Err(format!("pak index of {} bytes exceeds {} byte safety limit",
            footer.index_size, MAX_INDEX_BYTES));
    }
    let len = usize::try_from(footer.index_size).map_err(|_| "pak index length too large")?;
    let mut bytes = vec![0u8; len];
    file.seek(SeekFrom::Start(footer.index_offset)).map_err(|e| format!("seek pak index: {e}"))?;
    file.read_exact(&mut bytes).map_err(|e| format!("read pak index: {e}"))?;
    if footer.encrypted_index {
        if bytes.len() % 16 != 0 {
            return Err("AES-256 encrypted pak index is not block-aligned".into());
        }
        let cipher = Aes256::new(GenericArray::from_slice(key.expect("validated above")));
        for block in bytes.chunks_exact_mut(16) {
            cipher.decrypt_block(GenericArray::from_mut_slice(block));
        }
    }
    let digest = Sha1::digest(&bytes);
    if digest.as_slice() != footer.index_hash {
        return Err("pak index SHA-1 mismatch (corrupt data, wrong footer, or encrypted index)".into());
    }
    let (mount_point, entries) = read_index(&bytes, &footer)?;
    Ok(PakReport {
        footer, status: IndexStatus::Indexed { mount_point, entries }, file_size,
    })
}


/// Extract one exact, uncompressed and unencrypted source entry without
/// decompressing entire archives. The serialized FPakEntry header and the
/// payload SHA-1 must both agree with the verified index before admission.
/// Unknown compressed/encrypted payloads remain explicit unsupported cases.
pub fn extract_plain_entry(path: &Path, report: &PakReport, entry: &PakEntry) -> Result<Vec<u8>, String> {
    if report.footer.version < 3 || report.footer.version > 7 {
        return Err("plain entry extraction currently requires UE4 pak v3-v7".into());
    }
    if entry.encrypted || entry.compression_method != 0 {
        return Err(format!("source entry {:?} requires an encrypted or compressed payload decoder", entry.path));
    }
    if entry.compressed_size != entry.uncompressed_size || entry.uncompressed_size > MAX_ENTRY_BYTES {
        return Err(format!("source entry {:?} has mismatched or excessive byte counts", entry.path));
    }
    let head_size = 53u64; // uncompressed v3-v7 FPakEntry source metadata.
    let data_start = entry.offset.checked_add(head_size).ok_or("entry offset overflow")?;
    let end = data_start.checked_add(entry.compressed_size).ok_or("entry length overflow")?;
    if end > report.footer.index_offset || end > report.file_size {
        return Err(format!("source entry {:?} would escape original pak data", entry.path));
    }
    let mut file = File::open(path).map_err(|e| format!("open pak for extraction: {e}"))?;
    file.seek(SeekFrom::Start(entry.offset)).map_err(|e| format!("seek source entry: {e}"))?;
    let mut header = [0u8; 53];
    file.read_exact(&mut header).map_err(|e| format!("read source entry header: {e}"))?;
    let u64_at = |begin: usize| u64::from_le_bytes(header[begin..begin+8].try_into().unwrap());
    // Fortnite's serialized per-file FPakEntry uses zero for its local Offset;
    // the indexed FPakEntry carries the absolute archive offset.
    if !(u64_at(0) == 0 || u64_at(0) == entry.offset) || u64_at(8) != entry.compressed_size ||
        u64_at(16) != entry.uncompressed_size ||
        u32::from_le_bytes(header[24..28].try_into().unwrap()) != 0 ||
        header[28..48] != entry.content_hash ||
        header[48] & 1 != 0 {
        return Err(format!("source entry {:?} header disagrees with verified index", entry.path));
    }
    let mut data = vec![0u8; usize::try_from(entry.uncompressed_size)
        .map_err(|_| "source entry length exceeds address space")?];
    file.read_exact(&mut data).map_err(|e| format!("read source entry payload: {e}"))?;
    if Sha1::digest(&data).as_slice() != entry.content_hash {
        return Err(format!("source entry {:?} payload SHA-1 mismatch", entry.path));
    }
    Ok(data)
}

fn read_footer(file: &mut File, size: u64) -> Result<PakFooter, String> {
    // UE4 stores GUID and encrypted-index flag BEFORE Magic, but v8+ stores
    // its fixed-width compression-method table AFTER IndexHash. Therefore the
    // magic position must be version-specific, not assumed to be at the start
    // of the footer, or immediately before EOF. We only decode flat v1-v7
    // indexes; newer index formats remain explicitly unsupported.
    // tuple: (serialized footer bytes, magic position, first version, last).
    for &(length, magic_pos, low, high) in &[
        (44u64, 0usize, 1u32, 3u32),
        (45, 1, 4, 6),
        (61, 17, 7, 7),
        (189, 17, 8, 8), // UE4.22: 4 compression names
        (221, 17, 8, 12), // UE4.23+: 5 names
    ] {
        if size < length { continue; }
        let mut bytes = vec![0u8; length as usize];
        file.seek(SeekFrom::Start(size - length))
            .map_err(|e| format!("seek pak footer: {e}"))?;
        file.read_exact(&mut bytes).map_err(|e| format!("read pak footer: {e}"))?;
        let magic = &bytes[magic_pos..magic_pos + 44];
        if u32::from_le_bytes(magic[0..4].try_into().unwrap()) != MAGIC { continue; }
        let version = u32::from_le_bytes(magic[4..8].try_into().unwrap());
        if !(low..=high).contains(&version) { continue; }
        let index_offset = u64::from_le_bytes(magic[8..16].try_into().unwrap());
        let index_size = u64::from_le_bytes(magic[16..24].try_into().unwrap());
        let mut index_hash = [0u8; 20];
        index_hash.copy_from_slice(&magic[24..44]);
        let encrypted_index = version >= 4 && bytes[magic_pos - 1] != 0;
        let encryption_key_guid = if version >= 7 {
            let mut guid = [0u8; 16];
            guid.copy_from_slice(&bytes[magic_pos - 17..magic_pos - 1]);
            Some(guid)
        } else { None };
        let end = index_offset.checked_add(index_size)
            .ok_or("pak index offset+length overflow")?;
        if end > size - length {
            return Err(format!("pak index range {index_offset}..{end} overlaps footer at {}",
                size - length));
        }
        return Ok(PakFooter {
            version, index_offset, index_size, index_hash,
            encrypted_index, encryption_key_guid,
        });
    }
    Err("no supported UE4 FPakInfo footer (magic/version/size) found".into())
}

struct Cursor<'a> { bytes: &'a [u8], pos: usize }
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, pos: 0 } }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or("pak index cursor overflow")?;
        let value = self.bytes.get(self.pos..end).ok_or("truncated pak index record")?;
        self.pos = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, String> { Ok(self.take(1)?[0]) }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn i32(&mut self) -> Result<i32, String> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn string(&mut self) -> Result<String, String> {
        let count = self.i32()?;
        if count == 0 { return Ok(String::new()); }
        if count > 0 {
            let len = usize::try_from(count).map_err(|_| "invalid ANSI FString length")?;
            if len > MAX_STRING_UNITS { return Err("pak FString exceeds safety limit".into()); }
            let bytes = self.take(len)?;
            if bytes.last() != Some(&0) { return Err("pak FString is not NUL terminated".into()); }
            return String::from_utf8(bytes[..len - 1].to_vec())
                .map_err(|_| "pak ANSI FString is not UTF-8".into());
        }
        let len = usize::try_from(count.checked_neg().ok_or("invalid UTF-16 FString length")?)
            .map_err(|_| "invalid UTF-16 FString length")?;
        if len > MAX_STRING_UNITS { return Err("pak UTF-16 FString exceeds safety limit".into()); }
        let bytes = self.take(len.checked_mul(2).ok_or("UTF-16 length overflow")?)?;
        if &bytes[bytes.len() - 2..] != [0u8, 0u8] {
            return Err("pak UTF-16 FString is not NUL terminated".into());
        }
        String::from_utf16(&bytes[..bytes.len() - 2].chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect::<Vec<_>>())
            .map_err(|_| "invalid UTF-16 path in pak index".into())
    }
}

fn read_index(data: &[u8], footer: &PakFooter) -> Result<(String, Vec<PakEntry>), String> {
    let mut reader = Cursor::new(data);
    let mount_point = reader.string()?;
    let count = usize::try_from(reader.u32()?).map_err(|_| "pak entry count too large")?;
    if count > MAX_ENTRIES || count > data.len() / 35 {
        return Err(format!("implausible pak entry count: {count}"));
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let path = reader.string()?;
        if path.is_empty() || path.starts_with('/') || path.starts_with('\\') ||
            path.replace('\\', "/").split('/').any(|part| part == "..") {
            return Err(format!("unsafe pak index entry path: {path:?}"));
        }
        let offset = reader.u64()?;
        let compressed_size = reader.u64()?;
        let uncompressed_size = reader.u64()?;
        let compression_method = reader.u32()?;
        if footer.version == 1 { reader.take(8)?; } // retired timestamp
        let mut content_hash = [0u8; 20];
        content_hash.copy_from_slice(reader.take(20)?);
        if footer.version >= 3 {
            if compression_method != 0 {
                let blocks = usize::try_from(reader.u32()?).map_err(|_| "block count too large")?;
                let block_bytes = blocks.checked_mul(16).ok_or("compression block count overflow")?;
                reader.take(block_bytes)?;
            }
        }
        let (encrypted, compression_block_size) = if footer.version >= 3 {
            (reader.u8()? & 1 != 0, reader.u32()?)
        } else { (false, 0) };
        if offset > footer.index_offset ||
            offset.checked_add(compressed_size).is_none_or(|end| end > footer.index_offset) {
            return Err(format!("pak entry {path:?} has invalid source data range"));
        }
        entries.push(PakEntry {
            path, offset, compressed_size, uncompressed_size,
            compression_method, content_hash, encrypted, compression_block_size,
        });
    }
    if reader.pos != data.len() {
        let trailing = &data[reader.pos..];
        // The authenticated UE4 encrypted index can carry up to 15 bytes
        // of alignment padding that are not necessarily zero. SHA-1 over the
        // complete decrypted buffer was already matched to the source footer.
        if !footer.encrypted_index || trailing.len() >= 16 {
            return Err(format!("pak index contains {} unexplained trailing bytes",
                trailing.len()));
        }
    }
    Ok((mount_point, entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Write, sync::atomic::{AtomicU64, Ordering}};
    static FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn fake_pak(version: u32, encrypted: bool) -> (std::path::PathBuf, Vec<u8>) {
        let mut index = Vec::new();
        index.extend_from_slice(&5i32.to_le_bytes());
        index.extend_from_slice(b"Test\0");
        index.extend_from_slice(&1u32.to_le_bytes());
        index.extend_from_slice(&11i32.to_le_bytes());
        index.extend_from_slice(b"Level.umap\0"); // ten bytes including NUL
        index.extend_from_slice(&0u64.to_le_bytes()); // start of data
        index.extend_from_slice(&0u64.to_le_bytes());
        index.extend_from_slice(&0u64.to_le_bytes());
        index.extend_from_slice(&0u32.to_le_bytes());
        if version == 1 { index.extend_from_slice(&0u64.to_le_bytes()); }
        index.extend_from_slice(&[0u8; 20]);
        if version >= 3 {
            index.push(0);
            index.extend_from_slice(&0u32.to_le_bytes());
        }
        let hash = Sha1::digest(&index);
        let mut bytes = vec![0x42; 64]; // data region before index
        bytes.extend_from_slice(&index);
        let mut footer = Vec::new();
        if version >= 7 { footer.extend_from_slice(&[0; 16]); }
        if version >= 4 { footer.push(u8::from(encrypted)); }
        footer.extend_from_slice(&MAGIC.to_le_bytes());
        footer.extend_from_slice(&version.to_le_bytes());
        footer.extend_from_slice(&64u64.to_le_bytes());
        footer.extend_from_slice(&(index.len() as u64).to_le_bytes());
        footer.extend_from_slice(&hash);
        if version >= 8 { footer.extend_from_slice(&[0; 160]); }
        bytes.extend_from_slice(&footer);
        let path = std::env::temp_dir().join(format!(
            "fortnite_test_{}_{}_{}_{}.pak",
            std::process::id(), version, encrypted,
            FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)));
        fs::File::create(&path).unwrap().write_all(&bytes).unwrap();
        (path, bytes)
    }

    #[test]
    fn inspects_unencrypted_index_and_one_map() {
        let (path, _) = fake_pak(5, false);
        let result = inspect(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(result.footer.version, 5);
        match result.status {
            IndexStatus::Indexed { entries, .. } => assert_eq!(entries[0].path, "Level.umap"),
            other => panic!("expected index: {other:?}"),
        }
    }

    #[test]
    fn encrypted_index_is_reported_not_guessed() {
        let (path, _) = fake_pak(5, true);
        let result = inspect(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(result.status, IndexStatus::Encrypted);
    }

    #[test]
    fn version_seven_guid_precedes_magic() {
        let (path, _) = fake_pak(7, false);
        let report = inspect(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(report.footer.version, 7);
        assert!(report.footer.encryption_key_guid.is_some());
        assert!(matches!(report.status, IndexStatus::Indexed { .. }));
    }

    #[test]
    fn version_five_relative_offset_footer() {
        let (path, _) = fake_pak(5, false);
        let report = inspect(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(report.footer.version, 5);
        assert_eq!(report.footer.index_offset, 64);
        assert_eq!(report.footer.index_size, 81);
    }

    #[test]
    fn unsupported_newer_index_is_not_misparsed() {
        let (path, _) = fake_pak(8, false);
        let report = inspect(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(report.status, IndexStatus::UnsupportedVersion(8));
    }


    #[test]
    fn oldest_supported_pak_index_and_timestamp() {
        let (path, _) = fake_pak(1, false);
        let report = inspect(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(report.footer.version, 1);
        assert!(matches!(report.status, IndexStatus::Indexed { .. }));
    }

    #[test]
    fn version_four_index_encryption_flag() {
        let (path, _) = fake_pak(4, false);
        let report = inspect(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(report.footer.version, 4);
        assert!(matches!(report.status, IndexStatus::Indexed { .. }));
    }

    #[test]
    fn compressed_record_consumes_all_block_metadata() {
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&5i32.to_le_bytes());
        bytes.extend_from_slice(b"Test\0");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        let path = b"Maps/Alpha.umap\0";
        bytes.extend_from_slice(&(path.len() as i32).to_le_bytes());
        bytes.extend_from_slice(path);
        bytes.extend_from_slice(&16u64.to_le_bytes());
        bytes.extend_from_slice(&64u64.to_le_bytes());
        bytes.extend_from_slice(&128u64.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 20]);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        for (start, end) in [(0u64, 32u64), (32, 64)] {
            bytes.extend_from_slice(&start.to_le_bytes());
            bytes.extend_from_slice(&end.to_le_bytes());
        }
        bytes.push(1);
        bytes.extend_from_slice(&64u32.to_le_bytes());
        let footer = PakFooter {
            version: 5,
            index_offset: 1024,
            index_size: bytes.len() as u64,
            index_hash: [0; 20],
            encrypted_index: false,
            encryption_key_guid: None,
        };
        let (mount, entries) = read_index(&bytes, &footer).unwrap();
        assert_eq!(mount, "Test");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "Maps/Alpha.umap");
        assert_eq!(entries[0].compression_method, 1);
        assert_eq!(entries[0].compression_block_size, 64);
        assert!(entries[0].encrypted);
    }

    #[test]
    fn traversal_and_absolute_paths_rejected() {
        for path in ["../Outside.umap", "/Absolute.umap", "dir/../escape.umap"] {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&5i32.to_le_bytes());
            bytes.extend_from_slice(b"Test\0");
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&((path.len() + 1) as i32).to_le_bytes());
            bytes.extend_from_slice(path.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&[0; 24 + 4 + 20 + 1 + 4]);
            let footer = PakFooter {
                version: 5, index_offset: 1024, index_size: bytes.len() as u64,
                index_hash: [0; 20], encrypted_index: false, encryption_key_guid: None,
            };
            assert!(read_index(&bytes, &footer).unwrap_err().contains("unsafe"));
        }
    }

    #[test]
    fn malformed_utf16_length_fails_closed() {
        let bytes = i32::MIN.to_le_bytes();
        let mut input = Cursor::new(&bytes);
        assert!(input.string().is_err());
    }

    #[test]
    fn overlarge_entry_count_does_not_allocate() {
        let mut index = Vec::new();
        index.extend_from_slice(&0i32.to_le_bytes());
        index.extend_from_slice(&u32::MAX.to_le_bytes());
        let footer = PakFooter {
            version: 5, index_offset: 1024, index_size: index.len() as u64,
            index_hash: [0; 20], encrypted_index: false, encryption_key_guid: None,
        };
        assert!(read_index(&index, &footer).unwrap_err().contains("entry count"));
    }

    #[test]
    fn corrupt_index_is_rejected() {
        let (path, mut bytes) = fake_pak(5, false);
        bytes[66] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(inspect(&path).unwrap_err().contains("SHA-1 mismatch"));
        fs::remove_file(&path).unwrap();
    }
}
