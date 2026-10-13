//! Bounded Valve VPK v1/v2 directory reader with nested, single-file map VPKs.
//! Source content remains on disk; a 340 MB compiled map is not copied merely
//! to open its ~50 KB index. All offsets come from original VPK entries.

use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

const MAGIC: u32 = 0x55aa1234;
const DIR_ARCHIVE: u16 = 0x7fff;
const MAX_TREE_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 2_000_000;
const MAX_STRING: usize = 4096;
const MAX_READ_BYTES: usize = 512 * 1024 * 1024;

#[derive(Clone, Debug)]
struct Segment {
    path: PathBuf,
    start: u64,
    length: u64,
}

impl Segment {
    fn file(path: &Path) -> Result<Self, String> {
        let len = std::fs::metadata(path)
            .map_err(|e| format!("VPK file {}: {e}", path.display()))?.len();
        Ok(Self { path: path.to_owned(), start: 0, length: len })
    }
    fn slice(&self, start: u64, length: u64) -> Result<Self, String> {
        let end = start.checked_add(length).ok_or("VPK slice overflow")?;
        if end > self.length { return Err("VPK segment exceeds its enclosing source".into()); }
        Ok(Self { path: self.path.clone(), start: self.start + start, length })
    }
    fn read(&self, start: u64, count: usize) -> Result<Vec<u8>, String> {
        let end = start.checked_add(count as u64).ok_or("VPK range overflow")?;
        if end > self.length { return Err(format!(
            "VPK range {}..{} is beyond source {} bytes", start, end, self.length
        )); }
        if count > MAX_READ_BYTES { return Err(format!("VPK read larger than {MAX_READ_BYTES} bytes")); }
        let absolute = self.start.checked_add(start).ok_or("VPK absolute offset overflow")?;
        let mut file = File::open(&self.path)
            .map_err(|e| format!("open VPK data {}: {e}", self.path.display()))?;
        file.seek(SeekFrom::Start(absolute))
            .map_err(|e| format!("seek VPK {}: {e}", self.path.display()))?;
        let mut out = vec![0; count];
        file.read_exact(&mut out).map_err(|e| format!("read VPK {}: {e}", self.path.display()))?;
        Ok(out)
    }
}

fn le16(bytes: &[u8], pos: usize) -> Result<u16, String> {
    let b=bytes.get(pos..pos.checked_add(2).ok_or("u16 overflow")?).ok_or("truncated VPK u16")?;
    Ok(u16::from_le_bytes([b[0],b[1]]))
}
fn le32(bytes: &[u8], pos: usize) -> Result<u32, String> {
    let b=bytes.get(pos..pos.checked_add(4).ok_or("u32 overflow")?).ok_or("truncated VPK u32")?;
    Ok(u32::from_le_bytes([b[0],b[1],b[2],b[3]]))
}
fn cstring<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a str, String> {
    if *pos >= bytes.len() { return Err("VPK directory string exceeds tree".into()); }
    let data=&bytes[*pos..];
    let end=data.iter().take(MAX_STRING+1).position(|b| *b==0).ok_or("unterminated/oversized VPK path component")?;
    let str_value=std::str::from_utf8(&data[..end]).map_err(|_| "invalid UTF-8 in VPK directory")?;
    *pos += end + 1;
    Ok(str_value)
}
fn safe_path(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('/') && !s.contains('\\') && !s.contains(':') &&
        s.split('/').all(|p| !p.is_empty() && p!="." && p!="..")
}

#[derive(Clone, Debug)]
pub struct VpkEntry {
    pub crc32: u32,
    pub preload: Vec<u8>,
    pub archive_index: u16,
    pub offset: u32,
    pub length: u32,
}

#[derive(Clone, Debug)]
pub struct VpkArchive {
    segment: Segment,
    archive_prefix: Option<(PathBuf, String)>,
    pub version: u32,
    pub tree_bytes: u32,
    data_start: u64,
    entries: BTreeMap<String, VpkEntry>,
}

impl VpkArchive {
    /// Open a Workshop package like 3620630831_dir.vpk and find its _000,
    /// _001, ... data files in the same directory.
    pub fn open_directory(path: &Path) -> Result<Self, String> {
        let name = path.file_stem().and_then(|s| s.to_str()).ok_or("invalid VPK file name")?;
        let prefix = name.strip_suffix("_dir")
            .ok_or("expected a VPK directory file ending in _dir.vpk")?
            .to_owned();
        let parent = path.parent().unwrap_or_else(|| Path::new(".")).to_owned();
        Self::open_segment(Segment::file(path)?, Some((parent,prefix)))
    }

    /// Open a VPK contained as a file inside another VPK. A standalone nested
    /// VPK typically stores all its map data at archive index 0x7fff.
    pub fn open_nested(&self, entry_path: &str) -> Result<Self, String> {
        let entry=self.entries.get(entry_path).ok_or_else(||format!("VPK entry not found: {entry_path}"))?;
        if !entry.preload.is_empty() { return Err("nested VPK with preload is unsupported".into()); }
        let (segment,offset)=self.locate(entry)?;
        let inner=segment.slice(offset,entry.length as u64)?;
        Self::open_segment(inner,None)
    }

    fn open_segment(segment: Segment, archive_prefix: Option<(PathBuf,String)>) -> Result<Self,String> {
        if segment.length < 12 { return Err("truncated VPK header".into()); }
        let prefix=segment.read(0,segment.length.min(28) as usize)?;
        if le32(&prefix,0)? != MAGIC { return Err("invalid Valve VPK signature".into()); }
        let version=le32(&prefix,4)?;
        let header_size=match version { 1=>12usize, 2=>28usize, _=>return Err(format!("unsupported VPK version {version}")) };
        if segment.length<header_size as u64 { return Err("short VPK header".into()); }
        let tree_bytes=le32(&prefix,8)?;
        if tree_bytes as usize > MAX_TREE_BYTES { return Err("VPK tree exceeds size limit".into()); }
        let data_start=(header_size as u64).checked_add(tree_bytes as u64).ok_or("VPK tree overflow")?;
        if data_start>segment.length { return Err("truncated VPK tree".into()); }
        let tree=segment.read(header_size as u64,tree_bytes as usize)?;
        let mut entries=BTreeMap::new();
        let mut pos=0usize;
        loop {
            let ext=cstring(&tree,&mut pos)?;
            if ext.is_empty() { break; }
            if !safe_path(ext) || ext.contains('/') { return Err("unsafe VPK extension".into()); }
            loop {
                let folder=cstring(&tree,&mut pos)?;
                if folder.is_empty() { break; }
                if folder!=" " && !safe_path(folder) { return Err("unsafe VPK directory".into()); }
                loop {
                    let stem=cstring(&tree,&mut pos)?;
                    if stem.is_empty() { break; }
                    if !safe_path(stem) || stem.contains('/') { return Err("unsafe VPK filename".into()); }
                    let crc32=le32(&tree,pos)?;
                    let preload_len=le16(&tree,pos+4)? as usize;
                    let archive_index=le16(&tree,pos+6)?;
                    let offset=le32(&tree,pos+8)?;
                    let length=le32(&tree,pos+12)?;
                    if le16(&tree,pos+16)? != 0xffff { return Err("bad VPK entry sentinel".into()); }
                    pos=pos.checked_add(18).ok_or("entry metadata overflow")?;
                    let end=pos.checked_add(preload_len).ok_or("preload overflow")?;
                    let preload=tree.get(pos..end).ok_or("truncated VPK preload data")?.to_vec();
                    pos=end;
                    let name=format!("{}{}.{}",if folder==" " { "" } else { folder },if folder==" " { stem.to_owned() } else { format!("/{stem}") },ext);
                    if entries.insert(name,VpkEntry { crc32,preload,archive_index,offset,length }).is_some() {
                        return Err("duplicate path in VPK directory".into());
                    }
                    if entries.len()>MAX_ENTRIES { return Err("too many VPK entries".into()); }
                }
            }
        }
        if pos != tree.len() {
            return Err(format!("VPK tree has {} unparsed bytes",tree.len()-pos));
        }
        Ok(Self { segment, archive_prefix, version, tree_bytes, data_start, entries })
    }

    pub fn entries(&self) -> &BTreeMap<String,VpkEntry> { &self.entries }

    fn locate(&self, entry: &VpkEntry) -> Result<(Segment,u64),String> {
        if entry.archive_index==DIR_ARCHIVE {
            let offset=self.data_start.checked_add(entry.offset as u64).ok_or("inline VPK offset overflow")?;
            return Ok((self.segment.clone(),offset));
        }
        let (parent,prefix)=self.archive_prefix.as_ref()
            .ok_or_else(||format!("nested VPK unexpectedly references external archive {:03}",entry.archive_index))?;
        let archive=parent.join(format!("{prefix}_{:03}.vpk",entry.archive_index));
        Ok((Segment::file(&archive)?,entry.offset as u64))
    }

    /// Read exact author-supplied bytes. The CRC covers preload + payload.
    /// Reading the enclosing VPK or compiling engine files is not required.
    pub fn read_entry(&self, path: &str) -> Result<Vec<u8>,String> {
        let entry=self.entries.get(path).ok_or_else(||format!("VPK entry missing: {path}"))?;
        let count=entry.length as usize;
        if count.checked_add(entry.preload.len()).ok_or("VPK size overflow")?>MAX_READ_BYTES {
            return Err("VPK entry too large for in-memory decoding".into());
        }
        let (segment,offset)=self.locate(entry)?;
        let mut bytes=entry.preload.clone();
        bytes.extend_from_slice(&segment.read(offset,count)?);
        let crc=crc32fast::hash(&bytes);
        if crc!=entry.crc32 { return Err(format!("VPK CRC mismatch for {path}: {crc:08x} != {:08x}",entry.crc32)); }
        Ok(bytes)
    }

    /// Read the first few source bytes without loading a potentially enormous
    /// map, world-physics or texture payload. No CRC claim for partial reads.
    pub fn entry_prefix(&self,path:&str,limit:usize)->Result<Vec<u8>,String> {
        let entry=self.entries.get(path).ok_or_else(||format!("VPK entry missing: {path}"))?;
        let mut prefix=entry.preload[..entry.preload.len().min(limit)].to_vec();
        if prefix.len()<limit {
            let (segment,offset)=self.locate(entry)?;
            prefix.extend_from_slice(&segment.read(offset,(limit-prefix.len()).min(entry.length as usize))?);
        }
        Ok(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(text:&[u8], corrupt:bool) -> Vec<u8> {
        let mut tree=Vec::new();
        tree.extend_from_slice(b"txt\0maps\0hello\0");
        tree.extend_from_slice(&crc32fast::hash(text).to_le_bytes());
        tree.extend_from_slice(&0u16.to_le_bytes());
        tree.extend_from_slice(&DIR_ARCHIVE.to_le_bytes());
        tree.extend_from_slice(&0u32.to_le_bytes());
        tree.extend_from_slice(&(text.len() as u32).to_le_bytes());
        tree.extend_from_slice(&0xffffu16.to_le_bytes());
        tree.extend_from_slice(b"\0\0\0");
        let mut bytes=Vec::new();
        bytes.extend_from_slice(&MAGIC.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&(tree.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&[0;16]);
        bytes.extend_from_slice(&tree);
        bytes.extend_from_slice(text);
        if corrupt { *bytes.last_mut().unwrap() ^= 0x40; }
        bytes
    }
    fn temp_fixture(data:&[u8])->PathBuf{
        use std::time::{SystemTime,UNIX_EPOCH};
        let stamp=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path=std::env::temp_dir().join(format!("cs2-vpk-test-{}-{stamp}_dir.vpk",std::process::id()));
        std::fs::write(&path,data).unwrap();
        path
    }
    #[test]
    fn reads_real_vpk2_tree_shape_and_checks_crc() {
        let path=temp_fixture(&fixture(b"sample-source",false));
        let archive=VpkArchive::open_directory(&path).unwrap();
        assert_eq!(archive.version,2);
        assert_eq!(archive.entries().len(),1);
        assert_eq!(archive.read_entry("maps/hello.txt").unwrap(),b"sample-source");
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn corrupted_entry_must_not_be_admitted() {
        let path=temp_fixture(&fixture(b"sample-source",true));
        let archive=VpkArchive::open_directory(&path).unwrap();
        assert!(archive.read_entry("maps/hello.txt").unwrap_err().contains("CRC mismatch"));
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn supports_nested_map_archive_without_extracting_it() {
        let inner=fixture(b"retail-source",false);
        let mut tree=Vec::new();
        tree.extend_from_slice(b"vpk\0maps\0nested\0");
        tree.extend_from_slice(&crc32fast::hash(&inner).to_le_bytes());
        tree.extend_from_slice(&0u16.to_le_bytes());
        tree.extend_from_slice(&DIR_ARCHIVE.to_le_bytes());
        tree.extend_from_slice(&0u32.to_le_bytes());
        tree.extend_from_slice(&(inner.len() as u32).to_le_bytes());
        tree.extend_from_slice(&0xffffu16.to_le_bytes());
        tree.extend_from_slice(b"\0\0\0");
        let mut bytes=Vec::new();
        bytes.extend_from_slice(&MAGIC.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&(tree.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&[0;16]);
        bytes.extend_from_slice(&tree);
        bytes.extend_from_slice(&inner);
        let path=temp_fixture(&bytes);
        let outer=VpkArchive::open_directory(&path).unwrap();
        let nested=outer.open_nested("maps/nested.vpk").unwrap();
        assert_eq!(nested.read_entry("maps/hello.txt").unwrap(),b"retail-source");
        std::fs::remove_file(path).unwrap();
    }
}
