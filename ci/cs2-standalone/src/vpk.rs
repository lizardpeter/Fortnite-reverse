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
    /// Non-cached, compiled Source 2 base resources extracted from original
    /// anonymous Steam archives. Files retain their exact original bytes.
    /// A compact overlay is placed beside the Workshop _dir.vpk, under
    /// cs2-base-resources/materials/...; it never replaces the Workshop VPK.
    fn overlay_path(&self,name:&str)->Result<PathBuf,String>{
        if !safe_path(name) || !(
            name.ends_with(".vmat_c") ||
            name.ends_with(".vtex_c") ||
            (name.starts_with("shaders/vfx/") && name.ends_with(".vcs"))
        ) {
            return Err(format!("unsafe or unsupported original source overlay path {name}"));
        }
        let parent=self.segment.path.parent().ok_or("Workshop has no base directory")?;
        Ok(parent.join("cs2-base-resources").join(name))
    }
    pub fn overlay_available(&self,name:&str)->bool{
        self.archive_prefix.is_some() &&
            self.overlay_path(name).ok().is_some_and(|p|p.is_file())
    }
    pub fn read_overlay(&self,name:&str)->Result<Vec<u8>,String>{
        if self.archive_prefix.is_none() {
            return Err("nested map VPK has no external source asset overlay".into());
        }
        let path=self.overlay_path(name)?;
        let len=std::fs::metadata(&path).map_err(|e|format!("Source 2 overlay {}: {e}",path.display()))?.len();
        if len==0 || len>MAX_READ_BYTES as u64 {
            return Err(format!("invalid original source overlay size {len} for {name}"));
        }
        std::fs::read(&path).map_err(|e|format!("read compiled original resource {}: {e}",path.display()))
    }
    /// Enumerate only genuine loose, original compiled shader stages placed
    /// in the authenticated compact Source 2 overlay beside the Workshop VPK.
    /// Never recurse or follow symlinks; only Source 2 shader files are valid.
    pub fn overlay_vcs_paths(&self)->Vec<String>{
        let Some((parent,_))=self.archive_prefix.as_ref() else{return Vec::new()};
        let directory=parent.join("cs2-base-resources/shaders/vfx");
        let Ok(read_dir)=std::fs::read_dir(directory) else{return Vec::new()};
        let mut paths=Vec::new();
        for entry in read_dir.flatten(){
            if !entry.file_type().is_ok_and(|kind|kind.is_file()){continue;}
            let name=entry.file_name();
            let Some(name)=name.to_str() else{continue};
            let path=format!("shaders/vfx/{name}");
            if path.ends_with(".vcs") && safe_path(&path) {
                paths.push(path);
            }
        }
        paths.sort();
        paths.dedup();
        // A compact corpus cannot cause unbounded map-admission enumeration.
        paths.truncate(8192);
        paths
    }
    /// Read only VCS header / Resource-KV3 compiler metadata; never load the
    /// enormous appended native pixel-shader binary into RAM just to inspect
    /// names, ABI hashes, and static-combination definitions. A Source 2
    /// Resource header declares its metadata length independently of the
    /// potentially hundreds of MiB of trailing GPU bytecode.
    pub fn read_overlay_vcs_metadata(&self,name:&str,limit:usize)->Result<Vec<u8>,String>{
        if !(name.starts_with("shaders/vfx/") && name.ends_with(".vcs")) {
            return Err("only source VCS overlay stage metadata is supported".into());
        }
        let path=self.overlay_path(name)?;
        let length=std::fs::metadata(&path)
            .map_err(|e|format!("VCS overlay metadata {}: {e}",path.display()))?.len();
        if length<16{return Err("truncated original VCS overlay stage".into());}
        let mut source=File::open(&path)
            .map_err(|e|format!("open original VCS {}: {e}",path.display()))?;
        let mut prefix=[0u8;16];
        source.read_exact(&mut prefix)
            .map_err(|e|format!("read VCS Resource prefix: {e}"))?;
        let requested=if &prefix[0..4]==b"vcs2" {
            // Legacy VCS2 is not a Source 2 resource with declared file size.
            // Preserve full metadata only within a bounded reader budget.
            if length>limit as u64 {
                return Err("legacy VCS source exceeds metadata-only read limit".into());
            }
            length as usize
        }else{
            if le16(&prefix,4)?!=12 {
                return Err("unsupported original VCS Resource header version".into());
            }
            le32(&prefix,0)? as usize
        };
        if requested<16 || requested>limit || requested as u64>length {
            return Err(format!(
                "invalid VCS metadata extent {requested} for source {length} bytes"
            ));
        }
        source.seek(SeekFrom::Start(0))
            .map_err(|e|format!("seek VCS metadata: {e}"))?;
        let mut bytes=vec![0u8;requested];
        source.read_exact(&mut bytes)
            .map_err(|e|format!("read VCS compiler metadata: {e}"))?;
        Ok(bytes)
    }
    /// True only if a source entry's referenced physical archive is present
    /// and includes its exact byte range, not merely listed in pak01_dir.vpk.
    /// Supports intentional partial anonymous depot downloads.
    pub fn available(&self,path:&str)->bool{
        let Some(entry)=self.entries.get(path) else {return false};
        let Ok((segment,offset))=self.locate(entry) else{return false};
        offset.checked_add(entry.length as u64).is_some_and(|end|end<=segment.length)
    }

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
    fn compact_original_compiled_assets_are_read_beside_workshop(){
        let path=temp_fixture(&fixture(b"workshop-data",false));
        let root=path.parent().unwrap().join("cs2-base-resources").join("materials").join("overlay-test");
        std::fs::create_dir_all(&root).unwrap();
        let original=root.join("test.vtex_c");
        std::fs::write(&original,b"original-compiled-source-bytes").unwrap();
        let archive=VpkArchive::open_directory(&path).unwrap();
        assert!(archive.overlay_available("materials/overlay-test/test.vtex_c"));
        assert_eq!(archive.read_overlay("materials/overlay-test/test.vtex_c").unwrap(),
            b"original-compiled-source-bytes");
        assert!(archive.read_overlay("../unsafe.vtex_c").is_err());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(&original).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn authentic_shader_overlay_is_enumerated_without_loading_appended_bytecode(){
        let stamp=std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir=std::env::temp_dir()
            .join(format!("cs2-compact-vcs-{}-{stamp}",std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let index=dir.join("original_dir.vpk");
        std::fs::write(&index,fixture(b"workshop",false)).unwrap();
        let compiled=dir.join("cs2-base-resources/shaders/vfx/csgo_complex_vulkan_50_ps.vcs");
        std::fs::create_dir_all(compiled.parent().unwrap()).unwrap();
        let mut original=vec![0u8;4*1024*1024];
        original[0..4].copy_from_slice(&64u32.to_le_bytes());
        original[4..6].copy_from_slice(&12u16.to_le_bytes());
        original[6..8].copy_from_slice(&72u16.to_le_bytes());
        std::fs::write(&compiled,&original).unwrap();
        let archive=VpkArchive::open_directory(&index).unwrap();
        assert_eq!(archive.overlay_vcs_paths(),vec![
            "shaders/vfx/csgo_complex_vulkan_50_ps.vcs".to_string()]);
        assert!(archive.overlay_available("shaders/vfx/csgo_complex_vulkan_50_ps.vcs"));
        assert_eq!(archive.read_overlay_vcs_metadata(
            "shaders/vfx/csgo_complex_vulkan_50_ps.vcs",32*1024*1024
        ).unwrap().len(),64);
        assert!(archive.read_overlay_vcs_metadata(
            "../csgo_complex_vulkan_50_ps.vcs",32*1024*1024
        ).is_err());
        assert!(archive.overlay_vcs_paths().iter().all(|p|p.ends_with(".vcs")));
        std::fs::remove_dir_all(dir).unwrap();
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
