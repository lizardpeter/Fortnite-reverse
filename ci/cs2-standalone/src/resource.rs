//! Source 2 compiled resource block table, preserving source byte offsets.
//! A block's offset is relative to its own 4-byte offset field, not to the
//! beginning of the resource or the block descriptor.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceBlock {
    pub kind: [u8; 4],
    pub offset: usize,
    pub length: usize,
}
impl ResourceBlock {
    pub fn name(&self) -> String { String::from_utf8_lossy(&self.kind).into_owned() }
}

#[derive(Clone, Debug)]
pub struct ResourceHeader {
    pub declared_file_size: u32,
    pub header_version: u16,
    pub resource_version: u16,
    pub blocks: Vec<ResourceBlock>,
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(bytes.get(at..at.checked_add(2).ok_or("offset overflow")?)
        .ok_or("truncated Source 2 u16")?.try_into().map_err(|_| "bad u16")?))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(bytes.get(at..at.checked_add(4).ok_or("offset overflow")?)
        .ok_or("truncated Source 2 u32")?.try_into().map_err(|_| "bad u32")?))
}

impl ResourceHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 16 { return Err("truncated Source 2 resource header".into()); }
        let declared_file_size = u32_at(bytes, 0)?;
        let header_version = u16_at(bytes, 4)?;
        let resource_version = u16_at(bytes, 6)?;
        let block_table_offset = u32_at(bytes, 8)? as usize;
        let count = u32_at(bytes, 12)? as usize;
        if header_version != 12 { return Err(format!("unsupported Source 2 header version {header_version}")); }
        if count > 512 { return Err(format!("too many Source 2 resource blocks: {count}")); }
        // Source 2 block table offset is relative to header word at byte 8.
        let table_start = 8usize.checked_add(block_table_offset).ok_or("block offset overflow")?;
        let table_end = table_start.checked_add(count.checked_mul(12).ok_or("block count overflow")?)
            .ok_or("block table overflow")?;
        if table_end > bytes.len() { return Err("truncated Source 2 block descriptors".into()); }
        let mut blocks = Vec::with_capacity(count);
        for i in 0..count {
            let at = table_start + i * 12;
            let kind: [u8; 4] = bytes[at..at+4].try_into().unwrap();
            let rel = u32_at(bytes, at+4)? as usize;
            let length = u32_at(bytes, at+8)? as usize;
            let offset = (at+4).checked_add(rel).ok_or("block address overflow")?;
            // The top-level declared file size may exclude appended streaming GPU
            // payloads (observed in real vtex_c), so validate against bytes read.
            if offset.checked_add(length).ok_or("block size overflow")? > bytes.len() {
                return Err(format!("Source 2 block {} extends beyond supplied bytes", String::from_utf8_lossy(&kind)));
            }
            blocks.push(ResourceBlock { kind, offset, length });
        }
        Ok(Self { declared_file_size, header_version, resource_version, blocks })
    }
    pub fn block<'a>(&self, bytes: &'a [u8], tag: &[u8;4]) -> Option<&'a [u8]> {
        let found = self.blocks.iter().find(|b| &b.kind == tag)?;
        bytes.get(found.offset..found.offset+found.length)
    }
}


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalReference {
    pub id: u64,
    pub path: String,
}

impl ResourceHeader {
    /// Decode author/compiler-selected external resource references from RERL.
    /// Each offset is relative to its own source word; IDs are retained rather
    /// than manufactured from paths or names.
    pub fn external_references(&self, bytes: &[u8]) -> Result<Vec<ExternalReference>,String> {
        let Some(block)=self.block(bytes,b"RERL") else { return Ok(Vec::new()); };
        if block.len()<8 { return Err("short Source 2 RERL header".into()); }
        let table_start=u32_at(block,0)? as usize;
        let count=u32_at(block,4)? as usize;
        if count>100_000 { return Err("too many Source 2 external references".into()); }
        let table_len=count.checked_mul(16).ok_or("RERL table size overflow")?;
        let table_end=table_start.checked_add(table_len).ok_or("RERL table offset overflow")?;
        if table_end>block.len() { return Err("truncated Source 2 external reference table".into()); }
        let mut out=Vec::with_capacity(count);
        for i in 0..count {
            let base=table_start+i*16;
            let id=u64::from_le_bytes(block[base..base+8].try_into().unwrap());
            let relative=i32::from_le_bytes(block[base+8..base+12].try_into().unwrap());
            let absolute=(base as i64+8).checked_add(relative as i64)
                .ok_or("RERL string address overflow")?;
            if absolute<0 || absolute as usize>=block.len() {
                return Err(format!("RERL reference {i} has out-of-bounds string offset"));
            }
            let tail=&block[absolute as usize..];
            let end=tail.iter().position(|b|*b==0).ok_or("unterminated RERL resource path")?;
            if end>4096 { return Err("RERL resource path exceeds size limit".into()); }
            let path=std::str::from_utf8(&tail[..end])
                .map_err(|_|"invalid UTF-8 in RERL path")?.to_owned();
            out.push(ExternalReference { id,path });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_model_style_offsets_are_relative_to_descriptor() {
        let mut buf=vec![0; 112+24];
        buf[0..4].copy_from_slice(&(136u32).to_le_bytes());
        buf[4..6].copy_from_slice(&(12u16).to_le_bytes());
        buf[6..8].copy_from_slice(&(1u16).to_le_bytes());
        buf[8..12].copy_from_slice(&(8u32).to_le_bytes());
        buf[12..16].copy_from_slice(&(1u32).to_le_bytes());
        buf[16..20].copy_from_slice(b"MDAT");
        buf[20..24].copy_from_slice(&(92u32).to_le_bytes());
        buf[24..28].copy_from_slice(&(24u32).to_le_bytes());
        assert_eq!(ResourceHeader::parse(&buf).unwrap().blocks[0].offset,112);
    }

    #[test]
    fn rerl_references_retain_original_ids_and_paths() {
        let mut bytes=vec![0u8; 100];
        bytes[4..6].copy_from_slice(&12u16.to_le_bytes());
        bytes[8..12].copy_from_slice(&8u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
        bytes[16..20].copy_from_slice(b"RERL");
        bytes[20..24].copy_from_slice(&8u32.to_le_bytes()); // block starts at 28
        bytes[24..28].copy_from_slice(&72u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&8u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
        bytes[36..44].copy_from_slice(&0x123456789abcdef0u64.to_le_bytes());
        bytes[44..48].copy_from_slice(&8i32.to_le_bytes()); // string starts at 52
        let path=b"materials/foo.vmat\0";
        bytes[52..52+path.len()].copy_from_slice(path);
        let header=ResourceHeader::parse(&bytes).unwrap();
        assert_eq!(header.external_references(&bytes).unwrap(),vec![
            ExternalReference { id:0x123456789abcdef0,path:"materials/foo.vmat".to_string() }
        ]);
    }

    #[test]
    fn reject_out_of_bounds_block() {
        let mut buf = vec![0;40];
        buf[4..6].copy_from_slice(&(12u16).to_le_bytes());
        buf[8..12].copy_from_slice(&(8u32).to_le_bytes());
        buf[12..16].copy_from_slice(&(1u32).to_le_bytes());
        buf[16..20].copy_from_slice(b"DATA");
        buf[20..24].copy_from_slice(&(100u32).to_le_bytes());
        buf[24..28].copy_from_slice(&(200u32).to_le_bytes());
        assert!(ResourceHeader::parse(&buf).is_err());
    }
}
