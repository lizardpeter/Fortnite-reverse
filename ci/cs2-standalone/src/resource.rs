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
