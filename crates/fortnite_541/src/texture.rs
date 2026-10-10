//! Fortnite 5.41 / UE4.21 cooked UTexture2D external first-mip decoding.
//!
//! Retail landscape textures are 128x128 PF_B8G8R8A8. Their highest-resolution
//! mip is stored in the package's original .ubulk, not the smaller inline mips
//! at the end of .uexp. A signed serialized FPak bulk offset is relative to
//! the end of the logically concatenated .umap + .uexp minus four bytes.
//! Bounds, pixel format, byte count, mip dimensions and source object class
//! must be authenticated before any samples become terrain geometry.
use crate::{properties, uobject::{PackageCatalog, PackageExport}};
const MAX_MIP_BYTES: usize = 64*1024*1024;

#[derive(Debug, Clone)]
pub struct SourceTextureMip<'a> {
    pub width: u32,
    pub height: u32,
    pub format: &'static str,
    pub source_bulk_offset: usize,
    pub source_bulk_flags: u32,
    /// Exactly original source B,G,R,A bytes, without transcoding or scaling.
    pub bgra8: &'a [u8],
}
fn u32_at(bytes: &[u8], start: usize) -> Result<u32,String> {
    Ok(u32::from_le_bytes(bytes.get(start..start+4)
        .ok_or("truncated Fortnite UTexture2D mip")?.try_into().unwrap()))
}
fn i64_at(bytes: &[u8], start: usize) -> Result<i64,String> {
    Ok(i64::from_le_bytes(bytes.get(start..start+8)
        .ok_or("truncated Fortnite FByteBulkData signed offset")?.try_into().unwrap()))
}

/// Recover the source top mip. No guessed low-res replacements and no channel
/// reinterpretation: the actual raw pixels remain BGRA8.
pub fn first_mip_bgra8<'a>(
    catalog: &PackageCatalog,
    package_file: &[u8],
    companion_uexp: &[u8],
    companion_ubulk: &'a [u8],
    export: &PackageExport,
) -> Result<SourceTextureMip<'a>, String> {
    if catalog.export_class_name(export) != Some("Texture2D") {
        return Err("the source heightmap FPackageIndex does not point to Texture2D".into());
    }
    let serialized = catalog.export_data(package_file, companion_uexp, export)?;
    let props = properties::scan(catalog, serialized)?;
    let cooked = serialized.get(props.bytes_consumed..)
        .ok_or("source UTexture2D has no cooked platform data")?;

    // Source-confirmed Fortnite 5.41 UE4 cooked FTexturePlatformData layout.
    // A different source build must fail instead of silently reusing offsets.
    let width=u32_at(cooked,28)?;
    let height=u32_at(cooked,32)?;
    let depth=u32_at(cooked,36)?;
    let name_len=u32_at(cooked,40)? as usize;
    if name_len != 12 ||
        cooked.get(44..56) != Some(b"PF_B8G8R8A8\0".as_slice()) {
        return Err("source top mip is not PF_B8G8R8A8".into());
    }
    let flags=u32_at(cooked,68)?;
    let count=u32_at(cooked,72)? as usize;
    let stored=u32_at(cooked,76)? as usize;
    let signed_offset=i64_at(cooked,80)?;
    let mip_width=u32_at(cooked,88)?;
    let mip_height=u32_at(cooked,92)?;
    let mip_depth=u32_at(cooked,96)?;
    if width == 0 || height == 0 || width > 8192 || height > 8192 ||
        width != mip_width || height != mip_height ||
        depth != 1 || mip_depth != 1 {
        return Err("source texture first-mip dimensions differ from platform header".into());
    }
    let expected=(width as usize).checked_mul(height as usize)
        .and_then(|v|v.checked_mul(4)).ok_or("source mip dimensions overflow")?;
    if expected>MAX_MIP_BYTES || count!=expected || stored!=expected {
        return Err("source PF_B8G8R8A8 top mip byte count inconsistent".into());
    }
    // Fortnite 5.41 uses (bPayloadAtEndOfFile | bPayloadInSeperateFile
    // | bNoOffsetFixUp etc), observed as 0x0501. This parser is intentionally
    // version-pinned, not a general-purpose Unreal bulk-data decoder.
    if flags != 0x0501 {
        return Err(format!("unsupported source texture bulk flag pattern 0x{flags:x}"));
    }
    let package_total=package_file.len().checked_add(companion_uexp.len())
        .ok_or("UE4 source package size overflow")?;
    let bulk_offset=i64::try_from(package_total).map_err(|_| "source package too large")?
        .checked_sub(4).and_then(|x|x.checked_add(signed_offset))
        .ok_or("source relative .ubulk offset overflow")?;
    let start=usize::try_from(bulk_offset).map_err(|_| "source .ubulk offset is negative")?;
    let end=start.checked_add(expected).ok_or("source .ubulk range overflow")?;
    let bgra8=companion_ubulk.get(start..end)
        .ok_or("source first-mip bytes escape original .ubulk file")?;
    Ok(SourceTextureMip {
        width,height,format:"PF_B8G8R8A8",source_bulk_offset:start,
        source_bulk_flags:flags,bgra8,
    })
}

impl SourceTextureMip<'_> {
    /// UE4 landscape height is encoded in R(high) and G(low); B/A are the
    /// encoded tangent/normal channels, NOT extra height bits.
    pub fn height_u16(&self,x:u32,y:u32)->Result<u16,String>{
        if x>=self.width || y>=self.height {return Err("height sample outside texture".into());}
        let i=(y as usize*self.width as usize + x as usize)*4;
        let g=self.bgra8[i+1] as u16;
        let r=self.bgra8[i+2] as u16;
        Ok((r<<8)|g)
    }
    /// Original Unreal local landscape Z before Landscape actor scale:
    /// (stored 16-bit height minus 32768) / 128.
    pub fn height_local(&self,x:u32,y:u32)->Result<f32,String>{
        Ok((self.height_u16(x,y)? as f32-32768.0)/128.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn height_channels_use_bgra_red_and_green_not_blue_or_alpha() {
        let px=[0xFF,0x30,0x80,0x77];
        let mip=SourceTextureMip {
            width:1,height:1,format:"PF_B8G8R8A8",
            source_bulk_offset:0,source_bulk_flags:0x0501,bgra8:&px,
        };
        assert_eq!(mip.height_u16(0,0).unwrap(),0x8030);
        assert_eq!(mip.height_local(0,0).unwrap(),48.0/128.0);
        assert!(mip.height_u16(1,0).is_err());
    }
}
