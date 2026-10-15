//! Exact Source 2 2D-array BCn GPU payload transport.
//!
//! Source 2 v8.2 baked light uses *three distinct*, genuinely compiled VTEX
//! images: BC6H floating-point HDR irradiance, BC1 directional irradiance,
//! and BC4 primary/direct-light shadowing. The normal NeutralTexture RGBA8
//! bridge cannot preserve signed/HDR values or the authored three-channel
//! sampler contract. Never reinterpret these as generic RGBM lightmaps.
//!
//! This loader decodes only the outer Source 2 VTEX stream compression (raw
//! LZ4 or Zstd), then preserves each original block-compressed texel byte
//! exactly. The renderer should upload these bytes into matching native
//! Vulkan BC6H_UFLOAT_BLOCK, BC1_RGBA_UNORM_BLOCK and BC4_UNORM_BLOCK
//! image arrays and feed an exact universal shader translation. A typed GPU
//! upload manifest is NOT equivalent to completed lightmap shading.
use crate::texture::{self, Metadata};

#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub enum SourceNativeGpuBlockFormat{
    Bc1Unorm,
    Bc6hUnsignedFloat,
    Bc4Unorm,
}
impl SourceNativeGpuBlockFormat{
    pub fn source2_format_code(self)->u8{
        match self {Self::Bc1Unorm=>1,Self::Bc6hUnsignedFloat=>19,Self::Bc4Unorm=>27}
    }
    pub fn block_bytes(self)->usize{
        match self{Self::Bc6hUnsignedFloat=>16,_=>8}
    }
    pub fn vulkan_format_name(self)->&'static str{
        match self{
            Self::Bc1Unorm=>"VK_FORMAT_BC1_RGBA_UNORM_BLOCK",
            Self::Bc6hUnsignedFloat=>"VK_FORMAT_BC6H_UFLOAT_BLOCK",
            Self::Bc4Unorm=>"VK_FORMAT_BC4_UNORM_BLOCK",
        }
    }
    pub fn exact_level_bytes(self,width:u32,height:u32,layers:u16)->Option<usize>{
        (width.div_ceil(4) as usize).checked_mul(height.div_ceil(4) as usize)?
            .checked_mul(self.block_bytes())?.checked_mul(layers as usize)
    }
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct SourceNativeVtexMip{
    pub width:u32,pub height:u32,
    /// Original contiguous Source2 layer-major GPU compressed blocks.
    pub bytes:Vec<u8>,
    pub bytes_per_layer:usize,
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct SourceNativeVtexArray{
    pub name:String,
    pub width:u32,pub height:u32,pub layers:u16,
    pub format:SourceNativeGpuBlockFormat,
    /// Authored mip level order: 0 is full resolution.
    pub mips:Vec<SourceNativeVtexMip>,
}
impl SourceNativeVtexArray {
    pub fn original_gpu_bytes(&self)->usize{
        self.mips.iter().map(|m|m.bytes.len()).sum()
    }
    pub fn validate(&self)->Result<(),String>{
        if self.layers==0 || self.mips.is_empty() || self.mips.len()>16 {
            return Err("invalid original source VTEX native mip/layer layout".into());
        }
        for (index,mip) in self.mips.iter().enumerate(){
            let width=(self.width>>index).max(1);
            let height=(self.height>>index).max(1);
            let expected=self.format.exact_level_bytes(width,height,self.layers)
                .ok_or("source-native VTEX GPU block extent overflow")?;
            if mip.width!=width || mip.height!=height ||
               mip.bytes.len()!=expected || mip.bytes_per_layer!=expected/self.layers as usize {
                return Err(format!("source native VTEX level {index} does not match authored BCn layout"));
            }
        }
        Ok(())
    }
}
fn native_format(meta:&Metadata)->Result<SourceNativeGpuBlockFormat,String>{
    match meta.format{
        1=>Ok(SourceNativeGpuBlockFormat::Bc1Unorm),
        19=>Ok(SourceNativeGpuBlockFormat::Bc6hUnsignedFloat),
        27=>Ok(SourceNativeGpuBlockFormat::Bc4Unorm),
        other=>Err(format!(
            "original Source 2 baked VTEX uses unsupported native GPU block format {other}"
        )),
    }
}
/// Decompress *outer* Source2 VTEX mip framing, never the BCn texels. The
/// encoded bytes stay unmodified and retain actual HDR and shadow payloads.
pub fn decode_source_native_vtex_array(
    file:&[u8],name:&str
)->Result<SourceNativeVtexArray,String>{
    let meta=texture::inspect(file)?;
    if meta.flags & (texture::SOURCE_CUBE_FLAG|texture::SOURCE_VOLUME_FLAG)!=0 {
        return Err("Source2 baked image is a cube/3D texture, not a 2D array".into());
    }
    if meta.depth>1 && meta.flags&texture::SOURCE_ARRAY_FLAG==0 {
        return Err("Source2 VTEX multiple layers without TEXTURE_ARRAY flag".into());
    }
    if meta.depth==0 || meta.depth>256 {
        return Err("Source2 original 2D array layer count unsupported".into());
    }
    let format=native_format(&meta)?;
    let mut cursor=meta.data_offset;
    let mut levels=vec![None::<SourceNativeVtexMip>;meta.mips as usize];
    // Original VTEX streaming mips are physically smallest-to-largest;
    // present GPU image mips in logical level order, largest first.
    for mip in (0..meta.mips as usize).rev(){
        let w=(meta.width as u32>>mip).max(1);
        let h=(meta.height as u32>>mip).max(1);
        let exact=format.exact_level_bytes(w,h,meta.depth)
            .ok_or("Source2 native block mip size overflow")?;
        if exact>512*1024*1024 {
            return Err("Source2 native block mip exceeds bounded 512MiB".into());
        }
        let stored=meta.mip_disk_sizes.get(mip).copied()
            .map(|n|n as usize).unwrap_or(exact);
        if stored==0 || stored>exact {
            return Err("Source2 native VTEX mip stored payload size invalid".into());
        }
        let end=cursor.checked_add(stored)
            .ok_or("Source2 native VTEX offset overflow")?;
        let stored_bytes=file.get(cursor..end)
            .ok_or("Source2 original VTEX mip block truncated")?;
        cursor=end;
        let bytes=if stored==exact {
            stored_bytes.to_vec()
        } else {
            match meta.mip_compression {
                1=>crate::kv3::decode_source2_lz4_block(stored_bytes,exact)
                    .map_err(|err|format!("Source2 VTEX raw LZ4 mip {mip}: {err}"))?,
                2=>zstd::bulk::decompress(stored_bytes,exact)
                    .map_err(|err|format!("Source2 VTEX Zstd mip {mip}: {err}"))?,
                other=>return Err(format!(
                    "unsupported Source2 VTEX mip compression kind {other}"
                )),
            }
        };
        if bytes.len()!=exact{
            return Err("Source2 native VTEX decompressed extent differs from authored bytes".into());
        }
        levels[mip]=Some(SourceNativeVtexMip{
            width:w,height:h,bytes,
            bytes_per_layer:exact/meta.depth as usize,
        });
    }
    let mips=levels.into_iter()
        .map(|v|v.ok_or_else(||"Source2 native VTEX mip lost during decode".to_string()))
        .collect::<Result<Vec<_>,_>>()?;
    let array=SourceNativeVtexArray{
        name:name.to_owned(),width:meta.width as u32,
        height:meta.height as u32,layers:meta.depth,
        format,mips
    };
    array.validate()?;
    Ok(array)
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn exact_original_source_gpu_formats_are_not_generic_rgbm(){
        assert_eq!(native_format(&Metadata{
            width:4096,height:4096,depth:1,format:19,mips:1,flags:0x40,
            format_version:1,mip_compression:1,mip_disk_sizes:vec![],
            data_offset:0,
        }).unwrap(),SourceNativeGpuBlockFormat::Bc6hUnsignedFloat);
        assert_eq!(SourceNativeGpuBlockFormat::Bc6hUnsignedFloat
            .vulkan_format_name(),"VK_FORMAT_BC6H_UFLOAT_BLOCK");
        assert_eq!(SourceNativeGpuBlockFormat::Bc1Unorm
            .exact_level_bytes(4096,4096,1),Some(8_388_608));
        assert_eq!(SourceNativeGpuBlockFormat::Bc6hUnsignedFloat
            .exact_level_bytes(4096,4096,1),Some(16_777_216));
        assert_eq!(SourceNativeGpuBlockFormat::Bc4Unorm
            .exact_level_bytes(4096,4096,1),Some(8_388_608));
    }
    #[test]
    fn original_bc6h_hdr_payload_is_not_reencoded_as_rgba8(){
        let content=SourceNativeVtexArray{
            name:"g_tIrradiance".into(),width:4,height:4,layers:1,
            format:SourceNativeGpuBlockFormat::Bc6hUnsignedFloat,
            mips:vec![SourceNativeVtexMip{
                width:4,height:4,
                bytes:vec![0x81;16],bytes_per_layer:16
            }]
        };
        content.validate().unwrap();
        assert_eq!(content.mips[0].bytes,[0x81;16]);
        assert_eq!(content.original_gpu_bytes(),16);
        let mut invalid=content.clone();
        invalid.mips[0].bytes.pop();
        assert!(invalid.validate().is_err());
    }
}
