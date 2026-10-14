//! Source 2 compiled VTEX (resource version 1) pixel-data decoder.
//!
//! Exact VTEX metadata and mip bytes are read from the original VPK. Supports
//! author-compressed BC1/BC3/BC7, BC5 normals and raw RGBA/BGRA/R8 images.
//! No fallback noise, generated textures, or alternate game-specific shader.
use crate::resource::ResourceHeader;
use neutral_scene::NeutralTexture;
const MAX_PIXELS:usize = 4096 * 4096;
const MAX_MIPS:usize = 16;

fn u16_at(b:&[u8],at:usize)->Result<u16,String> {
    Ok(u16::from_le_bytes(b.get(at..at.checked_add(2).ok_or("VTEX u16 overflow")?)
       .ok_or("truncated VTEX u16")?.try_into().unwrap()))
}
fn u32_at(b:&[u8],at:usize)->Result<u32,String>{
    Ok(u32::from_le_bytes(b.get(at..at.checked_add(4).ok_or("VTEX u32 overflow")?)
       .ok_or("truncated VTEX u32")?.try_into().unwrap()))
}
fn mip_size(width:usize,height:usize,format:u8)->Result<usize,String>{
    let px=width.checked_mul(height).ok_or("VTEX dimensions overflow")?;
    if px>MAX_PIXELS{return Err("VTEX exceeds maximum per-level texel count".into());}
    let block_count=width.div_ceil(4).checked_mul(height.div_ceil(4))
        .ok_or("VTEX block count overflow")?;
    match format {
        1=>block_count.checked_mul(8), // DXT1 (BC1)
        2|20|21=>block_count.checked_mul(16), // DXT5, BC7, ATI2N
        4|28=>px.checked_mul(4), // RGBA8 / BGRA8
        3|33=>Some(px), // I8 / R8
        _=>return Err(format!("unsupported original Source 2 texture pixel format {format}")),
    }.ok_or("VTEX size overflow".into())
}
#[derive(Clone,Debug)]
pub struct Metadata{
    pub width:u16,pub height:u16,pub depth:u16,
    pub format:u8,pub mips:u8,pub flags:u16,pub format_version:u16,
    pub mip_compression:u32,pub mip_disk_sizes:Vec<u32>,
    pub data_offset:usize,
}
pub fn inspect(file:&[u8])->Result<Metadata,String>{
    let resource=ResourceHeader::parse(file)?;
    if resource.resource_version!=1{return Err(format!(
        "VTEX resource version {} unsupported",resource.resource_version));}
    let data=resource.blocks.iter().find(|b|&b.kind==b"DATA").ok_or("VTEX DATA block missing")?;
    let h=file.get(data.offset..data.offset+data.length).ok_or("VTEX truncated DATA")?;
    if h.len()<40 {return Err("short VTEX v1 DATA header".into());}
    let format_version=u16_at(h,0)?;
    if format_version!=1 {return Err(format!("unsupported VTEX payload version {format_version}"));}
    let width=u16_at(h,20)?;
    let height=u16_at(h,22)?;
    let depth=u16_at(h,24)?;
    let format=h[26];let mips=h[27];let flags=u16_at(h,2)?;
    if width==0||height==0||depth==0||mips==0||mips as usize>MAX_MIPS {
        return Err("invalid VTEX dimensions, depth or mip count".into());
    }
    let mut mip_compression=0u32;
    let mut mip_disk_sizes=Vec::new();
    let extra_rel=u32_at(h,32)? as usize;
    let extra_count=u32_at(h,36)? as usize;
    if extra_count>1024 {return Err("VTEX has too many extra metadata blocks".into());}
    if extra_count>0{
        let entries_base=40usize.checked_add(extra_rel).ok_or("VTEX metadata overflow")?;
        for i in 0..extra_count{
            let at=entries_base.checked_add(i.checked_mul(12).ok_or("VTEX descriptor overflow")?)
                .ok_or("VTEX descriptor overflow")?;
            let kind=u32_at(h,at)?;
            let size=u32_at(h,at+8)? as usize;
            let rel=u32_at(h,at+4)? as usize;
            // VRF: offset word (entry+4) is resource-relative; its value
            // is stored with an 8-byte header/metadata correction.
            let start=(at+4).checked_add(rel).ok_or("VTEX metadata offset overflow")?;
            let block=h.get(start..start.checked_add(size).ok_or("VTEX extra data size overflow")?)
                .ok_or("VTEX extra data out of bounds")?;
            if kind==4 {
                if block.len()<12{return Err("short VTEX compressed mip table".into());}
                mip_compression=u32_at(block,0)?;
                let table_start=4usize.checked_add(u32_at(block,4)? as usize)
                    .ok_or("VTEX mip table offset overflow")?;
                let count=u32_at(block,8)? as usize;
                if count!=mips as usize{return Err("VTEX compressed mip count mismatch".into());}
                for i in 0..count{
                    let at=table_start.checked_add(i.checked_mul(4).ok_or("VTEX mip size overflow")?)
                        .ok_or("VTEX mip size overflow")?;
                    mip_disk_sizes.push(u32_at(block,at)?);
                }
            }
        }
    }
    let data_offset=data.offset.checked_add(data.length).ok_or("VTEX pixel start overflow")?;
    Ok(Metadata{width,height,depth,format,mips,flags,format_version,
        mip_compression,mip_disk_sizes,data_offset})
}
fn decode_blocks(data:&[u8],width:usize,height:usize,format:u8)->Result<Vec<u8>,String>{
    let out_size=width.checked_mul(height).and_then(|x|x.checked_mul(4))
        .ok_or("VTEX output size overflow")?;
    let mut rgba=vec![0u8;out_size];
    let bpb=if format==1{8}else{16};
    for by in 0..height.div_ceil(4){
        for bx in 0..width.div_ceil(4){
            let block_idx=by*width.div_ceil(4)+bx;
            let off=block_idx.checked_mul(bpb).ok_or("VTEX block index overflow")?;
            let chunk=data.get(off..off+bpb).ok_or("VTEX truncated BCn block")?;
            let mut pixels=[0u8;64];
            match format{
                1=>bcdec_rs::bc1(chunk,&mut pixels,16),
                2=>bcdec_rs::bc3(chunk,&mut pixels,16),
                20=>bcdec_rs::bc7(chunk,&mut pixels,16),
                21=>{
                    let mut channels=[0u8;32];
                    bcdec_rs::bc5(chunk,&mut channels,8,false);
                    for i in 0..16 {
                        let x=channels[i*2] as f32/255.*2.-1.;
                        let y=channels[i*2+1] as f32/255.*2.-1.;
                        let z=(1.-x*x-y*y).max(0.).sqrt();
                        pixels[i*4]=(x*0.5+0.5).mul_add(255.,0.) as u8;
                        pixels[i*4+1]=(y*0.5+0.5).mul_add(255.,0.) as u8;
                        pixels[i*4+2]=(z*0.5+0.5).mul_add(255.,0.) as u8;
                        pixels[i*4+3]=255;
                    }
                },
                _=>return Err("unsupported VTEX block format".into())
            }
            for y in 0..4 {
                let py=by*4+y;if py>=height{continue;}
                for x in 0..4 {
                    let px=bx*4+x;if px>=width{continue;}
                    let src=(y*4+x)*4;let dst=(py*width+px)*4;
                    rgba[dst..dst+4].copy_from_slice(&pixels[src..src+4]);
                }
            }
        }
    }
    Ok(rgba)
}
fn decode_raw(data:&[u8],width:usize,height:usize,format:u8)->Result<Vec<u8>,String>{
    let mut rgba=vec![0u8;width*height*4];
    match format {
        4=>rgba.copy_from_slice(data),
        28=>{
            for (src,dst) in data.chunks_exact(4).zip(rgba.chunks_exact_mut(4)){
                dst.copy_from_slice(&[src[2],src[1],src[0],src[3]]);
            }
        },
        3|33=>{
            for (&src,dst) in data.iter().zip(rgba.chunks_exact_mut(4)){
                dst.copy_from_slice(&[src,src,src,255]);
            }
        },
        _=>return Err("unsupported uncompressed VTEX format".into())
    }
    Ok(rgba)
}
pub fn decode(file:&[u8],name:&str)->Result<NeutralTexture,String>{
    let h=inspect(file)?;
    if h.depth!=1{return Err("Source 2 cubemap/array/volume VTEX not admitted as 2D".into());}
    let mut pos=h.data_offset;
    for level in (1..h.mips as usize).rev(){
        let w=(h.width as usize>>level).max(1);
        let he=(h.height as usize>>level).max(1);
        let exact=mip_size(w,he,h.format)?;
        let compressed=h.mip_disk_sizes.get(level).copied().map(|x|x as usize).unwrap_or(exact);
        let skip=if compressed<exact{compressed}else{exact};
        pos=pos.checked_add(skip).ok_or("VTEX lower mip skip overflow")?;
    }
    let width=h.width as usize;let height=h.height as usize;
    let exact=mip_size(width,height,h.format)?;
    let stored=h.mip_disk_sizes.first().copied().map(|x|x as usize).unwrap_or(exact);
    let take=if stored<exact {stored}else{exact};
    let mip=file.get(pos..pos.checked_add(take).ok_or("VTEX largest mip overflow")?)
        .ok_or("VTEX largest mip not in source file")?;
    let bytes=if take==exact{mip.to_vec()}else {
        match h.mip_compression {
            1=>lz4_flex::block::decompress(mip,exact).map_err(|e|format!("VTEX LZ4 decompression failed: {e}"))?,
            2=>zstd::bulk::decompress(mip,exact).map_err(|e|format!("VTEX zstd decompression failed: {e}"))?,
            other=>return Err(format!("VTEX compressed mip code {other} unsupported"))
        }
    };
    if bytes.len()!=exact {return Err("VTEX largest mip decode extent mismatch".into());}
    let rgba=match h.format{
        1|2|20|21=>decode_blocks(&bytes,width,height,h.format)?,
        4|28|3|33=>decode_raw(&bytes,width,height,h.format)?,
        other=>return Err(format!("VTEX pixel type {other} not supported")),
    };
    Ok(NeutralTexture{
        name:name.to_owned(),width:width as u32,height:height as u32,rgba,
        mips:Vec::new(),compressed:None,
    })
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn bc1_constant_block_is_opaque(){
        let bytes=[0xff,0xff,0xff,0xff,0,0,0,0];
        let img=decode_blocks(&bytes,4,4,1).unwrap();
        assert_eq!(img.len(),64);assert!(img.chunks_exact(4).all(|x|x[3]==255));
    }
    #[test]
    fn malformed_payload_is_rejected(){
        assert!(inspect(&[0u8;16]).is_err());
        assert!(decode_blocks(&[],4,4,20).is_err());
    }
}