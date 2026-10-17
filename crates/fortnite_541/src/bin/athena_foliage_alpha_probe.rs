//! Authenticated original 5.41 grass Texture2D source-alpha census.
//! Alpha in the original BC1/BC3/BGRA mip is evidence of available pixel
//! coverage, NOT proof that the authored UE material uses it as OpacityMask.
//! No copied pixels or source asset bytes are written to public artifacts.
use std::{env,fs,path::PathBuf,process::ExitCode};
use fortnite_541_importer::{texture::{self,OriginalBcFormat},uobject};

const TEXTURES:&[&str]=&[
    "Environments/Foliage/Textures/T_FieldGrass_01_M",
    "Environments/Foliage/Textures/T_SwirlNoise_N",
    "Environments/Foliage/Textures/T_WavyGrass_01",
    "Environments/Foliage/Textures/T_WavyGrass_01_N",
    "Packages/DS_Fortnite_Terrain_NoLOD/Textures/T_Grasslands_D",
];

#[derive(Debug,Default,PartialEq,Eq)]
struct Coverage{
    total:u64,zero:u64,partial:u64,full:u64,
    // This is a hypothetical 1/3 alpha clip census, not a statement
    // that the authored material samples the alpha channel at all.
    below_ue_default_clip:u64,
}
impl Coverage{
    fn push(&mut self,a:u8){
        self.total+=1;
        if a==0{self.zero+=1;}
        else if a==255{self.full+=1;}
        else{self.partial+=1;}
        if a<85{self.below_ue_default_clip+=1;}
    }
}
fn bc3_alpha(block:&[u8],pixel:usize)->Result<u8,String>{
    if block.len()!=16||pixel>=16{return Err("BC3 alpha block or pixel invalid".into());}
    let a0=block[0] as u16;
    let a1=block[1] as u16;
    let mut table=[0u8;8];
    table[0]=a0 as u8;
    table[1]=a1 as u8;
    if a0>a1{
        for i in 1..=6 {
            table[i+1]=(((7-i) as u16*a0+i as u16*a1)/7) as u8;
        }
    }else{
        for i in 1..=4{
            table[i+1]=(((5-i) as u16*a0+i as u16*a1)/5) as u8;
        }
        table[6]=0;
        table[7]=255;
    }
    let mut indices=0u64;
    for i in 0..6 {indices|=(block[2+i] as u64)<<(8*i);}
    Ok(table[((indices>>(3*pixel))&7) as usize])
}
fn bc1_alpha(block:&[u8],pixel:usize)->Result<u8,String>{
    if block.len()!=8||pixel>=16{return Err("BC1 alpha block or pixel invalid".into());}
    let c0=u16::from_le_bytes([block[0],block[1]]);
    let c1=u16::from_le_bytes([block[2],block[3]]);
    let index=u32::from_le_bytes(block[4..8].try_into().unwrap());
    let select=(index>>(2*pixel))&3;
    Ok(if c0<=c1&&select==3 {0}else{255})
}
fn bc_coverage(blocks:&[u8],width:u32,height:u32,format:OriginalBcFormat)
    ->Result<Coverage,String>{
    if width==0||height==0||width>8192||height>8192 {
        return Err("source alpha census dimensions invalid".into());
    }
    let block_stride=match format{OriginalBcFormat::Bc1=>8,OriginalBcFormat::Bc3=>16};
    let bx=width.div_ceil(4) as usize;
    let by=height.div_ceil(4) as usize;
    let expected=bx.checked_mul(by).and_then(|n|n.checked_mul(block_stride))
        .ok_or("source BC alpha census byte count overflow")?;
    if blocks.len()!=expected {return Err("source BC alpha blocks wrong length".into());}
    let mut count=Coverage::default();
    for yb in 0..by{for xb in 0..bx{
        let offset=(yb*bx+xb)*block_stride;
        let block=&blocks[offset..offset+block_stride];
        for y in 0..4usize{for x in 0..4usize{
            if xb*4+x>=width as usize||yb*4+y>=height as usize{continue;}
            let a=match format{
                OriginalBcFormat::Bc1=>bc1_alpha(block,y*4+x)?,
                OriginalBcFormat::Bc3=>bc3_alpha(block,y*4+x)?,
            };
            count.push(a);
        }}
    }}
    Ok(count)
}
fn bgra_coverage(bytes:&[u8],width:u32,height:u32)->Result<Coverage,String>{
    let expected=(width as usize).checked_mul(height as usize)
        .and_then(|n|n.checked_mul(4)).ok_or("source BGRA mip extent overflow")?;
    if bytes.len()!=expected{return Err("source BGRA alpha mip length invalid".into());}
    let mut result=Coverage::default();
    for pixel in bytes.chunks_exact(4){result.push(pixel[3]);}
    Ok(result)
}
fn probe(root:&PathBuf,name:&str)->Result<(),String>{
    let base=root.join("FortniteGame/Content").join(name);
    let header=fs::read(base.with_extension("uasset"))
        .map_err(|e|format!("{name}: original UAsset missing: {e}"))?;
    let exports=fs::read(base.with_extension("uexp"))
        .map_err(|e|format!("{name}: original UExp missing: {e}"))?;
    let bulk=fs::read(base.with_extension("ubulk"))
        .map_err(|e|format!("{name}: original external mip missing: {e}"))?;
    let catalog=uobject::inspect(&header)?;
    let candidates=catalog.exports.iter()
        .filter(|e|catalog.export_class_name(e)==Some("Texture2D"))
        .collect::<Vec<_>>();
    if candidates.len()!=1{
        return Err(format!("{name}: expected exactly one original Texture2D, got {}",candidates.len()));
    }
    let entry=candidates[0];
    let (format,width,height,platform,first_mip,coverage)=match texture::first_mip_bc(
        &catalog,&header,&exports,&bulk,entry
    ){
        Ok(mip)=>(
            format!("{:?}",mip.format),mip.width,mip.height,
            [mip.platform_width,mip.platform_height],mip.first_resident_mip,
            bc_coverage(mip.blocks,mip.width,mip.height,mip.format)?
        ),
        Err(bc_reason)=>match texture::first_mip_bgra8(
            &catalog,&header,&exports,&bulk,entry
        ){
            Ok(mip)=>(
                "PF_B8G8R8A8".into(),mip.width,mip.height,
                [mip.width,mip.height],0,
                bgra_coverage(mip.bgra8,mip.width,mip.height)?
            ),
            Err(rgb_reason)=>{
                // The neutral original asset decoder supports more formats
                // (BC5 normals, G8, inline bulk). Do NOT relabel those as
                // opaque and do not invent alpha texels from format names.
                println!("AUTHORED_FOLIAGE_ALPHA_UNRESOLVED source={name} bc={bc_reason:?} bgra={rgb_reason:?}");
                return Ok(());
            },
        }
    };
    println!("AUTHORED_FOLIAGE_ORIGINAL_ALPHA_CENSUS source={name} format={format} resident={}x{} platform={}x{} original_first_resident_mip={} alpha_zero={} alpha_partial={} alpha_full={} source_alpha_below_default_one_third={} total={} alpha_is_not_proven_OpacityMask=true",
        width,height,platform[0],platform[1],first_mip,
        coverage.zero,coverage.partial,coverage.full,
        coverage.below_ue_default_clip,coverage.total);
    Ok(())
}
fn run()->Result<(),String>{
    let root=PathBuf::from(env::args_os().nth(1)
        .ok_or("usage: athena_foliage_alpha_probe VERIFIED_SOURCE_ROOT")?);
    for source in TEXTURES{probe(&root,source)?;}
    Ok(())
}
fn main()->ExitCode{
    match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{
        eprintln!("AUTHORED_FOLIAGE_ALPHA_PROBE_FAILED: {e}");ExitCode::FAILURE
    }}
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn bc1_three_color_mode_has_transparent_index_three(){
        // c0==c1 uses 3 colors + alpha; all fourth palette entries opaque.
        let mut block=[0u8;8];
        block[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        let c=bc_coverage(&block,4,4,OriginalBcFormat::Bc1).unwrap();
        assert_eq!(c.zero,16);
        block[0..2].copy_from_slice(&0xffffu16.to_le_bytes());
        let c=bc_coverage(&block,4,4,OriginalBcFormat::Bc1).unwrap();
        assert_eq!(c.full,16);
    }
    #[test]fn bc3_alpha_seven_and_five_step_tables_are_distinct(){
        let mut block=[0u8;16];
        block[0]=255;block[1]=0;
        // Index 2 uses 6/7*255 + 1/7*0.
        block[2]=2;
        assert_eq!(bc3_alpha(&block,0).unwrap(),(6*255/7) as u8);
        block[0]=0;block[1]=255;block[2]=6;
        assert_eq!(bc3_alpha(&block,0).unwrap(),0);
        block[2]=7;
        assert_eq!(bc3_alpha(&block,0).unwrap(),255);
    }
    #[test]fn cropped_bc_tile_does_not_count_padded_texels(){
        let block=[0u8;8];
        let c=bc_coverage(&block,1,3,OriginalBcFormat::Bc1).unwrap();
        assert_eq!(c.total,3);
        assert_eq!(c.full,3);
        assert!(bc_coverage(&block[..7],1,3,OriginalBcFormat::Bc1).is_err());
    }
    #[test]fn bgra_uses_alpha_byte_only_not_height_or_blue(){
        let c=bgra_coverage(&[255,7,0,0,0,255,2,255],2,1).unwrap();
        assert_eq!(c.zero,1);
        assert_eq!(c.full,1);
        assert_eq!(c.below_ue_default_clip,1);
    }
}
