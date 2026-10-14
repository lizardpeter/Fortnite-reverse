//! Source-only material and texture audit on original Workshop + base game VPKs.
//! Prints exact base archive numbers for missing source materials and their
//! original VTEX paths. Decodes genuine texture mip pixels in memory.
use cs2_importer::{material::{SourcePacks},vpk::VpkArchive,texture};
use std::{collections::{BTreeMap,BTreeSet},env,path::PathBuf,process::ExitCode};
fn run()->Result<(),String>{
    let workshop=PathBuf::from(env::args_os().nth(1).ok_or("expected Workshop _dir.vpk")?);
    let base=PathBuf::from(env::args_os().nth(2).ok_or("expected CS2 game pak01_dir.vpk")?);
    let outer=VpkArchive::open_directory(&workshop)?;
    let cs2=VpkArchive::open_directory(&base)?;
    for sample in [
        "materials/de_dust/hr_dust/hr_dust_decal_mudbrick_wear_01_color_psd_4a3a0ad0.vtex_c",
        "materials/de_dust/hr_dust/hr_dust_decal_road_striping_color_psd_3c1a7134.vtex_c",
    ]{
        if let Ok(bytes)=cs2.read_entry(sample){
            let resource=cs2_importer::resource::ResourceHeader::parse(&bytes)?;
            if let Some(data)=resource.blocks.iter().find(|b|&b.kind==b"DATA"){
                let h=bytes.get(data.offset..data.offset+data.length).unwrap_or(&[]);
                println!("CS2 VTEX RAW SOURCE {sample} resource_size={} data_offset={} data_bytes={} header_100={}",
                    bytes.len(),data.offset,data.length,
                    h.iter().take(100).map(|b|format!("{b:02x}")).collect::<Vec<_>>().join(" "));
                println!("CS2 VTEX DECODE INSPECT {:?}",cs2_importer::texture::inspect(&bytes));
            }
        }
    }

    for mat_name in ["materials/skybox/sky_de_dust2vmat.vmat_c","materials/skybox/sky_csgo_cloudy01.vmat_c"] {
        if let Ok(bytes)=cs2.read_entry(mat_name){
            match cs2_importer::material::material_bytes(&bytes,mat_name){
                Ok(mat)=>println!("CS2 SKY MATERIAL {} shader={} exact textures={:?} parameters={:?}",mat_name,mat.shader,mat.textures,mat.scalars),
                Err(e)=>println!("CS2 SKY MATERIAL NOT PARSED {}: {e}",mat_name),
            }
        }
    }
    let mut sample_texture_count=0;
    for path in outer.entries().keys().filter(|p|p.ends_with(".vtex_c")).take(30){
        match outer.read_entry(path).and_then(|b|texture::decode(&b,path)){
            Ok(tex)=>{
                sample_texture_count+=1;
                println!("CS2_TEXTURE_DECODE_OK {path}: {}x{} {} RGBA bytes",
                    tex.width,tex.height,tex.rgba.len());
            },
            Err(e)=>println!("CS2_TEXTURE_DECODE_UNSUPPORTED {path}: {e}"),
        }
    }
    if sample_texture_count==0 {
        return Err("no original Workshop VTEX pixel payload decoded".into());
    }
    for map in ["maps/de_dust2_christmas.vpk","maps/de_dust2_winter.vpk"]{
        let nested=outer.open_nested(map)?;
        let package=SourcePacks{workshop_outer:&outer,workshop_map:&nested,base_game:Some(&cs2)};
        let scenes=cs2_importer::scene::import_workshop_preview(&workshop,map)?;
        let names=BTreeSet::<String>::from_iter(scenes.materials.iter().map(|m|m.name.clone()));
        let coverage=package.audit(names.iter().map(String::as_str));
        let mut required=BTreeMap::<u16,usize>::new();
        let mut textures=BTreeMap::<String,u16>::new();
        for name in &names{
            let path=format!("{name}_c");
            if let Some(entry)=cs2.entries().get(&path){
                *required.entry(entry.archive_index).or_default()+=1;
                if let Ok(mat)=package.describe(name){
                    for texture_path in mat.textures.values(){
                        let target=if texture_path.ends_with("_c"){texture_path.clone()}else{format!("{texture_path}_c")};
                        if let Some(e)=cs2.entries().get(&target){
                            textures.insert(target,e.archive_index);
                        }
                    }
                }
            }
        }
        let mut texture_parts=BTreeMap::<u16,usize>::new();
        for archive in textures.values(){*texture_parts.entry(*archive).or_default()+=1;}
        println!("CS2_REAL_BASE_COVERAGE map={map} referenced={} material_decoded={} texture_paths={} resolved_texture_slots={} material_archive_indices={:?} texture_archive_indices={:?}",
            coverage.referenced,coverage.material_resolved,coverage.authored_texture_slots,
            coverage.texture_resolved,required,texture_parts);
        for mat in names.iter().filter_map(|n|package.describe(n).ok()).take(12){
            println!("CS2_REAL_VMATS path={} shader={} textures={:?} scalar_keys={:?}",
                mat.path,mat.shader,mat.textures,mat.scalars.keys().collect::<Vec<_>>());
        }
    }
    Ok(())
}
fn main()->ExitCode{match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("CS2 VTEX AUDIT ERROR {e}");ExitCode::FAILURE}}}
