//! Exact original Workshop map -> base CS2 archive dependency census.
use std::{collections::{BTreeMap,BTreeSet},env,path::PathBuf,process::ExitCode};
use cs2_importer::{vpk::VpkArchive,material::{SourcePacks,material_bytes},world};
fn run()->Result<(),String>{
    let args=env::args().collect::<Vec<_>>();
    if args.len()!=4 || !matches!(args[1].as_str(),"materials"|"textures"){
        return Err("usage: cs2_inventory <materials|textures> <workshop_dir.vpk> <base_pak01_dir.vpk>".into());
    }
    let workshop=PathBuf::from(&args[2]);
    let base_path=PathBuf::from(&args[3]);
    let outer=VpkArchive::open_directory(&workshop)?;
    let base=VpkArchive::open_directory(&base_path)?;
    let mut paths=BTreeSet::new();
    let mut raw_material_paths=BTreeSet::new();
    let mut already_workshop=0usize;
    let mut missing=Vec::new();
    let mut segments=BTreeMap::<u16,(usize,u64)>::new();
    for map in ["maps/de_dust2_christmas.vpk","maps/de_dust2_winter.vpk"]{
        // Fully source decoded draw-call material references, no filename guesses.
        let nested=outer.open_nested(map)?;
        let source=world::from_archive(&outer,map)?;
        // Source world scene is compiled from real original source buffers.
        let scene=cs2_importer::scene::import_workshop_preview(&workshop,map)?;
        for mat in &scene.materials {
            let v=if mat.name.ends_with("_c"){mat.name.to_owned()}else{format!("{}_c",mat.name)};
            raw_material_paths.insert(v);
        }
        // Skybox resource referenced by original authored entity lumps.
        for lump in cs2_importer::entity::from_nested_map(&nested)? {
            for entity in lump.entities {
                if entity.classname=="env_sky" || entity.classname=="worldspawn" {
                    if let Some(sky)=entity.string("skyname"){
                        if sky.ends_with(".vmat"){raw_material_paths.insert(format!("{sky}_c"));}
                    }
                }
            }
        }
        // Source world lightmap texture paths are tracked separately.
        for lightmap in source.lighting_textures {
            if lightmap.ends_with(".vtex"){paths.insert(format!("{lightmap}_c"));}
        }
        println!("INVENTORY_MAP {map} materials={} referenced_world_lightmaps={}",scene.materials.len(),paths.len());
    }
    raw_material_paths.insert("materials/skybox/sky_de_dust2vmat.vmat_c".to_owned());
    if args[1]=="materials"{
        paths.extend(raw_material_paths.iter().cloned());
    }else{
        for path in &raw_material_paths {
            let bytes=if outer.available(path){outer.read_entry(path)}
                else if base.available(path){base.read_entry(path)}
                else{missing.push(path.to_owned());continue};
            match bytes.and_then(|b|material_bytes(&b,path)){
                Ok(mat)=>{
                    for val in mat.textures.values() {
                        if val.ends_with(".vtex"){paths.insert(format!("{val}_c"));}
                        else if val.ends_with(".vtex_c"){paths.insert(val.to_owned());}
                    }
                },
                Err(e)=>{missing.push(format!("{path} ({e})"));}
            }
        }
    }
    for path in &paths{
        let available_workshop = outer.available(path) ||
            ["maps/de_dust2_christmas.vpk","maps/de_dust2_winter.vpk"].iter().any(|map|{
                outer.open_nested(map).is_ok_and(|nested|nested.available(path))
            });
        if available_workshop {already_workshop+=1;continue;}
        if let Some(e)=base.entries().get(path){
            if e.archive_index==0x7fff {continue;}
            let segment=segments.entry(e.archive_index).or_default();
            segment.0+=1;
            segment.1+=e.length as u64;
            // Exact original VPK resource index, including its preload prefix.
            let preload_hex=e.preload.iter().map(|b|format!("{b:02x}")).collect::<String>();
            println!("ASSET_PLAN_RESOURCE|{}|{:03}|{}|{}|{}|{}|{}",
                args[1],e.archive_index,path,e.crc32,e.offset,e.length,preload_hex);
        }else{
            missing.push(path.to_owned());
        }
    }
    println!("ASSET_PLAN_START stage={} source_paths={} workshop_fulfilled={} base_segments={} unresolved={}",
        args[1],paths.len(),already_workshop,segments.len(),missing.len());
    for (idx,(count,bytes)) in &segments{
        println!("ASSET_PLAN_PART|{}|{:03}|{}|{}",args[1],idx,count,bytes);
    }
    for path in missing.iter().take(150){
        println!("ASSET_PLAN_UNRESOLVED|{}|{}",args[1],path);
    }
    println!("ASSET_PLAN_END stage={} indices_csv={}",
        args[1],segments.keys().map(|n|format!("{n:03}")).collect::<Vec<_>>().join(","));
    Ok(())
}
fn main()->ExitCode{match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("CS2 source inventory failed: {e}");ExitCode::FAILURE}}}
