//! Source-only material/function and texture format discovery, sourced from
//! the verified master-material direct dependencies. Not a shader emulator.
use std::{collections::{BTreeMap,BTreeSet},env,fs,path::{Path,PathBuf},process::ExitCode};
use fortnite_541_importer::{material,properties,uobject,texture};
const DIRECT:&[&str]=&[
    "Athena/Environments/Landscape/MPC/MPC_Landscape",
    "Athena/Environments/Landscape/MaterialFunctions/Arid/MF_Athena_Arid_Rock",
    "Athena/Environments/Landscape/MaterialFunctions/Arid/MF_Athena_Arid_Rock_02",
    "Athena/Environments/Landscape/MaterialFunctions/Arid/MF_Athena_Arid_Sand",
    "Athena/Environments/Landscape/MaterialFunctions/MF_Athena_Material_BaseMultiply",
    "Athena/Environments/Landscape/MaterialFunctions/MF_Athena_ReplaceBaseColor",
    "Athena/Environments/Landscape/MaterialFunctions/MF_Athena_SedimentGradient",
    "Athena/Environments/Landscape/MaterialFunctions/MF_Athena_WorldHeightGrad",
    "Athena/Environments/Landscape/MaterialFunctions/MF_Athena_ZSandColor",
    "Athena/Environments/Landscape/MaterialFunctions/MF_FarmGrass_Colors",
    "Athena/Environments/Landscape/MaterialFunctions/MF_Landscape_GrassDistanceBlend",
    "Athena/Environments/Landscape/MaterialFunctions/MF_LawnGrassColoration",
    "Athena/Environments/Landscape/MaterialFunctions/MF_MountainGrass_Colors",
    "Athena/Environments/Landscape/MaterialFunctions/MF_TerrainDistanceFade",
    "Athena/Environments/Landscape/MaterialFunctions/MF_TerrainTopoAdjustment",
    "Athena/Environments/Landscape/MaterialFunctions/Standard/MF_Athena_Crater_01",
    "Athena/Environments/Landscape/MaterialFunctions/Standard/MF_Athena_Forest_01",
    "Athena/Environments/Landscape/MaterialFunctions/Standard/MF_Athena_Grass_01",
    "Athena/Environments/Landscape/MaterialFunctions/Standard/MF_Athena_Gravel_01",
    "Athena/Environments/Landscape/MaterialFunctions/Standard/MF_Athena_Mud_01",
    "Athena/Environments/Landscape/MaterialFunctions/Standard/MF_Athena_Road_01",
    "Athena/Environments/Landscape/MaterialFunctions/Standard/MF_Athena_Rock_01",
    "Athena/Environments/Landscape/Textures/T_Athena_Terrain_CombinedColors_01",
    "Athena/Environments/Landscape/Textures/T_Athena_Terrain_Topo_Mask",
];
fn inspect(base:&Path,graph_sum:&mut usize,types:&mut BTreeMap<String,usize>,dep:&mut BTreeSet<String>)->Result<(),String>{
    let uasset=fs::read(base.with_extension("uasset")).map_err(|e|format!("{}: {e}",base.display()))?;
    let uexp=fs::read(base.with_extension("uexp")).map_err(|e|format!("{}: {e}",base.display()))?;
    let cat=uobject::inspect(&uasset)?;
    let graph=material::inspect(&cat,&uasset,&uexp);
    if !graph.unresolved.is_empty(){println!("ATHENA_FN_UNSUPPORTED path={} unresolved={:?}",base.display(),graph.unresolved);}
    *graph_sum+=graph.expressions.len();
    for (class,count) in &graph.class_counts{*types.entry(class.to_owned()).or_default()+=count;}
    dep.extend(graph.external_dependencies.iter().cloned());
    println!("ATHENA_MATERIAL_PACKAGE path={} objects={} function_nodes={} classes={:?} external={:?} unresolved_count={}",
        base.display(),cat.exports.len(),graph.expressions.len(),graph.class_counts,
        graph.external_dependencies,graph.unresolved.len());
    for (idx,export) in cat.exports.iter().enumerate(){
        let class=cat.export_class_name(export).unwrap_or("<unknown>");
        if class!="Texture2D"{continue;}
        let data=cat.export_data(&uasset,&uexp,export)?;
        let tagged=properties::scan(&cat,data)?;
        let cooked=&data[tagged.bytes_consumed..];
        let fmt=String::from_utf8_lossy(cooked);
        let mut format_hits=Vec::new();
        for token in ["PF_B8G8R8A8","PF_DXT1","PF_DXT5","PF_BC4","PF_BC5","PF_BC6H","PF_BC7","PF_G8","PF_FloatRGBA","PF_A8","PF_R8G8B8A8"] {
            if fmt.contains(token){format_hits.push(token);}
        }
        let bulk=base.with_extension("ubulk");
        if let Ok(source_bulk)=fs::read(&bulk){
            println!("ATHENA_TEXTURE_BULK package={} source_bytes={} initial={:02x?}",
                base.display(),source_bulk.len(),&source_bulk[..source_bulk.len().min(32)]);
            let mip=texture::first_mip_bc(&cat,&uasset,&uexp,&source_bulk,export)?;
            if mip.width!=2048||mip.height!=2048||mip.source_bulk_offset!=0{
                return Err(format!("source original BC mip dimensions/bulk offset changed: {mip:?}"));
            }
            println!("ATHENA_SOURCE_BC_MIP_VERIFIED package={} format={:?} {}x{} source_blocks={} source_offset={} first_bytes={:02x?}",
                base.display(),mip.format,mip.width,mip.height,
                mip.blocks.len(),mip.source_bulk_offset,&mip.blocks[..16]);
        }
        // Inspect the source FByteBulkData header fingerprints, not guessed
        // mip positions. A full original format decoder must prove sizes.
        for off in 0..cooked.len().saturating_sub(32) {
            if u32::from_le_bytes(cooked[off..off+4].try_into().unwrap())!=0x501{continue;}
            let stored=u32::from_le_bytes(cooked[off+4..off+8].try_into().unwrap());
            let count=u32::from_le_bytes(cooked[off+8..off+12].try_into().unwrap());
            let offset=i64::from_le_bytes(cooked[off+12..off+20].try_into().unwrap());
            let w=u32::from_le_bytes(cooked[off+20..off+24].try_into().unwrap());
            let h=u32::from_le_bytes(cooked[off+24..off+28].try_into().unwrap());
            let d=u32::from_le_bytes(cooked[off+28..off+32].try_into().unwrap());
            if w<=8192&&h<=8192&&w>0&&h>0&&d<=8 {
                println!("ATHENA_ORIGINAL_MIP package={} cooked_offset={off} stored={stored} count={count} signed_bulk_offset={offset} mip_width={w} mip_height={h} mip_depth={d}",
                    base.display());
            }
        }
        println!("ATHENA_SOURCE_TEXTURE_HEADER package={} export={} tagged_properties={:?} first_cooked_bytes={:02x?} format_hits={format_hits:?} cooked_bytes={} has_ubulk={}",
            base.display(),idx+1,tagged.fields.iter().map(|p|(p.name.clone(),p.kind.clone())).collect::<Vec<_>>(),
            &cooked[..cooked.len().min(112)],cooked.len(),base.with_extension("ubulk").is_file());
    }
    Ok(())
}
fn run()->Result<(),String>{
    let root=PathBuf::from(env::args_os().nth(1).ok_or("usage: athena_texture_format_probe ORIGINAL_SOURCE_ROOT")?);
    let mut total_nodes=0;let mut classes=BTreeMap::new();let mut dep=BTreeSet::new();
    for sub in DIRECT {
        inspect(&root.join("FortniteGame/Content").join(sub),&mut total_nodes,&mut classes,&mut dep)?;
    }
    println!("ATHENA_MATERIAL_FUNCTION_CLOSURE direct_packages={} total_expression_nodes={} unique_node_classes={} external_objects={} class_census={classes:?}",
        DIRECT.len(),total_nodes,classes.len(),dep.len());
    for d in dep {println!("ATHENA_MATERIAL_TRANSITIVE_OBJECT {d}");}
    Ok(())
}
fn main()->ExitCode{match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("ATHENA_TEX_FORMAT_PROBE_FAILED: {e}");ExitCode::FAILURE}}}
