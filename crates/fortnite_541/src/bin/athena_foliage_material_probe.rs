//! Bounded, source-authenticated audit of original 5.41 Athena foliage source
//! material and mesh packages. No runtime shader or fabricated alpha masks.
use std::{collections::{BTreeMap,BTreeSet},env,fs,path::PathBuf,process::ExitCode};
use fortnite_541_importer::{material,properties,uobject};

const ROOTS:&[&str]=&[
    "Athena/Environments/Landscape/Foliage/MI_Athena_Grass_TopoColor",
    "Environments/Foliage/Materials/M_FieldGrassMatching",
    "Athena/Environments/Landscape/Foliage/Athena_SM_WavyGrass_TopologyColor",
    "Environments/Foliage/Meshes/S_WavyGrass_01",
    "Athena/Environments/Landscape/Foliage/M_Athena_Grass_Master",
    "Environments/Foliage/Textures/T_FieldGrass_01_M",
    "Environments/Foliage/Textures/T_SwirlNoise_N",
    "Environments/Foliage/Textures/T_WavyGrass_01",
    "Environments/Foliage/Textures/T_WavyGrass_01_N",
    "Packages/DS_Fortnite_Terrain_NoLOD/Textures/T_Grasslands_D",
];

fn inspect(root:&PathBuf,relative:&str)->Result<(),String>{
    let base=root.join("FortniteGame/Content").join(relative);
    let header=fs::read(base.with_extension("uasset"))
        .map_err(|e|format!("original foliage uasset {relative}: {e}"))?;
    let exports=fs::read(base.with_extension("uexp"))
        .map_err(|e|format!("original foliage uexp {relative}: {e}"))?;
    let cat=uobject::inspect(&header)?;
    let graph=material::inspect(&cat,&header,&exports);
    let mut classes=BTreeMap::<String,usize>::new();
    let mut inherited_materials=BTreeSet::<String>::new();
    let mut authored_surface_roots=BTreeSet::<String>::new();
    let mut source_textures=BTreeSet::<String>::new();
    let mut source_functions=BTreeSet::<String>::new();
    let mut roots=0usize;
    for (idx,entry) in cat.exports.iter().enumerate(){
        let class=cat.export_class_name(entry).unwrap_or("<unresolved>");
        *classes.entry(class.to_owned()).or_default()+=1;
        if !matches!(class,"Material"|"MaterialInstanceConstant"){continue;}
        roots+=1;
        let raw=cat.export_data(&header,&exports,entry)?;
        let properties=properties::scan(&cat,raw)
            .map_err(|e|format!("{relative} source material export {}: {e}",idx+1))?;
        for p in &properties.fields {
            let bytes=&raw[p.payload.clone()];
            if p.name=="Parent" &&p.kind=="ObjectProperty"&&bytes.len()==4 {
                let refid=i32::from_le_bytes(bytes.try_into().unwrap());
                let value=cat.source_object_path(refid)?;
                inherited_materials.insert(value.clone());
                println!("AUTHORED_FOLIAGE_MATERIAL_PARENT path={relative} parent={value}");
            }
            if matches!(p.name.as_str(),
                    "BlendMode"|"ShadingModel"|"TwoSided"|"OpacityMask"|
                    "OpacityMaskClipValue"|"WorldPositionOffset"|"BaseColor") {
                authored_surface_roots.insert(p.name.clone());
                let semantic=match (p.kind.as_str(),bytes.len()) {
                    ("FloatProperty",4)=>format!("source_f32={}",f32::from_le_bytes(bytes.try_into().unwrap())),
                    ("StructProperty",40)=>{
                        let reference=i32::from_le_bytes(bytes[0..4].try_into().unwrap());
                        format!("source_expression_ref={reference} identity={:?}",
                            cat.source_object_path(reference))
                    },
                    ("ByteProperty",8)|("NameProperty",8)=>{
                        let n=u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
                        format!("source_fname={:?}",cat.names.get(n))
                    },
                    _=>format!("serialized_bytes={}",bytes.len()),
                };
                println!("AUTHORED_FOLIAGE_SURFACE_ROOT path={relative} class={class} name={} kind={} metadata={:?} {semantic}",
                    p.name,p.kind,p.metadata);
            }
        }
    }
    for node in &graph.expressions {
        if node.class_name=="MaterialExpressionMaterialFunctionCall" {
            for link in &node.references {
                if link.property=="MaterialFunction"{
                    source_functions.insert(link.source_path.clone());
                }
            }
        }
        if node.class_name=="MaterialExpressionTextureSample"
            ||node.class_name=="MaterialExpressionTextureSampleParameter2D" {
            for link in &node.references {
                if link.property=="Texture"{
                    source_textures.insert(link.source_path.clone());
                }
            }
        }
    }
    println!("AUTHORED_FOLIAGE_SOURCE_CENSUS path={relative} exports={} material_roots={roots} expression_nodes={} classes={classes:?} tagged_surface_fields={authored_surface_roots:?} inherited_parents={inherited_materials:?} original_texture_refs={source_textures:?} original_material_functions={source_functions:?} external_graph_dependencies={} parser_frontiers={}",
        cat.exports.len(),graph.expressions.len(),graph.external_dependencies.len(),
        graph.unresolved.len());
    for error in graph.unresolved.iter().take(15){
        println!("AUTHORED_FOLIAGE_GRAPH_PARSER_FRONTIER source={relative} issue={error}");
    }
    Ok(())
}
fn run()->Result<(),String>{
    let root=PathBuf::from(env::args_os().nth(1)
        .ok_or("usage: athena_foliage_material_probe VERIFIED_RETAIL_SOURCE_ROOT")?);
    for source in ROOTS{inspect(&root,source)?;}
    println!("AUTHORED_FOLIAGE_SOURCE_PROBE_COMPLETE source_packages={}",ROOTS.len());
    Ok(())
}
fn main()->ExitCode{
    match run(){
        Ok(())=>ExitCode::SUCCESS,
        Err(e)=>{eprintln!("AUTHORED_FOLIAGE_SOURCE_PROBE_FAILED: {e}");ExitCode::FAILURE}
    }
}
