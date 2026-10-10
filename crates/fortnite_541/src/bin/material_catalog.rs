//! Inspect exact source-authored Fortnite 5.41 material package dependency
//! graphs without generating a substitute shader or synthesizing source nodes.
use std::{env,fs,path::PathBuf,process::ExitCode};
use fortnite_541_importer::{material,properties,uobject};

fn inspect_source(root:&PathBuf,name:&str)->Result<(),String>{
    let base=root.join("FortniteGame/Content/Athena/Environments/Landscape/Material").join(name);
    let h=fs::read(base.with_extension("uasset"))
        .map_err(|e|format!("read source material {name}.uasset: {e}"))?;
    let exp=fs::read(base.with_extension("uexp"))
        .map_err(|e|format!("read source material {name}.uexp: {e}"))?;
    let catalog=uobject::inspect(&h)?;
    println!("MATERIAL_PACKAGE {name} uasset_bytes={} uexp_bytes={} names={} imports={} exports={}",
        h.len(),exp.len(),catalog.names.len(),catalog.imports.len(),catalog.exports.len());
    for (i,entry) in catalog.exports.iter().enumerate(){
        let class=catalog.export_class_name(entry).unwrap_or("<unresolved>");
        let name_text=catalog.names.get(entry.object_name.name_index as usize)
            .map_or("<unknown>",String::as_str);
        let source_path=catalog.source_object_path(i as i32+1)?;
        let bytes=catalog.export_data(&h,&exp,entry)?;
        let tagged=match properties::scan(&catalog,bytes){
            Ok(p)=>{
                let labels=p.fields.iter().take(32)
                    .map(|f|format!("{}:{}[{}]",f.name,f.kind,f.payload.len()))
                    .collect::<Vec<_>>();
                format!("properties={} tagged_bytes={} first={labels:?} trailing={}",
                    p.fields.len(),p.bytes_consumed,bytes.len()-p.bytes_consumed)
            },
            Err(e)=>format!("unproven tag stream: {e}"),
        };
        println!("MATERIAL_EXPORT name={name} export={} source_path={source_path:?} class={class} object={name_text} serial_bytes={} {tagged}",
            i+1,bytes.len());
    }
    if name=="M_Athena_Terrain_Master" {
        let graph=material::inspect(&catalog,&h,&exp);
        let links=graph.expressions.iter().map(|n|n.expression_inputs.len()).sum::<usize>();
        let refs=graph.expressions.iter().map(|n|n.references.len()).sum::<usize>();
        println!("SOURCE_MATERIAL_GRAPH nodes={} by_class={:?} expr_input_links={} typed_refs={} unique_external_dependencies={} unresolved={:?}",
            graph.expressions.len(),graph.class_counts,links,refs,
            graph.external_dependencies.len(),graph.unresolved.iter().take(24).collect::<Vec<_>>());
        for node in graph.expressions.iter().filter(|node|
            node.class_name=="MaterialExpressionLandscapeLayerSample" ||
            node.class_name=="MaterialExpressionMaterialFunctionCall" ||
            node.class_name=="MaterialExpressionTextureSample"
        ).take(16) {
            println!("SOURCE_MATERIAL_NODE class={} export={} obj={} parameters={:?} refs={:?} input_edges={:?} tagged_properties={:?}",
                node.class_name,node.export_index,node.object_name,node.parameters,node.references,
                node.expression_inputs,node.properties);
        }
    }
    for (i,entry) in catalog.imports.iter().enumerate().take(50){
        let path=catalog.source_object_path(-1-(i as i32))?;
        println!("MATERIAL_IMPORT name={name} import={} class={:?} path={path:?}",i+1,
            catalog.names.get(entry.class_name.name_index as usize));
    }
    Ok(())
}
fn run()->Result<(),String>{
    let path=env::args_os().nth(1).map(PathBuf::from)
        .ok_or("usage: material_catalog PATH_TO_ATHENA_SOURCE_ROOT")?;
    for name in ["M_Athena_Terrain_01","M_Athena_Terrain_Master",
        "M_Athena_Terrain_01_NoAridRock","M_Athena_Terrain_01_Masked"]{
        inspect_source(&path,name)?;
    }
    Ok(())
}
fn main()->ExitCode{
    match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{
        eprintln!("Fortnite material source proof failed: {e}");ExitCode::FAILURE
    }}
}
