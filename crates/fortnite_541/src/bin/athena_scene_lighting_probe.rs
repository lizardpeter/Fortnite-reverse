//! Probe original Fortnite 5.41 Athena map and background lighting evidence.
//! Read-only: enumerate authored light, sky, fog, atmosphere and reflection
//! component exports; do not create fallback lights or synthetic skyboxes.
use std::{collections::BTreeMap,env,fs,path::PathBuf,process::ExitCode};
use fortnite_541_importer::{properties,uobject};
fn inspect(path:&PathBuf,extension:&str)->Result<(),String>{
    let package=fs::read(path.with_extension(extension)).map_err(|e|format!("{}: {e}",path.display()))?;
    let companion=fs::read(path.with_extension("uexp")).map_err(|e|format!("{}: {e}",path.display()))?;
    let cat=uobject::inspect(&package)?;
    let mut census=BTreeMap::<String,usize>::new();
    let mut total=0usize;
    let mut selected=0usize;
    for (ordinal,ex) in cat.exports.iter().enumerate(){
        let class=cat.export_class_name(ex).unwrap_or("<unknown>");
        *census.entry(class.to_owned()).or_default()+=1;
        let name=cat.names.get(ex.object_name.name_index as usize).map(String::as_str).unwrap_or("<bad-name>");
        let category=class.to_ascii_lowercase();
        let source_path=cat.source_object_path((ordinal+1) as i32).unwrap_or_default();
        let name_lower=format!("{name} {source_path}").to_ascii_lowercase();
        let relevant=["light","sun","sky","fog","atmosphere","reflection","postprocess","cloud","weather","worldsettings",
            "exponential","colorgrading","skylight","directional","ambient","timeofday","levelstreaming","worldmanager","todm"]
            .iter().any(|k|category.contains(k)||name_lower.contains(k));
        if relevant{
            total+=1;
            if selected<100 {
                let data=cat.export_data(&package,&companion,ex)?;
                let properties=properties::scan(&cat,data);
                let lines=match properties {
                    Ok(p)=>p.fields.iter().take(70).map(|field|{
                        let bytes=&data[field.payload.clone()];
                        let decoded=if field.kind=="FloatProperty" && bytes.len()==4{
                            format!("f32={:?}",f32::from_le_bytes(bytes.try_into().unwrap()))
                        } else if field.kind=="ObjectProperty" && bytes.len()==4{
                            let refid=i32::from_le_bytes(bytes.try_into().unwrap());
                            format!("ref={refid} path={:?}",cat.source_object_path(refid))
                        } else if field.kind=="StructProperty" &&bytes.len()==12{
                            format!("f32xyz={:?}",(0..3).map(|k|f32::from_le_bytes(bytes[k*4..k*4+4].try_into().unwrap())).collect::<Vec<_>>())
                        } else if field.kind=="StructProperty" &&bytes.len()==16{
                            format!("f32xyzw={:?}",(0..4).map(|k|f32::from_le_bytes(bytes[k*4..k*4+4].try_into().unwrap())).collect::<Vec<_>>())
                        } else if field.kind=="SoftObjectProperty" && bytes.len()==12{
                            let name_id=u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
                            let n=u32::from_le_bytes(bytes[4..8].try_into().unwrap());
                            let tail=i32::from_le_bytes(bytes[8..12].try_into().unwrap());
                            format!("SoftObjectPath={:?} FName-number={n} subpath-len={tail}",cat.names.get(name_id))
                        } else if field.kind=="NameProperty" && bytes.len()==8 {
                            let name_id=u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
                            let n=u32::from_le_bytes(bytes[4..8].try_into().unwrap());
                            format!("FName={:?} instance={n}",cat.names.get(name_id))
                        } else if field.kind=="BoolProperty"{
                            format!("{:?}",field.metadata)
                        } else {
                            format!("{} bytes",bytes.len())
                        };
                        format!("{}:{}:{}:{decoded}",field.name,field.kind,field.metadata.join(","))
                    }).collect::<Vec<_>>(),
                    Err(e)=>vec![format!("unparsed-properties: {e}")]
                };
                println!("ATHENA_SOURCE_LIGHT_EXPORT package={} ordinal={} class={class} name={name} props={lines:?}",
                    path.display(),ordinal+1);
                selected+=1;
            }
        }
    }
    println!("ATHENA_SOURCE_LIGHT_SUMMARY package={} total_exports={} related={total} printed={selected} class_census={census:?}",
        path.display(),cat.exports.len());
    Ok(())
}
fn run()->Result<(),String>{
    let root=PathBuf::from(env::args_os().nth(1).ok_or("usage: athena_scene_lighting_probe ORIGINAL_SOURCE_ROOT")?);
    for path in [
        "FortniteGame/Content/Athena/Maps/Athena_Terrain",
        "FortniteGame/Content/Athena/Maps/Background/Athena_Background",
        "FortniteGame/Content/Athena/Maps/Streaming/Sublevel_X0Y0",
    ]{
        inspect(&root.join(path),"umap")?;
    }
    let timeofday=root.join("FortniteGame/Content/TimeOfDay/TODM/BR/TODM_BR");
    if timeofday.with_extension("uasset").is_file(){
        inspect(&timeofday,"uasset")?;
    }else{
        println!("ATHENA_ORIGINAL_TIMEOFDAY_PACKAGE_NOT_PRESENT: {}",timeofday.display());
    }
    let grid=root.join("FortniteGame/Content/Athena/Maps/Athena_Streaming_Grid");
    if grid.with_extension("umap").is_file(){inspect(&grid,"umap")?;}
    Ok(())
}
fn main()->ExitCode{match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("ATHENA_SCENE_LIGHTING_PROBE_FAILED: {e}");ExitCode::FAILURE}}}
