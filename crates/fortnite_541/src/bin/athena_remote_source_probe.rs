//! Inspect SHA1-authenticated original Fortnite 5.41 TimeOfDay and skybox
//! packages recovered remotely from public split PAKs. Never reconstructs
//! invented sun/sky values or draws via a game-specific renderer.
use std::{collections::BTreeMap,env,fs,path::PathBuf,process::ExitCode};
use fortnite_541_importer::{properties,texture,uobject};
const TARGETS:&[&str]=&[
    "TimeOfDay/TODM/BR/TODM_BR",
    "Environments/World/Backgrounds/Transylvania/Meshes/TRV_Skybox_Mountain_04",
    "ContentCreationTools/TextureCreation/Textures/T_BPCreated_MacroNormal_01",
    "Environments/AutumnDecay/Terrain/Textures/T_Grass_AD_D",
];
fn inspect(root:&PathBuf,path:&str)->Result<(),String>{
    let base=root.join("FortniteGame/Content").join(path);
    let uasset=fs::read(base.with_extension("uasset"))
        .map_err(|e|format!("{}: {e}",base.display()))?;
    let uexp=fs::read(base.with_extension("uexp"))
        .map_err(|e|format!("{}: {e}",base.display()))?;
    let cat=uobject::inspect(&uasset)?;
    let mut classes=BTreeMap::<String,usize>::new();
    let mut findings=0usize;
    for (ordinal,export) in cat.exports.iter().enumerate(){
        let class=cat.export_class_name(export).unwrap_or("UnresolvedClass");
        *classes.entry(class.into()).or_default()+=1;
        let name=cat.names.get(export.object_name.name_index as usize)
            .map(String::as_str).unwrap_or("<invalid>");
        let raw=cat.export_data(&uasset,&uexp,export)?;
        println!("AUTHENTICATED_FORTNITE_ASSET_EXPORT package={path} ordinal={} class={class} name={name} bytes={}",ordinal+1,raw.len());
        if matches!(class,"Texture2D") {
            let props=properties::scan(&cat,raw)?;
            let cooked=raw.get(props.bytes_consumed..).ok_or("missing cooked platform data")?;
            let mut found=Vec::new();
            for token in [b"PF_DXT1".as_slice(),b"PF_DXT5",b"PF_B8G8R8A8",b"PF_BC5"] {
                if cooked.windows(token.len()).any(|w|w==token){found.push(String::from_utf8_lossy(token).into_owned());}
            }
            println!("AUTHENTICATED_FORTNITE_TEXTURE package={path} format={found:?} source_header_bytes={:02x?} has_bulk={}",
                &cooked[..cooked.len().min(110)],base.with_extension("ubulk").is_file());
            if found.iter().any(|s|s=="PF_DXT1"||s=="PF_DXT5"){
                let bulk=fs::read(base.with_extension("ubulk")).map_err(|e|format!("original source texture external bulk: {e}"))?;
                let mip=texture::first_mip_bc(&cat,&uasset,&uexp,&bulk,export)?;
                println!("AUTHENTICATED_FORTNITE_TEXTURE_TOP_MIP package={path} fmt={:?} {}x{} bytes={} offset={}",
                    mip.format,mip.width,mip.height,mip.blocks.len(),mip.source_bulk_offset);
            }
        }
        // A source BlueprintGeneratedClass export is a compiled metadata
        // structure; the source lighting values may be in the CDO object,
        // which is inspected by its original tagged properties, never guessed.
        if !matches!(class,"BlueprintGeneratedClass"|"FortWorldSettings"|"StaticMesh"|"FortTimeOfDayManager"|"SceneComponent"|"DirectionalLightComponent"|"SkyLightComponent"|"ExponentialHeightFogComponent")
            &&!name.starts_with("Default__")
            &&!class.to_ascii_lowercase().contains("tod")
            &&!name.to_ascii_lowercase().contains("sky") {continue;}
        let props=match properties::scan(&cat,raw) {
            Ok(v)=>v,Err(e)=>{
                println!("AUTHENTICATED_FORTNITE_EXPORT_UNSUPPORTED package={path} class={class} name={name} tag_error={e}");
                continue;
            }
        };
        findings+=1;
        for field in props.fields.iter().take(130){
            let data=&raw[field.payload.clone()];
            let repr=match (field.kind.as_str(),data.len()){
                ("FloatProperty",4)=>format!("f32={}",f32::from_le_bytes(data.try_into().unwrap())),
                ("IntProperty",4)=>format!("int={}",i32::from_le_bytes(data.try_into().unwrap())),
                ("ObjectProperty",4)=>{
                    let src=i32::from_le_bytes(data.try_into().unwrap());
                    format!("ref={src} source_path={:?}",cat.source_object_path(src))
                },
                ("SoftObjectProperty",12)=> {
                    let idx=u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
                    format!("SoftPath={:?}",cat.names.get(idx))
                },
                ("NameProperty",8)=> {
                    let idx=u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
                    format!("FName={:?}",cat.names.get(idx))
                },
                ("StructProperty",12) if matches!(field.metadata.first().map(String::as_str),Some("Vector")|Some("Rotator"))=>{
                    format!("float3={:?}",(0..3).map(|k|f32::from_le_bytes(data[k*4..k*4+4].try_into().unwrap())).collect::<Vec<_>>())
                },
                ("StructProperty",16) if matches!(field.metadata.first().map(String::as_str),Some("LinearColor")|Some("Quat")|Some("Vector4"))=>{
                    format!("float4={:?}",(0..4).map(|k|f32::from_le_bytes(data[k*4..k*4+4].try_into().unwrap())).collect::<Vec<_>>())
                },
                _=>format!("payload_bytes={} prefix={:02x?}",data.len(),&data[..data.len().min(16)]),
            };
            if field.name=="LightAndFogPhaseSettings" && field.kind=="StructProperty" {
                let phase=properties::scan(&cat,data)?;
                println!("AUTHORED_FORTNITE_TODM_PHASE source_slot={} source_fields={} source_bytes={}",
                    field.array_index,phase.fields.len(),data.len());
                for p in &phase.fields {
                    let b=&data[p.payload.clone()];
                    let value=match (p.kind.as_str(),b.len()) {
                        ("FloatProperty",4)=>format!("f32={}",f32::from_le_bytes(b.try_into().unwrap())),
                        ("BoolProperty",0)=>format!("bool_tag={:?}",p.metadata),
                        ("StructProperty",16)=>format!("float4={:?}",(0..4).map(|k|
                            f32::from_le_bytes(b[k*4..k*4+4].try_into().unwrap())).collect::<Vec<_>>()),
                        ("StructProperty",12)=>format!("float3={:?}",(0..3).map(|k|
                            f32::from_le_bytes(b[k*4..k*4+4].try_into().unwrap())).collect::<Vec<_>>()),
                        ("ObjectProperty",4)=>{
                            let id=i32::from_le_bytes(b.try_into().unwrap());
                            format!("reference={:?}",cat.source_object_path(id))
                        },
                        _=>format!("source_bytes={}",b.len()),
                    };
                    println!("AUTHORED_FORTNITE_TODM_PHASE_PROPERTY slot={} name={} kind={} meta={:?} {value}",field.array_index,p.name,p.kind,p.metadata);
                    if matches!(p.name.as_str(),"SkyLightValues"|"DirectionalLightValues"|"ExpHeightFogValues")
                        &&p.kind=="StructProperty" {
                        let inner=properties::scan(&cat,b)?;
                        println!("AUTHORED_FORTNITE_TODM_COMPONENT slot={} kind={} fields={} source_bytes={}",
                            field.array_index,p.name,inner.fields.len(),b.len());
                        for q in &inner.fields{
                            let payload=&b[q.payload.clone()];
                            let detail=match (q.kind.as_str(),payload.len()) {
                                ("FloatProperty",4)=>format!("f32={}",f32::from_le_bytes(payload.try_into().unwrap())),
                                ("IntProperty",4)=>format!("int={}",i32::from_le_bytes(payload.try_into().unwrap())),
                                ("BoolProperty",0)=>format!("bool={:?}",q.metadata),
                                ("StructProperty",16)=>format!("f32x4={:?}",(0..4).map(|k|f32::from_le_bytes(payload[k*4..k*4+4].try_into().unwrap())).collect::<Vec<_>>()),
                                ("StructProperty",12)=>format!("f32x3={:?}",(0..3).map(|k|f32::from_le_bytes(payload[k*4..k*4+4].try_into().unwrap())).collect::<Vec<_>>()),
                                _=>format!("bytes={}",payload.len()),
                            };
                            println!("AUTHORED_FORTNITE_TODM_COMPONENT_PROPERTY slot={} group={} name={} kind={} meta={:?} {detail}",
                                field.array_index,p.name,q.name,q.kind,q.metadata);
                        }
                    }

                }
            }
            println!("AUTHENTICATED_FORTNITE_ASSET_FIELD package={path} object={name} class={class} property={} kind={} metadata={:?} {repr}",
                field.name,field.kind,field.metadata);
        }
    }
    println!("AUTHENTICATED_FORTNITE_ASSET_CENSUS package={path} export_count={} relevant_properties_objects={findings} class_counts={classes:?}",cat.exports.len());
    Ok(())
}
fn run()->Result<(),String>{
    let root=PathBuf::from(env::args_os().nth(1).ok_or("usage: athena_remote_source_probe VERIFIED_REMOTE_SOURCE_ROOT")?);
    for path in TARGETS{inspect(&root,path)?;}
    Ok(())
}
fn main()->ExitCode{
    match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("AUTHENTICATED_FORTNITE_REMOTE_SOURCE_PROBE_FAILED: {e}");ExitCode::FAILURE}}
}
