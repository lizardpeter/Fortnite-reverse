//! Source-faithful reconnaissance of UE4 cooked landscape expression arrays:
//! MaterialFunctionInputs, LandscapeLayerBlend layers and nested links.
/// No fabricated AST edges and no executable shader guesses.
use std::{env,fs,path::PathBuf,process::ExitCode};
use fortnite_541_importer::{properties,uobject};
fn run()->Result<(),String>{
    let root=PathBuf::from(env::args_os().nth(1).ok_or("usage: athena_material_graph_probe ORIGINAL_ATHENA_SOURCE_ROOT")?);
    let path=root.join("FortniteGame/Content/Athena/Environments/Landscape/Material/M_Athena_Terrain_Master");
    let source=fs::read(path.with_extension("uasset")).map_err(|e|format!("master uasset: {e}"))?;
    let exp=fs::read(path.with_extension("uexp")).map_err(|e|format!("master uexp: {e}"))?;
    let cat=uobject::inspect(&source)?;
    let mut count=0usize;
    for (i,export) in cat.exports.iter().enumerate(){
        let name=cat.export_class_name(export).unwrap_or("<unknown>");
        if !matches!(name,"MaterialExpressionLandscapeLayerBlend"|"MaterialExpressionMaterialFunctionCall"
            |"MaterialExpressionLandscapeGrassOutput"|"MaterialExpressionTextureSample"
            |"MaterialExpressionLandscapeLayerSwitch"|"MaterialExpressionStaticSwitchParameter"
            |"MaterialExpressionTextureSampleParameter2D"){
            continue;
        }
        let raw=cat.export_data(&source,&exp,export)?;
        let props=properties::scan(&cat,raw)?;
        if name!="MaterialExpressionLandscapeLayerBlend" &&count>=32 {continue;}
        println!("AUTHORED_SHADER_NODE class={name} export={} input_properties={}",i+1,props.fields.len());
        for p in props.fields {
            let bytes=&raw[p.payload.clone()];
            if p.kind=="ArrayProperty" ||(p.kind=="StructProperty" &&bytes.len()>48) {
                let width=bytes.len().min(240);
                let hex=bytes[..width].iter().map(|b|format!("{b:02x}")).collect::<String>();
                let count=if bytes.len()>=4{Some(u32::from_le_bytes(bytes[..4].try_into().unwrap()))}else{None};
                println!("AUTHORED_SHADER_NESTED class={name} export={} property={} kind={} meta={:?} bytes={} array_count={count:?} prefix_hex={hex}",i+1,p.name,p.kind,p.metadata,bytes.len());
                if name=="MaterialExpressionLandscapeLayerBlend" && p.name=="Layers"
                    && bytes.len()>=53 {
                    let count=count.unwrap_or(0) as usize;
                    let inner=bytes.len()-53;
                    if count!=5 ||inner%count!=0 {
                        return Err(format!("authored LayerBlend array has unexpected count/length: count={count} inner={inner}"));
                    }
                    let chunk=inner/count;
                    println!("AUTHORED_SHADER_LAYER_RECORD_HEADER export={} count={} inner_tag={:02x?} layer_record_bytes={chunk}",
                        i+1,count,&bytes[4..53]);
                    for (slot,part) in bytes[53..].chunks_exact(chunk).enumerate() {
                        let props=properties::scan(&cat,part)?;
                        let decoded=props.fields.iter().map(|prop|{
                            let val=&part[prop.payload.clone()];
                            let detail=if prop.kind=="NameProperty" &&val.len()==8{
                                let index=u32::from_le_bytes(val[..4].try_into().unwrap()) as usize;
                                format!("FName={:?}",cat.names.get(index))
                            } else if prop.kind=="StructProperty" &&prop.metadata.first().map(String::as_str)==Some("ExpressionInput") && val.len()>=4 {
                                let id=i32::from_le_bytes(val[..4].try_into().unwrap());
                                format!("FExpressionInput ref={id} obj={:?}",cat.source_object_path(id))
                            } else if prop.kind=="FloatProperty" && val.len()==4{
                                format!("f32={}",f32::from_le_bytes(val.try_into().unwrap()))
                            } else {
                                format!("{} bytes",val.len())
                            };
                            format!("{}:{}:{:?}:{detail}",prop.name,prop.kind,prop.metadata)
                        }).collect::<Vec<_>>();
                        println!("AUTHORED_SHADER_LAYER_RECORD export={} slot={slot} consumed={} total={chunk} props={decoded:?}",
                            i+1,props.bytes_consumed);
                        if props.bytes_consumed!=chunk{return Err("source LayerBlend input has trailing bytes".into());}
                    }
                }
            }else if p.kind=="ObjectProperty" &&bytes.len()==4{
                let idx=i32::from_le_bytes(bytes.try_into().unwrap());
                println!("AUTHORED_SHADER_REF class={name} export={} property={} object_ref={idx} path={:?}",i+1,p.name,cat.source_object_path(idx));
            }else if p.kind=="NameProperty" &&bytes.len()==8{
                let idx=u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
                println!("AUTHORED_SHADER_PARAMETER class={name} export={} property={} FName={:?}",i+1,p.name,cat.names.get(idx));
            }else if p.kind=="FloatProperty" &&bytes.len()==4{
                println!("AUTHORED_SHADER_FLOAT class={name} export={} property={} value={}",i+1,p.name,f32::from_le_bytes(bytes.try_into().unwrap()));
            }
        }
        count+=1;
    }
    println!("AUTHORED_SHADER_NESTED_PROBE exported_nodes_examined={count}");
    Ok(())
}
fn main()->ExitCode{match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("AUTHORED_SHADER_GRAPH_PROBE_FAILED: {e}");ExitCode::FAILURE}}}
