//! Original Source 2 world graph: compiled world nodes, authored placements,
//! lighting asset paths and entity-lump identities. No invented scene objects.
use std::path::Path;
use crate::{kv3::{self,Value},resource::ResourceHeader,vpk::VpkArchive};
#[derive(Clone,Debug)]
pub struct SourcePlacement {
    pub model:String,
    pub rows:[[f32;4];3],
    pub object_id:i64,
    pub tint:Option<[f32;4]>,
    pub skin:Option<String>,
}
#[derive(Clone,Debug)]
pub struct SourceWorldNode {
    pub path:String,
    pub scene_objects:Vec<SourcePlacement>,
    pub aggregate_groups:usize,
    pub aggregate_draws:usize,
    pub aggregates:Vec<SourceAggregate>,
    pub unknown_scene_objects:usize,
}
#[derive(Clone,Debug)]
pub struct SourceFragment {
    pub draw_index:usize,
    pub rows:[[f32;4];3],
    pub tint:[f32;3],
    pub object_flags:i64,
    pub lod_mask:u32,
    pub lod_setup_index:i64,
}
#[derive(Clone,Debug)]
pub struct SourceAggregate {
    pub model:String,
    pub fragments:Vec<SourceFragment>,
    pub lod_setup_count:usize,
    pub unsupported_fragments:usize,
}
const IDENTITY:[[f32;4];3]=[[1.,0.,0.,0.],[0.,1.,0.,0.],[0.,0.,1.,0.]];
#[derive(Clone,Debug)]
pub struct SourceWorld {
    pub map_package:String,
    pub world_path:String,
    pub nodes:Vec<SourceWorldNode>,
    pub lighting_textures:Vec<String>,
    pub entity_lumps:Vec<String>,
    pub unresolved_placements:Vec<String>,
    pub source_bounds:Option<([f32;3],[f32;3])>,
}
fn compiled_path(path:&str)->Result<String,String> {
    let normalized=path.replace('\\',"/");
    if normalized.is_empty() || normalized.starts_with('/') ||
        normalized.contains(':') || normalized.split('/').any(|s|s==".." || s=="." || s.is_empty()) {
        return Err(format!("invalid original Source 2 resource path {path:?}"));
    }
    if normalized.ends_with("_c"){Ok(normalized)}
    else{Ok(format!("{normalized}_c"))}
}
fn number(value:&Value)->Result<f32,String>{
    let n=value.as_float().ok_or("non-numeric Source 2 transform component")?;
    if !n.is_finite() || n.abs()>1e20{return Err("unbounded Source 2 scene transform".into());}
    Ok(n as f32)
}
fn rows(value:&Value)->Result<[[f32;4];3],String>{
    let list=value.as_array().ok_or("Source 2 transform has no rows")?;
    if list.len()!=3{return Err("Source 2 transform is not 3x4".into());}
    let mut output=[[0.;4];3];
    for (i,v) in list.iter().enumerate(){
        let row=v.as_array().ok_or("invalid Source 2 transform row")?;
        if row.len()!=4{return Err("Source 2 transform row does not have four coefficients".into());}
        for (j,v) in row.iter().enumerate(){output[i][j]=number(v)?;}
    }
    Ok(output)
}
fn root_object(bytes:&[u8])->Result<Value,String>{
    let resource=ResourceHeader::parse(bytes)?;
    let payload=resource.block(bytes,b"DATA").ok_or("Source 2 resource is missing DATA")?;
    Ok(kv3::decode(payload)?.root)
}
pub fn from_workshop(directory:&Path,map_package:&str)->Result<SourceWorld,String>{
    let outer=VpkArchive::open_directory(directory)?;
    from_archive(&outer,map_package)
}
pub fn from_archive(outer:&VpkArchive,map_package:&str)->Result<SourceWorld,String>{
    let archive=outer.open_nested(map_package)?;
    let map_stem=map_package.strip_prefix("maps/").and_then(|x|x.strip_suffix(".vpk"))
        .ok_or("Source 2 map package must be maps/<name>.vpk")?;
    let world_path=format!("maps/{map_stem}/world.vwrld_c");
    let world_root=root_object(&archive.read_entry(&world_path)?)?;
    let source_nodes=world_root.field("m_worldNodes").and_then(Value::as_array)
        .ok_or("compiled Source 2 world has no world nodes")?;
    if source_nodes.is_empty(){return Err("compiled Source 2 world declares no nodes".into());}
    let source_bounds=source_nodes.first().and_then(|n|{
        let min=n.field("m_vMinBounds")?.as_array()?;
        let max=n.field("m_vMaxBounds")?.as_array()?;
        if min.len()!=3||max.len()!=3{return None}
        Some((
            [number(&min[0]).ok()?,number(&min[1]).ok()?,number(&min[2]).ok()?],
            [number(&max[0]).ok()?,number(&max[1]).ok()?,number(&max[2]).ok()?]
        ))
    });
    let lighting_textures=world_root.field("m_worldLightingInfo")
        .and_then(|x|x.field("m_lightMaps")).and_then(Value::as_array)
        .unwrap_or(&[]).iter().filter_map(Value::as_text).map(str::to_owned).collect();
    let entity_lumps=world_root.field("m_entityLumps").and_then(Value::as_array)
        .unwrap_or(&[]).iter().filter_map(Value::as_text).map(str::to_owned).collect();
    let mut nodes=Vec::with_capacity(source_nodes.len());
    let mut unresolved_placements=Vec::new();
    for node in source_nodes {
        let prefix=node.field("m_worldNodePrefix").and_then(Value::as_text)
            .ok_or("compiled Source 2 node lacks its source pathname")?;
        let path=compiled_path(&format!("{prefix}.vwnod"))?;
        let document=root_object(&archive.read_entry(&path)?)?;
        let source_objects=document.field("m_sceneObjects").and_then(Value::as_array)
            .ok_or_else(||format!("{path}: no authored scene objects"))?;
        let mut scene_objects=Vec::new();
        let mut unknown_scene_objects=0;
        for object in source_objects {
            let Some(model)=object.field("m_renderableModel").and_then(Value::as_text) else {
                unknown_scene_objects+=1;continue
            };
            if model.is_empty(){unknown_scene_objects+=1;continue}
            let model_path=compiled_path(model)?;
            let Some(transform)=object.field("m_vTransform") else {
                return Err(format!("{path}: renderable source model {model} has no transform"));
            };
            let transform=rows(transform)?;
            if !archive.entries().contains_key(&model_path) && !outer.entries().contains_key(&model_path) {
                if unresolved_placements.len()<100 {
                    unresolved_placements.push(model_path.clone());
                }
            }
            let object_id=object.field("m_nObjectID").and_then(Value::as_float).unwrap_or(0.) as i64;
            let tint=object.field("m_vTintColor").and_then(Value::as_array).and_then(|a|{
                if a.len()!=4{return None}
                Some([number(&a[0]).ok()?,number(&a[1]).ok()?,number(&a[2]).ok()?,number(&a[3]).ok()?])
            });
            let skin=object.field("m_skin").and_then(Value::as_text).map(str::to_owned);
            scene_objects.push(SourcePlacement{model:model_path,rows:transform,object_id,tint,skin});
        }
        let compiled_aggregates=document.field("m_aggregateSceneObjects").and_then(Value::as_array).unwrap_or(&[]);
        let mut aggregates=Vec::new();
        let mut aggregate_draws=0usize;
        for agg in compiled_aggregates {
            let fragments=agg.field("m_aggregateMeshes").and_then(Value::as_array)
                .ok_or_else(||format!("{path}: aggregate has no fragment array"))?;
            aggregate_draws+=fragments.len();
            let model=agg.field("m_renderableModel").and_then(Value::as_text)
                .ok_or_else(||format!("{path}: aggregate missing model reference"))?;
            let model=compiled_path(model)?;
            let transforms=agg.field("m_fragmentTransforms").and_then(Value::as_array).unwrap_or(&[]);
            let lod_setups=agg.field("m_lodSetups").and_then(Value::as_array).unwrap_or(&[]);
            let mut fragment_transform_index=0;
            let mut parsed=Vec::with_capacity(fragments.len());
            let mut unsupported_fragments=0;
            for frag in fragments {
                let Some(index)=frag.field("m_nDrawCallIndex").and_then(Value::as_float) else {
                    unsupported_fragments+=1;continue;
                };
                if !index.is_finite() || index<0. || index.fract()!=0. || index>250_000. {
                    return Err(format!("{path}: invalid aggregate draw index {index}"));
                }
                let has_transform=matches!(frag.field("m_bHasTransform"),Some(Value::Bool(true)));
                let rows=if has_transform {
                    let value=transforms.get(fragment_transform_index)
                        .ok_or_else(||format!("{path}: missing aggregate fragment transform"))?;
                    fragment_transform_index+=1;
                    rows(value)?
                } else { IDENTITY };
                let tint=frag.field("m_vTintColor").and_then(Value::as_array).map(|values|{
                    if values.len()!=3{return Err(format!("{path}: invalid fragment tint vector"));}
                    Ok([
                        number(&values[0])?/255.,
                        number(&values[1])?/255.,
                        number(&values[2])?/255.,
                    ])
                }).transpose()?.unwrap_or([1.;3]);
                let flags=frag.field("m_objectFlags").and_then(Value::as_float).unwrap_or(0.) as i64;
                let lod_mask=frag.field("m_nLODGroupMask").and_then(Value::as_float).unwrap_or(0.) as u32;
                let lod_setup_index=frag.field("m_nLODSetupIndex").and_then(Value::as_float).unwrap_or(-1.) as i64;
                parsed.push(SourceFragment{draw_index:index as usize,rows,tint,object_flags:flags,lod_mask,lod_setup_index});
            }
            aggregates.push(SourceAggregate{model,fragments:parsed,
                lod_setup_count:lod_setups.len(),unsupported_fragments});
        }
        nodes.push(SourceWorldNode{
            path,scene_objects,aggregate_groups:compiled_aggregates.len(),
            aggregate_draws,aggregates,unknown_scene_objects,
        });
    }
    Ok(SourceWorld{map_package:map_package.to_owned(),world_path,nodes,lighting_textures,
        entity_lumps,unresolved_placements,source_bounds})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_path_is_never_filename_synthesized(){
        assert_eq!(compiled_path(r"maps\de_dust2\worldnodes\node000.vwnod").unwrap(),
            "maps/de_dust2/worldnodes/node000.vwnod_c");
        assert!(compiled_path("../other/file.vmdl").is_err());
    }
    #[test]
    fn authored_transform_preserves_translation(){
        let value=Value::Array(vec![
            Value::Array(vec![Value::Float(1.),Value::Float(0.),Value::Float(0.),Value::Float(125.)]),
            Value::Array(vec![Value::Float(0.),Value::Float(1.),Value::Float(0.),Value::Float(-8.)]),
            Value::Array(vec![Value::Float(0.),Value::Float(0.),Value::Float(1.),Value::Float(24.)]),
        ]);
        let m=rows(&value).unwrap();
        assert_eq!([m[0][3],m[1][3],m[2][3]],[125.,-8.,24.]);
    }
}
