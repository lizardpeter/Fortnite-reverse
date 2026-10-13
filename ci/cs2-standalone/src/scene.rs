//! Source-backed CS2 mesh preview into the shared NeutralScene contract.
//! No game-specific Vulkan code, glTF pre-cook or synthesized source meshes.
//!
//! This is geometry-only admission: original VMAT shader graph, VTEX maps,
//! lightmaps, visibility and authored physics are *not* silently inferred.
use std::{collections::{BTreeMap,BTreeSet},path::Path};
use neutral_scene::{NeutralAlpha,NeutralInstance,NeutralMaterial,NeutralMesh,NeutralScene,NeutralVertex};
use crate::{draw,world,vpk::VpkArchive,surface};

const SOURCE_UNITS_TO_METRES:f32=0.0254; // Source 2 world unit convention (inch)
const MAX_SCENE_MESHES:usize=250_000;
const MAX_TRIANGLES:usize=15_000_000;

/// x,y,z (Source 2 Z-up) -> x,z,-y (shared engine right-handed Y-up).
fn engine_position(p:[f32;3])->[f32;3] {
    [p[0]*SOURCE_UNITS_TO_METRES,p[2]*SOURCE_UNITS_TO_METRES,-p[1]*SOURCE_UNITS_TO_METRES]
}
fn engine_axis(v:[f32;3])->[f32;3] { [v[0],v[2],-v[1]] }
/// F * R * inverse(F), with source-authored translation converted to meters.
fn engine_transform(s:[[f32;4];3])->[[f32;4];3]{
    [
        [s[0][0],s[0][2],-s[0][1],s[0][3]*SOURCE_UNITS_TO_METRES],
        [s[2][0],s[2][2],-s[2][1],s[2][3]*SOURCE_UNITS_TO_METRES],
        [-s[1][0],-s[1][2],s[1][1],-s[1][3]*SOURCE_UNITS_TO_METRES],
    ]
}
fn material(name:&str,alpha:Option<f32>)->NeutralMaterial{
    NeutralMaterial{
        name:name.to_owned(),base_color_texture:None,normal_texture:None,
        specular_texture:None,metallic_roughness_texture:None,emissive_texture:None,
        metallic:0.,emissive:[0.;3],roughness:1.,
        point_sampled:false,gloss_from_color_alpha:false,
        alpha:if alpha.is_some_and(|a|a<0.999) {NeutralAlpha::Blend} else{NeutralAlpha::Opaque},
        double_sided:false,front_culled:false,unlit:false,emissive_scale:1.,
        layers:Default::default(),visible:true,
        // Rendering geometry is not the same as an authored physics mesh.
        collides:false,program:None,
    }
}
fn instance(mesh:usize,source:[[f32;4];3])->NeutralInstance{
    NeutralInstance{
        mesh,rows:engine_transform(source),motion:None,camera_relative:false,
        irradiance_sh:None,reflection_probe:None,source_reflection_probe:None,
        sun_visibility:None,program_data:[[0.;4];8],
        program_data_valid_rows:0,vertex_data_override:None,
    }
}
fn append_source_model(
    scene:&mut NeutralScene,archive:&VpkArchive,outer:&VpkArchive,model:&str,
    material_ids:&mut BTreeMap<(String,u32),usize>,
    untextured:&mut BTreeSet<String>,
    triangles:&mut usize,
)->Result<Vec<usize>,String>{
    let file=if archive.entries().contains_key(model){archive.read_entry(model)?}
        else{outer.read_entry(model)?};
    let source=draw::decode_model(&file,model)?;
    let mut out=Vec::with_capacity(source.draws.len());
    for draw in &source.draws{
        if scene.meshes.len()>=MAX_SCENE_MESHES{
            return Err("CS2 preview exceeds protected scene mesh count".into());
        }
        let lower=surface::lower_draw(&source,draw)?;
        *triangles=triangles.checked_add(lower.indices.len()/3).ok_or("CS2 triangle counter overflow")?;
        if *triangles>MAX_TRIANGLES{return Err("CS2 preview exceeds triangle safety limit".into());}
        // Keep the distinct original source material *identity*. The neutral
        // renderer currently has no exact Source 2 shader/texture binding.
        // Source author tint is retained in the vertex colour, not presented
        // as a replacement for original diffuse texture.
        let key=(draw.material.clone(),u32::from(draw.alpha.unwrap_or(1.)<0.999));
        let mid=if let Some(idx)=material_ids.get(&key){*idx}else{
            let idx=scene.materials.len();
            scene.materials.push(material(&draw.material,draw.alpha));
            material_ids.insert(key,idx);
            idx
        };
        untextured.insert(draw.material.clone());
        let color=lower.tint.unwrap_or([1.;3]);
        let mut vertices=Vec::with_capacity(lower.vertices.len());
        for src in lower.vertices {
            let normal=engine_axis(src.normal);
            let tangent=engine_axis([src.tangent[0],src.tangent[1],src.tangent[2]]);
            vertices.push(NeutralVertex{
                position:engine_position(src.position),
                normal,tangent:[tangent[0],tangent[1],tangent[2],src.tangent[3]],
                uv:src.uv,lightmap_uv:src.secondary_uv.unwrap_or(src.uv),
                color:[color[0],color[1],color[2],lower.alpha.unwrap_or(1.)],
                ..Default::default()
            });
        }
        let idx=scene.meshes.len();
        scene.meshes.push(NeutralMesh{
            name:format!("{}#draw{}",model,idx),
            material:mid,vertices,indices:lower.indices,
            lightmap:None,model_vertex_base:0,vertex_light:None,source_vertices:None,
        });
        out.push(idx);
    }
    Ok(out)
}
/// Load ALL exact original direct world-node scene-object meshes with their
/// original placement transforms. Aggregate draw calls and Source 2 materials
/// are tracked as known gaps rather than inventing an equivalent shader.
pub fn import_workshop_preview(outer_directory:&Path,map_package:&str)->Result<NeutralScene,String>{
    let outer=VpkArchive::open_directory(outer_directory)?;
    let inner=outer.open_nested(map_package)?;
    let graph=world::from_archive(&outer,map_package)?;
    let mut scene=NeutralScene::default();
    let mut material_ids=BTreeMap::new();
    let mut untextured=BTreeSet::new();
    let mut cache=BTreeMap::<String,Vec<usize>>::new();
    let mut triangles=0usize;
    let mut aggregate_draws=0usize;
    let mut skipped=0usize;
    let mut rejected=Vec::<String>::new();
    let mut budget_skipped=0usize;
    for node in &graph.nodes {
        aggregate_draws+=node.aggregate_draws;
        skipped+=node.unknown_scene_objects;
        for placement in &node.scene_objects {
            if triangles>=MAX_TRIANGLES || scene.meshes.len()>=MAX_SCENE_MESHES {
                budget_skipped+=1;
                continue;
            }
            let mesh_list=if let Some(existing)=cache.get(&placement.model) {existing.clone()}
            else {
                // An unsupported source resource blocks that specific model,
                // never substitutes a cube or aborts the entire map preview.
                let before_meshes=scene.meshes.len();
                let before_triangles=triangles;
                let list=match append_source_model(&mut scene,&inner,&outer,&placement.model,
                    &mut material_ids,&mut untextured,&mut triangles) {
                    Ok(list)=>list,
                    Err(error)=>{
                        scene.meshes.truncate(before_meshes);
                        triangles=before_triangles;
                        if rejected.len()<512 {rejected.push(format!("{}: {error}",placement.model));}
                        Vec::new()
                    },
                };
                cache.insert(placement.model.clone(),list.clone());
                list
            };
            for mesh in mesh_list {scene.instances.push(instance(mesh,placement.rows));}
        }
    }
    if scene.meshes.is_empty(){return Err("Source 2 world contains no decodable original direct geometry".into());}
    scene.report.lines.push(format!(
        "CS2 source original geometry preview: map={map_package}; source models={}; triangle mesh draws={}; placement instances={}; original indexed triangles={triangles}.",
        cache.len(),scene.meshes.len(),scene.instances.len()
    ));
    scene.report.lines.push(format!(
        "Unresolved original Source 2 shading: {} distinct VMAT programs are referenced by decoded triangles; VTEX and shader programs not admitted. \
         Original source tints and UVs retained, but shared neutral materials remain DIAGNOSTIC and cannot be claimed retail-correct.",
        untextured.len()
    ));
    scene.report.lines.push(format!(
        "CS2 unsupported original model decodes ({} captured), source geometry preview budget skipped {} placements: {}",
        rejected.len(),budget_skipped,
        rejected.iter().take(12).cloned().collect::<Vec<_>>().join("; ")
    ));
    scene.report.lines.push(format!(
        "Remaining source world graph: {} aggregate draw references not yet merged, {} unrecognized scene objects, {} referenced baked lightmaps, {} entity lumps. \
         Retail-authored physics/spawns and visibility not yet lowered; the preview is incomplete.",
        aggregate_draws,skipped,graph.lighting_textures.len(),graph.entity_lumps.len()
    ));
    Ok(scene)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_xyz_to_engine_y_up_is_right_handed(){
        let p=engine_position([1.,2.,3.]);
        assert!((p[0]-0.0254).abs()<1e-6);
        assert!((p[1]-0.0762).abs()<1e-6);
        assert!((p[2]+0.0508).abs()<1e-6);
        let s=[[1.,0.,0.,200.],[0.,1.,0.,300.],[0.,0.,1.,400.]];
        let t=engine_transform(s);
        assert!((t[0][3]-5.08).abs()<1e-5);
        assert!((t[1][3]-10.16).abs()<1e-5);
        assert!((t[2][3]+7.62).abs()<1e-5);
        let x=engine_axis([1.,0.,0.]);
        let y=engine_axis([0.,1.,0.]);
        assert_eq!([x[1]*y[2]-x[2]*y[1],x[2]*y[0]-x[0]*y[2],x[0]*y[1]-x[1]*y[0]],[0.,1.,0.]);
    }
}
