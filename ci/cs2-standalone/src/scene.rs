//! Source-backed CS2 mesh preview into the shared NeutralScene contract.
//! No game-specific Vulkan code, glTF pre-cook or synthesized source meshes.
//!
//! This is geometry-only admission: original VMAT shader graph, VTEX maps,
//! lightmaps, visibility and authored physics are *not* silently inferred.
use std::{collections::{BTreeMap,BTreeSet},path::Path};
use neutral_scene::{NeutralAlpha,NeutralInstance,NeutralMaterial,NeutralMesh,NeutralScene,NeutralVertex,NeutralSky};
use crate::{draw,world,vpk::VpkArchive,surface,material,entity,lighting,bindings};

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
/// CS2 toolssolidblocklight is an authored shadow/lighting blocker. Its
/// worldnode *_shadow model is not a color-pass surface; drawing it as an
/// opaque neutral material created the 50-75 m triangles covering Dust2.
/// Keep the source mesh/placement data for provenance, but flag invisible so
/// the common NeutralScene bridge omits it from visible world instances.
fn source_color_pass_visible(name:&str)->bool{
    !matches!(name,"materials/tools/toolssolidblocklight.vmat"
        |"materials/tools/toolsnodraw.vmat")
}
fn material(name:&str,alpha:Option<f32>)->NeutralMaterial{
    NeutralMaterial{
        name:name.to_owned(),base_color_texture:None,normal_texture:None,
        specular_texture:None,metallic_roughness_texture:None,emissive_texture:None,
        metallic:0.,emissive:[0.;3],roughness:1.,
        point_sampled:false,gloss_from_color_alpha:false,
        alpha:if alpha.is_some_and(|a|a<0.999) {NeutralAlpha::Blend} else{NeutralAlpha::Opaque},
        double_sided:false,front_culled:false,unlit:false,emissive_scale:1.,
        layers:Default::default(),visible:source_color_pass_visible(name),
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
                color:[color[0]*src.color[0],color[1]*src.color[1],
                    color[2]*src.color[2],lower.alpha.unwrap_or(1.)*src.color[3]],
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
    let mut aggregate_fragments_admitted=0usize;
    let mut aggregate_fragment_failures=0usize;
    let mut aggregate_lod_filtered=0usize;
    let mut tinted_mesh_cache=BTreeMap::<(usize,[u32;3]),usize>::new();
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

        // Aggregate fragments reference a compiled source model and one exact
        // MDAT draw-call ordinal per fragment. Do not import each entire
        // aggregate as one visible mesh: doing so loses per-fragment placement,
        // tint, authored LOD and duplicates geometry for shared draw calls.
        for agg in &node.aggregates {
            if agg.fragments.is_empty(){continue;}
            let meshes=if let Some(existing)=cache.get(&agg.model) {existing.clone()}
            else {
                let before_meshes=scene.meshes.len();
                let before_triangles=triangles;
                let result=append_source_model(&mut scene,&inner,&outer,&agg.model,
                    &mut material_ids,&mut untextured,&mut triangles);
                let indices=match result {
                    Ok(v)=>v,
                    Err(error)=>{
                        scene.meshes.truncate(before_meshes);
                        triangles=before_triangles;
                        if rejected.len()<512 {rejected.push(format!("{}: {error}",agg.model));}
                        Vec::new()
                    },
                };
                cache.insert(agg.model.clone(),indices.clone());
                indices
            };
            if meshes.is_empty(){
                aggregate_fragment_failures+=agg.fragments.len();
                continue;
            }
            // For each source-defined LOD setup, keep only the finest
            // available level. The union of authored group masks determines
            // its actual first level; never assume bit 0 exists.
            let mut lod_setups=BTreeMap::<i64,u32>::new();
            for fragment in &agg.fragments {
                if fragment.lod_setup_index>=0 && fragment.lod_mask!=0 {
                    *lod_setups.entry(fragment.lod_setup_index).or_default() |= fragment.lod_mask;
                }
            }
            for frag in &agg.fragments {
                if frag.lod_mask!=0 && frag.lod_setup_index>=0 {
                    if let Some(&union)=lod_setups.get(&frag.lod_setup_index) {
                        if union!=0 && frag.lod_mask & (1u32 << union.trailing_zeros())==0 {
                            aggregate_lod_filtered+=1;
                            continue;
                        }
                    }
                }
                let Some(&source_mesh)=meshes.get(frag.draw_index) else{
                    aggregate_fragment_failures+=1;
                    if rejected.len()<512{
                        rejected.push(format!("{}: invalid aggregate draw {}",agg.model,frag.draw_index));
                    }
                    continue;
                };
                let white=frag.tint.iter().all(|&x|(x-1.).abs()<1e-6);
                let mesh=if white {source_mesh}else{
                    let color_bits=frag.tint.map(f32::to_bits);
                    let key=(source_mesh,color_bits);
                    if let Some(&existing)=tinted_mesh_cache.get(&key){existing}
                    else {
                        if scene.meshes.len()>=MAX_SCENE_MESHES {budget_skipped+=1;continue;}
                        let mut copy=scene.meshes[source_mesh].clone();
                        for vert in &mut copy.vertices {
                            for channel in 0..3 {vert.color[channel]*=frag.tint[channel];}
                        }
                        copy.name=format!("{}#fragment_tint_{:08x}_{:08x}_{:08x}",
                            copy.name,color_bits[0],color_bits[1],color_bits[2]);
                        let idx=scene.meshes.len();
                        let tris=copy.indices.len()/3;
                        if triangles.saturating_add(tris)>MAX_TRIANGLES{budget_skipped+=1;continue;}
                        triangles+=tris;
                        scene.meshes.push(copy);
                        tinted_mesh_cache.insert(key,idx);
                        idx
                    }
                };
                scene.instances.push(instance(mesh,frag.rows));
                aggregate_fragments_admitted+=1;
            }
            aggregate_fragment_failures+=agg.unsupported_fragments;
        }
    }
    if scene.meshes.is_empty(){return Err("Source 2 world contains no decodable original direct geometry".into());}
    let omitted_color_instances=scene.instances.iter().filter(|instance|{
        scene.meshes.get(instance.mesh).and_then(|mesh|scene.materials.get(mesh.material))
            .is_some_and(|mat|!mat.visible)
    }).count();
    scene.report.lines.push(format!(
        "CS2 SOURCE NON-COLOR GEOMETRY: {} tool shadow/blocklight/nodraw placements kept as original source but excluded from universal color render pass. Source2 shadow pipeline translation remains separate.",
        omitted_color_instances
    ));

    let authored_lumps=entity::from_nested_map(&inner)?;
    let authored_lighting=lighting::decode(&authored_lumps);
    let light_count=authored_lighting.local.len();
    let sun_present=authored_lighting.sun.is_some();
    let sky_material=authored_lighting.source_sky_material.clone();
    let source_lights_unsupported=authored_lighting.omitted;
    scene.sun=authored_lighting.sun;
    scene.local_lights=authored_lighting.local;
    scene.report.lines.push(format!(
        "CS2 ORIGINAL LIGHTING: {} author-positioned point lights using lumens/candelas, source sun={}, remaining Source2 area/disabled lights={}, authored sky material={:?} (sky texture shader pending). Shared Forward+ approximation, NOT baked Source2 parity.",
        light_count,sun_present,source_lights_unsupported,sky_material,
    ));

    scene.report.lines.push(format!(
        "CS2 source original geometry preview: map={map_package}; source models={}; triangle mesh draws={}; placement instances={}; original indexed triangles={triangles}.",
        cache.len(),scene.meshes.len(),scene.instances.len()
    ));
    let retail_game=material::base_game_archive()?;
    let packages=material::SourcePacks {
        workshop_outer:&outer,workshop_map:&inner,base_game:retail_game.as_ref(),
    };
    // Read the actual sky.vfx material and original BC6H HDR cubemap,
    // rather than painting an arbitrary blue procedural background.
    if let Some(path)=sky_material.as_deref() {
        match packages.describe(path) {
            Ok(sky_source) if sky_source.shader=="sky.vfx"=>{
                if let Some(texture_path)=sky_source.textures.get("g_tSkyTexture") {
                    let path=if texture_path.ends_with("_c"){texture_path.clone()}else{
                        format!("{texture_path}_c")
                    };
                    match packages.read(&path).and_then(|bytes|{
                        crate::texture::decode_hdr_cube_faces(
                            &bytes,&path,
                            sky_source.scalars.get("g_flBrightnessExposureBias").copied().unwrap_or(0.)
                        )
                    }){
                        Ok(faces)=>{
                            // A 90-degree world-axis change needs rotation
                            // WITHIN the six authored faces, not just face
                            // permutation. The earlier permutation generated
                            // a visible rectangular horizon seam.
                            let faces=crate::cubemap_axis::source_z_up_to_engine_y_up(faces)?;
                            scene.sky=Some(NeutralSky{faces,intensity:1.,cycle:None});
                            scene.report.lines.push(format!(
                                "CS2 ORIGINAL SKY: source-authored original BC1/BC6H cubemap {} decoded into 6 exact image faces (generic display approximation, sky.vfx exposure and Vulkan image-space validation pending).",
                                path
                            ));
                        },
                        Err(e)=>scene.report.lines.push(format!(
                            "CS2 ORIGINAL SKY UNSUPPORTED: source sky={} texture={}: {}",path,texture_path,e
                        )),
                    }
                }
            },
            Ok(m)=>scene.report.lines.push(format!("CS2 SKY SHADER PENDING: source {}",m.shader)),
            Err(e)=>scene.report.lines.push(format!("CS2 SKY SOURCE MISSING: {e}")),
        }
    }
    // Preserve a precise census of Source 2 baked texture dependencies.
    // Source2 lightmaps contain lighting data and encoding-specific layer
    // semantics. Never feed them to generic RGBM until the exact
    // atlas/UV placement mapping and light transport contract are decoded.
    let mut authored_lightmap_formats=Vec::new();
    for original in &graph.lighting_textures {
        let path=if original.ends_with("_c"){original.clone()}else{
            format!("{original}_c")
        };
        match packages.read(&path).and_then(|bytes|crate::texture::inspect(&bytes)) {
            Ok(meta)=>authored_lightmap_formats.push(format!(
                "{}: {}x{}, VTEX format {}, {} mip(s), flags 0x{:04x}",
                path,meta.width,meta.height,meta.format,meta.mips,meta.flags
            )),
            Err(error)=>authored_lightmap_formats.push(format!("{path}: {error}")),
        }
    }
    scene.report.lines.push(format!(
        "CS2 BAKED LIGHTMAP SOURCE AUDIT: {}/{} original lightmap reference(s) inspected. Original atlas UV/lighting semantics not yet translated: {}",
        authored_lightmap_formats.iter().filter(|value|value.contains("VTEX format")).count(),
        graph.lighting_textures.len(),authored_lightmap_formats.join("; ")
    ));
    let census=packages.audit(untextured.iter().map(String::as_str));
    let bound=bindings::bind(&mut scene,&packages);
    scene.report.lines.push(format!(
        "CS2 ORIGINAL EFFECT SHADING: {} authored additive csgo_effects.vfx material(s); {} have original g_tColor alpha * three source VTEX masks and source opacity scale compiled to universal ADDITIVE transparency. Source camera Fresnel/fade/depth-feather remains pending.",
        bound.additive_effect_materials,bound.original_effect_masks_combined
    ));
    scene.report.lines.push(format!(
        "CS2 ACTUAL VTEX MATERIAL INPUTS: {} original textures decoded ({} MiB decoded RGBA; limit {}), {}/{} original geometry materials with a source-backed base-color texture, {} direct normal bindings, {} unavailable/unsupported texture requests. Original metalness scalar mapped on {} materials. Additional original shader semantics pending: Layer2 blend={} materials, packed normal/roughness={} materials, self-illumination={} materials. Source shader graph translation, map lightmaps and skybox remain incomplete. Failure samples: {}",
        bound.vtex_loaded,bound.total_rgba_bytes/(1024*1024),
        bound.budget_bytes.map(|bytes|format!("{} MiB",bytes/(1024*1024))).unwrap_or_else(||"disabled".into()),
        bound.materials_with_albedo,scene.materials.len(),bound.materials_with_normal,
        bound.vtex_failed,bound.mapped_metalness,bound.authored_layer2,
        bound.authored_normal_roughness,bound.authored_self_illum,
        bound.missing.iter().take(8).cloned().collect::<Vec<_>>().join("; ")
    ));
    scene.report.lines.push(format!(
        "CS2 ORIGINAL VMAT COVERAGE: {}/{} compiled material resources resolved, {} material shader variants identified, {} authored texture slots discovered ({} VTEX resources present). Base CS2 archive configured: {}. Missing original material samples: {}",
        census.material_resolved,census.referenced,census.shaders.len(),
        census.authored_texture_slots,census.texture_resolved,
        retail_game.is_some(),
        census.material_unresolved.iter().take(10).cloned().collect::<Vec<_>>().join("; ")
    ));
    if let Some(base)=retail_game.as_ref() {
        // A VPK directory is only an index. A referenced resource listed in
        // pak01_dir.vpk is NOT available until its numbered VPK is present.
        // Report physical archive gaps in descending order of source usage,
        // so developers download the highest-impact original archives first.
        let mut missing_archive_files=BTreeSet::<String>::new();
        missing_archive_files.extend(census.texture_unresolved.iter().cloned());
        missing_archive_files.extend(census.material_unresolved.iter().map(|path|{
            if path.ends_with("_c"){path.clone()}else{format!("{path}_c")}
        }));
        let mut archive_paths=BTreeMap::<u16,usize>::new();
        for path in &missing_archive_files {
            if base.available(path){continue;}
            if let Some(entry)=base.entries().get(path) {
                if entry.archive_index != 0x7fff {
                    *archive_paths.entry(entry.archive_index).or_default()+=1;
                }
            }
        }
        if !archive_paths.is_empty() {
            let mut ranked=archive_paths.into_iter().collect::<Vec<_>>();
            ranked.sort_by(|a,b|b.1.cmp(&a.1).then_with(||a.0.cmp(&b.0)));
            scene.report.lines.push(format!(
                "CS2 MISSING PHYSICAL SOURCE VPKS: {} numbered original base-game archives absent. Highest-impact: {}. Keep downloaded pak01_XXX.vpk files beside pak01_dir.vpk; the index alone is insufficient to texture this map.",
                ranked.len(),
                ranked.iter().take(20).map(|(index,count)|
                    format!("pak01_{index:03}.vpk ({count} needed resources)")
                ).collect::<Vec<_>>().join(", ")
            ));
        }
    }
    if !census.texture_unresolved.is_empty() {
        scene.report.lines.push(format!(
            "CS2 missing compiled source textures: {} unique paths; first samples: {}",
            census.texture_unresolved.len(),
            census.texture_unresolved.iter().take(8).cloned().collect::<Vec<_>>().join("; ")
        ));
    }
    scene.report.lines.push(format!(
        "Incomplete original Source 2 shading: {} distinct VMAT identities referenced by decoded triangles; authored VTEX colour/normal channels admitted where available, but original Source 2 shader programs are not translated. \
         Original source tints and UVs retained, but shared neutral materials remain DIAGNOSTIC and cannot be claimed retail-correct.",
        untextured.len()
    ));
    scene.report.lines.push(format!(
        "CS2 unsupported original model decodes ({} captured), source geometry preview budget skipped {} placements: {}",
        rejected.len(),budget_skipped,
        rejected.iter().take(12).cloned().collect::<Vec<_>>().join("; ")
    ));
    scene.report.lines.push(format!(
        "Source 2 world aggregates: {} actual fragments admitted, {} filtered by authored lowest LOD, {} unresolved fragments, {} original aggregate fragment references. No aggregate geometry is invented.",
        aggregate_fragments_admitted,aggregate_lod_filtered,
        aggregate_fragment_failures,aggregate_draws
    ));
    scene.report.lines.push(format!(
        "Remaining source world graph: {} unrecognized scene objects, {} referenced baked lightmaps, {} entity lumps. \
         Retail-authored physics/spawns and visibility not yet lowered; the preview is incomplete.",
        skipped,graph.lighting_textures.len(),graph.entity_lumps.len()
    ));
    Ok(scene)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retail_shadow_blockers_are_not_visible_materials(){
        for name in ["materials/tools/toolssolidblocklight.vmat",
                     "materials/tools/toolsnodraw.vmat"] {
            assert!(!source_color_pass_visible(name));
            let mat=material(name,None);
            assert!(!mat.visible);
            assert!(!mat.collides);
        }
        assert!(source_color_pass_visible("materials/de_dust/hr_dust/hr_dust_plaster_01.vmat"));
        assert!(material("materials/de_dust/hr_dust/hr_dust_plaster_01.vmat",None).visible);
    }
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
