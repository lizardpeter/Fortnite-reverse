//! Source-backed CS2 mesh preview into the shared NeutralScene contract.
//! No game-specific Vulkan code, glTF pre-cook or synthesized source meshes.
//!
//! This is geometry-only admission: original VMAT shader graph, VTEX maps,
//! lightmaps, visibility and authored physics are *not* silently inferred.
use std::{collections::{BTreeMap,BTreeSet},path::Path};
use neutral_scene::{NeutralAlpha,NeutralInstance,NeutralMaterial,NeutralMesh,NeutralScene,NeutralVertex,NeutralSky};
use crate::{draw,world,vpk::VpkArchive,surface,material,entity,lighting,lightmap,bindings};

const SOURCE_UNITS_TO_METRES:f32=0.0254; // Source 2 world unit convention (inch)
const MAX_SCENE_MESHES:usize=250_000;
const MAX_TRIANGLES:usize=15_000_000;

/// Apply compiler-authored env_sky linear tint to original sRGB cube pixels.
/// Keep texture image resolution/orientation and all per-face source details;
/// Source2 sky shader exposure/bloom still requires native translation.
fn tint_source_sky_faces(
    mut faces:[neutral_scene::NeutralTexture;6],tint:[f32;3]
)->[neutral_scene::NeutralTexture;6]{
    let linear=|s:f32|if s<=0.04045{s/12.92}else{
        ((s+0.055)/1.055).powf(2.4)
    };
    let srgb=|s:f32|if s<=0.0031308{s*12.92}else{
        1.055*s.powf(1./2.4)-0.055
    };
    let tint_linear=tint.map(|v|linear(v.clamp(0.,1.)));
    for face in &mut faces{
        for pixel in face.rgba.chunks_exact_mut(4){
            for c in 0..3{
                let light=linear(pixel[c] as f32/255.)*tint_linear[c];
                pixel[c]=(srgb(light).clamp(0.,1.)*255.).round() as u8;
            }
        }
    }
    faces
}


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
        parallax_depth: 0.0, subsurface_scattering: false, name:name.to_owned(),base_color_texture:None,normal_texture:None,
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
    lightmap_uv_scale:[f32;2],
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
                uv:src.uv,
                // Source2 v8.2 baked UV is semantic TEXCOORD3 and must be
                // multiplied by m_vLightmapUvScale, not TEXCOORD1.
                // Do NOT silently substitute base UV when an authored baked
                // lightmap stream is absent. No baked texture is bound until
                // source lighting maps into the universal shader path.
                lightmap_uv:if lower.lightmapped {
                    src.lightmap_uv
                        .map(|uv|[uv[0]*lightmap_uv_scale[0],
                                  uv[1]*lightmap_uv_scale[1]])
                        .unwrap_or([0.,0.])
                }else{src.secondary_uv.unwrap_or(src.uv)},
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
                    &mut material_ids,&mut untextured,&mut triangles,graph.lightmap_uv_scale) {
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
                    &mut material_ids,&mut untextured,&mut triangles,graph.lightmap_uv_scale);
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
    let source_sky_tint=authored_lighting.sky_tint;
    let source_sky_brightness=authored_lighting.sky_brightness_scale;
    let gradient_fog=authored_lighting.gradient_fog_source.clone();
    let source_lights_unsupported=authored_lighting.omitted;
    scene.sun=authored_lighting.sun;
    scene.local_lights=authored_lighting.local;
    scene.fog=authored_lighting.fog;
    if let Some(fog)=gradient_fog.as_ref(){
        scene.report.lines.push(format!(
            "CS2 ORIGINAL GRADIENT FOG: authored source distance {:.1}..{:.1} units, color {:?}, distance exponent {:.2}, height enabled={} source height {:.1}..{:.1}, vertical exponent {:.2}; shared exponential-distance fog is a bounded approximation (Source2 gradient shader still pending).",
            fog.start_distance,fog.end_distance,scene.fog.as_ref().map(|f|f.color),
            fog.falloff_exponent,fog.source_height_enabled,
            fog.source_start_height,fog.source_end_height,fog.vertical_exponent
        ));
    }
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
                            let faces=if let Some(tint)=source_sky_tint{
                                tint_source_sky_faces(faces,tint)
                            }else{faces};
                            let faces=crate::cubemap_axis::source_z_up_to_engine_y_up(faces)?;
                            let intensity=source_sky_brightness.unwrap_or(1.).clamp(0.,16.);
                            scene.sky=Some(NeutralSky{faces,intensity,cycle:None});
                            scene.report.lines.push(format!(
                                "CS2 ORIGINAL SKY: source-authored BC1/BC6H cubemap {} decoded into 6 original faces, env_sky brightnessscale={} tint={:?} now applied in shared renderer (source sky.vfx exposure/image-space parity pending).",
                                path,intensity,source_sky_tint
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
    // Validate original Source 2 lightmap channel identity and native
    // texture-array layout. Original channels must NOT become generic RGBM.
    let atlas=lightmap::audit(&packages,&graph.lighting_textures,graph.lightmap_version);
    let atlas_files=atlas.channels.iter().map(|(slot,entry)|format!(
        "{slot}={} [{}x{} layers={} fmt={} mips={}]",
        entry.path,entry.meta.width,entry.meta.height,entry.meta.depth,
        entry.meta.format,entry.meta.mips
    )).collect::<Vec<_>>().join("; ");
    scene.report.lines.push(format!(
        "CS2 ORIGINAL BAKED LIGHTMAP ATLAS: shader version {}.{}, {}/{} required channels found, matching dimensions/layers={}, complete={}; authored TEXCOORD3 UV scale {:?}. Source VTEX array layers have an independent lossless BCn decoding path. Directional SH and shadow-mask shader translation / GPU array sampling are pending: channels are NOT generic RGBM. Channels: {}. Errors: {}",
        atlas.version[0],atlas.version[1],atlas.channels.len(),atlas.expected_channels.len(),
        atlas.matching_atlas_layout,atlas.complete,graph.lightmap_uv_scale,atlas_files,
        atlas.errors.iter().take(12).cloned().collect::<Vec<_>>().join("; ")
    ));
    let census=packages.audit(untextured.iter().map(String::as_str));
    // Rank SOURCE-AUTHORED VMAT feature signatures to prioritize actual
    // original VCS shader/permutation and ABI recovery. These are *not*
    // already translated or compiled shader programs.
    let top_signatures=census.ranked_feature_signatures().into_iter().take(12)
        .map(|(signature,count)|format!(
            "{count} material(s) {} switches={:?} texture_slots={:?}",
            signature.shader,signature.switches,signature.texture_slots
        )).collect::<Vec<_>>().join("; ");
    scene.report.lines.push(format!(
        "CS2 P0 SHADER TRANSLATION FRONTIER: {} referenced VMAT identities, {} source shader families, {} distinct authored VMAT switch/slot signatures (NOT compiled VCS permutations). {} packed normal/roughness, {} second-colour-layer, {} authored metalness, {} authored roughness, {} authored translucent/alpha-tested, {} missing VTEX. Exact VCS permutation decoding and surface-program admission are NOT implemented; 0 verified complete CS2 shader programs. Top source feature candidates: {}",
        census.referenced,census.shaders.len(),census.feature_signatures.len(),
        census.packed_normal_roughness,census.second_color_layer,
        census.authored_metalness,census.authored_roughness,
        census.authored_translucency_or_alpha_test,census.material_with_missing_vtex,
        top_signatures
    ));
    // VCS executable shader files are indexed independently from VMAT
    // authoring. This identifies actual source byte ownership and stable
    // header hashes; it does NOT select combos or bind a SurfaceProgram.
    let vcs=crate::vcs::audit(&packages,census.shaders.keys().map(String::as_str));
    // Link compiler-defined static combo *names and ranges* to authored VMAT
    // integer parameters. This is a constrained feature frontier, not a
    // selected VCS shader blob or a runnable SurfaceProgram.
    let source_materials=untextured.iter()
        .filter_map(|path|packages.describe(path).ok()).collect::<Vec<_>>();
    let selected=crate::vcs_selection::audit_materials(source_materials.iter(),&vcs);
    scene.report.lines.push(format!(
        "CS2 VCS STATIC SELECTION FRONTIER: {}/{} resolved VMATs have a readable original ABI-compatible VS/PS pair ({} candidate source pairs). {} VMATs constrain every compiler static feature by exact named value or compiler singleton, {} still have unresolved static values, {} have only invalid/out-of-range candidates; {} material candidate sets exceeded bounded pairing. These are candidate constraints, NOT native compiled permutation IDs or executed SurfacePrograms (0 admitted). Samples: {}. Missing: {}",
        selected.vmats_with_abi_pair,selected.vmats_checked,
        selected.compatible_pairs,selected.vmats_with_closed_static_values,
        selected.vmats_with_unresolved_values,selected.vmats_with_invalid_values,
        selected.candidate_pairs_truncated,
        selected.examples.join("; "),selected.missing_examples.join("; ")
    ));
    let named=vcs.sources.iter().filter(|row|row.header.is_some()).take(24)
        .map(|row|format!(
            "{}:{}:{}:{} v{} [{}]",
            row.identity.family,row.identity.platform,row.identity.shader_model,
            row.identity.stage,row.header.as_ref().unwrap().version,row.origin
        )).collect::<Vec<_>>().join("; ");
    // Count decoded original static combo definitions separately from
    // VMAT-authored guesses and from shader-program admission.
    let native_combo_definitions=vcs.sources.iter().filter_map(|s|s.header.as_ref())
        .map(|header|header.static_combo_definitions.len()).sum::<usize>();
    let combo_examples=vcs.sources.iter().filter_map(|row|
        row.header.as_ref().map(|header|(&row.identity,header))
    ).filter(|(_,hdr)|!hdr.static_combo_definitions.is_empty()).take(6)
        .map(|(identity,header)|format!("{}:{} [{}]",
            identity.family,identity.stage,
            header.static_combo_definitions.iter().take(12)
                .map(|c|format!("{}({}..{})",c.name,c.range_min,c.range_max))
                .collect::<Vec<_>>().join(", ")
        )).collect::<Vec<_>>().join("; ");
    let failures=vcs.sources.iter().filter_map(|row|row.error.as_ref()
        .map(|error|format!("{}: {error}",row.path))).take(12)
        .collect::<Vec<_>>().join("; ");
    scene.report.lines.push(format!(
        "CS2 ORIGINAL COMPILED VCS CENSUS: {} source shader families; {} have indexed VCS files, {} have both readable VS+PS headers. {} listed VCS stage files, {} readable VCS headers, {} indexed-but-missing physical files, {} unsupported headers; {} authentic static combo definition(s) recovered from complete VCS2/Resource files. Source-selected static combo IDs, shader ops and renderer SurfaceProgram admission remain pending (0 fully admitted). Combo samples: {}. Stage samples: {}. Missing families: {:?}. Failures: {}",
        vcs.expected_families,vcs.found_families,vcs.families_with_vertex_and_pixel,
        vcs.files_listed,vcs.verified_headers,vcs.missing_physical_file,vcs.unsupported_headers,
        native_combo_definitions,combo_examples,
        named,vcs.missing_families.iter().take(12).collect::<Vec<_>>(),failures
    ));
    let bound=bindings::bind(&mut scene,&packages);
    scene.report.lines.push(format!(
        "CS2 ORIGINAL EFFECT SHADING: {} additive and {} alpha-blended csgo_effects.vfx material(s); {} composited with 1-3 original VTEX masks, {} used exact source opacity scale, {} other VMATs have authored translucency and {} have authored alpha-test reference. Mask UV animation, camera Fresnel/fade/depth-feather remain pending.",
        bound.additive_effect_materials,bound.non_additive_effect_materials,
        bound.original_effect_masks_combined,bound.source_effect_opacity_scaled,
        bound.authored_translucent_materials,bound.authored_alpha_test_materials
    ));
    scene.report.lines.push(format!(
        "CS2 ACTUAL VTEX MATERIAL INPUTS: {} original textures decoded ({} MiB decoded RGBA; limit {}), {}/{} original geometry materials with a source-backed base-color texture, {} generic normal bindings, {} unavailable/unsupported texture requests. {} material(s) have shader-proven source HemiOct tangent-space normal unpacking, {} also have authored BC7 roughness mapped into universal PBR, {} unsupported packed conversions. Original metalness scalar mapped on {} materials. Remaining semantics: Layer2 blend={} materials, packed source references={} materials, self-illumination={} materials. VCS permutation replay and baked lightmap shader integration remain incomplete. Failure samples: {}",
        bound.vtex_loaded,bound.total_rgba_bytes/(1024*1024),
        bound.budget_bytes.map(|bytes|format!("{} MiB",bytes/(1024*1024))).unwrap_or_else(||"disabled".into()),
        bound.materials_with_albedo,scene.materials.len(),bound.materials_with_normal,
        bound.vtex_failed,bound.source_hemi_normal_materials,
        bound.source_hemi_roughness_materials,bound.source_hemi_unsupported,
        bound.mapped_metalness,bound.authored_layer2,
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

#[cfg(test)]
mod authored_christmas_sky_tests {
    use super::*;
    #[test]
    fn source_sky_linear_tint_preserves_cube_faces_and_alpha(){
        let source=std::array::from_fn(|i|
            neutral_scene::NeutralTexture{
                name:format!("sky face {i}"),width:1,height:1,
                rgba:vec![255,255,255,255],mips:vec![],compressed:None
            });
        let tinted=tint_source_sky_faces(source,[206./255.,218./255.,1.]);
        for face in tinted {
            assert_eq!(face.rgba,[206,218,255,255]);
            assert_eq!(face.width,1);
            assert_eq!(face.height,1);
        }
    }
}
