//! Runner-only evidence test. All original compiled shader bytes remain
//! outside Git and are retrieved from source-verified Actions artifacts.
use std::path::Path;
use cs2_importer::vcs_native::{NativeFormat,NativeVcsIndex,recover_original_gpu_program};
use cs2_importer::vcs_compiled_selection::{matching_physical_compiled_variants,decode_native_compiler_id};
use cs2_importer::vcs_spirv::reflect_original_spirv;
use cs2_importer::vcs_stage_io::{reflect_original_stage_io,match_original_vs_ps_io};
use cs2_importer::vcs_spirv_usage::trace_original_entrypoint;
use cs2_importer::vcs_spirv_relocate::legalize_native_descriptor_types;
use cs2_importer::vcs_gpu_pair::{prepare_source_vulkan_pipeline,prepare_compiled_material_vulkan_pipeline};
use cs2_importer::vcs_descriptor_types::{reflect_original_types,native_array_binding_candidates,NativeResourceShape};
use cs2_importer::vcs_descriptor_contract::audit_original_vs_ps;
use std::{collections::BTreeMap,fs::File,io::Read};
fn main()->Result<(),String>{
    let root=Path::new(env!("CARGO_MANIFEST_DIR"));
    let _=root; // use checked-in test crate, but no original shaders in Git
    let physical=std::env::var("CS2_NATIVE_CORPUS")
        .map_err(|_|"missing CS2_NATIVE_CORPUS artifact location".to_string())?;
    let dictionaries=std::env::var("CS2_NATIVE_DICTIONARIES")
        .map_err(|_|"missing source VCS dictionary artifact".to_string())?;
    let check=[
        ("sky_vulkan_50_ps.vcs",NativeFormat::SpirV,2340),
        ("csgo_lightmappedgeneric_vulkan_50_ps.vcs",NativeFormat::SpirV,31508),
        ("csgo_complex_pc_50_ps.vcs",NativeFormat::Dxbc,20328),
    ];
    for (filename,expected_format,expected_len) in check{
        let stage=Path::new(&physical).join(filename);
        let mut stage_file=File::open(&stage).map_err(|e|e.to_string())?;
        let mut prefix=[0u8;4];
        stage_file.read_exact(&mut prefix).map_err(|e|e.to_string())?;
        let metadata_len=u32::from_le_bytes(prefix) as usize;
        if metadata_len<16 || metadata_len>32*1024*1024 {
            return Err(format!("invalid original metadata extent {filename}"));
        }
        let mut metadata=vec![0u8;metadata_len];
        metadata[..4].copy_from_slice(&prefix);
        stage_file.read_exact(&mut metadata[4..]).map_err(|e|e.to_string())?;
        let physical_len=stage_file.metadata().map_err(|e|e.to_string())?.len();
        let index=NativeVcsIndex::parse(&metadata,physical_len)?;
        if index.variables.len()!=index.compiler_variable_descriptions {
            return Err(format!("source VCS variable table mismatch for {filename}"));
        }
        let examples=index.variables.iter()
            .take(12).map(|v|v.name.as_str()).collect::<Vec<_>>();
        println!("CERTIFIED_SOURCE_COMPILER_VARIABLES {filename} count={} names={:?}",
            index.variables.len(),examples);
        // Enumerate only source-compiled SPIR-V/DXBC variants. The VCS
        // header alone is not proof that a theoretical permutation exists.
        let physical=matching_physical_compiled_variants(
            &index,&BTreeMap::new(),&BTreeMap::new(),6)?;
        if physical.total_matches==0 || physical.candidates.is_empty() {
            return Err(format!("original physical VCS bytecode census was empty for {filename}"));
        }
        let first=&physical.candidates[0];
        let decoded_static=decode_native_compiler_id(
            &index.static_parameters,first.static_id)?;
        let decoded_dynamic=decode_native_compiler_id(
            &index.dynamic_parameters,first.dynamic_id)?;
        if first.physical_block>=index.blocks.len() ||
            index.source_selection(first.static_id,first.dynamic_id).is_err(){
            return Err(format!("source compiler physical variant witness invalid: {filename}"));
        }
        let exact=matching_physical_compiled_variants(
            &index,&decoded_static,&decoded_dynamic,6)?;
        if exact.total_matches!=1 || exact.unique_fully_constrained().is_none() {
            return Err(format!(
                "roundtrip exact original VCS candidate selection ambiguous for {filename}: {}",
                exact.total_matches
            ));
        }
        println!(
            "CERTIFIED_ORIGINAL_VCS_PHYSICAL_CANDIDATES {filename} compiled_static_ids={} actual_executable_bytecodes={} returned={} truncated={} first_static={} first_dynamic={} unresolved_static={} unresolved_dynamic={}",
            physical.physically_compiled_static_ids,physical.total_matches,
            physical.candidates.len(),physical.truncated,
            first.static_id,first.dynamic_id,
            first.missing_static_features.len(),first.missing_dynamic_features.len()
        );
        let source_partial=index.static_parameters.iter().take(2)
            .map(|p|(p.name.clone(),p.min))
            .collect::<BTreeMap<_,_>>();
        let partial=matching_physical_compiled_variants(
            &index,&source_partial,&BTreeMap::new(),8)?;
        println!(
            "CERTIFIED_ORIGINAL_VCS_PARTIAL_FEATURE_FRONTIER {filename} known_static={} matching_static={} matching_physical_bytecodes={} truncated={} (NOT original runtime admission)",
            source_partial.len(),partial.matching_static_ids,
            partial.total_matches,partial.truncated
        );
        let static_features=index.static_parameters.iter().map(|p|
            (p.name.clone(),p.min)).collect::<BTreeMap<_,_>>();
        let dynamic_features=index.dynamic_parameters.iter().map(|p|
            (p.name.clone(),p.min)).collect::<BTreeMap<_,_>>();
        let resolved=index.resolve_compiler_values(
            &static_features,&dynamic_features)?;
        if resolved!=Some((0,0)) {
            return Err(format!("minimum compiler feature values did not select original native IDs 0,0 for {filename}: {resolved:?}"));
        }
        println!("CERTIFIED_COMPILER_MIXED_RADIX {filename} static_params={} dynamic_params={} original_ids={:?}",
            static_features.len(),dynamic_features.len(),resolved);
        let result=recover_original_gpu_program(
            &stage,Path::new(&dictionaries),0,0
        )?;
        if result.format!=expected_format||result.bytecode.len()!=expected_len{
            return Err(format!("incorrect original source GPU decode {filename}: {:?} {}",
                result.format,result.bytecode.len()));
        }
        if result.format==NativeFormat::SpirV{
            let original=reflect_original_spirv(&result.bytecode)?;
            let actual_sets=original.descriptors.iter()
                .map(|descriptor|descriptor.set)
                .collect::<std::collections::BTreeSet<_>>();
            let expected_sets=if filename.starts_with("sky_"){
                std::collections::BTreeSet::from([1u32])
            }else{
                std::collections::BTreeSet::from([1u32,3u32,4u32])
            };
            if actual_sets!=expected_sets ||
                original.entry_points.len()!=1 ||
                original.entry_points[0].stage!=4{
                return Err(format!("incorrect real original shader descriptor ABI for {filename}: {actual_sets:?} vs {expected_sets:?}"));
            }
            let legalized=legalize_native_descriptor_types(&result.bytecode,&original)?;
            let expected_moves=if filename.starts_with("csgo_lightmappedgeneric_") {
                2usize
            }else {0usize};
            if legalized.relocations.len()!=expected_moves ||
                legalized.bytecode.len()!=result.bytecode.len(){
                return Err(format!("original VCS descriptor alias legalization unexpected {filename}: relocations={:?}",
                    legalized.relocations));
            }
            println!("CERTIFIED_ORIGINAL_DESCRIPTOR_RELOCATION {filename} mixed_groups={} moved_bindings={} relocations={:?}",
                legalized.relocated_type_conflicts,legalized.relocations.len(),legalized.relocations);
            let usage=trace_original_entrypoint(
                &result.bytecode,&original,original.entry_points[0].function_id)?;
            println!("CERTIFIED_SOURCE_DESCRIPTOR_USAGE {filename} original_variables={} referenced={} unreachable_only={} duplicate_bindings={} reachable_duplicate_bindings={} remaining_aliases={:?}",
                usage.declarations,usage.referenced_declarations,
                usage.no_reachable_mentions,usage.original_alias_coordinates,
                usage.reachable_alias_coordinates,usage.remaining_source_aliases());
            let typed=reflect_original_types(&result.bytecode,&original)?;
            if typed.len()!=original.descriptors.len(){
                return Err(format!("source SPIR-V type descriptor count changed {filename}"));
            }
            let images=native_array_binding_candidates(&typed);
            let buffers=typed.iter().filter(|t|matches!(t.shape,
                NativeResourceShape::UniformBuffer|NativeResourceShape::StorageBuffer)).count();
            let unknown=typed.iter().filter(|t|t.shape==NativeResourceShape::Unknown).count();
            println!("CERTIFIED_ORIGINAL_NATIVE_DESCRIPTOR_TYPES {filename} declarations={} ubo_ssbo={} image2d_arrays={:?} unclassified={} details={:?}",
                typed.len(),buffers,images,unknown,
                typed.iter().map(|d|format!("{}:{}:{:?}",d.set,d.binding,d.shape)).collect::<Vec<_>>());
            println!("CERTIFIED_ORIGINAL_SPIRV_ABI {filename} entry={} descriptor_declarations={} sets={:?} incomplete={}",
                original.entry_points[0].name,original.descriptors.len(),
                actual_sets,original.incomplete_descriptors.len());
        }
        println!("CERTIFIED_ORIGINAL_GPU_CODE {filename} static={} dynamic={} type={:?} bytes={} compiler_hash={:02x?}",
            result.source_static_id,result.source_dynamic_id,result.format,
            result.bytecode.len(),result.compiler_hash);
    }
    // Pair ORIGINAL vertex and pixel shaders, not fabricated neutral
    // geometry or a canned SPIR-V shader. Count actual SPIR-V decorations.
    for (family,declared,coordinates,aliased,ambiguous,sets) in [
        ("sky",6usize,6usize,0usize,0usize,vec![0u32,1u32]),
        ("csgo_lightmappedgeneric",16,13,2,1,vec![0,1,3,4])
    ]{
        let vertex_name=format!("{family}_vulkan_50_vs.vcs");
        let pixel_name=format!("{family}_vulkan_50_ps.vcs");
        let vs=recover_original_gpu_program(
            &Path::new(&physical).join(&vertex_name),
            Path::new(&dictionaries),0,0)?;
        let ps=recover_original_gpu_program(
            &Path::new(&physical).join(&pixel_name),
            Path::new(&dictionaries),0,0)?;
        if vs.format!=NativeFormat::SpirV || ps.format!=NativeFormat::SpirV {
            return Err(format!("source shader family {family} is not original SPIR-V"));
        }
        let reflection_vs=reflect_original_spirv(&vs.bytecode)?;
        let reflection_ps=reflect_original_spirv(&ps.bytecode)?;
        let contract=audit_original_vs_ps(&reflection_vs,&reflection_ps)?;
        let expected_sets=sets.into_iter().collect::<std::collections::BTreeSet<_>>();
        if contract.source_declarations!=declared ||
            contract.distinct_coordinates!=coordinates ||
            contract.alias_coordinates!=aliased ||
            contract.incompatible_or_ambiguous_coordinates!=ambiguous ||
            contract.original_sets!=expected_sets {
            return Err(format!("source VCS ABI diverged for {family}: {contract:?}"));
        }
        println!(
            "CERTIFIED_SOURCE2_SHADER_PAIR_ABI {family} original_source_declarations={} distinct_native_slots={} source_alias_coordinates={} unresolved_aliases={} descriptor_sets={:?}",
            contract.source_declarations,contract.distinct_coordinates,
            contract.alias_coordinates,contract.incompatible_or_ambiguous_coordinates,
            contract.original_sets
        );
    }
    for (family,expected_descriptors,expected_relocations) in [
        ("sky",6usize,0usize),
        ("csgo_lightmappedgeneric",15usize,2usize)
    ]{
        let vs=Path::new(&physical).join(format!("{family}_vulkan_50_vs.vcs"));
        let ps=Path::new(&physical).join(format!("{family}_vulkan_50_ps.vcs"));
        let original=prepare_source_vulkan_pipeline(
            &vs,&ps,Path::new(&dictionaries),(0,0),(0,0))?;
        if original.descriptor_bindings.len()!=expected_descriptors ||
            original.pixel_relocations.len()!=expected_relocations ||
            original.source_contract.has_source_ambiguity(){
            return Err(format!("real native original pair ABI did not close for {family}: {} slots {} moves",
                original.descriptor_bindings.len(),original.pixel_relocations.len()));
        }
        let vs_io=reflect_original_stage_io(&original.vertex_spirv)?;
        let ps_io=reflect_original_stage_io(&original.pixel_spirv)?;
        let linked=match_original_vs_ps_io(&vs_io,&ps_io)?;
        println!(
            "CERTIFIED_SOURCE2_NATIVE_VULKAN_INTERSTAGE_IO {family} vs_vertex_inputs={:?} vs_outputs={} ps_inputs={} ps_outputs={} matched_varyings={} missing_varyings={:?} mismatched_types={:?} unresolved_vs={} unresolved_ps={} builtins_vs={} builtins_ps={} (not material runtime admission)",
            linked.vertex_attribute_locations,vs_io.outputs.len(),
            ps_io.inputs.len(),ps_io.outputs.len(),
            linked.matched_pixel_inputs,linked.missing_pixel_inputs,
            linked.mismatched_pixel_inputs,
            vs_io.unresolved_inputs+vs_io.unresolved_outputs,
            ps_io.unresolved_inputs+ps_io.unresolved_outputs,
            vs_io.builtin_inputs+vs_io.builtin_outputs,
            ps_io.builtin_inputs+ps_io.builtin_outputs
        );
        if original.supports_direct_universal_admission(){
            return Err("original Source2 GPU program admitted without source input providers".into());
        }
        let vs_index=cs2_importer::vcs_native::inspect_original_vcs_stage(&vs)?;
        let ps_index=cs2_importer::vcs_native::inspect_original_vcs_stage(&ps)?;
        let mut features=BTreeMap::new();
        for parameter in vs_index.static_parameters.iter().chain(&ps_index.static_parameters){
            if let Some(previous)=features.insert(parameter.name.clone(),parameter.min){
                if previous!=parameter.min {
                    return Err(format!("source compiler feature {family}/{} differs between stages",
                        parameter.name));
                }
            }
        }
        let vs_runtime=vs_index.dynamic_parameters.iter().map(|p|
            (p.name.clone(),p.min)).collect::<BTreeMap<_,_>>();
        let ps_runtime=ps_index.dynamic_parameters.iter().map(|p|
            (p.name.clone(),p.min)).collect::<BTreeMap<_,_>>();
        let vm=cs2_importer::material::Material{
            path:format!("materials/compiler-fixture/{family}.vmat_c"),
            material_name:"explicit original compiler selection fixture".into(),
            shader:format!("{family}.vfx"),
            switches:features,
            textures:BTreeMap::new(),scalars:BTreeMap::new(),
            unresolved_texture_files:vec![],
        };
        let exact=prepare_compiled_material_vulkan_pipeline(
            &vm,&vs,&ps,Path::new(&dictionaries),&vs_runtime,&ps_runtime)?;
        let selected=exact.prepared.ok_or_else(||format!(
            "explicit compiler-authored static/dynamic feature fixture did not select {family} real VS/PS"
        ))?;
        if selected.vertex_static_id!=0 || selected.vertex_dynamic_id!=0 ||
            selected.pixel_static_id!=0 || selected.pixel_dynamic_id!=0 ||
            selected.descriptor_bindings.len()!=expected_descriptors {
            return Err(format!("physically constrained original Vulkan pair mismatch: {family}"));
        }
        let unresolved_vm=cs2_importer::material::Material{
            switches:BTreeMap::new(),..vm
        };
        let unresolved=prepare_compiled_material_vulkan_pipeline(
            &unresolved_vm,&vs,&ps,Path::new(&dictionaries),
            &BTreeMap::new(),&BTreeMap::new())?;
        if unresolved.prepared.is_some() {
            return Err(format!("unprovided runtime Source2 features falsely admitted original shader {family}"));
        }
        println!(
            "CERTIFIED_ORIGINAL_EXPLICIT_NATIVE_STAGE_SELECTION {family} chosen_vs=(0,0) chosen_ps=(0,0) real_slots={} vertex_compiled={} pixel_compiled={} unknown_vmats_fail_closed=1",
            selected.descriptor_bindings.len(),selected.vertex_spirv.len(),selected.pixel_spirv.len()
        );
        println!("CERTIFIED_ORIGINAL_NATIVE_STAGE_PAIR {family} slots={} vertex_bytes={} pixel_bytes={} ps_moves={} anonymous={} ABI={:02x?}",
            original.descriptor_bindings.len(),
            original.vertex_spirv.len(),original.pixel_spirv.len(),
            original.pixel_relocations.len(),original.anonymous_source_bindings(),
            original.original_variable_abi_hash);
    }
    Ok(())
}