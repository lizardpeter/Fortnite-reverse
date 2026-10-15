//! Runner-only evidence test. All original compiled shader bytes remain
//! outside Git and are retrieved from source-verified Actions artifacts.
use std::path::Path;
use cs2_importer::vcs_native::{NativeFormat,NativeVcsIndex,recover_original_gpu_program};
use cs2_importer::vcs_spirv::reflect_original_spirv;
use cs2_importer::vcs_spirv_usage::trace_original_entrypoint;
use cs2_importer::vcs_spirv_relocate::legalize_native_descriptor_types;
use cs2_importer::vcs_gpu_pair::prepare_source_vulkan_pipeline;
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
        if original.supports_direct_universal_admission(){
            return Err("original Source2 GPU program admitted without source input providers".into());
        }
        println!("CERTIFIED_ORIGINAL_NATIVE_STAGE_PAIR {family} slots={} vertex_bytes={} pixel_bytes={} ps_moves={} anonymous={} ABI={:02x?}",
            original.descriptor_bindings.len(),
            original.vertex_spirv.len(),original.pixel_spirv.len(),
            original.pixel_relocations.len(),original.anonymous_source_bindings(),
            original.original_variable_abi_hash);
    }
    Ok(())
}