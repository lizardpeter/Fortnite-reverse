//! Runner-only evidence test. All original compiled shader bytes remain
//! outside Git and are retrieved from source-verified Actions artifacts.
use std::path::Path;
use cs2_importer::vcs_native::{NativeFormat,NativeVcsIndex,recover_original_gpu_program};
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
        println!("CERTIFIED_ORIGINAL_GPU_CODE {filename} static={} dynamic={} type={:?} bytes={} compiler_hash={:02x?}",
            result.source_static_id,result.source_dynamic_id,result.format,
            result.bytecode.len(),result.compiler_hash);
    }
    Ok(())
}