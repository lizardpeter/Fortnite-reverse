//! Runner-only evidence test. All original compiled shader bytes remain
//! outside Git and are retrieved from source-verified Actions artifacts.
use std::path::Path;
use cs2_importer::vcs_native::{NativeFormat,recover_original_gpu_program};
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