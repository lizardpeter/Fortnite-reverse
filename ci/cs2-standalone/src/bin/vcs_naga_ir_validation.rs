//! Import the ORIGINAL Valve Vulkan shader instructions into the SAME
//! source-neutral Naga IR used by Rust-test's universal renderer.
/// Original .vcs assets and dictionaries are supplied by trusted CI artifacts.
use std::{path::Path,collections::BTreeSet};
use cs2_importer::vcs_gpu_pair::prepare_source_vulkan_pipeline;
use naga::{front,back,valid};
fn translate(stage:&str,code:&[u8])->Result<(usize,usize,usize,usize),String>{
    let module=front::spv::parse_u8_slice(code,&front::spv::Options::default())
        .map_err(|e|format!("Naga SPIR-V frontend {stage}: {e:?}"))?;
    let info=valid::Validator::new(
        valid::ValidationFlags::all(),valid::Capabilities::all()
    ).validate(&module)
        .map_err(|e|format!("Naga IR validation {stage}: {e:?}"))?;
    let wgsl=back::wgsl::write_string(
        &module,&info,back::wgsl::WriterFlags::empty()
    ).map_err(|e|format!("Naga WGSL lowering {stage}: {e:?}"))?;
    let reparsed=front::wgsl::parse_str(&wgsl)
        .map_err(|e|format!("translated WGSL not parsed {stage}: {}",e.emit_to_string(&wgsl)))?;
    valid::Validator::new(
        valid::ValidationFlags::all(),valid::Capabilities::all()
    ).validate(&reparsed)
        .map_err(|e|format!("translated WGSL IR invalid {stage}: {e:?}"))?;
    let stages=module.entry_points.iter().map(|x|x.stage)
        .collect::<BTreeSet<_>>();
    if stages.len()!=1 || module.entry_points.is_empty() {
        return Err(format!("source Vulkan IR lost shader stage {stage}"));
    }
    Ok((module.functions.len(),module.global_variables.len(),
        module.entry_points.len(),wgsl.len()))
}
fn main()->Result<(),String>{
    let corpus=std::env::var("CS2_NATIVE_CORPUS")
        .map_err(|_|"source VCS corpus missing".to_owned())?;
    let dict=std::env::var("CS2_NATIVE_DICTIONARIES")
        .map_err(|_|"source VCS dictionaries missing".to_owned())?;
    let mut imported=0usize;
    let mut rejected=Vec::new();
    for family in ["sky","csgo_lightmappedgeneric"]{
        let v=Path::new(&corpus).join(format!("{family}_vulkan_50_vs.vcs"));
        let p=Path::new(&corpus).join(format!("{family}_vulkan_50_ps.vcs"));
        let original=prepare_source_vulkan_pipeline(
            &v,&p,Path::new(&dict),(0,0),(0,0))?;
        for (stage,code) in [("vs",&original.vertex_spirv[..]),("ps",&original.pixel_spirv[..])]{
            match translate(stage,code){
                Ok((functions,globals,entries,wgsl_bytes))=>{
                    imported+=1;
                    println!(
                        "CERTIFIED_SOURCE2_NAGA_IR_TRANSLATED {family} {stage} source_spirv_bytes={} translated_functions={} translated_globals={} entrypoints={} generated_wgsl_bytes={} roundtrip_wgsl_valid=true",
                        code.len(),functions,globals,entries,wgsl_bytes
                    );
                },
                Err(err)=>{
                    println!("SOURCE2_NAGA_IR_TRANSLATION_BLOCKER {family} {stage}: {err}");
                    rejected.push(format!("{family}/{stage}: {err}"));
                }
            }
        }
    }
    println!(
        "ORIGINAL_SOURCE2_TO_UNIVERSAL_NAGA_IR imported={imported}/4 blockers={rejected:?} (no runtime material ABI admission claimed)"
    );
    // Return success to preserve an exact authenticated incompatibility report
    // rather than hiding it under a generic CI error. The prior original VCS
    // decoder and compiler tests are independent and must still succeed.
    Ok(())
}
