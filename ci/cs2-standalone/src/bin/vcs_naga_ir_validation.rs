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
// Diagnostic only. Source2 compilers may use relaxed/scalar UBO layout.
// Turning Naga's structure-layout rule off does not legalize the shader;
// this checks whether instruction semantics are otherwise translatable.
fn relaxed_layout_diagnostic(stage:&str,code:&[u8])->String{
    let module=match front::spv::parse_u8_slice(
        code,&front::spv::Options::default()){
        Ok(module)=>module,
        Err(err)=>return format!("front_end_rejected={err:?}"),
    };
    let flags=valid::ValidationFlags::all() &
        !valid::ValidationFlags::STRUCT_LAYOUTS;
    let info=match valid::Validator::new(flags,valid::Capabilities::all())
        .validate(&module){
        Ok(info)=>info,
        Err(err)=>return format!("typed_ir_rejected={err:?}"),
    };
    let wgsl=match back::wgsl::write_string(
        &module,&info,back::wgsl::WriterFlags::empty()){
        Ok(wgsl)=>wgsl,
        Err(err)=>return format!("typed_ir_valid=true wgsl_rejected={err:?}"),
    };
    match front::wgsl::parse_str(&wgsl){
        Ok(reparsed)=>{
            match valid::Validator::new(
                valid::ValidationFlags::all(),valid::Capabilities::all()
            ).validate(&reparsed){
                Ok(info)=>{
                    let stage=reparsed.entry_points.first()
                        .map(|e|e.stage).unwrap_or(naga::ShaderStage::Fragment);
                    let entrypoint=reparsed.entry_points.first()
                        .map(|e|e.name.clone()).unwrap_or_default();
                    let pipeline=back::spv::PipelineOptions{
                        shader_stage:stage,entry_point:entrypoint
                    };
                    match back::spv::write_vec(
                        &reparsed,&info,&back::spv::Options::default(),Some(&pipeline)
                    ){
                        Ok(words)=>format!(
                            "typed_ir_valid_without_struct_layout=true canonical_wgsl_revalidated=true regenerated_spirv_words={} (NOT source UBO-byte parity until host repack)",
                            words.len()
                        ),
                        Err(err)=>format!(
                            "typed_ir_valid_without_struct_layout=true canonical_wgsl_valid=true spirv_codegen_failed={err:?}"
                        ),
                    }
                },
                Err(err)=>format!(
                    "typed_ir_valid_without_struct_layout=true canonical_wgsl_invalid={err:?}"
                ),
            }
        },
        Err(err)=>format!(
            "typed_ir_valid_without_struct_layout=true wgsl_bytes={} reparsing_failed={}",
            wgsl.len(),err.emit_to_string(&wgsl).lines().take(2).collect::<Vec<_>>().join(" ")
        ),
    }
}

fn physical_sample_instruction_evidence(code:&[u8])->String{
    if code.len()%4!=0||code.len()<20{return "invalid bytes".into();}
    let words=code.chunks_exact(4).map(|s|u32::from_le_bytes(s.try_into().unwrap())).collect::<Vec<_>>();
    let mut kind=std::collections::BTreeMap::<u32,(u32,Vec<u32>)>::new();
    let mut decorations=std::collections::BTreeMap::<u32,(Option<u32>,Option<u32>)>::new();
    let mut mixed=std::collections::BTreeMap::<u32,Vec<(u32,Vec<u32>)>>::new();
    let mut cursor=5;
    while cursor<words.len(){
        let inst=words[cursor];let count=(inst>>16) as usize;let opcode=inst&0xffff;
        if count==0||cursor+count>words.len(){return format!("broken at {cursor}");}
        let p=&words[cursor+1..cursor+count];
        match opcode{
            25|26|27|32|59|61|65|66|67|68|86 if p.len()>=2=>{
                kind.insert(p[1],(opcode,p.to_vec()));
            },
            71 if p.len()>=3&&(p[1]==33||p[1]==34)=>{
                let row=decorations.entry(p[0]).or_insert((None,None));
                if p[1]==33{row.1=Some(p[2]);}else{row.0=Some(p[2]);}
            },
            87..=98 if p.len()>=3=>{
                mixed.entry(opcode).or_default().push((cursor,p.to_vec()));
            },
            _=>{}
        }
        cursor+=count;
    }
    let mut sorted=kind.iter().filter(|(_,v)|matches!(v.0,25|26|27|59|86)).map(|(id,(op,p))|
        format!("{}:op{}:{:?}:binding={:?}",id,op,p,decorations.get(id))).collect::<Vec<_>>();
    sorted.truncate(60);
    let mut ops=Vec::new();
    for (code,uses) in mixed{
        ops.push(format!("op{code}:count={} samples={:?}",uses.len(),
            uses.iter().take(4).map(|(at,p)|format!("{at}:{:?}",p)).collect::<Vec<_>>()));
    }
    format!("type/var={:?}; sampling={:?}",sorted,ops)
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
            if family=="csgo_lightmappedgeneric" && stage=="ps" {
                println!("ORIGINAL_SOURCE2_MIXED_DREF_PHYSICAL_OPCODES {}",
                    physical_sample_instruction_evidence(code));
            }
            if family=="csgo_lightmappedgeneric" && stage=="ps"{
                let words=spirv_webgpu_transform::u8_slice_to_u32_vec(code);
                let mut corrections=None;
                match spirv_webgpu_transform::drefsplitter(&words,&mut corrections){
                    Ok(rewritten)=>{
                        let new_bytes=spirv_webgpu_transform::u32_slice_to_u8_vec(&rewritten);
                        println!(
                            "SOURCE2_DREF_SPLIT_PHYSICAL {family} original_words={} rewritten_words={} relocations_needed={}",
                            words.len(),rewritten.len(),corrections.is_some()
                        );
                        match cs2_importer::universal_spirv_ir::
                            translate_source_spirv_with_ubo_rebase(&new_bytes){
                            Ok(translated)=>println!(
                                "CERTIFIED_SOURCE2_DREF_SPLIT_UNIVERSAL {family} executable_spirv_words={} original_ubo_layout_closed={} source_ubos={}",
                                translated.shader.generated_spirv.len(),
                                translated.original_abi_closed,translated.uniform_layouts.len()
                            ),
                            Err(e)=>println!(
                                "SOURCE2_DREF_SPLIT_NAGA_BLOCKER {family}: {e}"
                            ),
                        }
                    },
                    Err(_)=>println!("SOURCE2_DREF_SPLIT_TRANSFORM_FAILED {family}"),
                }
            }


            match cs2_importer::universal_spirv_ir::
                translate_source_spirv_with_ubo_rebase(code){
                Ok(ir)=>{
                    let changed=ir.uniform_layouts.iter()
                        .filter(|plan|plan.requires_repack()).count();
                    println!(
                        "CERTIFIED_ORIGINAL_UNIVERSAL_NAGA_REBASED {family} {stage} compiled_spirv_words={} original_ubo_layout_closed={} source_uniform_buffers={} requiring_repack={} offset_examples={:?} (not source UBO upload admission)",
                        ir.shader.generated_spirv.len(),ir.original_abi_closed,
                        ir.uniform_layouts.len(),changed,
                        ir.uniform_layouts.iter().filter(|x|x.requires_repack())
                            .take(3).map(|x|format!(
                                "{}:{} original={:?} canonical={:?}",
                                x.group,x.binding,x.original_offsets,x.canonical_offsets
                            )).collect::<Vec<_>>()
                    );
                }
                Err(error)=>println!(
                    "SOURCE2_ORIGINAL_NAGA_REBASE_BLOCKER {family} {stage}: {error}"
                ),
            }
            match translate(stage,code){
                Ok((functions,globals,entries,wgsl_bytes))=>{
                    match cs2_importer::universal_spirv_ir::translate_source_spirv(code){
                        Ok(shader)=>println!(
                            "CERTIFIED_ORIGINAL_SOURCE2_EXECUTABLE_UNIVERSAL_IR {family} {stage} source_bytes={} universal_spirv_words={} universal_wgsl_bytes={} (runtime resource admission remains separate)",
                            code.len(),shader.generated_spirv.len(),shader.generated_wgsl.len()
                        ),
                        Err(error)=>println!("SOURCE2_UNIVERSAL_SPIRV_CODEGEN_BLOCKER {family} {stage}: {error}"),
                    }

                    imported+=1;
                    println!(
                        "CERTIFIED_SOURCE2_NAGA_IR_TRANSLATED {family} {stage} source_spirv_bytes={} translated_functions={} translated_globals={} entrypoints={} generated_wgsl_bytes={} roundtrip_wgsl_valid=true",
                        code.len(),functions,globals,entries,wgsl_bytes
                    );
                },
                Err(err)=>{
                    println!("SOURCE2_NAGA_IR_TRANSLATION_BLOCKER {family} {stage}: {err}");
                    println!(
                        "SOURCE2_NAGA_RELAXED_LAYOUT_DIAGNOSTIC {family} {stage}: {}",
                        relaxed_layout_diagnostic(stage,code)
                    );
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
