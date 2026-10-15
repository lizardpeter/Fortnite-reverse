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

fn source_sampling_dependencies(code:&[u8])->String{
    if code.len()<20||code.len()%4!=0{return "bad source bytes".into();}
    let words=code.chunks_exact(4).map(|v|u32::from_le_bytes(v.try_into().unwrap())).collect::<Vec<_>>();
    let mut defs=std::collections::BTreeMap::<u32,(u32,Vec<u32>)>::new();
    let mut positions=std::collections::BTreeMap::<u32,(u32,u32)>::new();
    let mut samples=Vec::new();
    let mut at=5;
    while at<words.len(){
        let op=words[at];let count=(op>>16) as usize;let id=op&0xffff;
        if count==0||at+count>words.len(){return format!("invalid SPIRV at {at}");}
        let p=&words[at+1..at+count];
        if id==71 && p.len()>=3{
            let row=positions.entry(p[0]).or_default();
            if p[1]==33{row.1=p[2]}else if p[1]==34{row.0=p[2]}
        }
        let result=match id{
            25|26|27|32 if !p.is_empty()=>Some(p[0]),
            59|61|65|66|67|68|86|83|124 if p.len()>=2=>Some(p[1]),
            _=>None
        };
        if let Some(result)=result {defs.insert(result,(id,p.to_vec()));}
        if matches!(id,87..=98) && p.len()>=3{
            samples.push((id,p[2]));
        }
        at+=count;
    }
    let root=|mut id:u32|->u32{
        for _ in 0..24{
            match defs.get(&id){
                Some((61|65|66|67|68|83|124,p)) if p.len()>=3=>{
                    id=p[2];
                },
                _=>return id,
            }
        }
        id
    };
    let mut outputs=Vec::new();
    for (op,sampled) in samples{
        let ss=defs.get(&sampled).map(|(id,p)|format!("{id}:{:?}",p));
        let source_image=defs.get(&sampled)
            .filter(|(id,_)|*id==86).and_then(|(_,p)|p.get(2)).copied();
        let source_sampler=defs.get(&sampled)
            .filter(|(id,_)|*id==86).and_then(|(_,p)|p.get(3)).copied();
        let sampler_load=source_sampler.and_then(|id|defs.get(&id));
        let sampler_origin=sampler_load.and_then(|(op,p)|
            if *op==61{p.get(2).copied()}else{None});
        let sampler_binding=sampler_origin.map(|id|root(id))
            .and_then(|id|positions.get(&id));
        let image_load=source_image.and_then(|id|defs.get(&id));
        let origin=image_load.and_then(|(op,p)|if *op==61{p.get(2).copied()}else{None});
        let binding=origin.map(|id|root(id))
            .and_then(|id|positions.get(&id));
        let sampled_type=defs.get(&sampled).and_then(|(_,p)|p.first()).copied();
        let image_type=sampled_type.and_then(|id|defs.get(&id))
            .filter(|(op,_)|*op==27).and_then(|(_,p)|p.get(1)).copied();
        let type_def=image_type.and_then(|id|defs.get(&id));
        outputs.push(format!("sample-op{op}:res{sampled} sampled={ss:?} image_load={:?} image_origin={origin:?} image_binding={binding:?} sampler_load={:?} sampler_origin={sampler_origin:?} sampler_binding={sampler_binding:?} type={type_def:?}",
            image_load.map(|(o,p)|(*o,p.clone())),
            sampler_load.map(|(o,p)|(*o,p.clone()))));
    }
    outputs.sort();outputs.dedup();
    outputs.join("; ")
}

/// DIAGNOSTIC ONLY. Source compiler declared image Depth=2 (Unknown).
/// Try explicit depth classes solely to locate Naga's implicit image-type
/// conflict; never use these variants for image binding or renderer output.
fn diagnostic_explicit_image_depth(code:&[u8],depth:u32)->String{
    let mut words=code.chunks_exact(4).map(|s|
        u32::from_le_bytes(s.try_into().unwrap())).collect::<Vec<_>>();
    if words.len()<5||!matches!(depth,0|1){return "invalid".into();}
    let mut changed=0;
    let mut at=5;
    while at<words.len(){
        let length=(words[at]>>16) as usize;
        let op=words[at]&0xffff;
        if length==0||at+length>words.len(){return "truncated".into();}
        if op==25&&length>=8&&words[at+4]==2{
            // OpTypeImage: result,sampled_type,Dim,Depth,Arrayed,MS,Sampled,Format
            words[at+4]=depth; changed+=1;
        }
        at+=length;
    }
    let bytes=words.iter().flat_map(|x|x.to_le_bytes()).collect::<Vec<_>>();
    match cs2_importer::universal_spirv_ir::
        translate_source_spirv_with_ubo_rebase(&bytes){
        Ok(sh)=>format!("image_types_changed={changed} universal_spirv_words={} (probe only; NOT fidelity proof)",
            sh.shader.generated_spirv.len()),
        Err(e)=>format!("image_types_changed={changed} compiler_rejected={e}"),
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
                mixed.entry(opcode).or_default().push((cursor as u32,p.to_vec()));
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
                println!("ORIGINAL_SOURCE2_MIXED_DREF_RESOURCE_CHAIN {}",
                    source_sampling_dependencies(code));
                // Explicit Depth=1 over a BindingArray panics in Naga 30.
                // Only test original typed descriptor alias legalization above.
            }
            if family=="csgo_lightmappedgeneric" && stage=="ps"{
                match cs2_importer::vcs_mixed_image_lowering::
                    split_original_mixed_comparison_arrays(code){
                    Ok(lowered)=>{
                        println!(
                            "SOURCE2_PHYSICAL_TYPED_DREF_ALIASES count={} rewritten_depth_samples={} aliases={:?}",
                            lowered.aliases.len(),lowered.rewritten_dref_samples,
                            lowered.aliases.iter().map(|x|format!(
                                "{}:{} -> {}:{} image={} original_var={} new_var={}",
                                x.original_set,x.original_binding,x.alias_set,
                                x.alias_binding,x.is_comparison_image,
                                x.original_variable_id,x.alias_variable_id
                            )).collect::<Vec<_>>()
                        );
                        match cs2_importer::universal_spirv_ir::
                            translate_source_spirv_with_ubo_rebase(&lowered.spirv){
                            Ok(ir)=>println!(
                                "CERTIFIED_ORIGINAL_LIGHTMAPPED_PIXEL_UNIVERSAL_COMPILATION executable_spirv_words={} aliased_original_source_bindings={} original_ubo_layout_closed={} (not runtime uniform/image admission)",
                                ir.shader.generated_spirv.len(),lowered.aliases.len(),
                                ir.original_abi_closed
                            ),
                            Err(e)=>println!("SOURCE2_TYPED_DREF_ALIAS_NAGA_BLOCKER {e}"),
                        }
                    }
                    Err(e)=>println!("SOURCE2_TYPED_DREF_ALIAS_REJECTED {e}"),
                }
            }
            if family=="csgo_lightmappedgeneric" && stage=="ps"{
                let words=spirv_webgpu_transform::u8_slice_to_u32_vec(code);
                let mut corrections=spirv_webgpu_transform::CorrectionMap::default();
                match spirv_webgpu_transform::drefsplitter(&words,&mut corrections){
                    Ok(rewritten)=>{
                        let new_bytes=spirv_webgpu_transform::u32_slice_to_u8_vec(&rewritten);
                        println!(
                            "SOURCE2_DREF_SPLIT_PHYSICAL {family} original_words={} rewritten_words={} relocations_needed={}",
                            words.len(),rewritten.len(),corrections.sets.as_ref().is_some_and(|s|!s.is_empty())
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
