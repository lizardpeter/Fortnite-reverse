//! Universal, game-agnostic imported SPIR-V shader IR.
 //!
 //! The original bytes are consumed by Naga's typed SPIR-V frontend, the
 //! same IR used by our shared material shader compiler. Shader output is
 //! validated as WGSL and recompiled as Vulkan SPIR-V. No guessing original
 //! UBO offsets, texture identities or ambient equations is allowed.
use naga::{self,back,front,valid};
const MAX_SOURCE_SPV:usize=64*1024*1024;
pub struct TranslatedSourceShader {
    /// Source-neutral validated code which can be compiled by the shared
    /// Vulkan shader module backend after provider/descriptor admission.
    pub generated_spirv:Vec<u32>,
    /// Debug/reference form of the exact typed source-neutral shader IR.
    pub generated_wgsl:String,
    pub stage:naga::ShaderStage,
    pub source_entrypoint:String,
    pub translated_globals:usize,
    pub translated_functions:usize,
}
/// Translate executable GPU instructions into validated Naga IR and back to
/// executable SPIR-V, not a metadata census or an approximate PBR substitute.
/// Fail closed if Naga cannot represent source scalar UBO packing or mixed
/// compare/noncompare sampling.
pub fn translate_source_spirv(input:&[u8])->Result<TranslatedSourceShader,String>{
    if input.len()<20 || input.len()>MAX_SOURCE_SPV || input.len()%4!=0 {
        return Err("original SPIR-V code outside source-neutral byte limit".into());
    }
    let source=front::spv::parse_u8_slice(
        input,&front::spv::Options::default()
    ).map_err(|e|format!("SPIR-V to universal Naga IR failed: {e:?}"))?;
    if source.entry_points.len()!=1 {
        return Err("source shader must expose one unambiguous entrypoint".into());
    }
    let stage=source.entry_points[0].stage;
    let name=source.entry_points[0].name.clone();
    let globals=source.global_variables.len();
    let functions=source.functions.len();
    let info=valid::Validator::new(
        valid::ValidationFlags::all(),valid::Capabilities::all()
    ).validate(&source)
        .map_err(|e|format!("source shader IR is not universally valid: {e:?}"))?;
    let wgsl=back::wgsl::write_string(
        &source,&info,back::wgsl::WriterFlags::empty()
    ).map_err(|e|format!("universal shader WGSL lowering failed: {e:?}"))?;
    // Ensure the generated textual shader is itself a valid cross-backend
    // intermediate, not just Naga's best-effort printed representation.
    let canonical=front::wgsl::parse_str(&wgsl)
        .map_err(|e|format!("universal WGSL shader cannot be reparsed: {}",
            e.emit_to_string(&wgsl)))?;
    if canonical.entry_points.len()!=1 ||
        canonical.entry_points[0].stage!=stage{
        return Err("SPIR-V shader stage changed during universal WGSL lowering".into());
    }
    let canonical_info=valid::Validator::new(
        valid::ValidationFlags::all(),valid::Capabilities::all()
    ).validate(&canonical)
        .map_err(|e|format!("translated universal WGSL IR invalid: {e:?}"))?;
    let pipeline=back::spv::PipelineOptions{
        shader_stage:stage,entry_point:canonical.entry_points[0].name.clone()
    };
    let spirv=back::spv::write_vec(
        &canonical,&canonical_info,
        &back::spv::Options::default(),Some(&pipeline)
    ).map_err(|e|format!("universal IR -> Vulkan SPIR-V codegen failed: {e:?}"))?;
    if spirv.len()<5 || spirv[0]!=0x0723_0203{
        return Err("translated Vulkan shader is not executable SPIR-V".into());
    }
    Ok(TranslatedSourceShader{
        generated_spirv:spirv,generated_wgsl:wgsl,stage,
        source_entrypoint:name,translated_globals:globals,
        translated_functions:functions,
    })
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn input_bounds_reject_truncated_source_shader(){
        assert!(translate_source_spirv(&[]).is_err());
        assert!(translate_source_spirv(&[0;20]).is_err());
    }
    #[test]
    fn original_wgsl_instruction_roundtrip_produces_executable_universal_spirv(){
        let source=r#"
            @vertex
            fn vs(@location(0) position:vec3<f32>) -> @builtin(position) vec4<f32>{
                return vec4<f32>(position,1.0);
            }
        "#;
        let module=front::wgsl::parse_str(source).unwrap();
        let info=valid::Validator::new(
            valid::ValidationFlags::all(),valid::Capabilities::all()
        ).validate(&module).unwrap();
        let binary=back::spv::write_vec(
            &module,&info,&back::spv::Options::default(),
            Some(&back::spv::PipelineOptions{
                shader_stage:naga::ShaderStage::Vertex,entry_point:"vs".into(),
            })
        ).unwrap();
        let bytes=binary.iter().flat_map(|w|w.to_le_bytes()).collect::<Vec<_>>();
        let translated=translate_source_spirv(&bytes).unwrap();
        assert_eq!(translated.stage,naga::ShaderStage::Vertex);
        assert!(translated.generated_spirv.len()>5);
        assert!(!translated.generated_wgsl.is_empty());
    }
}
