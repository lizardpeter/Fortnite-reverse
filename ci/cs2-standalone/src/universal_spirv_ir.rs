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
/// An original shader's uniform structure may use a scalar/relaxed-block
/// source layout rather than WGSL's stricter uniform-buffer layout. We retain
/// the ORIGINAL member offsets and the generated canonical offsets together:
/// renderer uniform upload is not admissible until the provider supplies the
/// source-owned bytes and applies this mapping, including array/matrix stride.
#[derive(Clone,Debug)]
pub struct UniformLayoutRebase{
    pub group:u32,
    pub binding:u32,
    pub original_offsets:Vec<u32>,
    pub canonical_offsets:Vec<u32>,
    pub original_bytes:u32,
    pub canonical_bytes:u32,
}
impl UniformLayoutRebase{
    pub fn requires_repack(&self)->bool{
        self.original_offsets!=self.canonical_offsets ||
        self.original_bytes!=self.canonical_bytes
    }
}
pub struct RebasedUnboundShader{
    pub shader:TranslatedSourceShader,
    /// Shader source is now syntactically valid and executable, but this
    /// preserves original source byte-layout mismatch, not a made-up default
    /// GPU uniform value. This is not a binding admission certificate.
    pub uniform_layouts:Vec<UniformLayoutRebase>,
    pub original_abi_closed:bool,
}
fn uniform_structs(module:&naga::Module)
    ->Result<std::collections::BTreeMap<(u32,u32),(Vec<u32>,u32)>,String>
{
    let mut out=std::collections::BTreeMap::new();
    for (_,var) in module.global_variables.iter(){
        if var.space!=naga::AddressSpace::Uniform{continue;}
        let binding=var.binding.as_ref()
            .ok_or("source uniform buffer has no physical group/binding")?;
        let (members,span)=match &module.types[var.ty].inner{
            naga::TypeInner::Struct{members,span}=>(members,span),
            _=>return Err("original source uniform payload is not a typed struct".into()),
        };
        if members.len()>4096{return Err("source UBO member array exceeds safe limit".into())}
        let offsets=members.iter().map(|m|m.offset).collect::<Vec<_>>();
        let key=(binding.group,binding.binding);
        if out.insert(key,(offsets,*span)).is_some(){
            return Err("ambiguous duplicate source uniform descriptor coordinate".into())
        }
    }
    Ok(out)
}
/// IMPORTS the original shader operations into the common Naga IR and uses
/// the ordinary WGSL writer to canonicalize layout. Unlike the strict path,
/// this returns the *original and translated* UBO member offsets, so the
/// runtime can repack real source data before admitting the generated code.
///
/// Deliberately does NOT silently supply zero UBO values or claim the
/// generated code is equivalent with the *original* un-repacked buffer.
pub fn translate_source_spirv_with_ubo_rebase(
    input:&[u8]
)->Result<RebasedUnboundShader,String>{
    if input.len()<20 || input.len()>MAX_SOURCE_SPV || input.len()%4!=0{
        return Err("source shader outside universal bounded SPIR-V range".into());
    }
    let source=front::spv::parse_u8_slice(
        input,&front::spv::Options::default()
    ).map_err(|e|format!("source SPIR-V instruction import failed: {e:?}"))?;
    if source.entry_points.len()!=1 {
        return Err("ambiguous source-native shader entrypoint".into());
    }
    let layouts=uniform_structs(&source)?;
    // Naga cannot validate some author-approved Vulkan scalar-block
    // packing as WebGPU Uniform. Relax ONLY host-shareable struct layout
    // for THIS import. The canonical WGSL is strictly revalidated below.
    let relaxed=valid::ValidationFlags::all() &
        !valid::ValidationFlags::STRUCT_LAYOUTS;
    let info=valid::Validator::new(relaxed,valid::Capabilities::all())
        .validate(&source)
        .map_err(|e|format!("source shader invalid outside source UBO layout: {e:?}"))?;
    let wgsl=back::wgsl::write_string(
        &source,&info,back::wgsl::WriterFlags::empty()
    ).map_err(|e|format!("source shader IR canonicalization failed: {e:?}"))?;
    let normalized=front::wgsl::parse_str(&wgsl)
        .map_err(|e|format!("canonical shader WGSL cannot parse: {}",
            e.emit_to_string(&wgsl)))?;
    if normalized.entry_points.len()!=1 ||
        normalized.entry_points[0].stage!=source.entry_points[0].stage {
        return Err("source shader stage changed during canonicalization".into());
    }
    let normalized_info=valid::Validator::new(
        valid::ValidationFlags::all(),valid::Capabilities::all()
    ).validate(&normalized)
        .map_err(|e|format!("canonical shader layout still invalid: {e:?}"))?;
    let normalized_layouts=uniform_structs(&normalized)?;
    if layouts.len()!=normalized_layouts.len() ||
        layouts.keys().any(|key|!normalized_layouts.contains_key(key)){
        return Err("canonical shader changed a source uniform descriptor identity".into());
    }
    let mut original_abi_closed=true;
    let mut changes=Vec::new();
    for ((group,binding),(source_offsets,source_bytes)) in layouts{
        let (target_offsets,target_bytes)=normalized_layouts
            .get(&(group,binding)).ok_or("canonical uniform lost descriptor")?;
        if source_offsets.len()!=target_offsets.len() {
            return Err("canonical shader reordered/dropped source uniform fields".into());
        }
        let change=UniformLayoutRebase{
            group,binding,
            original_offsets:source_offsets,
            canonical_offsets:target_offsets.clone(),
            original_bytes:source_bytes,canonical_bytes:*target_bytes,
        };
        original_abi_closed &= !change.requires_repack();
        changes.push(change);
    }
    let options=back::spv::PipelineOptions{
        shader_stage:normalized.entry_points[0].stage,
        entry_point:normalized.entry_points[0].name.clone(),
    };
    let spirv=back::spv::write_vec(
        &normalized,&normalized_info,
        &back::spv::Options::default(),Some(&options)
    ).map_err(|e|format!("canonical shader Vulkan code generation failed: {e:?}"))?;
    if spirv.len()<5 || spirv[0]!=0x0723_0203 {
        return Err("rebased source shader did not generate actual Vulkan SPIR-V".into());
    }
    Ok(RebasedUnboundShader{
        shader:TranslatedSourceShader{
            generated_spirv:spirv,generated_wgsl:wgsl,
            stage:source.entry_points[0].stage,
            source_entrypoint:source.entry_points[0].name.clone(),
            translated_globals:source.global_variables.len(),
            translated_functions:source.functions.len(),
        },
        uniform_layouts:changes,original_abi_closed
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
