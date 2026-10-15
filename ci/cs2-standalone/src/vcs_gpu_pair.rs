//! Typed source-exact Vulkan stage pair preparation for universal GPU backend.
//!
//! This is the next bridge from original Source2 VCS static/dynamic IDs to
//! independently legal Vulkan SPIR-V stages and one common resource contract.
//! The output has real executable source shader code and verified descriptor
//! coordinates. It is NOT yet a rendered SurfaceProgram: source runtime
//! uniform providers, texture identities, vertex input ABI and exact sampler
//! states still need real source-backed values before runtime admission.
use std::{collections::BTreeMap,path::Path};
use crate::{
    vcs_native::{self,NativeFormat},
    vcs_spirv::reflect_original_spirv,
    vcs_spirv_relocate::{legalize_native_descriptor_types,SourceDescriptorRelocation},
    vcs_descriptor_contract::{self,NativeStageDescriptorContract},
    vcs_descriptor_types::{self,NativeResourceShape},
};

#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub enum SourceGpuStage { Vertex, Pixel }
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct SourceGpuDescriptor {
    pub set:u32,
    pub binding:u32,
    pub shape:NativeResourceShape,
    pub used_by_vertex:bool,
    pub used_by_pixel:bool,
    /// Original stage-local OpVariable IDs. These are NOT uniform names.
    pub source_variables:Vec<(SourceGpuStage,u32)>,
}
#[derive(Clone,Debug)]
pub struct PreparedSourceGpuPipeline {
    /// Real original GPU code with ONLY necessary OpDecorate Binding changes.
    pub vertex_spirv:Vec<u8>,
    pub pixel_spirv:Vec<u8>,
    pub vertex_compiler_hash:[u8;16],
    pub pixel_compiler_hash:[u8;16],
    pub original_variable_abi_hash:[u8;16],
    pub original_vertex_program_hash:[u8;16],
    pub original_pixel_program_hash:[u8;16],
    pub vertex_static_id:i64,
    pub vertex_dynamic_id:i64,
    pub pixel_static_id:i64,
    pub pixel_dynamic_id:i64,
    pub descriptor_bindings:Vec<SourceGpuDescriptor>,
    pub vertex_relocations:Vec<SourceDescriptorRelocation>,
    pub pixel_relocations:Vec<SourceDescriptorRelocation>,
    pub source_contract:NativeStageDescriptorContract,
}
impl PreparedSourceGpuPipeline {
    /// A real shader pair may be prepared even if not all resources have
    /// verifiable names. The renderer MUST NOT bind imaginary textures.
    pub fn anonymous_source_bindings(&self)->usize {
        self.source_contract.descriptors.iter()
            .filter(|coordinate|coordinate.claims.iter()
                .all(|claim|claim.authored_name.is_none())).count()
    }
    pub fn supports_direct_universal_admission(&self)->bool {
        // This flag cannot be true until Source2 uniform buffer providers,
        // vertex/varying ABI, texture and sampler identities are certified.
        false
    }
}
#[derive(Clone,Debug)]
struct Stage {
    code:Vec<u8>,
    compiler_hash:[u8;16],
    original_program_hash:[u8;16],
    original_variable_abi_hash:[u8;16],
    family:String,
    model:String,
    static_id:i64,
    dynamic_id:i64,
    relocations:Vec<SourceDescriptorRelocation>
}
fn physical_source_identity(source:&Path,stage:SourceGpuStage)
    ->Result<(String,String),String>{
    let file=source.file_name().and_then(|f|f.to_str())
        .ok_or("original native VCS file has no UTF8 identity")?;
    let basename=file.strip_suffix(".vcs")
        .ok_or("selected native shader does not end in .vcs")?;
    let mut segments=basename.rsplitn(4,'_');
    let name_stage=segments.next().ok_or("VCS native shader stage absent")?;
    let model=segments.next().ok_or("VCS native target model absent")?;
    let platform=segments.next().ok_or("VCS native GPU platform absent")?;
    let family=segments.next().ok_or("VCS native shader family absent")?;
    if platform!="vulkan" || family.is_empty() ||
        !matches!(model,"50"|"60") ||
        name_stage!=(match stage {
            SourceGpuStage::Vertex=>"vs",SourceGpuStage::Pixel=>"ps"
        }) {
        return Err("original VCS stage family, target or shader stage invalid".into());
    }
    Ok((family.to_owned(),model.to_owned()))
}
fn prepare(
    source:&Path, dictionaries:&Path,
    static_id:i64,dynamic_id:i64,stage:SourceGpuStage
)->Result<Stage,String>{
    let (family,model)=physical_source_identity(source,stage)?;
    let decoded=vcs_native::recover_original_gpu_program(
        source,dictionaries,static_id,dynamic_id)?;
    if decoded.format!=NativeFormat::SpirV{
        return Err("source-native Vulkan stage pair requires original SPIR-V".into());
    }
    let reflection=reflect_original_spirv(&decoded.bytecode)?;
    let model=match stage {
        SourceGpuStage::Vertex=>0,
        SourceGpuStage::Pixel=>4
    };
    if reflection.entry_points.len()!=1 ||
        reflection.entry_points[0].stage!=model {
        return Err("selected original VCS shader stage is not the required VS or PS".into());
    }
    let rewritten=legalize_native_descriptor_types(
        &decoded.bytecode,&reflection)?;
    Ok(Stage{
        code:rewritten.bytecode,
        compiler_hash:decoded.compiler_hash,
        original_program_hash:decoded.original_program_hash,
        original_variable_abi_hash:decoded.original_variable_abi_hash,
        family,model,
        static_id,dynamic_id,
        relocations:rewritten.relocations,
    })
}
/// Recover a physically source-selected vertex + pixel shader pair, adjust
/// only incompatible source Binding decorations, and create a typed common
/// coordinate table. Resource *values* are not yet assigned by this function.
pub fn prepare_source_vulkan_pipeline(
    vertex_source:&Path,pixel_source:&Path,
    dictionaries:&Path,
    vertex_ids:(i64,i64),pixel_ids:(i64,i64),
)->Result<PreparedSourceGpuPipeline,String>{
    let vs=prepare(vertex_source,dictionaries,
        vertex_ids.0,vertex_ids.1,SourceGpuStage::Vertex)?;
    let ps=prepare(pixel_source,dictionaries,
        pixel_ids.0,pixel_ids.1,SourceGpuStage::Pixel)?;
    if vs.family!=ps.family || vs.model!=ps.model ||
        vs.original_variable_abi_hash!=ps.original_variable_abi_hash {
        return Err("selected original native VS and PS are not a compiler-ABI-compatible stage pair".into());
    }
    let vs_ref=reflect_original_spirv(&vs.code)?;
    let ps_ref=reflect_original_spirv(&ps.code)?;
    let contract=vcs_descriptor_contract::audit_original_vs_ps(
        &vs_ref,&ps_ref)?;
    if contract.has_source_ambiguity(){
        return Err("type conflict or partial descriptor remains in legalized source stage pair".into());
    }
    let vs_types=vcs_descriptor_types::reflect_original_types(&vs.code,&vs_ref)?;
    let ps_types=vcs_descriptor_types::reflect_original_types(&ps.code,&ps_ref)?;
    let mut entries=BTreeMap::<(u32,u32),SourceGpuDescriptor>::new();
    for (stage,source) in [
        (SourceGpuStage::Vertex,&vs_types),
        (SourceGpuStage::Pixel,&ps_types)
    ]{
        for desc in source{
            if desc.shape==NativeResourceShape::Unknown{
                return Err("original source descriptor type not classified".into());
            }
            let slot=entries.entry((desc.set,desc.binding)).or_insert_with(||
                SourceGpuDescriptor{
                    set:desc.set,binding:desc.binding,
                    shape:desc.shape.clone(),
                    used_by_vertex:false,used_by_pixel:false,
                    source_variables:vec![]
                }
            );
            if slot.shape!=desc.shape{
                return Err(format!(
                    "original VS/PS require incompatible Vulkan descriptors at {}:{}",
                    desc.set,desc.binding
                ));
            }
            match stage{
                SourceGpuStage::Vertex=>slot.used_by_vertex=true,
                SourceGpuStage::Pixel=>slot.used_by_pixel=true,
            }
            slot.source_variables.push((stage,desc.variable_id));
        }
    }
    Ok(PreparedSourceGpuPipeline{
        vertex_spirv:vs.code,pixel_spirv:ps.code,
        vertex_compiler_hash:vs.compiler_hash,
        pixel_compiler_hash:ps.compiler_hash,
        original_variable_abi_hash:vs.original_variable_abi_hash,
        original_vertex_program_hash:vs.original_program_hash,
        original_pixel_program_hash:ps.original_program_hash,
        vertex_static_id:vs.static_id,
        vertex_dynamic_id:vs.dynamic_id,
        pixel_static_id:ps.static_id,
        pixel_dynamic_id:ps.dynamic_id,
        descriptor_bindings:entries.into_values().collect(),
        vertex_relocations:vs.relocations,
        pixel_relocations:ps.relocations,
        source_contract:contract,
    })
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn invalid_gpu_source_files_cannot_produce_synthetic_native_pipeline(){
        let dir=std::env::temp_dir();
        assert!(prepare_source_vulkan_pipeline(
            &dir.join("nonexistent_vs.vcs"),
            &dir.join("nonexistent_ps.vcs"),
            &dir, (0,0),(0,0)
        ).is_err());
    }
    #[test]
    fn descriptor_provenance_remains_stage_local(){
        let sample=SourceGpuDescriptor{
            set:4,binding:46,
            shape:NativeResourceShape::SampledImage{
                dim:1,arrayed:false,multisampled:false
            },
            used_by_vertex:false,used_by_pixel:true,
            source_variables:vec![(SourceGpuStage::Pixel,4640)]
        };
        assert_eq!(sample.source_variables[0],(SourceGpuStage::Pixel,4640));
        assert!(!sample.used_by_vertex);
    }
}
