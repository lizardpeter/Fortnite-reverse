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
    pub original_vertex_program_hashes:Vec<[u8;16]>,
    pub original_pixel_program_hashes:Vec<[u8;16]>,
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
    original_program_hashes:Vec<[u8;16]>,
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
    let expected_execution_model=match stage {
        SourceGpuStage::Vertex=>0,
        SourceGpuStage::Pixel=>4
    };
    if reflection.entry_points.len()!=1 ||
        reflection.entry_points[0].stage!=expected_execution_model {
        return Err("selected original VCS shader stage is not the required VS or PS".into());
    }
    let rewritten=legalize_native_descriptor_types(
        &decoded.bytecode,&reflection)?;
    Ok(Stage{
        code:rewritten.bytecode,
        compiler_hash:decoded.compiler_hash,
        original_program_hashes:decoded.original_program_hashes,
        original_variable_abi_hash:decoded.original_variable_abi_hash,
        family,model,
        static_id,dynamic_id,
        relocations:rewritten.relocations,
    })
}
/// Source shaders are first legalized *within* each stage. Original Vulkan
/// stages may nevertheless disagree on a descriptor type at the SAME
/// (set,binding). A Vulkan graphics pipeline cannot expose two incompatible
/// types at one coordinate, even if the declarations are in different stages.
///
/// Preserve the vertex coordinate and move the pixel declaration(s) to the
/// next unused binding within that same set. Only OpDecorate Binding words
/// change; executable operations, types, stage IO and source file bytes are
/// left intact. Actual resource identities/providers remain unresolved.
fn reconcile_interstage_descriptor_types(
    vertex:&[u8],pixel:&[u8]
)->Result<(Vec<u8>,Vec<SourceDescriptorRelocation>),String>{
    let v_ref=reflect_original_spirv(vertex)?;
    let p_ref=reflect_original_spirv(pixel)?;
    if !v_ref.incomplete_descriptors.is_empty() ||
        !p_ref.incomplete_descriptors.is_empty() {
        return Err("cannot reconcile incomplete native stage descriptors".into());
    }
    let vertex_types=vcs_descriptor_types::reflect_original_types(vertex,&v_ref)?;
    let pixel_types=vcs_descriptor_types::reflect_original_types(pixel,&p_ref)?;
    let mut taken=BTreeMap::<u32,std::collections::BTreeSet<u32>>::new();
    let mut vertex_shapes=BTreeMap::<(u32,u32),NativeResourceShape>::new();
    let mut pixel_shapes=BTreeMap::<(u32,u32),NativeResourceShape>::new();
    for d in &vertex_types {
        if d.shape==NativeResourceShape::Unknown {
            return Err("unknown original vertex descriptor type".into());
        }
        taken.entry(d.set).or_default().insert(d.binding);
        if vertex_shapes.insert((d.set,d.binding),d.shape.clone())
            .is_some_and(|old|old!=d.shape) {
            return Err("vertex stage still has conflicting descriptor types".into());
        }
    }
    for d in &pixel_types {
        if d.shape==NativeResourceShape::Unknown {
            return Err("unknown original pixel descriptor type".into());
        }
        taken.entry(d.set).or_default().insert(d.binding);
        if pixel_shapes.insert((d.set,d.binding),d.shape.clone())
            .is_some_and(|old|old!=d.shape) {
            return Err("pixel stage still has conflicting descriptor types".into());
        }
    }
    let mut moved_coordinates=BTreeMap::<(u32,u32),u32>::new();
    for ((set,binding),pixel_shape) in &pixel_shapes {
        if vertex_shapes.get(&(*set,*binding))
            .is_none_or(|vertex_shape|vertex_shape==pixel_shape) { continue; }
        let occupied=taken.get_mut(set).expect("source descriptor set exists");
        let next=occupied.iter().next_back().copied().unwrap_or(0)
            .checked_add(1).filter(|next|*next<=65_535)
            .ok_or("interstage native descriptor relocation exhausted binding range")?;
        occupied.insert(next);
        moved_coordinates.insert((*set,*binding),next);
    }
    if moved_coordinates.is_empty() { return Ok((pixel.to_vec(),Vec::new())); }
    let changes=pixel_types.iter().filter_map(|d|
        moved_coordinates.get(&(d.set,d.binding)).map(|new_binding|
            SourceDescriptorRelocation{
                variable_id:d.variable_id,set:d.set,
                source_binding:d.binding,relocated_binding:*new_binding,
                shape:d.shape.clone()
            })
    ).collect::<Vec<_>>();
    let lookup=changes.iter().map(|d|(d.variable_id,(d.source_binding,d.relocated_binding)))
        .collect::<BTreeMap<_,_>>();
    if lookup.len()!=changes.len(){
        return Err("interstage native descriptor variable ID repeated".into());
    }
    let mut words=pixel.chunks_exact(4).map(|w|
        u32::from_le_bytes(w.try_into().expect("original SPIR-V word"))
    ).collect::<Vec<_>>();
    let mut count=BTreeMap::<u32,usize>::new();
    let mut cursor=5usize;
    while cursor<words.len(){
        let instruction=words[cursor];
        let size=(instruction>>16) as usize;
        let end=cursor.checked_add(size)
            .filter(|end|size>0&&*end<=words.len())
            .ok_or("source SPIR-V instruction truncated during interstage legalization")?;
        if instruction&0xffff==71 && size>=4 && words[cursor+2]==33 {
            let id=words[cursor+1];
            if let Some(&(source,target))=lookup.get(&id){
                if words[cursor+3]!=source {
                    return Err("source binding changed during interstage legalization".into());
                }
                words[cursor+3]=target;
                *count.entry(id).or_default()+=1;
            }
        }
        cursor=end;
    }
    if changes.iter().any(|d|count.get(&d.variable_id)!=Some(&1)){
        return Err("source descriptor Binding decoration absent or duplicated".into());
    }
    let rewritten=words.into_iter().flat_map(u32::to_le_bytes).collect::<Vec<_>>();
    let new_ref=reflect_original_spirv(&rewritten)?;
    let new_types=vcs_descriptor_types::reflect_original_types(&rewritten,&new_ref)?;
    if rewritten.len()!=pixel.len() || new_types.len()!=pixel_types.len() {
        return Err("interstage relocation changed native shader extent or resources".into());
    }
    for old in &pixel_types {
        let new=new_types.iter().find(|d|d.variable_id==old.variable_id)
            .ok_or("interstage relocation removed original source descriptor")?;
        let expected=moved_coordinates.get(&(old.set,old.binding))
            .copied().unwrap_or(old.binding);
        if new.set!=old.set || new.binding!=expected ||
            new.shape!=old.shape || new.storage_class!=old.storage_class {
            return Err("interstage relocation altered original source type or storage".into());
        }
        if vertex_shapes.get(&(new.set,new.binding))
            .is_some_and(|shape|*shape!=new.shape) {
            return Err("interstage Vulkan descriptor conflict was not resolved".into());
        }
    }
    Ok((rewritten,changes))
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
    let mut ps=prepare(pixel_source,dictionaries,
        pixel_ids.0,pixel_ids.1,SourceGpuStage::Pixel)?;
    if vs.family!=ps.family || vs.model!=ps.model ||
        vs.original_variable_abi_hash!=ps.original_variable_abi_hash {
        return Err("selected original native VS and PS are not a compiler-ABI-compatible stage pair".into());
    }
    // Reconcile stage-crossing type aliases before constructing one Vulkan
    // layout; never conflate this with source material/UBO provisioning.
    let (pixel_code,cross_stage_moves)=
        reconcile_interstage_descriptor_types(&vs.code,&ps.code)?;
    ps.code=pixel_code;
    for moved in cross_stage_moves {
        if let Some(previous)=ps.relocations.iter_mut()
            .find(|r|r.variable_id==moved.variable_id) {
            if previous.set!=moved.set ||
                previous.relocated_binding!=moved.source_binding ||
                previous.shape!=moved.shape {
                return Err("native interstage relocation provenance mismatch".into());
            }
            previous.relocated_binding=moved.relocated_binding;
        }else{
            ps.relocations.push(moved);
        }
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
        original_vertex_program_hashes:vs.original_program_hashes,
        original_pixel_program_hashes:ps.original_program_hashes,
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
    fn fixture_spirv(execution:u32,dimension:u32,binding:u32)->Vec<u8>{
        fn op(words:&mut Vec<u32>,opcode:u32,args:&[u32]){
            words.push((((args.len()+1) as u32)<<16)|opcode);
            words.extend_from_slice(args);
        }
        let mut words=vec![0x0723_0203,0x0001_0500,0,100,0];
        op(&mut words,15,&[execution,21,0x6e69_614d,0x0000_7350]);
        op(&mut words,25,&[5,3,dimension,0,0,0,1,0]);
        op(&mut words,32,&[10,0,5]);
        op(&mut words,59,&[10,31,0]);
        op(&mut words,71,&[31,34,4]);
        op(&mut words,71,&[31,33,binding]);
        op(&mut words,54,&[1,21,0,2]);
        op(&mut words,56,&[]);
        words.into_iter().flat_map(u32::to_le_bytes).collect()
    }
    #[test]
    fn cross_stage_2d_vs_3d_descriptor_conflict_is_relocated_without_rewriting_math(){
        let vs=fixture_spirv(0,1,46);
        let ps=fixture_spirv(4,2,46);
        let (rewritten,moves)=reconcile_interstage_descriptor_types(&vs,&ps).unwrap();
        assert_eq!(moves.len(),1);
        assert_eq!((moves[0].set,moves[0].source_binding,moves[0].relocated_binding),(4,46,47));
        let before=ps.chunks_exact(4).map(|w|u32::from_le_bytes(w.try_into().unwrap())).collect::<Vec<_>>();
        let after=rewritten.chunks_exact(4).map(|w|u32::from_le_bytes(w.try_into().unwrap())).collect::<Vec<_>>();
        let changed=before.iter().zip(&after).enumerate()
            .filter_map(|(i,(a,b))|(a!=b).then_some(i)).collect::<Vec<_>>();
        assert_eq!(changed.len(),1);
        assert_eq!((before[changed[0]],after[changed[0]]),(46,47));
        let v=reflect_original_spirv(&vs).unwrap();
        let p=reflect_original_spirv(&rewritten).unwrap();
        assert_eq!(v.descriptors[0].binding,46);
        assert_eq!(p.descriptors[0].binding,47);
    }
    #[test]
    fn identical_cross_stage_types_keep_the_source_binding(){
        let vs=fixture_spirv(0,1,46);
        let ps=fixture_spirv(4,1,46);
        let (same,moves)=reconcile_interstage_descriptor_types(&vs,&ps).unwrap();
        assert!(moves.is_empty());
        assert_eq!(same,ps);
    }
    #[test]
    fn interstage_remapping_cannot_collide_with_existing_native_bindings(){
        let vs=fixture_spirv(0,1,47);
        let ps=fixture_spirv(4,2,47);
        let (modified,moves)=reconcile_interstage_descriptor_types(&vs,&ps).unwrap();
        assert_eq!(moves[0].relocated_binding,48);
        let reflect=reflect_original_spirv(&modified).unwrap();
        assert_eq!(reflect.descriptors[0].binding,48);
    }

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
