//! Source-exact SPIR-V descriptor-coordinate legalization.
//!
//! Some real Source2 VCS Vulkan stages declare *simultaneously referenced*
//! 2D, 3D and cube sampled-image variables at the SAME (set,binding).
//! Dead-variable elimination is not sufficient: the original selected
//! lightmapped pixel stage references all of them. Vulkan needs distinct
//! typed resources for those declarations, so the shared native-stage
//! importer must be able to retarget ONLY OpDecorate Binding literals while
//! preserving shader instructions and source values.
//!
//! The patch never fabricates source texture identities or writes descriptors.
//! A moved binding has no provider until the corresponding original material
//! or runtime input is actually resolved. The returned remap is part of the
//! source-to-universal GPU resource ABI; zero runtime shader admission is
//! asserted here.
use std::collections::{BTreeMap,BTreeSet};
use crate::{
    vcs_spirv::{reflect_original_spirv,SpirvSourceReflection},
    vcs_descriptor_types::{reflect_original_types,NativeResourceShape,NativeTypedDescriptor},
};

const OP_DECORATE:u32=71;
const DECORATION_BINDING:u32=33;
const MAX_NATIVE_BINDING:u32=65_535;

#[derive(Clone,Debug,PartialEq,Eq)]
pub struct SourceDescriptorRelocation {
    pub variable_id:u32,
    pub set:u32,
    pub source_binding:u32,
    pub relocated_binding:u32,
    pub shape:NativeResourceShape,
}
#[derive(Clone,Debug)]
pub struct LegalizedNativeSpirv {
    /// Original native executable with ONLY affected OpDecorate Binding
    /// operand literals changed. No shader operations are transformed.
    pub bytecode:Vec<u8>,
    pub relocations:Vec<SourceDescriptorRelocation>,
    pub original_binding_claims:usize,
    pub legalized_binding_claims:usize,
    pub relocated_type_conflicts:usize,
}
fn type_conflicts(descriptors:&[NativeTypedDescriptor])->usize{
    let mut groups=BTreeMap::<(u32,u32),BTreeSet<NativeResourceShape>>::new();
    for source in descriptors{
        groups.entry((source.set,source.binding))
            .or_default().insert(source.shape.clone());
    }
    groups.values().filter(|shapes|shapes.len()>1).count()
}
/// For every source coordinate with heterogeneous image/buffer/sampler types,
/// keep its earliest source variable at the original binding and assign each
/// additional original type its own otherwise unused binding in the SAME set.
/// Type-identical source aliases stay aliases; this does not blindly duplicate
/// original samplers or identical UBOs.
///
/// The caller must supply a reflection from THIS exact shader module.
pub fn legalize_native_descriptor_types(
    original:&[u8],
    reflected:&SpirvSourceReflection,
)->Result<LegalizedNativeSpirv,String>{
    if original.len()<20 || original.len()%4!=0 || original.len()>64*1024*1024{
        return Err("original shader cannot be legalized outside SPIR-V size bounds".into());
    }
    let original_reflection=reflect_original_spirv(original)?;
    if original_reflection.descriptors!=reflected.descriptors ||
        original_reflection.entry_points!=reflected.entry_points{
        return Err("source descriptor reflection differs from physical shader".into());
    }
    if !reflected.incomplete_descriptors.is_empty(){
        return Err("source shader contains incomplete descriptor-set declarations".into());
    }
    let typed=reflect_original_types(original,reflected)?;
    if typed.iter().any(|descriptor|descriptor.shape==NativeResourceShape::Unknown){
        return Err("source shader type is not classified: cannot legalize without guessing".into());
    }
    let original_conflicts=type_conflicts(&typed);
    if original_conflicts==0 {
        return Ok(LegalizedNativeSpirv{
            bytecode:original.to_vec(),relocations:vec![],
            original_binding_claims:typed.len(),legalized_binding_claims:typed.len(),
            relocated_type_conflicts:0
        });
    }
    let mut taken=BTreeMap::<u32,BTreeSet<u32>>::new();
    let mut groups=BTreeMap::<(u32,u32),Vec<&NativeTypedDescriptor>>::new();
    for t in &typed{
        taken.entry(t.set).or_default().insert(t.binding);
        groups.entry((t.set,t.binding)).or_default().push(t);
    }
    let mut changes=Vec::new();
    for ((set,original_binding),mut group) in groups{
        group.sort_by_key(|item|item.variable_id);
        let distinct=group.iter().map(|item|item.shape.clone())
            .collect::<BTreeSet<_>>();
        if distinct.len()<2{continue;}
        let mut shape_binding=BTreeMap::<NativeResourceShape,u32>::new();
        // The earliest source declaration retains the original coordinate.
        shape_binding.insert(group[0].shape.clone(),original_binding);
        for variable in group {
            if shape_binding.contains_key(&variable.shape){continue;}
            let used=taken.get_mut(&set).expect("source set exists");
            let next=used.iter().next_back().copied().unwrap_or(0)
                .checked_add(1).filter(|v|*v<=MAX_NATIVE_BINDING)
                .ok_or("Source2 descriptor relocation exhausted Vulkan binding range")?;
            if !used.insert(next){
                return Err("source SPIR-V descriptor relocation collision".into());
            }
            shape_binding.insert(variable.shape.clone(),next);
        }
        for variable in &typed {
            if variable.set!=set||variable.binding!=original_binding{continue;}
            let target=shape_binding[&variable.shape];
            if target==original_binding{continue;}
            changes.push(SourceDescriptorRelocation{
                variable_id:variable.variable_id,set,
                source_binding:original_binding,
                relocated_binding:target,shape:variable.shape.clone()
            });
        }
    }
    changes.sort_by_key(|c|(c.set,c.source_binding,c.variable_id));
    let expected=changes.iter().map(|r|(r.variable_id,r.source_binding))
        .collect::<BTreeMap<_,_>>();
    if expected.len()!=changes.len(){
        return Err("source descriptor contains duplicate relocation IDs".into());
    }
    let mut words=original.chunks_exact(4).map(|w|
        u32::from_le_bytes(w.try_into().expect("4-byte instruction"))
    ).collect::<Vec<_>>();
    let mut touched=BTreeMap::<u32,usize>::new();
    let mut cursor=5usize;
    while cursor<words.len(){
        let word=words[cursor];
        let count=(word>>16) as usize;
        let end=cursor.checked_add(count)
            .filter(|end|count>0&&*end<=words.len())
            .ok_or("original source SPIR-V instruction truncated")?;
        if word&0xffff==OP_DECORATE && count>=4 &&
            words[cursor+2]==DECORATION_BINDING{
            let id=words[cursor+1];
            if let Some(&old)=expected.get(&id){
                if words[cursor+3]!=old{
                    return Err("source native binding changed between reflection and patch".into());
                }
                let target=changes.iter().find(|r|r.variable_id==id)
                    .expect("source ID has relocation");
                words[cursor+3]=target.relocated_binding;
                *touched.entry(id).or_default()+=1;
            }
        }
        cursor=end;
    }
    if changes.iter().any(|change|touched.get(&change.variable_id)!=Some(&1)){
        return Err("source shader has missing or duplicated original Binding decoration".into());
    }
    let bytecode=words.into_iter().flat_map(u32::to_le_bytes).collect::<Vec<_>>();
    // Re-reflect both the original and rewritten modules. SPIR-V executable
    // instructions stay byte-for-byte identical; only literal binding words
    // change. No shader effect/program lowering occurs here.
    let rewritten=reflect_original_spirv(&bytecode)?;
    let new_types=reflect_original_types(&bytecode,&rewritten)?;
    if new_types.len()!=typed.len() || type_conflicts(&new_types)>0{
        return Err("Vulkan source descriptor type conflict remained after relocation".into());
    }
    let expected_locations=changes.iter().map(|x|
        (x.variable_id,(x.set,x.relocated_binding))
    ).collect::<BTreeMap<_,_>>();
    for old in &typed {
        let now=new_types.iter().find(|d|d.variable_id==old.variable_id)
            .ok_or("relocated Source2 descriptor disappeared")?;
        let (set,binding)=expected_locations.get(&old.variable_id)
            .copied().unwrap_or((old.set,old.binding));
        if now.set!=set||now.binding!=binding||
            now.shape!=old.shape||now.storage_class!=old.storage_class {
            return Err("source shader relocation changed original descriptor semantics".into());
        }
    }
    Ok(LegalizedNativeSpirv{
        bytecode,relocations:changes,
        original_binding_claims:typed.len(),
        legalized_binding_claims:new_types.len(),
        relocated_type_conflicts:original_conflicts
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn op(words:&mut Vec<u32>,id:u32,operands:&[u32]){
        words.push((((operands.len()+1) as u32)<<16)|id);
        words.extend_from_slice(operands);
    }
    fn source_shader()->Vec<u8>{
        let mut w=vec![0x07230203,0x00010500,0,100,0];
        // Source vertex/pixel function and entry point.
        op(&mut w,15,&[4,21,0x6e69614d,0x00007350]);
        op(&mut w,25,&[5,3,1,0,0,0,1,0]); // 2D
        op(&mut w,25,&[6,3,2,0,0,0,1,0]); // 3D
        op(&mut w,32,&[10,0,5]);
        op(&mut w,32,&[11,0,6]);
        op(&mut w,59,&[10,31,0]);
        op(&mut w,59,&[11,32,0]);
        for id in [31,32]{
            op(&mut w,71,&[id,34,4]);
            op(&mut w,71,&[id,33,46]);
        }
        op(&mut w,54,&[1,21,0,2]);op(&mut w,56,&[]);
        w.into_iter().flat_map(u32::to_le_bytes).collect()
    }
    #[test]
    fn legalize_only_conflicting_source_descriptor_types(){
        let src=source_shader();
        let ref0=reflect_original_spirv(&src).unwrap();
        let out=legalize_native_descriptor_types(&src,&ref0).unwrap();
        assert_eq!(out.relocated_type_conflicts,1);
        assert_eq!(out.relocations.len(),1);
        assert_eq!(out.relocations[0].set,4);
        assert_eq!(out.relocations[0].source_binding,46);
        assert_eq!(out.relocations[0].relocated_binding,47);
        assert_eq!(type_conflicts(&reflect_original_types(
            &out.bytecode,&reflect_original_spirv(&out.bytecode).unwrap()
        ).unwrap()),0);
        assert_eq!(out.bytecode.len(),src.len());
        assert_eq!(legalize_native_descriptor_types(
            &out.bytecode,&reflect_original_spirv(&out.bytecode).unwrap()
        ).unwrap().relocations.len(),0);
    }
    #[test]
    fn never_create_fake_relocations_for_identical_sampler_aliases(){
        let mut w=source_shader().chunks_exact(4).map(|c|
            u32::from_le_bytes(c.try_into().unwrap())).collect::<Vec<_>>();
        // Rewrite second 3D image type to the existing 2D image type.
        // Source variable (id 32) has OpTypePointer 11 -> type 6 (3D),
        // so change pointer pointee 6 to 5 in the reflected module.
        let needle=w.windows(4).position(|v|v==[0x40020,11,0,6])
            .expect("pointer source fixture");
        w[needle+3]=5;
        let bytes=w.into_iter().flat_map(u32::to_le_bytes).collect::<Vec<_>>();
        let old=reflect_original_spirv(&bytes).unwrap();
        let out=legalize_native_descriptor_types(&bytes,&old).unwrap();
        assert!(out.relocations.is_empty());
        assert_eq!(bytes,out.bytecode);
    }
}
