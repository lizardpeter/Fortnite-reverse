//! Physically compiled Source 2 Vulkan shader permutation selection.
//!
//! This scanner operates on the source VCS static IDs, dynamic IDs and
//! bytecode block indices, not on header-only guesses or a fabricated zero
//! permutation. Material switches are partial constraints; missing source
//! runtime uniforms/features remain explicitly unresolved. The presence
//! of one compiled candidate is not proof that the runtime picked it.
use std::collections::BTreeMap;
use crate::vcs_native::{NativeComboParameter, NativeVcsIndex};

/// Source-authored, physically present GPU bytecode. Never an invented combo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhysicalCompiledVariant {
    pub static_id: i64,
    pub dynamic_id: i64,
    pub physical_block: usize,
    pub bytecode_index: usize,
    pub missing_static_features: Vec<String>,
    pub missing_dynamic_features: Vec<String>,
}
impl PhysicalCompiledVariant {
    /// A unique *compiler-record* candidate is not proof of a runtime choice.
    pub fn is_fully_constrained(&self)->bool {
        self.missing_static_features.is_empty() &&
        self.missing_dynamic_features.is_empty()
    }
}
#[derive(Clone, Debug, Default)]
pub struct PhysicalCompilerFrontier {
    /// Number of physically compiled candidates matching partial constraints,
    /// including matches beyond the returned bounded example inventory.
    pub total_matches: usize,
    pub physically_compiled_static_ids: usize,
    pub matching_static_ids: usize,
    pub candidates: Vec<PhysicalCompiledVariant>,
    pub truncated: bool,
}
impl PhysicalCompilerFrontier {
    pub fn unique_fully_constrained(&self)->Option<&PhysicalCompiledVariant>{
        (self.total_matches==1 && !self.truncated)
            .then(||self.candidates.first()).flatten()
            .filter(|variant|variant.is_fully_constrained())
    }
}

/// Recover the actual compiler mixed-radix digits of an existing physical
/// static/dynamic ID. No unprovided VMAT feature is replaced with zero.
/// Missing parameters are singleton only when the original compiler says so.
/// Ignore unrelated VMAT parameters: they are not in this stage's native ABI.
pub fn decode_native_compiler_id(
    params:&[NativeComboParameter], id:i64,
)->Result<BTreeMap<String,i64>,String>{
    if id<0{return Err("negative compiler-native combo ID".into());}
    let mut result=BTreeMap::new();
    let mut extent=1i64;
    for p in params{
        if p.stride!=extent || p.min>p.max || p.stride<=0 {
            return Err(format!("VCS authored invalid mixed radix at {}",p.name));
        }
        let width=p.max.checked_sub(p.min)
            .and_then(|v|v.checked_add(1))
            .ok_or("native compiler feature range overflow")?;
        extent=extent.checked_mul(width)
            .ok_or("native compiler shader feature space overflow")?;
        let digit=(id/p.stride)%width;
        result.insert(p.name.clone(),p.min+digit);
    }
    if id>=extent{return Err(format!(
        "original compiler ID {id} outside physical mixed radix 0..{extent}"
    ));}
    Ok(result)
}
fn matching_features(
    params:&[NativeComboParameter],
    authored:&BTreeMap<String,i64>,
    id:i64,
)->Result<Option<Vec<String>>,String>{
    let values=decode_native_compiler_id(params,id)?;
    let mut missing=Vec::new();
    for p in params{
        let physical=values[&p.name];
        match authored.get(&p.name){
            Some(value) if *value<p.min || *value>p.max =>
                return Err(format!(
                    "VMAT/native constraint {}={} outside compiler range {}..{}",
                    p.name,value,p.min,p.max
                )),
            Some(value) if *value!=physical=>return Ok(None),
            Some(_)=>{},
            None if p.min!=p.max=>missing.push(p.name.clone()),
            None=>{},
        }
    }
    Ok(Some(missing))
}
/// Enumerate only physically present native records; never iterate the full
/// theoretical Cartesian product of Source 2 compiler feature ranges.
/// Caller controls the bounded returned list. The total still counts ALL
/// source bytecodes admitted by the constraints, not just first N examples.
pub fn matching_physical_compiled_variants(
    index:&NativeVcsIndex,
    material_static:&BTreeMap<String,i64>,
    runtime_dynamic:&BTreeMap<String,i64>,
    limit:usize,
)->Result<PhysicalCompilerFrontier,String>{
    if !(1..=4096).contains(&limit){
        return Err("original shader candidate bound must be 1..4096".into());
    }
    let mut result=PhysicalCompilerFrontier::default();
    for static_combo in &index.static_combos{
        let Some(block_index)=static_combo.block else{continue;};
        let block=index.blocks.get(block_index)
            .ok_or("native shader physical bytecode block absent")?;
        result.physically_compiled_static_ids+=1;
        let Some(missing_static)=matching_features(
            &index.static_parameters,material_static,static_combo.static_id
        )? else{continue;};
        result.matching_static_ids+=1;
        for &(dynamic_id,code) in &static_combo.dynamic{
            let Some(bytecode_index)=code else{continue;};
            if bytecode_index>=block.original_hashes.len(){
                return Err("original VCS dynamic bytecode index out of bounds".into());
            }
            let Some(missing_dynamic)=matching_features(
                &index.dynamic_parameters,runtime_dynamic,dynamic_id
            )? else{continue;};
            result.total_matches+=1;
            if result.candidates.len()<limit {
                result.candidates.push(PhysicalCompiledVariant{
                    static_id:static_combo.static_id,dynamic_id,
                    physical_block:block_index,bytecode_index,
                    missing_static_features:missing_static.clone(),
                    missing_dynamic_features:missing_dynamic,
                });
            }else{result.truncated=true;}
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests{
    use super::*;
    use crate::vcs_native::{NativeByteCodeBlock,NativeStaticCombo};
    fn p(name:&str,min:i64,max:i64,stride:i64)->NativeComboParameter{
        NativeComboParameter{name:name.into(),min,max,stride}
    }
    fn fixture()->NativeVcsIndex{
        NativeVcsIndex{
            declared_metadata_bytes:0,compiler_static_ids:3,
            original_program_hashes:vec![],original_variable_abi_hash:[0;16],
            static_parameters:vec![p("F_DECAL",0,1,1),p("F_LAYERS",0,2,2)],
            dynamic_parameters:vec![p("D_LIGHT",0,1,1)],
            compiler_dynamic_definitions:1,compiler_variable_descriptions:0,
            variables:vec![],
            blocks:vec![NativeByteCodeBlock{
                file_offset:0,compressed_size:32,offsets:vec![0,4,8],
                original_hashes:vec![[1;16],[2;16]],
            }],
            static_combos:vec![
                NativeStaticCombo{
                    static_id:0,block:Some(0),
                    dynamic:vec![(0,Some(0)),(1,None)]
                },
                NativeStaticCombo{
                    static_id:3,block:Some(0),
                    dynamic:vec![(0,Some(0)),(1,Some(1))]
                },
                NativeStaticCombo{
                    static_id:5,block:Some(0),
                    dynamic:vec![(0,None),(1,Some(1))]
                },
                NativeStaticCombo{
                    static_id:1,block:None,dynamic:vec![(0,None)],
                },
            ]
        }
    }
    #[test]
    fn physical_compiler_index_decodes_source_mixed_radix_not_guessed_zero(){
        assert_eq!(decode_native_compiler_id(&fixture().static_parameters,5)
            .unwrap(),BTreeMap::from([
                ("F_DECAL".into(),1),("F_LAYERS".into(),2)
            ]));
        assert!(decode_native_compiler_id(&fixture().static_parameters,6).is_err());
        assert!(decode_native_compiler_id(&fixture().static_parameters,-1).is_err());
    }
    #[test]
    fn physically_missing_or_uncompiled_ids_never_become_candidates(){
        let f=matching_physical_compiled_variants(
            &fixture(),&BTreeMap::new(),&BTreeMap::new(),128
        ).unwrap();
        assert_eq!(f.physically_compiled_static_ids,3);
        assert_eq!(f.matching_static_ids,3);
        assert_eq!(f.total_matches,4);
        assert!(f.candidates.iter().all(|c|c.static_id!=1));
        assert!(!f.candidates.iter().any(|c|
            c.static_id==5 && c.dynamic_id==0));
    }
    #[test]
    fn source_material_constraints_filter_original_native_static_and_dynamic_ids(){
        let static_features=BTreeMap::from([
            ("F_DECAL".into(),1),("F_LAYERS".into(),1),
            ("UNRELATED_VMAT_SWITCH".into(),9)
        ]);
        let dynamic_features=BTreeMap::from([("D_LIGHT".into(),1)]);
        let f=matching_physical_compiled_variants(
            &fixture(),&static_features,&dynamic_features,16
        ).unwrap();
        assert_eq!(f.total_matches,1);
        let unique=f.unique_fully_constrained().unwrap();
        assert_eq!((unique.static_id,unique.dynamic_id),(3,1));
        assert_eq!((unique.physical_block,unique.bytecode_index),(0,1));
    }
    #[test]
    fn unresolved_compiler_values_remain_explicit_even_with_one_physical_match(){
        let f=matching_physical_compiled_variants(
            &fixture(),&BTreeMap::from([("F_LAYERS".into(),2)]),
            &BTreeMap::from([("D_LIGHT".into(),1)]),8
        ).unwrap();
        assert_eq!(f.total_matches,1);
        assert_eq!(f.candidates[0].static_id,5);
        assert_eq!(f.candidates[0].missing_static_features,vec!["F_DECAL"]);
        assert!(f.unique_fully_constrained().is_none());
    }
    #[test]
    fn bounded_inventory_keeps_complete_match_count_without_fabrication(){
        let f=matching_physical_compiled_variants(
            &fixture(),&BTreeMap::new(),&BTreeMap::new(),1
        ).unwrap();
        assert_eq!(f.total_matches,4);
        assert_eq!(f.candidates.len(),1);
        assert!(f.truncated);
        assert!(f.unique_fully_constrained().is_none());
        assert!(matching_physical_compiled_variants(
            &fixture(),&BTreeMap::new(),&BTreeMap::new(),0
        ).is_err());
    }
    #[test]
    fn out_of_range_authored_constraints_do_not_truncate_into_zero(){
        assert!(matching_physical_compiled_variants(
            &fixture(),&BTreeMap::from([("F_DECAL".into(),9)]),
            &BTreeMap::new(),8
        ).is_err());
    }
}
