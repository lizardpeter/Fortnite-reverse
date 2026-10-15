//! Exact descriptor ABI merger for original Source 2 compiled VS+PS pairs.
//!
//! Vulkan descriptor bindings are indexed by (set,binding), NOT by OpVariable
//! declarations. Valve's shipped lightmapped shader contains several native
//! variables decorated with the SAME coordinates; treating each variable as a
//! distinct descriptor silently creates invalid layouts and incorrect
//! baked-lightmap bindings. This module preserves these alias declarations
//! and reports unresolved compiler type conflicts without fabricating slots.
//!
//! Source SPIR-V reflection is a prerequisite for universal SurfaceProgram
//! admission, not evidence that original shaders are executable in our engine.
use std::collections::{BTreeMap,BTreeSet};
use crate::vcs_spirv::{SpirvSourceReflection,SpirvResource};

#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub enum NativePipelineStage { Vertex, Pixel }
impl NativePipelineStage {
    pub fn execution_model(self)->u32 {
        match self { Self::Vertex=>0, Self::Pixel=>4 }
    }
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct NativeDescriptorClaim {
    pub stage:NativePipelineStage,
    /// Original SPIR-V OpVariable source result ID.
    pub variable_id:u32,
    /// Original SPIR-V pointer result type ID (not shared across modules).
    pub type_id:u32,
    pub storage_class:u32,
    pub authored_name:Option<String>,
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct NativeDescriptorCoordinate {
    pub set:u32,
    pub binding:u32,
    /// ALL shader compiler source declarations at this coordinate.
    pub claims:Vec<NativeDescriptorClaim>,
    pub stages:BTreeSet<NativePipelineStage>,
    /// Multiple original SPIR-V variables use this same (set,binding) in
    /// at least one shader stage; there must be ONE Vulkan descriptor slot.
    pub aliased_in_stage:bool,
    /// Same-stage alias has different original SPIR-V type or storage class.
    /// The importer cannot prove these are compatible with one native
    /// descriptor layout, even if the bindings happen to be equal.
    pub unresolved_source_types:bool,
    /// VS and PS use the same location with different storage classes.
    /// Shared SPIR-V type IDs cannot be compared between modules.
    pub different_stage_storage_classes:bool,
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct NativeStageDescriptorContract {
    pub vertex_entrypoint:String,
    pub pixel_entrypoint:String,
    pub source_declarations:usize,
    pub distinct_coordinates:usize,
    pub alias_coordinates:usize,
    pub incompatible_or_ambiguous_coordinates:usize,
    pub original_sets:BTreeSet<u32>,
    pub descriptors:Vec<NativeDescriptorCoordinate>,
    pub incomplete_source_declarations:usize,
    pub source_specialization_constants:usize,
}
impl NativeStageDescriptorContract {
    /// A clean reflection-only contract is still NOT runtime program
    /// admission: Source2 scene-global and material buffer lifetimes,
    /// vertex formats and texture bindings must be resolved separately.
    pub fn has_source_ambiguity(&self)->bool {
        self.incomplete_source_declarations>0 ||
            self.incompatible_or_ambiguous_coordinates>0
    }
}
fn check_entrypoint(reflection:&SpirvSourceReflection,stage:NativePipelineStage)
    ->Result<String,String>{
    let found=reflection.entry_points.iter()
        .filter(|e|e.stage==stage.execution_model())
        .collect::<Vec<_>>();
    if found.len()!=1 || reflection.entry_points.len()!=1{
        return Err(format!(
            "Source2 {:?} shader requires one compiler-authored entry point",
            stage
        ));
    }
    Ok(found[0].name.clone())
}
fn claims_for(
    map:&mut BTreeMap<(u32,u32),Vec<NativeDescriptorClaim>>,
    stage:NativePipelineStage,source:&[SpirvResource]
){
    for r in source{
        map.entry((r.set,r.binding)).or_default().push(NativeDescriptorClaim{
            stage,variable_id:r.id,type_id:r.type_id,
            storage_class:r.storage_class,authored_name:r.name.clone()
        });
    }
}
pub fn audit_original_vs_ps(
    vertex:&SpirvSourceReflection,
    pixel:&SpirvSourceReflection,
)->Result<NativeStageDescriptorContract,String>{
    let vertex_entrypoint=check_entrypoint(vertex,NativePipelineStage::Vertex)?;
    let pixel_entrypoint=check_entrypoint(pixel,NativePipelineStage::Pixel)?;
    let mut source=BTreeMap::<(u32,u32),Vec<NativeDescriptorClaim>>::new();
    claims_for(&mut source,NativePipelineStage::Vertex,&vertex.descriptors);
    claims_for(&mut source,NativePipelineStage::Pixel,&pixel.descriptors);
    if source.len()>16384{
        return Err("Source2 shader descriptor contract exceeds bounded resource count".into());
    }
    let mut descriptors=Vec::with_capacity(source.len());
    let mut aliases=0;
    let mut ambiguous=0;
    let mut original_sets=BTreeSet::new();
    for ((set,binding),mut claims) in source{
        claims.sort_by_key(|c|(c.stage,c.variable_id));
        let stages=claims.iter().map(|c|c.stage).collect::<BTreeSet<_>>();
        let mut aliased_in_stage=false;
        let mut unresolved_source_types=false;
        let mut different_stage_storage_classes=false;
        for stage in [NativePipelineStage::Vertex,NativePipelineStage::Pixel]{
            let declared=claims.iter().filter(|c|c.stage==stage)
                .collect::<Vec<_>>();
            if declared.len()>1{
                aliased_in_stage=true;
                if declared.iter().any(|c|c.type_id!=declared[0].type_id ||
                    c.storage_class!=declared[0].storage_class){
                    unresolved_source_types=true;
                }
            }
        }
        if stages.len()>1{
            let first=claims[0].storage_class;
            if claims.iter().any(|c|c.storage_class!=first){
                different_stage_storage_classes=true;
            }
        }
        aliases+=usize::from(aliased_in_stage);
        ambiguous+=usize::from(unresolved_source_types ||
            different_stage_storage_classes);
        original_sets.insert(set);
        descriptors.push(NativeDescriptorCoordinate{
            set,binding,claims,stages,aliased_in_stage,
            unresolved_source_types,different_stage_storage_classes
        });
    }
    Ok(NativeStageDescriptorContract{
        vertex_entrypoint,pixel_entrypoint,
        source_declarations:vertex.descriptors.len()+pixel.descriptors.len(),
        distinct_coordinates:descriptors.len(),
        alias_coordinates:aliases,
        incompatible_or_ambiguous_coordinates:ambiguous,
        original_sets,descriptors,
        incomplete_source_declarations:
            vertex.incomplete_descriptors.len()+pixel.incomplete_descriptors.len(),
        source_specialization_constants:
            vertex.specialization_constant_ids.len()+
            pixel.specialization_constant_ids.len(),
    })
}
#[cfg(test)]
mod tests{
    use super::*;
    use crate::vcs_spirv::SpirvEntryPoint;
    fn fixture(stage:u32,descriptors:Vec<SpirvResource>)->SpirvSourceReflection{
        SpirvSourceReflection{
            version_word:0x10500,original_id_bound:100,
            entry_points:vec![SpirvEntryPoint{
                stage,function_id:1,name:if stage==0{"MainVs"}else{"MainPs"}.into(),
            }],
            descriptors,incomplete_descriptors:vec![],
            specialization_constant_ids:vec![],declared_location_count:0,
        }
    }
    fn declaration(id:u32,ty:u32,set:u32,binding:u32,storage:u32)->SpirvResource{
        SpirvResource{
            id,type_id:ty,set,binding,storage_class:storage,
            name:None,
        }
    }
    #[test]
    fn original_same_stage_alias_is_one_vulkan_binding_not_two(){
        let vs=fixture(0,vec![declaration(2,5,0,0,2)]);
        let ps=fixture(4,vec![
            declaration(12,8,4,29,0),
            declaration(13,8,4,29,0),
        ]);
        let audit=audit_original_vs_ps(&vs,&ps).unwrap();
        assert_eq!(audit.source_declarations,3);
        assert_eq!(audit.distinct_coordinates,2);
        assert_eq!(audit.alias_coordinates,1);
        assert_eq!(audit.incompatible_or_ambiguous_coordinates,0);
        assert_eq!(audit.descriptors[1].claims.len(),2);
    }
    #[test]
    fn source2_lightmapped_type_alias_must_remain_unresolved(){
        let vs=fixture(0,vec![declaration(2,5,0,0,2)]);
        let ps=fixture(4,vec![
            declaration(31,8,4,46,0),
            declaration(32,9,4,46,0),
            declaration(33,10,4,46,0),
        ]);
        let audit=audit_original_vs_ps(&vs,&ps).unwrap();
        assert_eq!(audit.source_declarations,4);
        assert_eq!(audit.distinct_coordinates,2);
        assert_eq!(audit.alias_coordinates,1);
        assert_eq!(audit.incompatible_or_ambiguous_coordinates,1);
        assert!(audit.has_source_ambiguity());
    }
    #[test]
    fn original_cross_stage_descriptor_class_collision_blocks_admission(){
        let vs=fixture(0,vec![declaration(2,5,1,0,2)]);
        let ps=fixture(4,vec![declaration(3,7,1,0,12)]);
        let audit=audit_original_vs_ps(&vs,&ps).unwrap();
        assert!(audit.descriptors[0].different_stage_storage_classes);
        assert!(audit.has_source_ambiguity());
    }
    #[test]
    fn original_vs_ps_stage_must_match_compiled_entrypoint(){
        let wrong=fixture(4,vec![]);
        assert!(audit_original_vs_ps(&wrong,&wrong).is_err());
    }
}
