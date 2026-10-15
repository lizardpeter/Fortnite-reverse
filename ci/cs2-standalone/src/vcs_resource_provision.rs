//! Source-exact resource provisioning for CS2 compiled materials and baked light.
//!
//! Builds actual original VTEX read/decode requests and preserves Source2 SH2
//! lightmap arrays, direct-light shadows, and VMAT texture/constant semantics
//! as independent resource identities. It intentionally does NOT reinterpret
//! an SH channel as RGBM or silently assume Source2 register offsets are
//! Vulkan binding numbers. Only an exact OpName on a non-ambiguous source
//! SPIR-V descriptor is sufficient to associate a named input to a native
//! coordinate. A later shared Vulkan descriptor backend consumes this
//! contract; unknown scene-global buffers remain explicitly unresolved.
use std::collections::{BTreeMap,BTreeSet};
use neutral_scene::NeutralTexture;
use crate::{
    lightmap::{self,LightmapAudit},
    material::{Material,SourcePacks},
    texture,
    vcs_descriptor_contract::NativeStageDescriptorContract,
    vcs_variable_contract::CompilerSourceVariable,
};

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum OriginalLightingPolicy {
    /// Source baked lighting and author/runtime real-time light inputs.
    BakedAndDynamic,
    /// Preserve authored realtime lights, do not sample baked arrays.
    DynamicOnly,
    /// Source baked arrays, realtime lights disabled by scene settings.
    BakedOnly,
    /// Do not sample either baked light or runtime lights (flashlight or user
    /// supplied scene lighting may be enabled independently).
    ExternalOnly,
}
impl OriginalLightingPolicy {
    pub fn baked_enabled(self)->bool {
        matches!(self,Self::BakedAndDynamic|Self::BakedOnly)
    }
    pub fn dynamic_enabled(self)->bool {
        matches!(self,Self::BakedAndDynamic|Self::DynamicOnly)
    }
}
#[derive(Clone,Debug,PartialEq)]
pub enum NativeInput {
    MaterialTexture { path:String },
    MaterialScalar(f32),
    MaterialSwitch(i64),
    /// Source2 lightmaps are distinct TEXTURE_ARRAY textures, not a generic
    /// single neutral-scene RGBA image. In particular this retains SH2 R/G/B
    /// coefficients and original shadow-mask channel independently.
    BakedTextureArray { path:String, width:u32, height:u32, layers:u32 },
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub enum NativeBindingState {
    /// Shader's OpName exactly matches a registered source variable name.
    /// A single non-conflicting (set,binding) exists in the compiled SPIR-V.
    SourceNamed { set:u32,binding:u32 },
    /// Real compiled stage contains a binding alias that cannot yet be
    /// proven equivalent. The engine MUST NOT create a guessed descriptor.
    SourceAliasUnresolved,
    /// Original Vulkan SPIR-V lacks the name -> descriptor relationship.
    /// The Source2 runtime binder must be reversed before admission.
    NativeBindingUnresolved,
}
#[derive(Clone,Debug,PartialEq)]
pub struct PreparedNativeInput {
    pub name:String,
    pub input:NativeInput,
    pub native_binding:NativeBindingState,
}
#[derive(Clone,Debug,Default)]
pub struct NativeProvisionPlan {
    pub compiler_variable_count:usize,
    pub physical_inputs:Vec<PreparedNativeInput>,
    pub missing_source_files:Vec<String>,
    pub missing_shader_input_names:Vec<String>,
    pub ambiguous_source_variable_names:Vec<String>,
    pub reserved_native_descriptors:usize,
    pub native_descriptors_needing_runtime_mapping:usize,
    pub unresolved_native_aliases:usize,
    pub expected_baked_channels:usize,
    pub provisioned_baked_channels:usize,
    pub lighting_mode:Option<OriginalLightingPolicy>,
}
impl NativeProvisionPlan {
    pub fn native_admission_blocked(&self)->bool {
        !self.missing_source_files.is_empty() ||
        !self.missing_shader_input_names.is_empty() ||
        !self.ambiguous_source_variable_names.is_empty() ||
        (self.lighting_mode.is_some_and(OriginalLightingPolicy::baked_enabled) &&
            self.provisioned_baked_channels!=self.expected_baked_channels) ||
        self.native_descriptors_needing_runtime_mapping>0 ||
        self.unresolved_native_aliases>0
    }
    pub fn loaded_names(&self)->BTreeSet<&str> {
        self.physical_inputs.iter().map(|p|p.name.as_str()).collect()
    }
}
fn compiled_vtex(raw:&str)->Result<String,String>{
    let path=raw.replace('\\',"/");
    if path.is_empty()||path.starts_with('/')||path.contains(':')||
        path.split('/').any(|component|component.is_empty()||
            component=="."||component==".."){
        return Err("original source VTEX path unsafe".into());
    }
    if path.ends_with(".vtex_c"){Ok(path)}
    else if path.ends_with(".vtex"){Ok(format!("{path}_c"))}
    else{Err(format!("material texture has no original .vtex source: {path}"))}
}
fn original_native_coordinate(
    name:&str,contract:&NativeStageDescriptorContract
)->NativeBindingState {
    let matches=contract.descriptors.iter().filter(|coordinate|
        coordinate.claims.iter().any(|claim|
            claim.authored_name.as_deref()==Some(name)
        )
    ).collect::<Vec<_>>();
    if matches.len()!=1 {return NativeBindingState::NativeBindingUnresolved;}
    let coordinate=matches[0];
    if coordinate.unresolved_source_types||coordinate.different_stage_storage_classes{
        return NativeBindingState::SourceAliasUnresolved;
    }
    NativeBindingState::SourceNamed{
        set:coordinate.set,binding:coordinate.binding
    }
}
/// Prepare the resources the Source2 compiler actually names. VMAT input
/// maps and VCS variable arrays are retained independently: an absent
/// runtime-only uniform is not renamed into a guessed material parameter.
///
/// The baked atlas is deliberately optional and controlled by lighting policy.
/// Atlas channels are kept by their exact Source2 global names, not mapped
/// into per-material g_tColor or generic ambient_rgbm slots.
pub fn plan_original_inputs(
    packs:&SourcePacks<'_>,
    material:&Material,
    compiler_vars:&[CompilerSourceVariable],
    atlas:Option<&LightmapAudit>,
    contract:&NativeStageDescriptorContract,
    policy:OriginalLightingPolicy,
)->NativeProvisionPlan{
    let mut plan=NativeProvisionPlan{
        compiler_variable_count:compiler_vars.len(),
        lighting_mode:Some(policy),
        reserved_native_descriptors:contract.distinct_coordinates,
        unresolved_native_aliases:contract.incompatible_or_ambiguous_coordinates+
            contract.incomplete_source_declarations,
        ..Default::default()
    };
    let mut named=BTreeMap::<String,Vec<usize>>::new();
    for variable in compiler_vars{
        named.entry(variable.name.clone()).or_default().push(variable.index);
    }
    plan.ambiguous_source_variable_names=named.iter()
        .filter(|(_,ids)|ids.len()>1).map(|(name,_)|name.clone()).collect();
    let mut used= BTreeSet::<String>::new();
    // Preserve actual shader variable order and never invent slots for
    // original Source2 materials absent from the compiled stage.
    for variable in compiler_vars {
        if !used.insert(variable.name.clone()){continue;}
        let name=&variable.name;
        let source=if let Some(path)=material.textures.get(name){
            match compiled_vtex(path) {
                Ok(path)=>{
                    if !packs.has(&path){plan.missing_source_files.push(path.clone());}
                    Some(NativeInput::MaterialTexture{path})
                },
                Err(err)=>{plan.missing_source_files.push(format!("{name}: {err}"));None}
            }
        }else if let Some(scalar)=material.scalars.get(name){
            if scalar.is_finite(){Some(NativeInput::MaterialScalar(*scalar))}
            else {None}
        }else if let Some(value)=material.switches.get(name){
            Some(NativeInput::MaterialSwitch(*value))
        }else if policy.baked_enabled(){
            atlas.and_then(|a|a.channels.get(name)).map(|channel|
                NativeInput::BakedTextureArray{
                    path:channel.path.clone(),
                    width:channel.meta.width as u32,
                    height:channel.meta.height as u32,
                    layers:channel.meta.depth as u32
                })
        }else{None};
        if let Some(input)=source{
            let native_binding=original_native_coordinate(name,contract);
            plan.physical_inputs.push(PreparedNativeInput{
                name:name.clone(),input,native_binding
            });
        }else{
            plan.missing_shader_input_names.push(name.clone());
        }
    }
    if policy.baked_enabled(){
        if let Some(atlas)=atlas{
            plan.expected_baked_channels=atlas.expected_channels.len();
            plan.provisioned_baked_channels=plan.physical_inputs.iter()
                .filter(|p|matches!(p.input,NativeInput::BakedTextureArray{..})).count();
            if !atlas.complete{
                plan.missing_source_files.extend(atlas.errors.iter().cloned());
            }
            if plan.provisioned_baked_channels!=plan.expected_baked_channels{
                plan.missing_source_files.push(format!(
                    "original lightmap shader requires {} distinct Source2 array channels, only {} can be attached by compiler name",
                    plan.expected_baked_channels,plan.provisioned_baked_channels
                ));
            }
        }else{
            plan.missing_source_files.push(
                "original baked lighting selected, but Source2 WorldLightingInfo/VTEX atlas is absent".into()
            );
        }
    }
    // A Source2 SPIR-V OpName might be stripped. In that case, having the
    // original VCS register offset DOES NOT prove what Vulkan binding it is.
    // Count unresolved source-native shader descriptors directly.
    let identified=plan.physical_inputs.iter()
        .filter_map(|p|match p.native_binding {
            NativeBindingState::SourceNamed{set,binding}=>Some((set,binding)),
            _=>None
        }).collect::<BTreeSet<_>>();
    plan.native_descriptors_needing_runtime_mapping=contract.descriptors.iter()
        .filter(|d|!identified.contains(&(d.set,d.binding))).count();
    plan
}
/// Perform an actual original source VTEX read/decode when the shared renderer
/// requests the named resource. Never retain all alternate maps or stages.
#[derive(Clone,Debug)]
pub enum OriginalLoadedInput {
    Texture2D(NeutralTexture),
    TextureArray(Vec<NeutralTexture>),
    Scalar(f32),
    Switch(i64),
}
pub fn load_original_input(
    packs:&SourcePacks<'_>,prepared:&PreparedNativeInput
)->Result<OriginalLoadedInput,String>{
    match &prepared.input{
        NativeInput::MaterialTexture{path}=>{
            let pixels=texture::decode(&packs.read(path)?,path)?;
            Ok(OriginalLoadedInput::Texture2D(pixels))
        },
        NativeInput::BakedTextureArray{path,width,height,layers}=>{
            if *layers==0 || *layers>16384{
                return Err("source baked atlas layer count outside supported range".into());
            }
            let file=packs.read(path)?;
            let decoded=texture::decode_2d_array_layers(&file,path)?;
            if decoded.len()!=*layers as usize || decoded.iter().any(|layer|
                layer.width!=*width||layer.height!=*height){
                return Err("original Source2 atlas VTEX layer topology mismatch".into());
            }
            Ok(OriginalLoadedInput::TextureArray(decoded))
        },
        NativeInput::MaterialScalar(value)=>Ok(OriginalLoadedInput::Scalar(*value)),
        NativeInput::MaterialSwitch(value)=>Ok(OriginalLoadedInput::Switch(*value)),
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    use crate::vcs_descriptor_contract::{
        NativeDescriptorCoordinate,NativeDescriptorClaim,NativePipelineStage
    };
    fn contract(claim:Option<&str>)->NativeStageDescriptorContract{
        NativeStageDescriptorContract{
            vertex_entrypoint:"MainVs".into(),pixel_entrypoint:"MainPs".into(),
            source_declarations:1,distinct_coordinates:1,alias_coordinates:0,
            incompatible_or_ambiguous_coordinates:0,
            original_sets:BTreeSet::from([4]),
            descriptors:vec![NativeDescriptorCoordinate{
                set:4,binding:29,
                claims:vec![NativeDescriptorClaim{
                    stage:NativePipelineStage::Pixel,variable_id:8,
                    type_id:9,storage_class:0,
                    authored_name:claim.map(str::to_owned),
                }],
                stages:BTreeSet::from([NativePipelineStage::Pixel]),
                aliased_in_stage:false,unresolved_source_types:false,
                different_stage_storage_classes:false,
            }],
            incomplete_source_declarations:0,
            source_specialization_constants:0,
        }
    }
    #[test]
    fn compile_source_texture_paths_are_validated_not_guessed(){
        assert_eq!(compiled_vtex("materials/a.vtex").unwrap(),
            "materials/a.vtex_c");
        assert!(compiled_vtex("../materials/a.vtex").is_err());
        assert!(compiled_vtex("C:/a.vtex").is_err());
        assert!(compiled_vtex("materials/a.png").is_err());
    }
    #[test]
    fn unproven_shader_opname_does_not_become_fake_descriptor_slot(){
        assert_eq!(original_native_coordinate("g_tColor",&contract(None)),
            NativeBindingState::NativeBindingUnresolved);
        assert_eq!(original_native_coordinate("g_tColor",&contract(Some("g_tColor"))),
            NativeBindingState::SourceNamed{set:4,binding:29});
    }
    #[test]
    fn live_and_baked_modes_are_independent_and_explicit(){
        assert!(OriginalLightingPolicy::BakedOnly.baked_enabled());
        assert!(!OriginalLightingPolicy::BakedOnly.dynamic_enabled());
        assert!(OriginalLightingPolicy::DynamicOnly.dynamic_enabled());
        assert!(!OriginalLightingPolicy::DynamicOnly.baked_enabled());
        assert!(!OriginalLightingPolicy::ExternalOnly.baked_enabled());
        assert!(!OriginalLightingPolicy::ExternalOnly.dynamic_enabled());
    }
}
