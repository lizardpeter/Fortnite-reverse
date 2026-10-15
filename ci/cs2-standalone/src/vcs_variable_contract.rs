//! Original VCS v72 compiler variable descriptions and VMAT parameter names.
//!
//! Source shader material parameters must only be paired through exact,
//! compiler-authored names. A VCS variable's m_nRegisterOffset is NOT assumed
//! to be a SPIR-V OpDecorate Binding; actual Vulkan source decoration is
//! independently reflected by vcs_spirv and reconciled by
//! vcs_descriptor_contract. Runtime-only uniforms remain unbound until their
//! original provider is decoded; never guess material defaults or binding IDs.
use std::collections::{BTreeMap,BTreeSet};
use crate::{kv3::Value,material::Material};

#[derive(Clone,Debug,PartialEq,Eq)]
pub struct CompilerSourceVariable {
    pub index:usize,
    pub name:String,
    pub variable_source:Option<i64>,
    pub source_index:Option<i64>,
    pub value_type:Option<i64>,
    pub register_type:Option<i64>,
    pub register_offset:Option<i64>,
    pub descriptor_set:Option<i64>,
    pub register_elements:Option<i64>,
    pub default_texture:Option<String>,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum MaterialValueKind { Texture, Scalar, Switch }
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct AuthoredMaterialVariableMatch {
    pub compiler_index:usize,
    pub name:String,
    pub kind:MaterialValueKind,
    /// The original VCS variable's declared set, if present. This does NOT
    /// prove its compiled SPIR-V resource binding number.
    pub compiler_set:Option<i64>,
    pub compiler_register_offset:Option<i64>,
}
#[derive(Clone,Debug,Default)]
pub struct MaterialShaderVariableContract {
    pub original_compiler_variables:usize,
    pub authored_material_parameters:usize,
    pub exact_matches:Vec<AuthoredMaterialVariableMatch>,
    pub unmatched_material_parameters:Vec<String>,
    /// Source-defined shader variables not present in the VMAT. Many are
    /// engine/runtime inputs; they are NOT assigned default values here.
    pub compiler_only_variables:Vec<String>,
}
impl MaterialShaderVariableContract {
    pub fn matched_texture_count(&self)->usize{
        self.exact_matches.iter().filter(|m|m.kind==MaterialValueKind::Texture).count()
    }
}
fn integer(v:&Value)->Result<i64,String>{
    match v {
        Value::Int(n)=>Ok(*n),
        Value::UInt(n)=>i64::try_from(*n)
            .map_err(|_|"original VCS variable integer outside i64".into()),
        Value::Flagged(_,inner)=>integer(inner),
        _=>Err("original VCS register metadata is not an integer".into())
    }
}
fn optional_int(source:&Value,name:&str)->Result<Option<i64>,String>{
    source.field(name).map(integer).transpose()
}
/// Parse exact original compiler names and metadata from the v70–72 KV3
/// program's m_variableDescriptionArray, preserving source array indexes.
pub fn compiler_source_variables(root:&Value)->Result<Vec<CompilerSourceVariable>,String>{
    let authored=root.field("m_variableDescriptionArray")
        .and_then(Value::as_array)
        .ok_or("original VCS compiler variable array missing")?;
    if authored.len()>100_000{return Err("VCS variable census exceeds bound".into());}
    let mut result=Vec::with_capacity(authored.len());
    for (index,var) in authored.iter().enumerate(){
        let name=var.field("m_szName").and_then(Value::as_text)
            .ok_or("original VCS variable lacks authored name")?;
        if name.len()>4096 || name.is_empty(){
            return Err("invalid original VCS variable name extent".into());
        }
        result.push(CompilerSourceVariable{
            index,name:name.to_owned(),
            variable_source:optional_int(var,"m_sourceType")?,
            source_index:optional_int(var,"m_sourceIndex")?,
            value_type:optional_int(var,"m_type")?,
            register_type:optional_int(var,"m_registerType")?,
            register_offset:optional_int(var,"m_nRegisterOffset")?,
            descriptor_set:optional_int(var,"m_nDescriptorSet")?,
            register_elements:optional_int(var,"m_nRegisterElements")?,
            default_texture:var.field("m_defaultInputTexture")
                .and_then(Value::as_text).map(str::to_owned)
        });
    }
    Ok(result)
}
/// Exact CASE-SENSITIVE matches only. Source2 compiler material parameter
/// names are not inferred from resource file names or texture heuristics.
pub fn match_original_vmat(
    compiler:&[CompilerSourceVariable],
    material:&Material,
)->MaterialShaderVariableContract{
    let mut report=MaterialShaderVariableContract{
        original_compiler_variables:compiler.len(),
        authored_material_parameters:material.textures.len()+
            material.scalars.len()+material.switches.len(),
        ..Default::default()
    };
    let mut found=BTreeSet::new();
    for variable in compiler {
        let kind=if material.textures.contains_key(&variable.name){
            Some(MaterialValueKind::Texture)
        }else if material.scalars.contains_key(&variable.name){
            Some(MaterialValueKind::Scalar)
        }else if material.switches.contains_key(&variable.name){
            Some(MaterialValueKind::Switch)
        }else{None};
        if let Some(kind)=kind{
            found.insert(variable.name.clone());
            report.exact_matches.push(AuthoredMaterialVariableMatch{
                compiler_index:variable.index,
                name:variable.name.clone(),
                kind,
                compiler_set:variable.descriptor_set,
                compiler_register_offset:variable.register_offset,
            });
        } else {
            report.compiler_only_variables.push(variable.name.clone());
        }
    }
    let mut authored=BTreeMap::<String,MaterialValueKind>::new();
    authored.extend(material.textures.keys().cloned()
        .map(|name|(name,MaterialValueKind::Texture)));
    authored.extend(material.scalars.keys().cloned()
        .map(|name|(name,MaterialValueKind::Scalar)));
    authored.extend(material.switches.keys().cloned()
        .map(|name|(name,MaterialValueKind::Switch)));
    report.unmatched_material_parameters=authored.keys()
        .filter(|name|!found.contains(*name)).cloned().collect();
    report
}
#[cfg(test)]
mod tests {
    use super::*;
    fn variable(index:usize,name:&str)->CompilerSourceVariable{
        CompilerSourceVariable{
            index,name:name.into(),variable_source:Some(3),
            source_index:Some(0),value_type:Some(3),
            register_type:Some(4),register_offset:Some(30),
            descriptor_set:Some(4),register_elements:Some(1),
            default_texture:None
        }
    }
    fn vmat()->Material{
        Material{
            path:"materials/retail.vmat_c".into(),
            material_name:"retail".into(),
            shader:"csgo_lightmappedgeneric.vfx".into(),
            textures:BTreeMap::from([("g_tColor".into(),"materials/retail_color.vtex".into())]),
            scalars:BTreeMap::from([("g_flRoughness".into(),0.4)]),
            switches:BTreeMap::from([("F_NORMAL_MAP".into(),1)]),
            unresolved_texture_files:vec![],
        }
    }
    #[test]
    fn exact_compiler_name_matches_original_vmat_texture_but_never_guesses_runtime_globals(){
        let vars=vec![
            variable(8,"g_tColor"),
            variable(9,"g_tGlobalLightmap"),
            variable(10,"g_flRoughness")
        ];
        let report=match_original_vmat(&vars,&vmat());
        assert_eq!(report.matched_texture_count(),1);
        assert_eq!(report.exact_matches.len(),2);
        assert_eq!(report.exact_matches[0].compiler_index,8);
        assert_eq!(report.exact_matches[0].compiler_set,Some(4));
        assert_eq!(report.compiler_only_variables,vec!["g_tGlobalLightmap"]);
        assert_eq!(report.unmatched_material_parameters,vec!["F_NORMAL_MAP"]);
    }
    #[test]
    fn compiler_source_variable_offsets_are_metadata_not_vulkan_binding_ids(){
        let root=Value::Object(vec![(
            "m_variableDescriptionArray".into(),
            Value::Array(vec![Value::Object(vec![
                ("m_szName".into(),Value::Text("g_tColor".into())),
                ("m_sourceType".into(),Value::Int(1)),
                ("m_nDescriptorSet".into(),Value::UInt(4)),
                ("m_nRegisterOffset".into(),Value::UInt(30)),
            ])])
        )]);
        let out=compiler_source_variables(&root).unwrap();
        assert_eq!(out.len(),1);
        assert_eq!(out[0].name,"g_tColor");
        assert_eq!(out[0].descriptor_set,Some(4));
        assert_eq!(out[0].register_offset,Some(30));
        assert_eq!(out[0].register_type,None);
    }
}
