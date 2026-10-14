//! Exact compiled Source 2 VMAT source descriptions.
//! The Source 2 shader name and texture slots come from decoded KV3, not from
//! heuristic filename matching. No textures are considered available until
//! their actual compiled VTEX files resolve in a source package.
use crate::{kv3::{self,Value},resource::ResourceHeader,vpk::VpkArchive};
use std::{collections::{BTreeMap,BTreeSet},path::Path};

#[derive(Clone,Debug)]
pub struct Material {
    pub path:String,
    pub material_name:String,
    pub shader:String,
    pub textures:BTreeMap<String,String>,
    pub scalars:BTreeMap<String,f32>,
    pub switches:BTreeMap<String,i64>,
    pub unresolved_texture_files:Vec<String>,
}
#[derive(Clone,Debug,Default)]
pub struct MaterialCoverage {
    pub referenced:usize,
    pub material_resolved:usize,
    pub material_unresolved:Vec<String>,
    pub shaders:BTreeMap<String,usize>,
    pub authored_texture_slots:usize,
    pub texture_resolved:usize,
    pub texture_unresolved:Vec<String>,
}
fn source_path(path:&str,extension:&str)->Result<String,String>{
    let path=path.replace('\\',"/");
    if path.is_empty() || path.starts_with('/') || path.contains(':') ||
        path.split('/').any(|s|s.is_empty()||s=="."||s=="..") {
        return Err(format!("unsafe Source 2 source resource path {path:?}"));
    }
    if path.ends_with("_c"){Ok(path)}
    else if path.ends_with(extension){Ok(format!("{path}_c"))}
    else{Err(format!("expected {extension} path, got {path}"))}
}
fn collection<'a>(obj:&'a Value,key:&str)->&'a[Value]{
    obj.field(key).and_then(Value::as_array).unwrap_or(&[])
}
pub fn material_bytes(data:&[u8],path:&str)->Result<Material,String>{
    let resource=ResourceHeader::parse(data)?;
    let payload=resource.block(data,b"DATA").ok_or("compiled Source 2 material has no DATA block")?;
    let kv3=kv3::decode(payload)?.root;
    let shader=kv3.field("m_shaderName").and_then(Value::as_text).ok_or("VMAT has no shader")?;
    if shader.is_empty(){return Err(format!("VMAT {path} has empty shader name"));}
    let material_name=kv3.field("m_materialName").and_then(Value::as_text).unwrap_or(path).to_owned();
    let mut textures=BTreeMap::new();
    for item in collection(&kv3,"m_textureParams"){
        let key=item.field("m_name").and_then(Value::as_text).ok_or("VMAT texture without authored parameter name")?;
        let value=item.field("m_pValue").and_then(Value::as_text).ok_or("VMAT texture slot with no source path")?;
        textures.insert(key.to_owned(),value.to_owned());
    }
    let mut scalars=BTreeMap::new();
    for item in collection(&kv3,"m_floatParams"){
        if let (Some(key),Some(value))=(item.field("m_name").and_then(Value::as_text),
            item.field("m_flValue").and_then(Value::as_float)){
            if value.is_finite(){scalars.insert(key.to_owned(),value as f32);}
        }
    }
    let mut switches=BTreeMap::new();
    for item in collection(&kv3,"m_intParams"){
        if let (Some(key),Some(value))=(item.field("m_name").and_then(Value::as_text),
            item.field("m_nValue").and_then(Value::as_float)){
            if value.is_finite(){switches.insert(key.to_owned(),value as i64);}
        }
    }
    Ok(Material{path:path.to_owned(),material_name,shader:shader.to_owned(),textures,scalars,switches,unresolved_texture_files:Vec::new()})
}
pub struct SourcePacks<'a> {
    pub workshop_outer:&'a VpkArchive,
    pub workshop_map:&'a VpkArchive,
    pub base_game:Option<&'a VpkArchive>,
}
impl SourcePacks<'_>{
    pub fn has(&self,path:&str)->bool{
        self.workshop_map.available(path) ||
            self.workshop_outer.available(path) ||
            self.base_game.is_some_and(|v|v.available(path))
    }
    pub fn read(&self,path:&str)->Result<Vec<u8>,String>{
        if self.workshop_map.entries().contains_key(path){self.workshop_map.read_entry(path)}
        else if self.workshop_outer.entries().contains_key(path){self.workshop_outer.read_entry(path)}
        else if let Some(base)=self.base_game {
            if base.entries().contains_key(path){return base.read_entry(path);}
            Err(format!("Source 2 resource is not in any configured original archive: {path}"))
        } else{Err(format!("Source 2 resource {path} absent from Workshop; configure original CS2 game files"))}
    }
    pub fn describe(&self,original:&str)->Result<Material,String>{
        let path=source_path(original,".vmat")?;
        let mut material=material_bytes(&self.read(&path)?,&path)?;
        for path in material.textures.values(){
            if let Ok(compiled)=source_path(path,".vtex"){
                if !self.has(&compiled){material.unresolved_texture_files.push(compiled);}
            }
        }
        Ok(material)
    }
    pub fn audit<'a>(&self,names:impl IntoIterator<Item=&'a str>)->MaterialCoverage{
        let originals=BTreeSet::<String>::from_iter(names.into_iter().map(str::to_owned));
        let mut audit=MaterialCoverage{referenced:originals.len(),..Default::default()};
        let mut missing_textures=BTreeSet::new();
        for path in &originals{
            match self.describe(path){
                Ok(m)=>{
                    audit.material_resolved+=1;
                    *audit.shaders.entry(m.shader).or_default()+=1;
                    audit.authored_texture_slots+=m.textures.len();
                    audit.texture_resolved+=m.textures.len()-m.unresolved_texture_files.len();
                    missing_textures.extend(m.unresolved_texture_files);
                },
                Err(_)=>audit.material_unresolved.push(path.clone()),
            }
        }
        audit.texture_unresolved=missing_textures.into_iter().collect();
        audit
    }
}
/// Allows standard Steam CS2 installs or an explicit original pak01_dir.vpk.
/// Does not copy Valve data or attempt to download restricted game files.
pub fn base_game_archive() ->Result<Option<VpkArchive>,String>{
    let mut paths=Vec::new();
    if let Some(path)=std::env::var_os("RUST_TEST_CS2_GAME_VPK_DIR"){
        let path=std::path::PathBuf::from(path);
        paths.push(if path.is_dir(){path.join("pak01_dir.vpk")}else{path});
    }
    if let Some(program_files)=std::env::var_os("ProgramFiles(x86)"){
        paths.push(Path::new(&program_files).join("Steam/steamapps/common/Counter-Strike Global Offensive/game/csgo/pak01_dir.vpk"));
    }
    match paths.into_iter().find(|p|p.is_file()){
        Some(path)=>VpkArchive::open_directory(&path).map(Some),
        None=>Ok(None),
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn resource_path_security(){
        assert_eq!(source_path("materials/foo.vmat",".vmat").unwrap(),"materials/foo.vmat_c");
        assert!(source_path("../evil.vmat",".vmat").is_err());
    }
}