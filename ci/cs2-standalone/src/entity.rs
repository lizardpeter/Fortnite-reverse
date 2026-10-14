//! Compiled Source 2 entity-lump records. Reads original KV3 attributes,
//! including zero-length blob slots (not binary reinterpretation guesses).
//! No fabricated spawn positions, sky asset names or light parameters.
use crate::{kv3::{self,Value},resource::ResourceHeader,vpk::VpkArchive};
use std::collections::BTreeMap;

const MAX_ENTITIES:usize=100_000;
#[derive(Clone,Debug)]
pub struct Entity {
    pub classname:String,
    pub properties:Value,
}
#[derive(Clone,Debug)]
pub struct EntityLump {
    pub source_path:String,
    pub entities:Vec<Entity>,
}
#[derive(Clone,Debug)]
pub struct Spawn {
    pub classname:String,
    pub source_origin:[f32;3],
    /// Source 2 editor Euler degrees (pitch, yaw, roll), untouched.
    pub source_angles:[f32;3],
}
impl Entity {
    pub fn string(&self, key:&str)->Option<&str>{
        self.properties.field(key).and_then(Value::as_text)
    }
    pub fn source_vec3(&self,key:&str)->Option<[f32;3]>{
        let v=self.properties.field(key)?;
        source_vec3(v)
    }
}
fn source_vec3(value:&Value)->Option<[f32;3]>{
    match value{
        Value::Array(values) if values.len()==3 => Some([
            finite(values[0].as_float()?)?,finite(values[1].as_float()?)?,finite(values[2].as_float()?)?
        ]),
        Value::Text(s)=>{
            let parts=s.split_ascii_whitespace().collect::<Vec<_>>();
            if parts.len()!=3 {return None;}
            Some([
                finite(parts[0].parse::<f64>().ok()?)?,
                finite(parts[1].parse::<f64>().ok()?)?,
                finite(parts[2].parse::<f64>().ok()?)?,
            ])
        },
        Value::Flagged(_,inner)=>source_vec3(inner),
        _=>None
    }
}
fn finite(n:f64)->Option<f32>{
    if n.is_finite() && n.abs()<1e9 {Some(n as f32)}else{None}
}
pub fn decode_lump(data:&[u8],path:&str)->Result<EntityLump,String>{
    let header=ResourceHeader::parse(data)?;
    let bytes=header.block(data,b"DATA").ok_or("compiled Source 2 entity lump missing DATA")?;
    let root=kv3::decode(bytes)?.root;
    let entities=root.field("m_entityKeyValues").and_then(Value::as_array)
        .ok_or_else(||format!("{path}: missing m_entityKeyValues"))?;
    if entities.len()>MAX_ENTITIES{return Err(format!("{path}: too many source entities"));}
    let mut out=Vec::with_capacity(entities.len());
    for (index,entry) in entities.iter().enumerate(){
        let props=entry.field("keyValues3Data")
            .and_then(|data|data.field("values"))
            .or_else(||entry.field("m_keyValuesData"));
        let Some(props)=props else{continue};
        let Some(name)=props.field("classname").and_then(Value::as_text) else {
            // Old non-KV3 binary entity formats remain unadmitted.
            continue;
        };
        if name.is_empty() {return Err(format!("{path}: entity {index} has empty classname"));}
        out.push(Entity{classname:name.to_owned(),properties:props.clone()});
    }
    Ok(EntityLump{source_path:path.to_owned(),entities:out})
}
pub fn from_nested_map(archive:&VpkArchive)->Result<Vec<EntityLump>,String>{
    let mut lumps=Vec::new();
    for path in archive.entries().keys().filter(|p|p.ends_with(".vents_c")){
        lumps.push(decode_lump(&archive.read_entry(path)?,path)?);
    }
    Ok(lumps)
}
pub fn team_spawns(lumps:&[EntityLump])->Vec<Spawn>{
    let mut spawns=Vec::new();
    for entity in lumps.iter().flat_map(|l|l.entities.iter()){
        if !matches!(entity.classname.as_str(),
            "info_player_terrorist"|"info_player_counterterrorist"|"info_team_spawn"|"info_player_start") {
            continue;
        }
        let Some(origin)=entity.source_vec3("origin") else {continue};
        let angles=entity.source_vec3("angles").unwrap_or([0.;3]);
        spawns.push(Spawn{classname:entity.classname.clone(),source_origin:origin,source_angles:angles});
    }
    spawns
}
pub fn sky_name(lumps:&[EntityLump])->Option<String>{
    lumps.iter().flat_map(|l|l.entities.iter())
        .find(|e|e.classname=="worldspawn")?.string("skyname").map(str::to_owned)
}
pub fn class_counts(lumps:&[EntityLump])->BTreeMap<String,usize>{
    let mut result=BTreeMap::new();
    for e in lumps.iter().flat_map(|l|l.entities.iter()){
        *result.entry(e.classname.clone()).or_insert(0)+=1;
    }
    result
}
pub fn engine_feet(source:[f32;3])->[f32;3]{
    [source[0]*0.0254,source[2]*0.0254,-source[1]*0.0254]
}
pub fn engine_yaw(source_angles:[f32;3])->f32{
    // Source +Z yaw rotates +X toward +Y; after +Y -> engine -Z this
    // is a negative yaw in engine coordinates. Keep the original source
    // Euler triplet on Spawn for future pitch/roll replay.
    -source_angles[1].to_radians()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_source_feet_and_angles(){
        let entity=Entity{
            classname:"info_player_terrorist".into(),
            properties:Value::Object(vec![
                ("origin".into(),Value::Text("120.25 -80 72".into())),
                ("angles".into(),Value::Text("0 90 0".into()))
            ])
        };
        assert_eq!(entity.source_vec3("origin"),Some([120.25,-80.,72.]));
        assert_eq!(engine_feet([0.,0.,72.]),[0.,72.*0.0254,0.]);
        assert!((engine_yaw(entity.source_vec3("angles").unwrap())+std::f32::consts::FRAC_PI_2).abs()<0.0001);
    }
    #[test]
    fn select_only_source_spawn_entities(){
        let e=|classname:&str|Entity{classname:classname.into(),properties:Value::Object(vec![
            ("origin".into(),Value::Text("0 0 80".into()))
        ])};
        let lump=EntityLump{source_path:"map.vents_c".into(),entities:vec![e("worldspawn"),e("info_player_terrorist"),e("info_player_counterterrorist")]};
        assert_eq!(team_spawns(&[lump]).len(),2);
    }
}