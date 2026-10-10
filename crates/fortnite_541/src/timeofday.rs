//! Source-authenticated Fortnite 5.41 BR time-of-day cooked blueprint state.
//! No guessed sun direction, extra lights, phase timing or sky materials.
//! Float units, explicit defaults and the original day-phase object identities
//! are kept distinct from engine-neutral renderer semantics.
use crate::{properties, uobject};
use std::path::Path;

const RELATIVE:&str="FortniteGame/Content/TimeOfDay/TODM/BR/TODM_BR";

#[derive(Clone,Copy,Debug)]
pub struct OriginalPhase {
    pub slot:usize,
    pub time_phase_begins:Option<f32>,
    pub phase_length_hours:Option<f32>,
    pub skylight_linear_rgba:[f32;4],
    pub directional_light_brightness:f32,
    pub directional_light_bgra:[u8;4],
    pub fog_color_linear_rgba:[f32;4],
    pub fog_density:f32,
    pub fog_height_falloff:f32,
}
#[derive(Clone,Debug)]
pub struct OriginalTimeOfDay {
    pub phases:[OriginalPhase;4],
    pub default_object_name:String,
}
fn f32_value(props:&properties::Properties,raw:&[u8],name:&str)->Result<Option<f32>,String>{
    let prop=props.fields.iter().filter(|p|p.name==name).collect::<Vec<_>>();
    if prop.is_empty(){return Ok(None);}
    if prop.len()!=1||prop[0].kind!="FloatProperty"||prop[0].payload.len()!=4 {
        return Err(format!("source TODM {name} must be a unique float"));
    }
    let v=f32::from_le_bytes(raw[prop[0].payload.clone()].try_into().unwrap());
    if !v.is_finite(){return Err(format!("nonfinite original TODM {name}"));}
    Ok(Some(v))
}
fn linear4(props:&properties::Properties,raw:&[u8],name:&str)->Result<Option<[f32;4]>,String>{
    let prop=props.fields.iter().filter(|p|p.name==name).collect::<Vec<_>>();
    if prop.is_empty(){return Ok(None);}
    if prop.len()!=1||prop[0].kind!="StructProperty"||
        prop[0].metadata.first().map(String::as_str)!=Some("LinearColor")||prop[0].payload.len()!=16{
        return Err(format!("source TODM {name} must be original LinearColor"));
    }
    let b=&raw[prop[0].payload.clone()];
    let c=std::array::from_fn(|i|f32::from_le_bytes(b[i*4..i*4+4].try_into().unwrap()));
    if !c.iter().all(|v|v.is_finite()){return Err(format!("nonfinite original TODM {name}"));}
    Ok(Some(c))
}
fn struct_data<'a>(p:&properties::Properties,raw:&'a [u8],field:&str,kind:&str)->Result<&'a [u8],String>{
    let matching=p.fields.iter().filter(|x|x.name==field).collect::<Vec<_>>();
    if matching.len()!=1||matching[0].kind!="StructProperty"||
        matching[0].metadata.first().map(String::as_str)!=Some(kind){
        return Err(format!("original TODM {field} {kind} missing/multiple/unexpected type"));
    }
    Ok(&raw[matching[0].payload.clone()])
}
fn phase(catalog:&uobject::PackageCatalog,raw:&[u8],slot:usize)->Result<OriginalPhase,String>{
    let props=properties::scan(catalog,raw)?;
    if props.bytes_consumed!=raw.len(){return Err(format!("source phase {slot} has extra unexpected bytes"));}
    let sky_raw=struct_data(&props,raw,"SkyLightValues","SkyLightValues")?;
    let sun_raw=struct_data(&props,raw,"DirectionalLightValues","DirectionalLightValues")?;
    let fog_raw=struct_data(&props,raw,"ExpHeightFogValues","ExponentialHeightFogValues")?;
    let sky=properties::scan(catalog,sky_raw)?;
    let sun=properties::scan(catalog,sun_raw)?;
    let fog=properties::scan(catalog,fog_raw)?;
    let skylight_linear_rgba=linear4(&sky,sky_raw,"SkyLightColor")?
        .ok_or("original SkyLightColor is missing")?;
    let directional_light_brightness=f32_value(&sun,sun_raw,"Brightness")?
        .ok_or("original sun Brightness absent")?;
    let color=sun.fields.iter().find(|p|p.name=="LightColor")
        .ok_or("original sun LightColor absent")?;
    if color.kind!="StructProperty"||color.metadata.first().map(String::as_str)!=Some("Color")||color.payload.len()!=4{
        return Err("source DirectionalLightValues.LightColor is not UE4 FColor".into());
    }
    let directional_light_bgra=sun_raw[color.payload.clone()].try_into().unwrap();
    let fog_color_linear_rgba=linear4(&fog,fog_raw,"FogInscatteringColor")?
        .ok_or("original FogInscatteringColor absent")?;
    let fog_density=f32_value(&fog,fog_raw,"FogDensity")?
        .ok_or("original fog density absent")?;
    let fog_height_falloff=f32_value(&fog,fog_raw,"FogHeightFalloff")?
        .ok_or("original fog falloff absent")?;
    if fog_density<0.||fog_height_falloff<0.||directional_light_brightness<0.{
        return Err("original TODM physical coefficients cannot be negative".into());
    }
    Ok(OriginalPhase{
        slot,time_phase_begins:f32_value(&props,raw,"TimePhaseBegins")?,
        phase_length_hours:f32_value(&props,raw,"PhaseLengthInHours")?,
        skylight_linear_rgba,directional_light_brightness,
        directional_light_bgra,fog_color_linear_rgba,fog_density,fog_height_falloff,
    })
}
pub fn inspect_source(header:&[u8],companion:&[u8])->Result<OriginalTimeOfDay,String>{
    let catalog=uobject::inspect(header)?;
    let mut matching=catalog.exports.iter().filter(|e|
        catalog.names.get(e.object_name.name_index as usize)
            .is_some_and(|n|n=="Default__TODM_BR_C"));
    let export=matching.next().ok_or("source TODM BR class default object missing")?;
    if matching.next().is_some(){return Err("ambiguous original TODM BR class default object".into());}
    if catalog.export_class_name(export)!=Some("TODM_BR_C"){return Err("wrong source TODM class".into());}
    let raw=catalog.export_data(header,companion,export)?;
    let props=properties::scan(&catalog,raw)?;
    let mut phases=Vec::new();
    let mut indices=Vec::new();
    for field in props.fields.iter().filter(|f|f.name=="LightAndFogPhaseSettings"){
        if field.kind!="StructProperty"||
            field.metadata.first().map(String::as_str)!=Some("DayPhaseInfo"){
            return Err("source time-of-day phase is not authored DayPhaseInfo".into());
        }
        let slot=usize::try_from(field.array_index).map_err(|_|"negative source day phase")?;
        phases.push(phase(&catalog,&raw[field.payload.clone()],slot)?);
        indices.push(slot);
    }
    if indices!=[0,1,2,3] {return Err(format!("original TODM four phase slots not closed: {indices:?}"));}
    let phases: [OriginalPhase;4]=phases.try_into().map_err(|_|"expected exactly four original day phases")?;
    Ok(OriginalTimeOfDay{phases,default_object_name:"Default__TODM_BR_C".into()})
}
pub fn from_source_root(root:&Path)->Result<OriginalTimeOfDay,String>{
    let base=root.join(RELATIVE);
    let header=std::fs::read(base.with_extension("uasset"))
        .map_err(|e|format!("original TODM_BR.uasset {}: {e}",base.display()))?;
    let companion=std::fs::read(base.with_extension("uexp"))
        .map_err(|e|format!("original TODM_BR.uexp {}: {e}",base.display()))?;
    inspect_source(&header,&companion)
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn no_implicit_time_phase_defaults(){
        let p=OriginalPhase{slot:1,time_phase_begins:Some(7.),
            phase_length_hours:Some(12.),skylight_linear_rgba:[0.61144,0.780079,1.1,0.8],
            directional_light_brightness:3.,directional_light_bgra:[255;4],
            fog_color_linear_rgba:[0.2,0.526164,1.,1.],fog_density:0.004,
            fog_height_falloff:0.2};
        assert_eq!(p.time_phase_begins,Some(7.));
        assert_eq!(p.fog_density,0.004);
    }
}
