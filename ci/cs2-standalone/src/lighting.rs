//! Source-authored CS2 light entities lowered into universal lighting.
//!
//! This is a physically motivated realtime approximation until Source 2's
//! original baked lightmaps, area-luminaire geometry and shadow masks are
//! translated. The exact Source entity color, position, lumens, range and
//! sun orientation remain the authority. No hardcoded Dust2 light placements.
use crate::entity::{self, EntityLump};
use neutral_scene::{NeutralLocalLight,NeutralLocalLightKind,NeutralSun};

#[derive(Debug,Default)]
pub struct Lighting {
    pub sun:Option<NeutralSun>,
    pub local:Vec<NeutralLocalLight>,
    pub omitted:usize,
    pub source_sky_material:Option<String>,
}
fn numeric(e:&entity::Entity,name:&str)->Option<f32>{
    let v=e.properties.field(name)?;
    let n=v.as_float().or_else(||v.as_text()?.parse::<f64>().ok())?;
    if n.is_finite() && n.abs()<1e9 {Some(n as f32)} else {None}
}
fn enabled(e:&entity::Entity)->bool {
    match e.properties.field("enabled") {
        None=>true,
        Some(crate::kv3::Value::Bool(v))=>*v,
        _=>numeric(e,"enabled").map(|x|x!=0.).unwrap_or(true)
    }
}
fn color(e:&entity::Entity,field:&str)->Option<[f32;3]>{
    let v=e.properties.field(field)?.as_array()?;
    if v.len()!=3{return None}
    let mut rgb=[0.;3];
    for i in 0..3{
        let x=v[i].as_float().or_else(||v[i].as_text()?.parse::<f64>().ok())?;
        if !x.is_finite() || !(0.0..=255.0).contains(&x){return None}
        rgb[i]=x as f32/255.;
    }
    Some(rgb)
}
fn source_sun(angles:[f32;3])->[f32;3]{
    let pitch=angles[0].to_radians();
    let yaw=angles[1].to_radians();
    // Source view direction: +x at zero, +y at positive yaw, -z at
    // positive pitch. Sun-to-world direction is the opposite vector.
    // Convert Source +Z up into renderer +Y up.
    let [cp,sp]=[pitch.cos(),pitch.sin()];
    let n=[-cp*yaw.cos(),sp,cp*yaw.sin()];
    let magnitude=(n[0]*n[0]+n[1]*n[1]+n[2]*n[2]).sqrt();
    if magnitude>0. {n.map(|c|c/magnitude)} else {[0.,1.,0.]}
}
pub fn decode(lumps:&[EntityLump])->Lighting{
    let mut out=Lighting::default();
    for e in lumps.iter().flat_map(|l|l.entities.iter()){
        if e.classname=="env_sky" {
            out.source_sky_material=e.string("skyname").map(str::to_owned);
            continue;
        }
        if !enabled(e){continue}
        match e.classname.as_str(){
            "light_environment"=>{
                if let (Some(rgb),Some(angles))=(color(e,"color"),e.source_vec3("angles")) {
                    let intensity=numeric(e,"brightness").unwrap_or(1.).max(0.)*
                        numeric(e,"brightnessscale").unwrap_or(1.).max(0.);
                    out.sun=Some(NeutralSun {
                        direction_to_light:source_sun(angles),color:rgb,intensity,
                    });
                } else {out.omitted+=1;}
            },
            "light_omni2"|"light_omni"=>{
                let Some(position)=e.source_vec3("origin") else{out.omitted+=1;continue};
                let Some(rgb)=color(e,"color") else{out.omitted+=1;continue};
                let range=numeric(e,"range").unwrap_or(0.)*0.0254;
                if !range.is_finite() || range<=0. {out.omitted+=1;continue}
                // Source 2's luminaire is stored in lumens; convert to
                // candela for isotropic point intensity (flux / 4*pi).
                // The shared Forward+ point attenuation differs from
                // Source 2 barn/omni2; this is a *reported* lighting floor.
                let candela=numeric(e,"brightness_candelas")
                    .or_else(||numeric(e,"brightness_lumens").map(|n|n/std::f32::consts::TAU/2.))
                    .unwrap_or(0.).max(0.);
                let intensity=candela*numeric(e,"brightnessscale").unwrap_or(1.).max(0.);
                if intensity<=0. {out.omitted+=1;continue}
                out.local.push(NeutralLocalLight{
                    kind:NeutralLocalLightKind::Point,
                    position:entity::engine_feet(position),
                    direction:[0.,0.,0.],
                    color:rgb,intensity,radius:range,
                    inner_angle_degrees:0.,outer_angle_degrees:180.,
                    specular_strength:1.,
                });
            },
            "light_rect"|"light_barn"=>{
                // Retain as an explicit gap. Converting Source area
                // luminaires to an arbitrary cone would be false parity.
                out.omitted+=1;
            },
            _=>{}
        }
    }
    out
}
#[cfg(test)]
mod tests{
    use super::*;
    use crate::{entity::{Entity,EntityLump},kv3::Value};
    #[test]
    fn original_light_reconstructs_meters_and_candela(){
        let obj=|v:Vec<(&str,Value)>|Value::Object(v.into_iter().map(|(k,v)|(k.to_owned(),v)).collect());
        let e=Entity{classname:"light_omni2".into(),properties:obj(vec![
            ("origin",Value::Text("0 0 128".into())),
            ("range",Value::Float(512.)),
            ("brightness_candelas",Value::Float(8.)),
            ("brightnessscale",Value::Float(1.)),
            ("color",Value::Array(vec![Value::UInt(255),Value::UInt(214),Value::UInt(180)])),
        ])};
        let l=decode(&[EntityLump{source_path:"test".into(),entities:vec![e]}]);
        assert_eq!(l.local.len(),1);
        assert_eq!(l.local[0].position,[0.,128.*0.0254,0.]);
        assert!((l.local[0].radius-13.0048).abs()<1e-4);
        assert!((l.local[0].intensity-8.).abs()<1e-5);
    }
    #[test]
    fn original_sun_direction_faces_up(){
        let v=source_sun([45.,45.,0.]);
        assert!(v[1]>0.6);
        assert!((v.iter().map(|v|v*v).sum::<f32>()-1.).abs()<1e-4);
    }
}
