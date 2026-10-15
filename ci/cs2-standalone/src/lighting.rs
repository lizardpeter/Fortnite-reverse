//! Source-authored CS2 light entities lowered into universal lighting.
//!
//! This is a physically motivated realtime approximation until Source 2's
//! original baked lightmaps, area-luminaire geometry and shadow masks are
//! translated. The exact Source entity color, position, lumens, range and
//! sun orientation remain the authority. No hardcoded Dust2 light placements.
use crate::entity::{self, EntityLump};
use neutral_scene::{NeutralFog,NeutralLocalLight,NeutralLocalLightKind,NeutralSun};

#[derive(Debug,Default)]
pub struct Lighting {
    pub sun:Option<NeutralSun>,
    pub local:Vec<NeutralLocalLight>,
    pub omitted:usize,
    pub source_sky_material:Option<String>,
    /// Original env_sky values, not an invented default intensity/tint.
    pub sky_brightness_scale:Option<f32>,
    pub sky_tint:Option<[f32;3]>,
    /// Source2 env_gradient_fog lowered to the shared neutral exponential
    /// fog until the Source2 distance/vertical power curves are supported.
    pub fog:Option<NeutralFog>,
    pub gradient_fog_source:Option<SourceGradientFog>,
}
/// Preserve the source's real gradient fog controls for later exact GPU
/// translation. The current shared fog shader is an exponential approximation.
#[derive(Clone,Debug)]
pub struct SourceGradientFog {
    pub start_distance:f32,
    pub end_distance:f32,
    pub falloff_exponent:f32,
    pub vertical_exponent:f32,
    pub source_height_enabled:bool,
    pub source_start_height:f32,
    pub source_end_height:f32,
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
fn gradient_fog(e:&entity::Entity)->Option<(NeutralFog,SourceGradientFog)> {
    let color=color(e,"fogcolor")?;
    let start=numeric(e,"fogstart")?;
    let end=numeric(e,"fogend")?;
    let strength=numeric(e,"fogstrength").unwrap_or(1.);
    let opacity=numeric(e,"fogmaxopacity").unwrap_or(1.).clamp(0.,1.);
    if end<=start || !start.is_finite() || !end.is_finite() ||
       strength<=0. || opacity<=0. {
        return None;
    }
    let falloff_exponent=numeric(e,"fogfalloffexponent").unwrap_or(1.);
    let vertical_exponent=numeric(e,"fogverticalexponent").unwrap_or(1.);
    if !falloff_exponent.is_finite() || falloff_exponent<=0. ||
        !vertical_exponent.is_finite() || vertical_exponent<=0. {
        return None;
    }
    let source_height_enabled=matches!(
        e.properties.field("heightfog"),Some(crate::kv3::Value::Bool(true))
    );
    let source_start_height=numeric(e,"fogstartheight").unwrap_or(0.);
    let source_end_height=numeric(e,"fogendheight").unwrap_or(0.);
    let source=SourceGradientFog {
        start_distance:start,end_distance:end,falloff_exponent,
        vertical_exponent,source_height_enabled,
        source_start_height,source_end_height,
    };
    // The generic GPU can express exponential optical depth, NOT the
    // original Source 2 power-shaped distance/height gradient. Match the
    // source falloff at its midpoint using the authored exponent. Do not
    // pass source distance units directly into a renderer operating in m.
    // The original opacity at midpoint is 0.5^exponent * fogstrength.
    let midpoint=(end-start)*0.5*0.0254;
    let midpoint_opacity=(0.5f32.powf(falloff_exponent)*
        strength).clamp(0.,0.999);
    let density=-(1.-midpoint_opacity).ln()/midpoint.max(0.001);
    if !density.is_finite() || density<0. {return None;}
    Some((NeutralFog {
        color,density,base_height:0.,height_falloff:0.,
        max_opacity:opacity,sun:None,
    },source))
}
/// Apply compiler-authored env_sky linear tint to original sRGB cube pixels.
/// Keep texture image resolution/orientation and all per-face source details;
/// Source2 sky shader exposure/bloom still requires native translation.
pub fn tint_source_sky_faces(
    mut faces:[neutral_scene::NeutralTexture;6],tint:[f32;3]
)->[neutral_scene::NeutralTexture;6]{
    let linear=|s:f32|if s<=0.04045{s/12.92}else{
        ((s+0.055)/1.055).powf(2.4)
    };
    let srgb=|s:f32|if s<=0.0031308{s*12.92}else{
        1.055*s.powf(1./2.4)-0.055
    };
    let tint_linear=tint.map(|v|linear(v.clamp(0.,1.)));
    for face in &mut faces{
        for pixel in face.rgba.chunks_exact_mut(4){
            for c in 0..3{
                let light=linear(pixel[c] as f32/255.)*tint_linear[c];
                pixel[c]=(srgb(light).clamp(0.,1.)*255.).round() as u8;
            }
        }
    }
    faces
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
        if !enabled(e){continue}
        if e.classname=="env_sky" {
            out.source_sky_material=e.string("skyname").map(str::to_owned);
            out.sky_brightness_scale=numeric(e,"brightnessscale")
                .filter(|v|v.is_finite()&&*v>=0.);
            out.sky_tint=color(e,"tint_color");
            continue;
        }
        if e.classname=="env_gradient_fog" {
            if let Some((fog,source))=gradient_fog(e) {
                out.fog=Some(fog);
                out.gradient_fog_source=Some(source);
            }else{out.omitted+=1;}
            continue;
        }
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
    fn original_srgb_sky_tint_applies_all_source_channels_without_face_loss(){
        let original=std::array::from_fn(|i|neutral_scene::NeutralTexture{
            name:format!("original_face_{i}"),width:1,height:1,
            rgba:vec![255,255,255,255],mips:Vec::new(),compressed:None,
        });
        let tinted=tint_source_sky_faces(original,[206./255.,218./255.,1.]);
        for face in tinted {
            assert_eq!(face.rgba,[206,218,255,255]);
            assert_eq!((face.width,face.height),(1,1));
        }
    }
    #[test]
    fn original_christmas_env_sky_brightness_tint_and_gradient_fog_are_preserved(){
        let obj=|v:Vec<(&str,Value)>|Value::Object(v.into_iter()
            .map(|(k,v)|(k.to_owned(),v)).collect());
        let sky=Entity{classname:"env_sky".into(),properties:obj(vec![
            ("skyname",Value::Text("materials/skybox/sky_de_dust2vmat.vmat".into())),
            ("brightnessscale",Value::Float(0.4)),
            ("tint_color",Value::Array(vec![Value::UInt(206),Value::UInt(218),Value::UInt(255)])),
        ])};
        let fog=Entity{classname:"env_gradient_fog".into(),properties:obj(vec![
            ("fogcolor",Value::Array(vec![Value::UInt(204),Value::UInt(205),Value::UInt(213)])),
            ("fogstart",Value::Float(0.)),
            ("fogend",Value::Float(4000.)),
            ("fogstrength",Value::Float(1.)),
            ("fogmaxopacity",Value::Float(1.)),
            ("fogfalloffexponent",Value::Float(2.)),
            ("fogverticalexponent",Value::Float(2.)),
            ("heightfog",Value::Bool(true)),
            ("fogstartheight",Value::Float(0.)),
            ("fogendheight",Value::Float(4000.)),
        ])};
        let l=decode(&[EntityLump{source_path:"original".into(),
            entities:vec![sky,fog]}]);
        assert_eq!(l.source_sky_material.as_deref(),
            Some("materials/skybox/sky_de_dust2vmat.vmat"));
        assert_eq!(l.sky_brightness_scale,Some(0.4));
        assert!((l.sky_tint.unwrap()[0]-206./255.).abs()<1e-5);
        let source=l.gradient_fog_source.unwrap();
        assert_eq!(source.start_distance,0.);
        assert_eq!(source.end_distance,4000.);
        assert_eq!(source.falloff_exponent,2.);
        assert!(source.source_height_enabled);
        let fog=l.fog.unwrap();
        assert!((fog.color[0]-204./255.).abs()<1e-5);
        // At half source fog distance (~50.8 m) original squared curve
        // reaches 25% opacity; the shared exponential fit must agree.
        let opacity=1.-(-fog.density*50.8).exp();
        assert!((opacity-0.25).abs()<1e-5);
        assert_eq!(fog.height_falloff,0.);
    }
    #[test]
    fn original_sun_direction_faces_up(){
        let v=source_sun([45.,45.,0.]);
        assert!(v[1]>0.6);
        assert!((v.iter().map(|v|v*v).sum::<f32>()-1.).abs()<1e-4);
    }
}
