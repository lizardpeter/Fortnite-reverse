//! Inspect actual original Source2 entity-defined lighting / fog controllers.
use std::{path::Path,collections::BTreeMap};
use cs2_importer::{entity,vpk::VpkArchive};
fn main()->Result<(),String>{
 let root=std::env::var("ORIGINAL_CS2_WORKSHOP_DIR").map_err(|e|e.to_string())?;
 let archive=VpkArchive::open_directory(&Path::new(&root).join("3620630831_dir.vpk"))?;
 for map in ["maps/de_dust2_christmas.vpk","maps/de_dust2_winter.vpk"] {
   let inner=archive.open_nested(map)?;
   let lumps=entity::from_nested_map(&inner)?;
   let original=cs2_importer::lighting::decode(&lumps);
   if map=="maps/de_dust2_christmas.vpk" {
     let fog=original.fog.as_ref().ok_or("Christmas original env_gradient_fog did not lower")?;
     let source=original.gradient_fog_source.as_ref().ok_or("Christmas original gradient metadata lost")?;
     if (fog.color[0]-204./255.).abs()>1e-5 ||
        source.end_distance!=4000. || source.falloff_exponent!=2. ||
        original.sky_brightness_scale.map(|x|(x-0.4).abs()>1e-5)!=Some(false) ||
        original.sky_tint.map(|x|(x[0]-206./255.).abs()>1e-5)!=Some(false) {
       return Err(format!("original Christmas sky/fog values changed: {:?} {:?}",
         original.sky_brightness_scale,source));
     }
     println!("CERTIFIED_ORIGINAL_CHRISTMAS_ENV_SKY_FOG brightness={:?} tint={:?} fogcolor={:?} fogdensity={} source_gradient={:?}",
       original.sky_brightness_scale,original.sky_tint,fog.color,fog.density,source);
   }
   let mut classes=BTreeMap::<String,usize>::new();
   for e in lumps.iter().flat_map(|l|l.entities.iter()){
     *classes.entry(e.classname.clone()).or_default()+=1;
     if e.classname.starts_with("env_")||e.classname.contains("fog")||
        e.classname.contains("postprocess")||e.classname.contains("tonemap")||
        e.classname.contains("color_correction")||e.classname=="light_environment" {
        println!("CS2_SOURCE_ENVIRONMENT {} {} {:?}",map,e.classname,e.properties);
     }
   }
   println!("CS2_ORIGINAL_SOURCE_CLASS_CENSUS {map} {:?}", classes.iter().filter(|(name,_)|
     name.starts_with("env_")||name.starts_with("light_")||
     name.contains("fog")||name.contains("postprocess")
   ).collect::<Vec<_>>());
 }
 Ok(())
}