//! Source 2 baked-lightmap channel integrity and exact VTEX atlas decoding.
//!
//! WorldLightingInfo identifies original textures and Source 2 shader minor
//! version. These channels are NOT generic RGBM: particularly SH2 v8.3/8.4
//! must remain five distinct source channels until their sampling shader is
//! lowered into the universal lighting program. Do not bind an arbitrary
//! source channel to NeutralLightmap::ambient_rgbm.
use std::collections::{BTreeMap,BTreeSet};
use crate::{material::SourcePacks,texture::{self,Metadata}};
use neutral_scene::NeutralTexture;
use crate::vtex_native_array::{self,SourceNativeVtexArray};

/// Names are source-defined renderer uniforms (v8.X). Not file substring
/// heuristics; match the exact original source filename without extension.
const V81:&[&str]=&["g_tIrradiance","g_tDirectionalIrradiance",
    "g_tDirectLightIndices","g_tDirectLightStrengths"];
const V82:&[&str]=&["g_tIrradiance","g_tDirectionalIrradiance","g_tDirectLightShadows"];
const V83:&[&str]=&["g_tIrradiance",
    "g_tDirectionalIrradianceR","g_tDirectionalIrradianceG",
    "g_tDirectionalIrradianceB","g_tDirectLightShadows"];
/// Exact Source 2 shader uniform semantics: both irradiance and SH2 DC
/// source filenames intentionally supply the SAME g_tIrradiance uniform.
fn uniform(name:&str)->Option<&'static str>{
    match name {
        "irradiance"|"directional_irradiance_sh2_dc"=>Some("g_tIrradiance"),
        "directional_irradiance"=>Some("g_tDirectionalIrradiance"),
        "directional_irradiance_sh2_r"=>Some("g_tDirectionalIrradianceR"),
        "directional_irradiance_sh2_g"=>Some("g_tDirectionalIrradianceG"),
        "directional_irradiance_sh2_b"=>Some("g_tDirectionalIrradianceB"),
        "direct_light_shadows"=>Some("g_tDirectLightShadows"),
        "direct_light_indices"=>Some("g_tDirectLightIndices"),
        "direct_light_strengths"=>Some("g_tDirectLightStrengths"),
        _=>None,
    }
}
#[derive(Clone,Debug)]
pub struct LightmapChannel {
    pub path:String,
    pub meta:Metadata,
}
#[derive(Clone,Debug,Default)]
pub struct LightmapAudit {
    pub version:[i64;2],
    pub expected_channels:Vec<&'static str>,
    pub channels:BTreeMap<String,LightmapChannel>,
    pub errors:Vec<String>,
    pub matching_atlas_layout:bool,
    pub complete:bool,
}
fn expected(version:[i64;2])->&'static [&'static str]{
    match version {
        [8,1]=>V81,[8,2]=>V82,[8,3|4]=>V83,_=>&[],
    }
}
fn channel_name(path:&str)->Option<&str>{
    let file=path.rsplit('/').next()?;
    file.strip_suffix(".vtex_c").or_else(||file.strip_suffix(".vtex"))
}
fn compiled(path:&str)->Result<String,String>{
    let path=path.replace('\\',"/");
    if path.is_empty()||path.starts_with('/')||path.contains(':')||
        path.split('/').any(|s|s.is_empty()||s=="."||s==".."){
        return Err("invalid Source 2 authored lightmap path".into());
    }
    if path.ends_with(".vtex_c"){Ok(path)}
    else if path.ends_with(".vtex"){Ok(format!("{path}_c"))}
    else{Err("Source 2 authored lightmap is not VTEX".into())}
}
pub fn audit(packs:&SourcePacks<'_>,names:&[String],version:[i64;2])->LightmapAudit{
    let required=expected(version);
    let mut out=LightmapAudit{
        version,expected_channels:required.to_vec(),..Default::default()
    };
    if required.is_empty(){
        out.errors.push(format!("Source2 baked lightmap shader version {}.{} not lowered",version[0],version[1]));
        return out;
    }
    let required_set=BTreeSet::<&str>::from_iter(required.iter().copied());
    for original in names {
        let path=match compiled(original){
            Ok(p)=>p,Err(e)=>{out.errors.push(format!("{original}: {e}"));continue}
        };
        let Some(name)=channel_name(&path) else {
            out.errors.push(format!("Unrecognized lightmap source path {path}"));continue
        };
        // Unknown channels may be useful for charts/debugging but cannot
        // silently stand in for any required lighting input.
        let Some(slot)=uniform(name) else {continue};
        if !required_set.contains(slot){continue;}
        if out.channels.contains_key(slot){
            out.errors.push(format!("Duplicate authored lightmap channel {slot}"));
            continue;
        }
        match packs.read(&path).and_then(|bytes|texture::inspect(&bytes)){
            Ok(meta)=>{
                if meta.flags&texture::SOURCE_CUBE_FLAG!=0 ||
                    meta.flags&texture::SOURCE_VOLUME_FLAG!=0 {
                    out.errors.push(format!("{path}: not a 2D texture array"));
                    continue;
                }
                if meta.depth>1 && meta.flags&texture::SOURCE_ARRAY_FLAG==0{
                    out.errors.push(format!("{path}: depth>1 but TEXTURE_ARRAY is not authored"));
                    continue;
                }
                out.channels.insert(slot.to_owned(),LightmapChannel{path,meta});
            },
            Err(e)=>out.errors.push(format!("{path}: {e}")),
        }
    }
    for &needed in required {
        if !out.channels.contains_key(needed) {
            out.errors.push(format!("Missing authored Source 2 lightmap channel {needed}"));
        }
    }
    let mut dims=out.channels.values().map(|v|
        (v.meta.width,v.meta.height,v.meta.depth));
    if let Some(first)=dims.next(){
        out.matching_atlas_layout=dims.all(|v|v==first);
        if !out.matching_atlas_layout {
            out.errors.push("Source 2 baked lightmap channel dimensions or layer count differ".into());
        }
    }
    out.complete=out.errors.is_empty() && out.matching_atlas_layout
        && out.channels.len()==required.len();
    out
}
/// Three/five individually source-named typed GPU sampled 2D arrays. These
/// are *not* generic lightmaps and are deliberately NOT RGBA8 lighting maps.
/// The shared GPU backend may upload all source blocks without losing HDR or
/// changing the original shadow-mask representation. Runtime shading still
/// requires an original or source-equivalent complete Source2 lightmap program.
#[derive(Clone,Debug)]
pub struct SourceNativeLightmapAtlas{
    pub version:[i64;2],
    pub channels:BTreeMap<String,SourceNativeVtexArray>,
    pub width:u32,
    pub height:u32,
    pub layers:u16,
    pub total_native_gpu_bytes:usize,
}
/// Fully decode exact authored mip compression into original GPU compressed
/// BCn bitstreams. No float->RGBM, BC6H->RGBA8, or synthetic shadows.
/// All requested source slots are mandatory and failed decode fails closed.
pub fn decode_native_atlas(
    packs:&SourcePacks<'_>,audit:&LightmapAudit
)->Result<SourceNativeLightmapAtlas,String>{
    if !audit.complete {
        return Err(format!(
            "cannot provision incomplete Source2 lightmap v{}.{}: {}",
            audit.version[0],audit.version[1],audit.errors.join("; ")
        ));
    }
    let mut channels=BTreeMap::new();
    let mut total_native_gpu_bytes=0usize;
    let mut geometry=None;
    for slot in &audit.expected_channels {
        let input=audit.channels.get(*slot)
            .ok_or_else(||format!("Source2 original required lightmap {slot} missing"))?;
        let bytes=packs.read(&input.path)?;
        let decoded=vtex_native_array::decode_source_native_vtex_array(
            &bytes,&input.path)?;
        let dims=(decoded.width,decoded.height,decoded.layers);
        if dims!=(input.meta.width as u32,input.meta.height as u32,input.meta.depth){
            return Err(format!("source-native lightmap VTEX changed after audit: {}",input.path));
        }
        if let Some(previous)=geometry{
            if previous!=dims {
                return Err("Source2 native baked-lighting array dimensions differ".into());
            }
        }else{geometry=Some(dims);}
        total_native_gpu_bytes=total_native_gpu_bytes
            .checked_add(decoded.original_gpu_bytes())
            .ok_or("Source2 native atlas GPU bytes overflow")?;
        if channels.insert((*slot).to_owned(),decoded).is_some(){
            return Err(format!("duplicate native baked-lighting source slot {slot}"));
        }
    }
    let (width,height,layers)=geometry.ok_or(
        "original baked-lighting channel inventory is empty"
    )?;
    Ok(SourceNativeLightmapAtlas{
        version:audit.version,channels,width,height,layers,total_native_gpu_bytes,
    })
}
/// Recover original GPU-ready BC blocks and RGBA pixels, in source array layer
/// order. A later Source 2 shader program must consume all required channels
/// together; this loader never guesses generic RGBM or creates fake shadows.
pub fn decode_channel(
    packs:&SourcePacks<'_>,channel:&LightmapChannel
)->Result<Vec<NeutralTexture>,String>{
    let file=packs.read(&channel.path)?;
    let layers=texture::decode_2d_array_layers(&file,&channel.path)?;
    if layers.len()!=channel.meta.depth as usize || layers.iter().any(|l|
        l.width!=channel.meta.width as u32 || l.height!=channel.meta.height as u32){
        return Err(format!("Source 2 lightmap array dimensions changed: {}",channel.path));
    }
    Ok(layers)
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn original_version_8_channel_sets_are_distinct(){
        assert_eq!(expected([8,1]).len(),4);
        assert_eq!(expected([8,2]).len(),3);
        assert_eq!(expected([8,3]).len(),5);
        assert_eq!(expected([8,4]),expected([8,3]));
        assert!(expected([8,9]).is_empty());
        assert!(expected([6,0]).is_empty());
        assert_eq!(channel_name("maps/foo/lightmaps/directional_irradiance_sh2_dc.vtex_c"),
            Some("directional_irradiance_sh2_dc"));
        assert_eq!(uniform("irradiance"),uniform("directional_irradiance_sh2_dc"));
    }
    #[test]
    fn rejects_unsafe_lightmap_paths(){
        assert!(compiled("../lightmaps/irradiance.vtex").is_err());
        assert!(compiled("C:/lightmaps/irradiance.vtex").is_err());
        assert_eq!(compiled("lightmaps/irradiance.vtex").unwrap(),"lightmaps/irradiance.vtex_c");
    }
}
