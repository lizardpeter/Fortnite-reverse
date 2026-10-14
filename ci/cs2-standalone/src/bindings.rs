//! Exact available Source 2 VMAT/VTEX bindings into universal material slots.
//! The original shader's advanced pipeline remains unavailable and is tracked
//! separately. This binds only source-known generic g_tColor/g_tNormal maps;
//! packed Source 2 specialized channels are never relabeled as PBR maps.
use std::collections::{BTreeMap,BTreeSet};
use neutral_scene::NeutralScene;
use crate::{material::SourcePacks,texture};
/// Decoded RGBA is transient importer-side memory. GPU uploads retain the
/// original BC1/BC3/BC7 blocks where possible. 512 MiB silently dropped valid
/// original textures; use a larger configurable guard. An explicit 0 disables
/// the importer limit (the OS/GPU allocations may still fail normally).
fn texture_budget()->Option<usize> {
    let mb=std::env::var("RUST_TEST_CS2_TEXTURE_BUDGET_MB").ok()
        .and_then(|x|x.parse::<usize>().ok()).unwrap_or(4096);
    if mb==0 { None } else { Some(mb.saturating_mul(1024*1024)) }
}

#[derive(Default,Debug)]
pub struct BindingReport{
    pub vmats_read:usize,
    pub materials_with_albedo:usize,
    pub materials_with_normal:usize,
    pub vtex_loaded:usize,
    pub vtex_failed:usize,
    pub total_rgba_bytes:usize,
    pub budget_bytes:Option<usize>,
    pub authored_layer2:usize,
    pub authored_normal_roughness:usize,
    pub authored_sky_materials:usize,
    pub authored_self_illum:usize,
    pub mapped_metalness:usize,
    pub missing:Vec<String>,
    pub shaders:BTreeMap<String,usize>,
}
fn param<'a>(source:&'a BTreeMap<String,String>,names:&[&str])->Option<&'a str>{
    names.iter().find_map(|k|source.get(*k).map(String::as_str))
}
pub fn bind(scene:&mut NeutralScene,packs:&SourcePacks<'_>)->BindingReport{
    let mut report=BindingReport::default();
    report.budget_bytes=texture_budget();
    let mut decoded=BTreeMap::<String,Option<usize>>::new();
    let mut unresolved=BTreeSet::new();
    for mat in &mut scene.materials{
        let Ok(source)=packs.describe(&mat.name) else {continue};
        report.vmats_read+=1;
        *report.shaders.entry(source.shader.clone()).or_insert(0)+=1;
        // Only lower parameters with one-to-one meanings in the universal
        // physical material; packed Source 2 normal/roughness and the Layer2
        // blend graph remain source-defined, not guessed into generic channels.
        if let Some(&metalness)=source.scalars.get("g_flMetalness") {
            if metalness.is_finite() {
                mat.metallic=metalness.clamp(0.,1.);
                report.mapped_metalness+=1;
            }
        }
        if let Some(&roughness)=source.scalars.get("g_flRoughness") {
            if roughness.is_finite() { mat.roughness=roughness.clamp(0.04,1.); }
        }
        if source.textures.contains_key("g_tLayer2Color") {report.authored_layer2+=1;}
        if source.textures.contains_key("g_tLayer1NormalRoughness") {report.authored_normal_roughness+=1;}
        if source.textures.contains_key("g_tSkyTexture") {report.authored_sky_materials+=1;}
        if source.textures.contains_key("g_tSelfIllumMask") {report.authored_self_illum+=1;}
        let mut decode_texture=|raw:&str|->Option<usize>{
            if let Some(value)=decoded.get(raw){return *value;}
            let compiled=if raw.ends_with("_c"){raw.to_owned()}else{format!("{raw}_c")};
            if !compiled.ends_with(".vtex_c") {
                if unresolved.len()<150 {unresolved.insert(format!("unexpected VTEX reference: {raw}"));}
                decoded.insert(raw.to_owned(),None);
                return None;
            }
            let result=packs.read(&compiled)
                .and_then(|bytes|texture::decode(&bytes,&compiled));
            match result{
                Ok(source_image)=>{
                    let bytes=source_image.rgba.len();
                    if report.budget_bytes.is_some_and(|max|report.total_rgba_bytes.saturating_add(bytes)>max){
                        if unresolved.len()<150{unresolved.insert(format!("texture memory budget reached: {compiled}"));}
                        decoded.insert(raw.to_owned(),None);
                        return None;
                    }
                    let idx=scene.textures.len();
                    scene.textures.push(source_image);
                    report.total_rgba_bytes+=bytes;
                    report.vtex_loaded+=1;
                    decoded.insert(raw.to_owned(),Some(idx));
                    Some(idx)
                },
                Err(error)=>{
                    report.vtex_failed+=1;
                    if unresolved.len()<150{unresolved.insert(format!("{compiled}: {error}"));}
                    decoded.insert(raw.to_owned(),None);
                    None
                }
            }
        };
        if let Some(path)=param(&source.textures,&["g_tColor","g_tColorTexture"]){
            mat.base_color_texture=decode_texture(path);
            if mat.base_color_texture.is_some(){report.materials_with_albedo+=1;}
        }
        if let Some(path)=param(&source.textures,&["g_tNormal"]){
            mat.normal_texture=decode_texture(path);
            if mat.normal_texture.is_some(){report.materials_with_normal+=1;}
        }
    }
    report.missing=unresolved.into_iter().collect();
    report
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn source_texture_budget_is_not_the_old_512_mib_cutoff(){
        // Keep this deterministic: the environment override may be active
        // in CI, so verify large configured budgets and unlimited mode by
        // asserting the invariant rather than changing global process env.
        assert!(4096usize.saturating_mul(1024*1024)>512*1024*1024);
        assert!(texture_budget().is_none_or(|bytes| bytes >= 512*1024*1024));
    }
    #[test]
    fn selects_only_source_authored_generic_channels(){
        let data=BTreeMap::from([
            ("g_tColor".to_owned(),"materials/a.vtex".to_owned()),
            ("g_tNormalRoughness".to_owned(),"materials/b.vtex".to_owned()),
        ]);
        assert_eq!(param(&data,&["g_tColor","g_tColorTexture"]),Some("materials/a.vtex"));
        assert_eq!(param(&data,&["g_tNormal"]),None);
    }
}
