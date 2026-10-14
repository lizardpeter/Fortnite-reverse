//! Exact available Source 2 VMAT/VTEX bindings into universal material slots.
//! The original shader's advanced pipeline remains unavailable and is tracked
//! separately. This binds only source-known generic g_tColor/g_tNormal maps;
//! packed Source 2 specialized channels are never relabeled as PBR maps.
use std::collections::{BTreeMap,BTreeSet};
use neutral_scene::NeutralScene;
use crate::{material::SourcePacks,texture};
const MAX_RGBA_TEXTURE_BYTES:usize=256*1024*1024;

#[derive(Default,Debug)]
pub struct BindingReport{
    pub vmats_read:usize,
    pub materials_with_albedo:usize,
    pub materials_with_normal:usize,
    pub vtex_loaded:usize,
    pub vtex_failed:usize,
    pub total_rgba_bytes:usize,
    pub missing:Vec<String>,
    pub shaders:BTreeMap<String,usize>,
}
fn param<'a>(source:&'a BTreeMap<String,String>,names:&[&str])->Option<&'a str>{
    names.iter().find_map(|k|source.get(*k).map(String::as_str))
}
pub fn bind(scene:&mut NeutralScene,packs:&SourcePacks<'_>)->BindingReport{
    let mut report=BindingReport::default();
    let mut decoded=BTreeMap::<String,Option<usize>>::new();
    let mut unresolved=BTreeSet::new();
    for mat in &mut scene.materials{
        let Ok(source)=packs.describe(&mat.name) else {continue};
        report.vmats_read+=1;
        *report.shaders.entry(source.shader.clone()).or_insert(0)+=1;
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
                    if report.total_rgba_bytes.saturating_add(bytes)>MAX_RGBA_TEXTURE_BYTES{
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
    fn selects_only_source_authored_generic_channels(){
        let data=BTreeMap::from([
            ("g_tColor".to_owned(),"materials/a.vtex".to_owned()),
            ("g_tNormalRoughness".to_owned(),"materials/b.vtex".to_owned()),
        ]);
        assert_eq!(param(&data,&["g_tColor","g_tColorTexture"]),Some("materials/a.vtex"));
        assert_eq!(param(&data,&["g_tNormal"]),None);
    }
}
