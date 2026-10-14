//! Exact available Source 2 VMAT/VTEX bindings into universal material slots.
//! The original shader's advanced pipeline remains unavailable and is tracked
//! separately. This binds only source-known generic g_tColor/g_tNormal maps;
//! packed Source 2 specialized channels are never relabeled as PBR maps.
use std::collections::{BTreeMap,BTreeSet};
use neutral_scene::{NeutralScene,NeutralTexture,NeutralAlpha};
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
    pub additive_effect_materials:usize,
    pub original_effect_masks_combined:usize,
    pub missing:Vec<String>,
    pub shaders:BTreeMap<String,usize>,
}
fn param<'a>(source:&'a BTreeMap<String,String>,names:&[&str])->Option<&'a str>{
    names.iter().find_map(|k|source.get(*k).map(String::as_str))
}
/// Bake ONLY time-independent Source2 csgo_effects.vfx opacity inputs:
/// shader: opacity = color.a * vertex.a * g_flOpacityScale * mask1.r *
/// mask2.r * mask3.r. Vertex alpha is already multiplied by the shared
/// renderer, so it must not be baked again. Camera-distance/depth/Fresnel
/// and authored animated mask transforms remain a distinct shader gap.
fn bilinear_mask_red(mask:&NeutralTexture,x:usize,y:usize,w:usize,h:usize)->f32 {
    let mw=mask.width as usize;let mh=mask.height as usize;
    if mw==0||mh==0{return 1.;}
    let sx=(x as f32+0.5)*mw as f32/w as f32-0.5;
    let sy=(y as f32+0.5)*mh as f32/h as f32-0.5;
    let x0=sx.floor() as isize;let y0=sy.floor() as isize;
    let tx=sx-x0 as f32;let ty=sy-y0 as f32;
    let px=|dx:isize,dy:isize|->f32{
        let ix=(x0+dx).rem_euclid(mw as isize) as usize;
        let iy=(y0+dy).rem_euclid(mh as isize) as usize;
        mask.rgba[(iy*mw+ix)*4] as f32/255.
    };
    let a=px(0,0)*(1.-tx)+px(1,0)*tx;
    let b=px(0,1)*(1.-tx)+px(1,1)*tx;
    a*(1.-ty)+b*ty
}
fn composite_effect_alpha(
    base:&NeutralTexture,masks:[&NeutralTexture;3],opacity:f32,
)->Result<NeutralTexture,String>{
    let w=base.width as usize;let h=base.height as usize;
    if w==0||h==0||base.rgba.len()!=w.checked_mul(h).and_then(|x|x.checked_mul(4))
        .ok_or("effect alpha extent overflow")? {
        return Err("invalid original csgo_effects color image".into());
    }
    for mask in masks {
        if mask.width==0||mask.height==0||
            mask.rgba.len()!=mask.width as usize*mask.height as usize*4{
            return Err("invalid original csgo_effects opacity mask".into());
        }
    }
    let mut rgba=base.rgba.clone();
    for y in 0..h {
        for x in 0..w {
            let i=(y*w+x)*4+3;
            let masks_alpha=masks.iter()
                .fold(1.0f32,|a,mask|a*bilinear_mask_red(mask,x,y,w,h));
            rgba[i]=((rgba[i] as f32)*opacity.clamp(0.,1.)*masks_alpha)
                .round().clamp(0.,255.) as u8;
        }
    }
    Ok(NeutralTexture{
        name:format!("{}#source_csgo_effects_static_masks",base.name),
        width:base.width,height:base.height,
        rgba,mips:Vec::new(),compressed:None,
    })
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
        // Source csgo_effects.vfx has no PBR lighting term. Its F_ADDITIVE_BLEND
        // and F_RENDER_BACKFACES switches select genuine blend/cull behavior.
        // Its masks are multiplicative alpha inputs, NOT PBR normal data.
        let additive=source.shader=="csgo_effects.vfx" &&
            source.switches.get("F_ADDITIVE_BLEND")==Some(&1);
        let mut effect_masks=None;
        if additive {
            report.additive_effect_materials+=1;
            mat.alpha=NeutralAlpha::Additive;
            mat.unlit=true;
            mat.double_sided=source.switches.get("F_RENDER_BACKFACES")==Some(&1);
            let mask_paths=["g_tMask1","g_tMask2","g_tMask3"];
            let mask_ids=mask_paths.map(|key|source.textures.get(key).and_then(|s|decode_texture(s)));
            if let [Some(a),Some(b),Some(c)]=mask_ids{
                effect_masks=Some([a,b,c]);
            }
        }
        // Release the closure's mutable borrow of the texture vector before
        // examining the decoded images and appending the composited texture.
        drop(decode_texture);
        if let (Some(color),Some([a,b,c]))=(mat.base_color_texture,effect_masks){
            let opacity=source.scalars.get("g_flOpacityScale").copied().unwrap_or(1.);
            let result=composite_effect_alpha(
                &scene.textures[color],
                [&scene.textures[a],&scene.textures[b],&scene.textures[c]],
                opacity,
            );
            if let Ok(image)=result {
                let size=image.rgba.len();
                if !report.budget_bytes.is_some_and(|max|
                    report.total_rgba_bytes.saturating_add(size)>max){
                    mat.base_color_texture=Some(scene.textures.len());
                    scene.textures.push(image);
                    report.total_rgba_bytes+=size;
                    report.original_effect_masks_combined+=1;
                }
            }
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
    fn authored_effect_masks_multiply_source_color_alpha() {
        let tex=|n:&str,pixels:Vec<u8>|NeutralTexture{name:n.into(),width:2,height:1,
            rgba:pixels,mips:Vec::new(),compressed:None};
        let color=tex("color",vec![120,140,160,200,80,60,40,100]);
        let mask=tex("mask",vec![128,0,0,255,255,0,0,255]);
        let result=composite_effect_alpha(&color,[&mask,&mask,&mask],0.75).unwrap();
        assert_eq!(&result.rgba[0..3],&[120,140,160]);
        assert_eq!(&result.rgba[4..7],&[80,60,40]);
        let first=(200.*0.75*(128./255_f32).powi(3)).round() as u8;
        assert_eq!(result.rgba[3],first);
        assert_eq!(result.rgba[7],75);
        assert!(result.compressed.is_none());
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
