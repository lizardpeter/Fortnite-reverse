//! Assemble exactly the six original Athena landscape sublevels into an
//! isolated source-backed terrain model. Never insert empty or invented tiles.
use crate::{landscape, terrain, texture, uobject};
use std::{collections::{BTreeMap, BTreeSet}, fs, path::Path};

/// All positions are source UE4 landscape-local XYZ until the application
/// lowers them into the source-neutral Y-up engine world.
#[derive(Debug)]
pub struct AthenaTerrain {
    pub patches: Vec<terrain::LocalTerrainPatch>,
    pub shared_height_samples: usize,
    pub source_material_paths: BTreeSet<String>,
    pub source_grid_min: [i32; 2],
    pub source_grid_max: [i32; 2],
}
impl AthenaTerrain {
    /// A deterministic, explicitly *preview-only* ground spawn sampled from
    /// decoded retail height bytes. This is NOT an authored Fortnite player start.
    pub fn preview_spawn_source_xyz(&self) -> Result<[f32;3],String> {
        let cx=(self.source_grid_min[0]+self.source_grid_max[0]) as f32*0.5;
        let cy=(self.source_grid_min[1]+self.source_grid_max[1]) as f32*0.5;
        let mut best:Option<(f32,[f32;3])>=None;
        for patch in &self.patches {
            let side=patch.side();
            let n=patch.component_size_quads as f32;
            let x=(cx-patch.section_base[0] as f32).clamp(0.0,n);
            let y=(cy-patch.section_base[1] as f32).clamp(0.0,n);
            // Choose an original height sample, not a guessed elevation.
            let ix=x.round() as usize;
            let iy=y.round() as usize;
            let position=patch.vertices_source_xyz[iy*side+ix];
            let dx=position[0]-cx;
            let dy=position[1]-cy;
            let distance=dx*dx+dy*dy;
            if best.as_ref().is_none_or(|(prev,_)| distance<*prev) {
                best=Some((distance,position));
            }
        }
        best.map(|(_,p)|p).ok_or("source Athena terrain contains no spawnable height samples".into())
    }
}

pub fn load_verified_athena(root: &Path)->Result<AthenaTerrain,String> {
    let mut patches=Vec::new();
    let mut seam=terrain::LandscapeSeamAudit::default();
    let mut occupied=BTreeSet::new();
    let mut source_material_paths=BTreeSet::new();
    let mut min=[i32::MAX;2];
    let mut max=[i32::MIN;2];
    for section in 0..6 {
        let base=root.join(format!(
            "FortniteGame/Content/Athena/Maps/Landscape/Athena_Terrain_LS_{section:02}"
        ));
        let package=fs::read(base.with_extension("umap"))
            .map_err(|e|format!("Athena LS_{section:02} requires verified source .umap at {}: {e}; run python asset_import/importers/fortnite_541/tools/fetch_athena_541.py --all-landscape --with-terrain-materials",root.display()))?;
        let uexp=fs::read(base.with_extension("uexp"))
            .map_err(|e|format!("Athena LS_{section:02} original .uexp: {e}"))?;
        let ubulk=fs::read(base.with_extension("ubulk"))
            .map_err(|e|format!("Athena LS_{section:02} original .ubulk: {e}"))?;
        let catalog=uobject::inspect(&package)?;
        let mut proxy_offsets=BTreeMap::<i32,[i32;2]>::new();
        for export in &catalog.exports {
            if catalog.export_class_name(export)!=Some("LandscapeStreamingProxy"){continue;}
            let raw=catalog.export_data(&package,&uexp,export)?;
            let proxy=landscape::inspect_proxy(&catalog,raw)?;
            if let Ok(path)=catalog.source_object_path(proxy.material_ref){
                source_material_paths.insert(path);
            }
            for component_ref in proxy.component_refs {
                if component_ref<=0 {return Err(format!("Athena LS_{section:02}: non-local landscape component ref"));}
                let component_export=catalog.exports.get(component_ref as usize-1)
                    .ok_or("Athena source proxy referenced a missing landscape component")?;
                if catalog.export_class_name(component_export)!=Some("LandscapeComponent"){
                    return Err("Athena source proxy component reference has wrong class".into());
                }
                if proxy_offsets.insert(component_ref,proxy.section_offset).is_some(){
                    return Err("Athena source landscape component has multiple owning proxies".into());
                }
            }
        }
        let before=patches.len();
        for (index,export) in catalog.exports.iter().enumerate() {
            if catalog.export_class_name(export)!=Some("LandscapeComponent"){continue;}
            let raw=catalog.export_data(&package,&uexp,export)?;
            let component=landscape::inspect(&catalog,raw)
                .map_err(|e|format!("Athena LS_{section:02} component {}: {e}",index+1))?;
            let (relative,was_written)=landscape::relative_component_location(&catalog,raw)?;
            let offset=proxy_offsets.get(&((index+1) as i32)).copied().unwrap_or([0,0]);
            for axis in 0..2 {
                if (relative[axis]+offset[axis] as f32-component.section_base[axis] as f32).abs()>0.0001{
                    return Err(format!("Athena LS_{section:02} source LandscapeSectionOffset/RelativeLocation mismatch"));
                }
            }
            if !was_written && component.section_base!=offset{
                return Err(format!("Athena LS_{section:02} has unproven default component placement"));
            }
            let texture_ref=usize::try_from(component.heightmap_texture_ref-1)
                .map_err(|_|"Athena source heightmap is not a local export")?;
            let texture_export=catalog.exports.get(texture_ref)
                .ok_or("Athena source heightmap export not found")?;
            let mip=texture::first_mip_bgra8(&catalog,&package,&uexp,&ubulk,texture_export)?;
            let patch=terrain::build_patch(&component,&mip)?;
            seam.admit(&patch)?;
            if !occupied.insert(patch.section_base){
                return Err(format!("Athena source duplicate landscape component position {:?}",patch.section_base));
            }
            for axis in 0..2 {
                min[axis]=min[axis].min(patch.section_base[axis]);
                max[axis]=max[axis].max(patch.section_base[axis]+patch.component_size_quads as i32);
            }
            patches.push(patch);
        }
        if patches.len()==before {
            return Err(format!("Athena LS_{section:02} contains no source LandscapeComponent exports"));
        }
    }
    if seam.mismatched_shared_samples!=0 {
        return Err(format!("Athena heightfield seams disagree: {} different samples, first {:?}",seam.mismatched_shared_samples,seam.mismatches.first()));
    }
    // Authenticated 5.41 original source has exactly 94 components. Refuse to
    // present missing sublevels as a successfully loaded complete terrain.
    if patches.len()!=94 {
        return Err(format!("Athena terrain is incomplete: decoded {} of the 94 original source components",patches.len()));
    }
    Ok(AthenaTerrain {
        patches,shared_height_samples:seam.matching_shared_samples,
        source_material_paths,source_grid_min:min,source_grid_max:max,
    })
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn no_synthetic_map_when_source_absent(){
        let empty=std::env::temp_dir().join(format!("athena_missing_{}",std::process::id()));
        assert!(load_verified_athena(&empty).is_err());
    }
    #[test]
    fn preview_spawn_uses_original_height(){
        let t=AthenaTerrain{
            patches:vec![terrain::LocalTerrainPatch{
                section_base:[10,20],component_size_quads:1,
                vertices_source_xyz:vec![[10.,20.,3.],[11.,20.,4.],[10.,21.,5.],[11.,21.,6.]],
                height_samples:vec![0;4],indices:vec![0,2,1,1,2,3],
            }],shared_height_samples:0,source_material_paths:BTreeSet::new(),
            source_grid_min:[10,20],source_grid_max:[11,21],
        };
        let p=t.preview_spawn_source_xyz().unwrap();
        assert_eq!(p[0],11.);
        assert_eq!(p[1],21.);
        assert_eq!(p[2],6.);
    }
}
