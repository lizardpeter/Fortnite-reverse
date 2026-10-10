//! Exact source-local UE4 landscape geometry from authenticated height texture
//! bytes. These are source XYZ positions, not the engine's Y-up metre space:
//! LandscapeStreamingProxy/ULandscape actor transforms are required before
//! constructing NeutralScene and physics collision. No fallback mesh exists.
use crate::{landscape::LandscapeComponent, texture::SourceTextureMip};
use std::collections::HashMap;

pub const UE4_LANDSCAPE_ZSCALE: f32 = 1.0 / 128.0;

#[derive(Debug,Clone)]
pub struct LocalTerrainPatch {
    /// UE4 source-local section origin measured in authored landscape quads.
    pub section_base: [i32;2],
    pub component_size_quads: u32,
    /// Source-local (X,Y,Z) positions; Z is raw height before actor scale.
    pub vertices_source_xyz: Vec<[f32;3]>,
    /// Source top-mip packed 16-bit height samples in vertex order.
    pub height_samples: Vec<u16>,
    pub indices: Vec<u32>,
}
impl LocalTerrainPatch {
    pub fn vertex_count(&self)->usize{self.vertices_source_xyz.len()}
    pub fn triangle_count(&self)->usize{self.indices.len()/3}
    pub fn side(&self)->usize{self.component_size_quads as usize+1}
    pub fn height(&self,x:usize,y:usize)->u16{self.height_samples[y*self.side()+x]}
}

fn local_texture_coordinate(source: f32, scale: f32, bias:f32, length:u32)->Result<u32,String> {
    let mapped=(source*scale+bias)*length as f32;
    if !mapped.is_finite(){return Err("nonfinite source landscape heightmap coordinate".into());}
    let rounded=mapped.round();
    if (mapped-rounded).abs()>0.0001 || rounded<0.0 || rounded>=length as f32 {
        return Err(format!("source heightmap UV {mapped} does not address an exact original texel"));
    }
    Ok(rounded as u32)
}

/// Generate only geometry whose source texture, placement scale, height
/// encoding and exact sample coordinates have all been verified.
pub fn build_patch(component:&LandscapeComponent,mip:&SourceTextureMip<'_>)
    ->Result<LocalTerrainPatch,String>{
    if component.num_subsections != 1 || component.subsection_size_quads!=component.component_size_quads {
        return Err("multi-subsection UE4 landscape component needs exact seam layout".into());
    }
    let n=usize::try_from(component.component_size_quads).map_err(|_| "invalid quad count")?;
    if n==0 || n>8191 {return Err("invalid terrain component size".into());}
    let side=n.checked_add(1).ok_or("terrain vertex side overflow")?;
    let count=side.checked_mul(side).ok_or("terrain vertex count overflow")?;
    if count>16*1024*1024 {return Err("terrain source vertices over safety limit".into());}
    let mut vertices=Vec::with_capacity(count);
    let mut heights=Vec::with_capacity(count);
    let scale=component.heightmap_scale_bias;
    for y in 0..side {
        let v=local_texture_coordinate(y as f32,scale[1],scale[3],mip.height)?;
        for x in 0..side {
            let u=local_texture_coordinate(x as f32,scale[0],scale[2],mip.width)?;
            let h=mip.height_u16(u,v)?;
            heights.push(h);
            vertices.push([
                (component.section_base[0] as f32)+(x as f32),
                (component.section_base[1] as f32)+(y as f32),
                (h as f32-32768.0)*UE4_LANDSCAPE_ZSCALE,
            ]);
        }
    }
    let mut indices=Vec::with_capacity(n.checked_mul(n)
        .and_then(|quads|quads.checked_mul(6)).ok_or("terrain index capacity overflow")?);
    for y in 0..n {
        for x in 0..n {
            let a=(y*side+x) as u32;
            let b=a+1;
            let c=((y+1)*side+x) as u32;
            let d=c+1;
            // Authored UE4 local terrain is Z-up. Defer handedness and
            // normal winding conversion to the source->neutral transform.
            indices.extend_from_slice(&[a,c,b,b,c,d]);
        }
    }
    Ok(LocalTerrainPatch {
        section_base:component.section_base,
        component_size_quads:component.component_size_quads,
        vertices_source_xyz:vertices,
        height_samples:heights,
        indices,
    })
}

#[derive(Debug,Default)]
pub struct LandscapeSeamAudit {
    stored:HashMap<(i32,i32),u16>,
    pub matching_shared_samples:usize,
    pub mismatched_shared_samples:usize,
    pub mismatches:Vec<((i32,i32),u16,u16)>,
}
impl LandscapeSeamAudit {
    /// Compare every duplicated grid-edge vertex across independently
    /// decoded landscape textures, preserving the original 16-bit values.
    pub fn admit(&mut self,patch:&LocalTerrainPatch)->Result<(),String>{
        let side=patch.side();
        let n=side-1;
        if patch.height_samples.len()!=side*side {return Err("source terrain sample count mismatch".into());}
        for y in 0..side {
            for x in 0..side {
                if x!=0 && x!=n && y!=0 && y!=n {continue;}
                let point=(patch.section_base[0]+x as i32,patch.section_base[1]+y as i32);
                let h=patch.height(x,y);
                if let Some(previous)=self.stored.insert(point,h) {
                    if previous==h {self.matching_shared_samples+=1;} else {
                        self.mismatched_shared_samples+=1;
                        if self.mismatches.len()<16{self.mismatches.push((point,previous,h));}
                    }
                }
            }
        }
        Ok(())
    }
    pub fn unique_boundary_vertices(&self)->usize{self.stored.len()}
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn source_height_grid_and_two_triangles() {
        let raw=[
            0,0,128,0, 0,1,128,0,
            0,2,128,0, 0,3,128,0
        ];
        let mip=SourceTextureMip {
            width:2,height:2,format:"PF_B8G8R8A8",
            source_bulk_offset:0,source_bulk_flags:0x0501,bgra8:&raw,
        };
        let comp=LandscapeComponent {
            section_base:[127,254],section_base_serialized:[true,true],
            component_size_quads:1,subsection_size_quads:1,num_subsections:1,
            heightmap_scale_bias:[0.5,0.5,0.0,0.0],heightmap_texture_ref:1,
            heightmap_texture_name:Some("test".into()),
            weightmap_texture_refs:vec![],material_instance_refs:vec![],
        };
        let result=build_patch(&comp,&mip).unwrap();
        assert_eq!(result.height_samples,[32768,32769,32770,32771]);
        assert_eq!(result.vertices_source_xyz[0],[127.0,254.0,0.0]);
        assert_eq!(result.indices,[0,2,1,1,2,3]);
        assert_eq!(result.triangle_count(),2);
    }
    #[test]
    fn seam_conflict_detected_from_original_heights() {
        let a=LocalTerrainPatch{section_base:[0,0],component_size_quads:1,
            vertices_source_xyz:vec![[0.0;3];4],height_samples:vec![1,2,3,4],
            indices:vec![0,2,1,1,2,3]};
        let b=LocalTerrainPatch{section_base:[1,0],component_size_quads:1,
            vertices_source_xyz:vec![[0.0;3];4],height_samples:vec![2,8,9,10],
            indices:vec![0,2,1,1,2,3]};
        let mut audit=LandscapeSeamAudit::default();
        audit.admit(&a).unwrap();
        audit.admit(&b).unwrap();
        assert_eq!(audit.matching_shared_samples,1);
        assert_eq!(audit.mismatched_shared_samples,1);
    }
}
