//! Original UE4.21 LandscapeComponent placement and heightmap reference
//! extraction. This does NOT generate a fake mesh. Until source Texture2D
//! bulk height samples are decoded, geometry remains explicitly unavailable.
use crate::{properties::{self, Properties, Property}, uobject::PackageCatalog};

#[derive(Clone, Debug)]
pub struct LandscapeComponent {
    /// Original UE4 component grid origin (landscape quads, not metres).
    pub section_base: [i32; 2],
    /// True when original cooked UObject explicitly serialized the value;
    /// false means UE4 ULandscapeComponent CDO's zero default was applied.
    pub section_base_serialized: [bool; 2],
    pub component_size_quads: u32,
    pub subsection_size_quads: u32,
    pub num_subsections: u32,
    pub heightmap_scale_bias: [f32; 4],
    /// Exact FPackageIndex referring to an original source texture export/import.
    pub heightmap_texture_ref: i32,
    pub heightmap_texture_name: Option<String>,
    pub weightmap_texture_refs: Vec<i32>,
    pub material_instance_refs: Vec<i32>,
}

#[derive(Debug,Clone)]
pub struct LandscapeProxy {
    /// Source-authored landscape section origin in landscape quad coordinates.
    pub section_offset: [i32;2],
    pub component_refs: Vec<i32>,
    pub material_ref: i32,
    pub landscape_guid: [u8;16],
    /// Original LandscapeStreamingProxy RootComponent, not a default transform.
    pub root_component_ref: i32,
}

/// Original ULandscapeStreamingProxy root transform resolved into *world* UE
/// centimetres. Source component grid X/Y is in landscape quad coordinates;
/// decoded source height Z is in UE landscape local units before actor scale.
#[derive(Clone,Copy,Debug)]
pub struct LandscapeWorldTransform {
    pub grid_origin_cm: [f32;3],
    pub local_scale_cm: [f32;3],
}
impl LandscapeWorldTransform {
    pub fn world_meters(self,source_local_xyz:[f32;3])->[f32;3] {
        std::array::from_fn(|axis|(
            self.grid_origin_cm[axis]+source_local_xyz[axis]*self.local_scale_cm[axis]
        )*0.01)
    }
    /// Verify independently authored landscape sublevels describe ONE global
    /// landscape; otherwise combining them would introduce source gaps/warps.
    pub fn verify_same_world(self,other:Self)->Result<(),String>{
        for axis in 0..3 {
            if (self.local_scale_cm[axis]-other.local_scale_cm[axis]).abs()>0.0001
                || (self.grid_origin_cm[axis]-other.grid_origin_cm[axis]).abs()>0.25 {
                return Err(format!("Athena landscape proxy root transforms disagree on world axis {axis}: {self:?} vs {other:?}"));
            }
        }
        Ok(())
    }
}

/// Read the source actor root's explicit UE4 USceneComponent translation and
/// scale; do not mistake SectionBase/RelativeLocation (quad-local) for metres.
/// For the six Athena 5.41 landscape sections, section offsets translate the
/// individual proxy roots into the same global landscape grid origin.
pub fn proxy_world_transform(
    catalog:&PackageCatalog,package:&[u8],uexp:&[u8],proxy:&LandscapeProxy
)->Result<LandscapeWorldTransform,String>{
    let index=usize::try_from(proxy.root_component_ref.checked_sub(1)
        .ok_or("Athena landscape proxy has no original RootComponent")?)
        .map_err(|_|"Athena landscape proxy root is not a local export")?;
    let root=catalog.exports.get(index).ok_or("Athena landscape proxy root export missing")?;
    if catalog.export_class_name(root)!=Some("SceneComponent") {
        return Err("Athena landscape proxy root is not a SceneComponent".into());
    }
    let data=catalog.export_data(package,uexp,root)?;
    let props=properties::scan(catalog,data)?;
    // Both fields exist explicitly on all six retail 5.41 landscape roots.
    // A rotation, attached parent or source variant must be reconstructed,
    // never dropped silently.
    if props.fields.iter().any(|p|matches!(p.name.as_str(),"RelativeRotation"|"AttachParent"|"AttachSocketName")) {
        return Err("Athena landscape root has an unsupported authored rotation or parent attachment".into());
    }
    let xyz=source_vector(&props,data,"RelativeLocation")?;
    let scale=source_vector(&props,data,"RelativeScale3D")?;
    if scale.iter().any(|v|*v<=0.0) {return Err("Athena landscape root scale must be positive".into());}
    let mut origin=xyz;
    for axis in 0..2 {
        origin[axis]-=proxy.section_offset[axis] as f32*scale[axis];
    }
    Ok(LandscapeWorldTransform{grid_origin_cm:origin,local_scale_cm:scale})
}

fn source_vector(props:&Properties,data:&[u8],name:&str)->Result<[f32;3],String>{
    let p=named(props,name,"StructProperty",data)?;
    if p.metadata.first().map(String::as_str)!=Some("Vector") ||p.payload.len()!=12 {
        return Err(format!("Athena root {name} is not original FVector"));
    }
    let raw=&data[p.payload.clone()];
    let xyz=std::array::from_fn(|axis|f32::from_le_bytes(raw[axis*4..axis*4+4].try_into().unwrap()));
    if xyz.iter().any(|v|!v.is_finite()) {return Err(format!("Athena root {name} contains nonfinite values"));}
    Ok(xyz)
}


pub fn inspect_proxy(catalog:&PackageCatalog,data:&[u8])->Result<LandscapeProxy,String>{
    let props=properties::scan(catalog,data)?;
    let offset=named(&props,"LandscapeSectionOffset","StructProperty",data)?;
    if offset.metadata.first().map(String::as_str)!=Some("IntPoint") ||
        offset.payload.len()!=8 {
        return Err("source LandscapeSectionOffset is not an FIntPoint".into());
    }
    let raw=&data[offset.payload.clone()];
    let section_offset=[
        i32::from_le_bytes(raw[0..4].try_into().unwrap()),
        i32::from_le_bytes(raw[4..8].try_into().unwrap()),
    ];
    let guid_prop=named(&props,"LandscapeGuid","StructProperty",data)?;
    if guid_prop.metadata.first().map(String::as_str)!=Some("Guid") ||
        guid_prop.payload.len()!=16 {
        return Err("source LandscapeGuid is not an FGuid".into());
    }
    let mut landscape_guid=[0u8;16];
    landscape_guid.copy_from_slice(&data[guid_prop.payload.clone()]);
    let component_refs=object_refs(&props,data,"LandscapeComponents")?;
    let material_ref=integer(&props,data,"LandscapeMaterial","ObjectProperty")?;
    let root_component_ref=integer(&props,data,"RootComponent","ObjectProperty")?;
    Ok(LandscapeProxy {section_offset,component_refs,material_ref,landscape_guid,root_component_ref})
}

pub fn relative_component_location(
    catalog:&PackageCatalog,data:&[u8]
)->Result<([f32;3],bool),String> {
    let props=properties::scan(catalog,data)?;
    let matching=props.fields.iter().filter(|p|p.name=="RelativeLocation").collect::<Vec<_>>();
    if matching.is_empty(){return Ok(([0.0,0.0,0.0],false));}
    if matching.len()!=1 ||
        matching[0].kind!="StructProperty" ||
        matching[0].metadata.first().map(String::as_str)!=Some("Vector") ||
        matching[0].payload.len()!=12 {
        return Err("source component RelativeLocation is not exactly FVector".into());
    }
    let raw=&data[matching[0].payload.clone()];
    let mut xyz=[0f32;3];
    for (i,slot) in xyz.iter_mut().enumerate(){
        *slot=f32::from_le_bytes(raw[i*4..i*4+4].try_into().unwrap());
        if !slot.is_finite(){return Err("source component RelativeLocation contains NaN/Inf".into());}
    }
    Ok((xyz,true))
}

fn named<'a>(props: &'a Properties, name: &str, kind: &str, bytes: &[u8]) -> Result<&'a Property, String> {
    let matches = props.fields.iter().filter(|p| p.name == name).collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!("expected one source LandscapeComponent {name} property; got {}", matches.len()));
    }
    let prop = matches[0];
    if prop.kind != kind || prop.payload.end > bytes.len() {
        return Err(format!("source landscape property {name} wrong kind/range"));
    }
    Ok(prop)
}

fn integer(props: &Properties, bytes: &[u8], name: &str, kind: &str) -> Result<i32, String> {
    let p = named(props, name, kind, bytes)?;
    let raw = bytes.get(p.payload.clone()).ok_or("source landscape integer missing")?;
    if raw.len() != 4 { return Err(format!("source {name} is not a 32-bit value")); }
    Ok(i32::from_le_bytes(raw.try_into().unwrap()))
}
/// ULandscapeComponent class defaults SectionBaseX/Y to zero in UE4.
/// Cooked UObject property tagging omits fields equal to their class defaults.
/// Track that provenance rather than misreporting zero as an explicit value.
fn section_base(props: &Properties, bytes: &[u8], name: &str) -> Result<(i32, bool), String> {
    let matches=props.fields.iter().filter(|p| p.name==name).count();
    if matches==0 { return Ok((0,false)); }
    if matches!=1 { return Err(format!("duplicate source {name} tags")); }
    Ok((integer(props,bytes,name,"IntProperty")?,true))
}

fn vec4(props: &Properties, bytes: &[u8], name: &str) -> Result<[f32;4], String> {
    let p = named(props, name, "StructProperty", bytes)?;
    if p.metadata.first().map(String::as_str) != Some("Vector4") {
        return Err(format!("source {name} is not a FVector4"));
    }
    let raw = bytes.get(p.payload.clone()).ok_or("source landscape FVector4 missing")?;
    if raw.len() != 16 { return Err(format!("source {name} is not four f32 values")); }
    let mut out=[0f32;4];
    for i in 0..4 {
        out[i]=f32::from_le_bytes(raw[i*4..i*4+4].try_into().unwrap());
        if !out[i].is_finite() { return Err(format!("source {name} contains non-finite component")); }
    }
    Ok(out)
}
fn object_refs(props: &Properties, bytes: &[u8], name: &str) -> Result<Vec<i32>, String> {
    let p = named(props, name, "ArrayProperty", bytes)?;
    if p.metadata.first().map(String::as_str) != Some("ObjectProperty") {
        return Err(format!("source {name} is not an object reference array"));
    }
    let raw = bytes.get(p.payload.clone()).ok_or("source landscape refs missing")?;
    if raw.len() < 4 {return Err(format!("source {name} array has no count"));}
    let count=u32::from_le_bytes(raw[0..4].try_into().unwrap()) as usize;
    if count>100000 {return Err(format!("source {name} array count too large"));}
    if count.checked_mul(4).and_then(|n| n.checked_add(4)) != Some(raw.len()) {
        return Err(format!("source {name} array payload length disagrees with count"));
    }
    Ok(raw[4..].chunks_exact(4).map(|data| i32::from_le_bytes(data.try_into().unwrap())).collect())
}

/// Produce a source-backed landscape component descriptor, never interpolated
/// or guessed source transforms, heights or materials.
pub fn inspect(catalog: &PackageCatalog, data: &[u8]) -> Result<LandscapeComponent, String> {
    let p=properties::scan(catalog,data)?;
    let heightmap_texture_ref=integer(&p,data,"HeightmapTexture","ObjectProperty")?;
    let component_size_quads=integer(&p,data,"ComponentSizeQuads","IntProperty")?;
    let subsection_size_quads=integer(&p,data,"SubsectionSizeQuads","IntProperty")?;
    let num_subsections=integer(&p,data,"NumSubsections","IntProperty")?;
    if component_size_quads<=0 || subsection_size_quads<=0 || num_subsections<=0 ||
        subsection_size_quads.checked_mul(num_subsections)!=Some(component_size_quads) {
        return Err("source landscape subsection size does not close to component quad size".into());
    }
    let heightmap_scale_bias=vec4(&p,data,"HeightmapScaleBias")?;
    let weightmap_texture_refs=object_refs(&p,data,"WeightmapTextures")?;
    let material_instance_refs=object_refs(&p,data,"MaterialInstances")?;
    let (section_x, serialized_x)=section_base(&p,data,"SectionBaseX")?;
    let (section_y, serialized_y)=section_base(&p,data,"SectionBaseY")?;
    Ok(LandscapeComponent {
        section_base: [section_x,section_y],
        section_base_serialized: [serialized_x,serialized_y],
        component_size_quads: component_size_quads as u32,
        subsection_size_quads: subsection_size_quads as u32,
        num_subsections: num_subsections as u32,
        heightmap_scale_bias,
        heightmap_texture_ref,
        heightmap_texture_name: catalog.resolve_package_name(heightmap_texture_ref).map(str::to_owned),
        weightmap_texture_refs,
        material_instance_refs,
    })
}

#[cfg(test)]
mod world_transform_tests{
    use super::*;
    #[test]
    fn fortnite_retail_landscape_scale_and_translation_are_real_world_meters(){
        // Source-audited LS00 RootComponent and LandscapeSectionOffset.
        let scale=[200.7874,200.7874,50.];
        let offset=[127,254];
        let mut origin=[-127500.,-102000.,-1692.];
        for axis in 0..2 {origin[axis]-=offset[axis] as f32*scale[axis];}
        let t=LandscapeWorldTransform{grid_origin_cm:origin,local_scale_cm:scale};
        let at_first_proxy=t.world_meters([127.,254.,0.]);
        assert!((at_first_proxy[0]+1275.).abs()<0.01);
        assert!((at_first_proxy[1]+1020.).abs()<0.01);
        assert!((at_first_proxy[2]+16.92).abs()<0.001);
        let at_center=t.world_meters([762.,762.,87.40625]);
        assert!(at_center[0].abs()<0.01 && at_center[1].abs()<0.01);
        assert!((at_center[2]-26.783125).abs()<0.001);
    }
    #[test]
    fn refuses_different_original_source_root_scale(){
        let original=LandscapeWorldTransform{grid_origin_cm:[-153000.,-153000.,-1692.],local_scale_cm:[200.7874,200.7874,50.]};
        assert!(original.verify_same_world(original).is_ok());
        let wrong=LandscapeWorldTransform{local_scale_cm:[100.,200.7874,50.],..original};
        assert!(original.verify_same_world(wrong).is_err());
    }
}
