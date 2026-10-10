//! Source-authenticated Fortnite 5.41 UE4.21 ULandscapeComponent weightmap
//! allocation decoding. Every layer binds the cooked LandscapeLayerInfoObject
//! FPackageIndex to an exact source Texture2D RGBA channel.
//!
//! The original WeightmapLayerAllocations tagged FScriptArray payload contains:
//!   int32 count,
//!   FPropertyTag tagged *inner* StructProperty header (49 bytes), and
//!   count contiguous 105-byte WeightmapLayerAllocationInfo tagged structs.
//! This is a source-pinned format contract, NOT guessed paint/ground albedo.
use crate::{properties, uobject::PackageCatalog};

const INNER_STRUCT_TAG_BYTES: usize = 49;
const LAYER_RECORD_BYTES: usize = 105;
const MAX_LAYERS: usize = 64;

#[derive(Clone,Debug,PartialEq,Eq)]
pub struct WeightmapLayerAllocation {
    /// Original referenced LandscapeLayerInfoObject (not inferred from RGB).
    pub layer_info_ref: i32,
    pub layer_info_path: String,
    /// Index into ULandscapeComponent.WeightmapTextures.
    pub texture_index: u8,
    /// Unreal semantic channel R=0, G=1, B=2, A=3.
    pub channel_rgba: u8,
}

fn named<'a>(cat:&'a PackageCatalog,raw:&[u8],offset:usize)
    ->Result<(&'a str,u32),String>{
    let bytes=raw.get(offset..offset+8).ok_or("short source FName in weightmap layer")?;
    let idx=u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let serial=u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let text=cat.names.get(idx).ok_or_else(||format!("unknown weightmap FName index {idx}"))?;
    Ok((text.as_str(),serial))
}
fn property_value<'a>(name:&str,kind:&str,catalog:&PackageCatalog,
    fields:&'a properties::Properties,entry:&'a [u8])->Result<&'a [u8],String>{
    let found=fields.fields.iter().filter(|p|p.name==name).collect::<Vec<_>>();
    if found.len()!=1 {return Err(format!("weightmap layer expected exactly one {name}, got {}",found.len()));}
    let field=found[0];
    if field.kind!=kind ||field.array_index!=0{return Err(format!("weightmap {name} wrong source type/array index"));}
    if kind=="ByteProperty" && field.metadata.first().map(String::as_str)!=Some("None"){
        return Err(format!("weightmap {name} has unhandled enum metadata {:?}",field.metadata));
    }
    let _=catalog; // original source type/payload is checked by scan above
    Ok(&entry[field.payload.clone()])
}
pub fn decode_layer_allocations(
    cat:&PackageCatalog,
    component_export_data:&[u8],
    weightmap_textures:&[i32],
)->Result<Vec<WeightmapLayerAllocation>,String>{
    let props=properties::scan(cat,component_export_data)?;
    let matching=props.fields.iter().filter(|p|p.name=="WeightmapLayerAllocations").collect::<Vec<_>>();
    if matching.len()!=1 {return Err(format!("expected one original WeightmapLayerAllocations property, got {}",matching.len()));}
    let tag=matching[0];
    if tag.kind!="ArrayProperty" ||tag.metadata.first().map(String::as_str)!=Some("StructProperty") {
        return Err("WeightmapLayerAllocations is not original ArrayProperty<StructProperty>".into());
    }
    let raw=&component_export_data[tag.payload.clone()];
    if raw.len()<4+INNER_STRUCT_TAG_BYTES{return Err("truncated cooked WeightmapLayerAllocations header".into());}
    let count=u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
    if count>MAX_LAYERS{return Err(format!("unreasonable source landscape paint layer count: {count}"));}
    if weightmap_textures.len()>255{return Err("source weightmap texture table exceeds u8 address space".into());}
    let inner=&raw[4..4+INNER_STRUCT_TAG_BYTES];
    let (inner_name,instance)=named(cat,inner,0)?;
    let (inner_kind,kind_instance)=named(cat,inner,8)?;
    let (struct_name,struct_instance)=named(cat,inner,24)?;
    if inner_name!="WeightmapLayerAllocations" ||instance!=0
        ||inner_kind!="StructProperty" ||kind_instance!=0
        ||struct_name!="WeightmapLayerAllocationInfo" ||struct_instance!=0
        ||u32::from_le_bytes(inner[20..24].try_into().unwrap())!=0
        ||inner[48]!=0
        ||inner[32..48].iter().any(|byte|*byte!=0)
    {
        return Err(format!("unexpected original UE4 cooked weightmap inner array tag: {inner_name} {inner_kind} {struct_name}"));
    }
    let serialized=raw.len()-4-INNER_STRUCT_TAG_BYTES;
    if serialized!=count*LAYER_RECORD_BYTES {
        return Err(format!("source weightmap allocation array size mismatch: count={count} payload={serialized}, expected={}",count*LAYER_RECORD_BYTES));
    }
    let mut out=Vec::with_capacity(count);
    for (i,entry) in raw[4+INNER_STRUCT_TAG_BYTES..].chunks_exact(LAYER_RECORD_BYTES).enumerate(){
        let decoded=properties::scan(cat,entry)
            .map_err(|e|format!("weightmap layer #{i}: malformed 105-byte source struct: {e}"))?;
        if decoded.bytes_consumed!=LAYER_RECORD_BYTES ||decoded.fields.len()!=3 {
            return Err(format!("weightmap layer #{i}: unexpected tagged fields/count or trailing bytes: {:?}",decoded.fields));
        }
        let obj=property_value("LayerInfo","ObjectProperty",cat,&decoded,entry)?;
        let index=property_value("WeightmapTextureIndex","ByteProperty",cat,&decoded,entry)?;
        let channel=property_value("WeightmapTextureChannel","ByteProperty",cat,&decoded,entry)?;
        if obj.len()!=4 ||index.len()!=1 ||channel.len()!=1{
            return Err(format!("weightmap layer #{i}: source field byte lengths invalid"));
        }
        let layer_info_ref=i32::from_le_bytes(obj.try_into().unwrap());
        if layer_info_ref==0 {return Err(format!("weightmap layer #{i} has null LayerInfo"));}
        let layer_info_path=cat.source_object_path(layer_info_ref)
            .map_err(|e|format!("weightmap layer #{i} has unresolvable LayerInfo: {e}"))?;
        if index[0] as usize>=weightmap_textures.len() ||channel[0]>=4{
            return Err(format!("weightmap layer #{i}: invalid weightmap texture {} / RGBA channel {} ({} referenced textures)",
                index[0],channel[0],weightmap_textures.len()));
        }
        out.push(WeightmapLayerAllocation {
            layer_info_ref,layer_info_path,texture_index:index[0],channel_rgba:channel[0],
        });
    }
    Ok(out)
}

/// Unreal's logical R/G/B/A channels are stored in BGRA8 byte ordering.
pub fn bgra_byte_index(channel_rgba:u8)->Result<usize,String>{
    match channel_rgba{
        0=>Ok(2),1=>Ok(1),2=>Ok(0),3=>Ok(3),
        _=>Err(format!("original weightmap channel {channel_rgba} out of range")),
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn rgb_channel_order_is_correct_for_packed_ue4_weightmaps(){
        let pixel=[0x31,0x42,0x53,0x64];
        assert_eq!((0..4).map(|c|pixel[bgra_byte_index(c).unwrap()]).collect::<Vec<_>>(),vec![0x53,0x42,0x31,0x64]);
        assert!(bgra_byte_index(4).is_err());
    }
}
