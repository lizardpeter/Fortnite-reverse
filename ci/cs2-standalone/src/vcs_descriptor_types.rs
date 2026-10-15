//! Classify *real* Source2 SPIR-V descriptor resource types independently of
//! VCS register guesses. Read OpTypeImage / OpTypePointer / Block / runtime
//! array declarations exactly as shipped and retain native descriptor set and
//! binding from the independently verified vcs_spirv resource index.
//!
//! This distinguishes image2D arrays required for directional SH atlas and
//! direct-light shadow masks from ordinary 2D material textures, plus uniform
//! and storage buffers. A compatible shape alone is NOT sufficient to assign
//! a Source2 VMAT variable to an anonymous Vulkan descriptor location.
use std::collections::{BTreeMap,BTreeSet};
use crate::vcs_spirv::SpirvSourceReflection;

#[derive(Clone,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub enum NativeResourceShape {
    UniformBuffer,
    StorageBuffer,
    Sampler,
    SampledImage { dim:u32, arrayed:bool, multisampled:bool },
    StorageImage { dim:u32, arrayed:bool, multisampled:bool },
    CombinedImageSampler { dim:u32, arrayed:bool, multisampled:bool },
    Unknown,
}
impl NativeResourceShape {
    pub fn is_sampled_texture_array_2d(&self)->bool {
        matches!(self,Self::SampledImage{dim:1,arrayed:true,..}|
            Self::CombinedImageSampler{dim:1,arrayed:true,..})
    }
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct NativeTypedDescriptor {
    pub variable_id:u32,
    pub set:u32,
    pub binding:u32,
    pub storage_class:u32,
    pub shape:NativeResourceShape,
    pub source_name:Option<String>,
}
#[derive(Clone,Debug,Default)]
struct Decorations {
    block:bool,
    buffer_block:bool,
}
#[derive(Clone,Debug)]
enum TypeKind {
    Pointer{pointee:u32},
    Image{dim:u32,arrayed:bool,multisampled:bool,sampled:u32},
    Sampler,
    SampledImage{image_type:u32},
    Struct,
    Array{element:u32},
}
fn u32_words(bytes:&[u8])->Result<Vec<u32>,String>{
    if bytes.len()<20 || bytes.len()>64*1024*1024 || bytes.len()%4!=0{
        return Err("invalid original SPIR-V type layout bytes".into());
    }
    let words=bytes.chunks_exact(4).map(|b|
        u32::from_le_bytes(b.try_into().expect("word"))
    ).collect::<Vec<_>>();
    if words[0]!=0x07230203 || words[3]==0 || words[3]>10_000_000 ||
        words[4]!=0 {
        return Err("SPIR-V native type header invalid".into());
    }
    Ok(words)
}
fn resolve_type(
    types:&BTreeMap<u32,TypeKind>,
    decorations:&BTreeMap<u32,Decorations>,
    type_id:u32,storage:u32,
)->NativeResourceShape {
    let mut cursor=type_id;
    let mut visited=BTreeSet::new();
    let mut combined=false;
    for _ in 0..32 {
        if !visited.insert(cursor){return NativeResourceShape::Unknown;}
        match types.get(&cursor){
            Some(TypeKind::Pointer{pointee})=>cursor=*pointee,
            Some(TypeKind::Array{element})=>cursor=*element,
            Some(TypeKind::SampledImage{image_type})=>{
                combined=true;cursor=*image_type
            },
            Some(TypeKind::Sampler)=>return NativeResourceShape::Sampler,
            Some(TypeKind::Image{dim,arrayed,multisampled,sampled})=>{
                if combined{
                    return NativeResourceShape::CombinedImageSampler{
                        dim:*dim,arrayed:*arrayed,multisampled:*multisampled
                    };
                }
                return if *sampled==1{
                    NativeResourceShape::SampledImage{
                        dim:*dim,arrayed:*arrayed,multisampled:*multisampled
                    }
                }else if *sampled==2{
                    NativeResourceShape::StorageImage{
                        dim:*dim,arrayed:*arrayed,multisampled:*multisampled
                    }
                }else{NativeResourceShape::Unknown};
            },
            Some(TypeKind::Struct)=>{
                if storage==12{
                    return NativeResourceShape::StorageBuffer;
                }
                let decorations=decorations.get(&cursor);
                if storage==2 && decorations.is_some_and(|d|d.block){
                    return NativeResourceShape::UniformBuffer;
                }
                if storage==2 && decorations.is_some_and(|d|d.buffer_block){
                    return NativeResourceShape::StorageBuffer;
                }
                return NativeResourceShape::Unknown;
            },
            None=>return NativeResourceShape::Unknown,
        }
    }
    NativeResourceShape::Unknown
}
/// Decode native descriptor GPU **shapes** from exact original SPIR-V. Retain
/// every original compiler-authored OpVariable even if two variables alias
/// one Vulkan descriptor. Shape classification never resolves an anonymous
/// SPIR-V binding to an original material/resource variable by proximity.
pub fn reflect_original_types(
    spirv:&[u8],reflection:&SpirvSourceReflection
)->Result<Vec<NativeTypedDescriptor>,String>{
    let words=u32_words(spirv)?;
    let mut types=BTreeMap::<u32,TypeKind>::new();
    let mut decorations=BTreeMap::<u32,Decorations>::new();
    let mut cursor=5usize;
    while cursor<words.len(){
        let op=words[cursor];let len=(op>>16) as usize;
        if len==0 || cursor.checked_add(len).is_none_or(|end|end>words.len()){
            return Err("truncated original SPIR-V type instruction".into());
        }
        let operands=&words[cursor+1..cursor+len];
        let opname=op&0xffff;
        let described=match opname{
            25 if operands.len()>=8=>Some((operands[0],TypeKind::Image{
                dim:operands[2],arrayed:operands[4]!=0,
                multisampled:operands[5]!=0,sampled:operands[6]
            })),
            26 if !operands.is_empty()=>Some((operands[0],TypeKind::Sampler)),
            27 if operands.len()>=2=>Some((operands[0],TypeKind::SampledImage{
                image_type:operands[1]
            })),
            28|29 if operands.len()>=2=>Some((operands[0],TypeKind::Array{
                element:operands[1]
            })),
            30 if !operands.is_empty()=>Some((operands[0],TypeKind::Struct)),
            32 if operands.len()>=3=>Some((operands[0],TypeKind::Pointer{
                pointee:operands[2]
            })),
            _=>None
        };
        if let Some((id,kind))=described{
            if id==0 || id>=words[3] || types.insert(id,kind).is_some(){
                return Err("duplicate or invalid SPIR-V source type ID".into());
            }
        }
        if opname==71 && operands.len()>=2{
            let row=decorations.entry(operands[0]).or_default();
            match operands[1] {
                2=>row.block=true,
                3=>row.buffer_block=true,
                _=>{},
            }
        }
        cursor+=len;
    }
    let mut out=Vec::with_capacity(reflection.descriptors.len());
    for variable in &reflection.descriptors{
        if variable.id>=words[3] || variable.type_id>=words[3]{
            return Err("reflection refers to SPIR-V ID outside original type module".into());
        }
        out.push(NativeTypedDescriptor{
            variable_id:variable.id,
            set:variable.set,binding:variable.binding,
            storage_class:variable.storage_class,
            shape:resolve_type(&types,&decorations,variable.type_id,
                variable.storage_class),
            source_name:variable.name.clone(),
        });
    }
    out.sort_by_key(|r|(r.set,r.binding,r.variable_id));
    Ok(out)
}
/// A Source2 baked lightmap is a source-native 2D texture ARRAY. A normal
/// material texture, a shadow-mask scalar, and an SSBO cannot be substituted.
pub fn native_array_binding_candidates(
    descriptors:&[NativeTypedDescriptor]
)->Vec<(u32,u32)>{
    descriptors.iter().filter(|resource|
        resource.shape.is_sampled_texture_array_2d()
    ).map(|resource|(resource.set,resource.binding))
        .collect::<BTreeSet<_>>().into_iter().collect()
}
#[cfg(test)]
mod tests{
    use super::*;
    use crate::vcs_spirv::{SpirvEntryPoint,SpirvResource};
    fn op(v:&mut Vec<u32>,code:u32,args:&[u32]){
        v.push((((args.len()+1) as u32)<<16)|code);
        v.extend_from_slice(args);
    }
    #[test]
    fn original_sampled_texture_array_does_not_alias_regular_2d_sampler(){
        let mut code=vec![0x07230203,0x10500,0,100,0];
        // Image result 4, float type 3, 2D dim=1, arrayed=1, sampled=1
        op(&mut code,25,&[4,3,1,0,1,0,1,0]);
        op(&mut code,25,&[5,3,1,0,0,0,1,0]);
        op(&mut code,32,&[10,0,4]);
        op(&mut code,32,&[11,0,5]);
        let bytes=code.iter().flat_map(|w|w.to_le_bytes()).collect::<Vec<_>>();
        let source=SpirvSourceReflection{
            entry_points:vec![SpirvEntryPoint{stage:4,function_id:20,name:"MainPs".into()}],
            original_id_bound:100,
            descriptors:vec![
                SpirvResource{id:30,type_id:10,storage_class:0,set:4,binding:29,name:None},
                SpirvResource{id:31,type_id:11,storage_class:0,set:4,binding:30,name:None},
            ],
            ..Default::default()
        };
        let typed=reflect_original_types(&bytes,&source).unwrap();
        assert_eq!(native_array_binding_candidates(&typed),vec![(4,29)]);
        assert!(matches!(typed[1].shape,NativeResourceShape::SampledImage{arrayed:false,..}));
    }
    #[test]
    fn original_uniform_and_storage_buffers_keep_distinct_gpu_resource_classes(){
        let mut code=vec![0x07230203,0x10500,0,100,0];
        op(&mut code,30,&[4,3]);
        op(&mut code,71,&[4,2]); // Block struct
        op(&mut code,32,&[10,2,4]);
        op(&mut code,32,&[11,12,4]);
        let bytes=code.iter().flat_map(|w|w.to_le_bytes()).collect::<Vec<_>>();
        let source=SpirvSourceReflection{
            descriptors:vec![
                SpirvResource{id:30,type_id:10,storage_class:2,set:1,binding:0,name:None},
                SpirvResource{id:31,type_id:11,storage_class:12,set:3,binding:30,name:None},
            ],
            ..Default::default()
        };
        let typed=reflect_original_types(&bytes,&source).unwrap();
        assert_eq!(typed[0].shape,NativeResourceShape::UniformBuffer);
        assert_eq!(typed[1].shape,NativeResourceShape::StorageBuffer);
    }
}