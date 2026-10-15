//! Source-backed SPIR-V descriptor/frontier reflection for original CS2 VCS.
//!
//! This is introspection, NOT a Source 2 descriptor-set implementation and NOT
//! a universal SurfaceProgram lowering. Preserve compiler-emitted set/binding,
//! storage class, input location and specialization-constant decorations.
//! Never invent authored names, texture slots or default buffer bindings.
use std::collections::{BTreeMap,BTreeSet};

const SPIRV_MAGIC:u32=0x0723_0203;
const MAX_SPIRV_BYTES:usize=64*1024*1024;
const MAX_SPIRV_ID_BOUND:u32=10_000_000;

#[derive(Clone,Debug,PartialEq,Eq)]
pub struct SpirvEntryPoint {
    pub stage:u32,
    pub function_id:u32,
    pub name:String,
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct SpirvResource {
    pub id:u32,
    pub name:Option<String>,
    pub type_id:u32,
    pub storage_class:u32,
    pub set:u32,
    pub binding:u32,
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct SpirvPartialResource {
    pub id:u32,
    pub type_id:u32,
    pub storage_class:u32,
    pub set:Option<u32>,
    pub binding:Option<u32>,
}
#[derive(Clone,Debug,Default,PartialEq,Eq)]
pub struct SpirvSourceReflection {
    pub version_word:u32,
    pub original_id_bound:u32,
    pub entry_points:Vec<SpirvEntryPoint>,
    pub descriptors:Vec<SpirvResource>,
    /// An incomplete source descriptor declaration is NOT treated as a
    /// usable renderer binding.
    pub incomplete_descriptors:Vec<SpirvPartialResource>,
    pub specialization_constant_ids:Vec<u32>,
    pub declared_location_count:usize,
}
fn read_words(shader:&[u8])->Result<Vec<u32>,String>{
    if shader.len()<20 || shader.len()>MAX_SPIRV_BYTES || shader.len()%4!=0{
        return Err("Source 2 original SPIR-V size is invalid".into());
    }
    let words=shader.chunks_exact(4).map(|c|
        u32::from_le_bytes(c.try_into().expect("4 bytes"))
    ).collect::<Vec<_>>();
    if words[0]!=SPIRV_MAGIC || words[4]!=0 || words[3]==0 ||
        words[3]>MAX_SPIRV_ID_BOUND {
        return Err("Source2 SPIR-V header magic, schema or result ID bound invalid".into());
    }
    Ok(words)
}
fn shader_string(words:&[u32])->Result<String,String>{
    if words.len()>4096{return Err("original shader string exceeds hard bound".into());}
    let mut bytes=Vec::with_capacity(words.len()*4);
    for w in words{bytes.extend_from_slice(&w.to_le_bytes());}
    let terminator=bytes.iter().position(|c|*c==0)
        .ok_or("unterminated original SPIR-V string")?;
    std::str::from_utf8(&bytes[..terminator])
        .map(str::to_owned)
        .map_err(|_|"invalid source SPIR-V UTF-8".into())
}
#[derive(Clone,Debug,Default)]
struct Variable {
    type_id:u32,
    storage_class:u32,
}
#[derive(Clone,Debug,Default)]
struct Decorations {
    set:Option<u32>,
    binding:Option<u32>,
    location:Option<u32>,
}
/// Return every *physically declared* source descriptor, retaining duplicate
/// set/binding coordinates if the compiled source contains them. No one-to-one
/// mapping from these variables to Source2 VMAT textures is claimed.
pub fn reflect_original_spirv(shader:&[u8])->Result<SpirvSourceReflection,String>{
    let words=read_words(shader)?;
    let mut names=BTreeMap::<u32,String>::new();
    let mut decorations=BTreeMap::<u32,Decorations>::new();
    let mut variables=BTreeMap::<u32,Variable>::new();
    let mut entry_points=Vec::new();
    let mut specializations=BTreeSet::new();
    let mut cursor=5usize;
    while cursor<words.len(){
        let instruction=words[cursor];
        let word_count=(instruction>>16) as usize;
        let opcode=instruction & 0xffff;
        if word_count==0 {
            return Err("Source2 SPIR-V instruction has zero word count".into());
        }
        let end=cursor.checked_add(word_count)
            .filter(|end|*end<=words.len())
            .ok_or("Source2 SPIR-V instruction exceeds source shader")?;
        let operands=&words[cursor+1..end];
        match opcode{
            5 if operands.len()>=2=>{
                let id=operands[0];
                if id>=words[3]{return Err("SPIR-V OpName target exceeds ID bound".into());}
                names.insert(id,shader_string(&operands[1..])?);
            },
            15 if operands.len()>=3=>{
                let stage=operands[0];
                let function_id=operands[1];
                if function_id>=words[3]{return Err("SPIR-V entry ID exceeds bound".into());}
                // After OpEntryPoint name comes optional interface IDs. A
                // literal NUL in the source string terminates before those.
                let name=shader_string(&operands[2..])?;
                entry_points.push(SpirvEntryPoint{stage,function_id,name});
            },
            71 if operands.len()>=3=>{
                let id=operands[0];
                if id>=words[3]{return Err("SPIR-V decoration ID exceeds bound".into());}
                let row=decorations.entry(id).or_default();
                match operands[1]{
                    33=>row.binding=Some(operands[2]),
                    34=>row.set=Some(operands[2]),
                    30=>row.location=Some(operands[2]),
                    _=>{},
                }
            },
            59 if operands.len()>=3=>{
                let type_id=operands[0];
                let id=operands[1];
                if type_id>=words[3] || id>=words[3] || variables.insert(
                    id,Variable{type_id,storage_class:operands[2]}
                ).is_some(){
                    return Err("Source2 SPIR-V OpVariable has invalid/duplicate ID".into());
                }
            },
            48|49|50|51|52 if operands.len()>=2=>{
                if operands[1]>=words[3] {
                    return Err("SPIR-V specialization constant ID exceeds bound".into());
                }
                specializations.insert(operands[1]);
            },
            _=>{},
        }
        cursor=end;
    }
    let mut reflected=SpirvSourceReflection{
        version_word:words[1],
        original_id_bound:words[3],
        entry_points,
        specialization_constant_ids:specializations.into_iter().collect(),
        declared_location_count:decorations.values()
            .filter(|value|value.location.is_some()).count(),
        ..Default::default()
    };
    for (id,variable) in variables {
        let Some(decoration)=decorations.get(&id) else{continue};
        if decoration.set.is_none() && decoration.binding.is_none(){continue;}
        if let (Some(set),Some(binding))=(decoration.set,decoration.binding){
            reflected.descriptors.push(SpirvResource{
                id,name:names.remove(&id).filter(|n|!n.is_empty()),
                type_id:variable.type_id,storage_class:variable.storage_class,
                set,binding
            });
        }else{
            reflected.incomplete_descriptors.push(SpirvPartialResource{
                id,type_id:variable.type_id,storage_class:variable.storage_class,
                set:decoration.set,binding:decoration.binding,
            });
        }
    }
    reflected.descriptors.sort_by_key(|r|(r.set,r.binding,r.id));
    reflected.incomplete_descriptors.sort_by_key(|r|r.id);
    if reflected.entry_points.is_empty(){
        return Err("original SPIR-V has no declared entry point".into());
    }
    Ok(reflected)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn string_words(value:&str)->Vec<u32>{
        let mut bytes=value.as_bytes().to_vec();
        bytes.push(0);
        while bytes.len()%4!=0{bytes.push(0);}
        bytes.chunks_exact(4).map(|x|u32::from_le_bytes(x.try_into().unwrap())).collect()
    }
    fn instruction(words:&mut Vec<u32>,op:u32,args:&[u32]){
        words.push((((args.len()+1) as u32)<<16)|op);
        words.extend(args);
    }
    #[test]
    fn reflect_actual_spirv_descriptor_decorations_without_inventing_texture_slot_names(){
        let mut words=vec![SPIRV_MAGIC,0x0001_0500,0,100,0];
        let mut entry=vec![4,10];entry.extend(string_words("MainPs"));
        instruction(&mut words,15,&entry);
        let mut name=vec![23];name.extend(string_words("SourceLightmap"));
        instruction(&mut words,5,&name);
        instruction(&mut words,71,&[23,34,4]);
        instruction(&mut words,71,&[23,33,29]);
        instruction(&mut words,59,&[12,23,0]);
        instruction(&mut words,71,&[24,34,3]); // incomplete
        instruction(&mut words,59,&[12,24,12]);
        let bytes=words.iter().flat_map(|w|w.to_le_bytes()).collect::<Vec<_>>();
        let r=reflect_original_spirv(&bytes).unwrap();
        assert_eq!(r.entry_points[0].name,"MainPs");
        assert_eq!(r.descriptors.len(),1);
        assert_eq!((r.descriptors[0].set,r.descriptors[0].binding),(4,29));
        assert_eq!(r.descriptors[0].name.as_deref(),Some("SourceLightmap"));
        assert_eq!(r.incomplete_descriptors.len(),1);
        assert_eq!(r.incomplete_descriptors[0].set,Some(3));
        assert_eq!(r.incomplete_descriptors[0].binding,None);
    }
    #[test]
    fn source_spirv_instruction_extent_and_binding_id_must_be_valid(){
        let mut words=vec![SPIRV_MAGIC,0x0001_0500,0,20,0];
        let mut entry=vec![4,10];entry.extend(string_words("MainPs"));
        instruction(&mut words,15,&entry);
        let mut invalid=words.iter().flat_map(|w|w.to_le_bytes()).collect::<Vec<_>>();
        invalid[20..24].copy_from_slice(&(0u32).to_le_bytes());
        assert!(reflect_original_spirv(&invalid).is_err());
        let good=words.iter().flat_map(|w|w.to_le_bytes()).collect::<Vec<_>>();
        assert_eq!(reflect_original_spirv(&good).unwrap().descriptors.len(),0);
    }
}
