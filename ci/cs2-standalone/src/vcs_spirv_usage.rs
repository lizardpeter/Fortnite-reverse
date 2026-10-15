//! Source2 original SPIR-V entry-point descriptor-use frontier.
//!
//! Compiler-produced modules may declare alternative image2D, image3D and
//! cube views on identical descriptor coordinates. Only declarations
//! referenced in the selected entry point's reachable function graph can be
//! candidates for native shader descriptor-layout allocation. This analyzer
//! uses a *conservative lexical operand scan*: accidental integer literals
//! equal to source IDs may yield false positives (never unsafe omissions).
//! An absent reference is a strong reachability exclusion, but this is still
//! not native descriptor-set admission or an equivalent of spirv-val.
//!
//! Specialization branches remain unpruned. No shader is patched or rewritten.
use std::collections::{BTreeMap,BTreeSet,VecDeque};
use crate::vcs_spirv::{SpirvSourceReflection,SpirvResource};

const OP_ENTRY_POINT:u32=15;
const OP_FUNCTION:u32=54;
const OP_FUNCTION_END:u32=56;
const OP_FUNCTION_CALL:u32=57;
const MAX_WORDS:usize=16*1024*1024;
const MAX_FUNCTIONS:usize=500_000;

#[derive(Clone,Debug,PartialEq,Eq)]
pub struct NativeDescriptorUsage {
    pub variable_id:u32,
    pub set:u32,
    pub binding:u32,
    /// One or more operand-word occurrences in a function reachable from
    /// the compiler-authored selected entry point.
    pub reachable_operand_mentions:usize,
    /// Mentions in uncalled helper functions only (not runtime bindings).
    pub unreachable_operand_mentions:usize,
}
#[derive(Clone,Debug,Default,PartialEq,Eq)]
pub struct NativeDescriptorUsageFrontier {
    pub entry_function_id:u32,
    pub source_functions:usize,
    pub reachable_functions:usize,
    pub declarations:usize,
    pub referenced_declarations:usize,
    pub no_reachable_mentions:usize,
    pub original_alias_coordinates:usize,
    pub reachable_alias_coordinates:usize,
    pub descriptors:Vec<NativeDescriptorUsage>,
}
#[derive(Clone,Debug,Default)]
struct FunctionBody {
    operands:Vec<u32>,
    direct_calls:Vec<u32>,
}
impl NativeDescriptorUsageFrontier {
    /// Coordinates for which two or more *reachable operand-mentioned* SPIR-V
    /// source variables still compete. Other layout conflicts may remain.
    pub fn remaining_source_aliases(&self)->Vec<(u32,u32,Vec<u32>)>{
        let mut groups=BTreeMap::<(u32,u32),Vec<u32>>::new();
        for descriptor in &self.descriptors {
            if descriptor.reachable_operand_mentions>0{
                groups.entry((descriptor.set,descriptor.binding))
                    .or_default().push(descriptor.variable_id);
            }
        }
        groups.into_iter().filter_map(|((set,binding),ids)|
            (ids.len()>1).then_some((set,binding,ids))
        ).collect()
    }
}
fn read_words(bytes:&[u8])->Result<Vec<u32>,String>{
    if bytes.len()<20||bytes.len()%4!=0||bytes.len()/4>MAX_WORDS{
        return Err("source SPIR-V descriptor use exceeds byte bound".into());
    }
    let words=bytes.chunks_exact(4).map(|c|
        u32::from_le_bytes(c.try_into().expect("4-byte source word"))
    ).collect::<Vec<_>>();
    if words[0]!=0x07230203||words[3]==0||words[4]!=0 {
        return Err("original SPIR-V descriptor use has invalid header".into());
    }
    Ok(words)
}
fn alias_count(source:impl IntoIterator<Item=(u32,u32)>)->usize{
    let mut groups=BTreeMap::<(u32,u32),usize>::new();
    for item in source{*groups.entry(item).or_default()+=1;}
    groups.values().filter(|count|**count>1).count()
}
/// Recover original shader module entry-point reachability without assuming
/// a local texture or a copied shader variable name. Spec/conditional branches
/// are never pruned because runtime specialization values are not known.
pub fn trace_original_entrypoint(
    shader:&[u8],reflection:&SpirvSourceReflection,entry_function_id:u32
)->Result<NativeDescriptorUsageFrontier,String>{
    let words=read_words(shader)?;
    if entry_function_id==0||entry_function_id>=words[3] ||
        !reflection.entry_points.iter().any(|e|e.function_id==entry_function_id){
        return Err("requested original SPIR-V entry point is not source-authored".into());
    }
    let mut functions=BTreeMap::<u32,FunctionBody>::new();
    let mut current:Option<u32>=None;
    let mut pos=5usize;
    while pos<words.len(){
        let opword=words[pos];let opcode=opword&0xffff;
        let count=(opword>>16) as usize;
        let end=pos.checked_add(count)
            .filter(|end|count>0&&*end<=words.len())
            .ok_or("truncated original SPIR-V reachability instruction")?;
        let args=&words[pos+1..end];
        if opcode==OP_FUNCTION{
            if current.is_some()||args.len()<4{
                return Err("nested/truncated SPIR-V OpFunction".into());
            }
            let id=args[1];
            if id==0||id>=words[3]||functions.len()>=MAX_FUNCTIONS ||
                functions.insert(id,FunctionBody::default()).is_some(){
                return Err("invalid/duplicate source SPIR-V function ID".into());
            }
            current=Some(id);
        }else if opcode==OP_FUNCTION_END{
            if current.take().is_none(){return Err("unpaired SPIR-V function end".into());}
        }else if let Some(id)=current{
            let body=functions.get_mut(&id).expect("existing function");
            body.operands.extend_from_slice(args);
            // OpFunctionCall has result type, result ID, callee ID, then
            // arguments. Calls must be followed even through helper chains.
            if opcode==OP_FUNCTION_CALL{
                if args.len()<3{return Err("malformed SPIR-V OpFunctionCall".into());}
                body.direct_calls.push(args[2]);
            }
        }else if opcode==OP_ENTRY_POINT{
            if args.len()<3 {return Err("truncated SPIR-V OpEntryPoint".into());}
            if args[1]==entry_function_id && args[1]>=words[3]{
                return Err("SPIR-V entry function outside declared bound".into());
            }
        }
        pos=end;
    }
    if current.is_some(){return Err("unterminated SPIR-V function".into());}
    if !functions.contains_key(&entry_function_id){
        return Err("selected SPIR-V entry point implementation absent".into());
    }
    let mut reachable=BTreeSet::<u32>::new();
    let mut queue=VecDeque::from([entry_function_id]);
    while let Some(id)=queue.pop_front(){
        if !reachable.insert(id){continue;}
        let body=functions.get(&id).ok_or_else(||
            format!("SPIR-V source function call {id} is not defined"))?;
        for target in &body.direct_calls{queue.push_back(*target);}
    }
    let mut descriptors=Vec::with_capacity(reflection.descriptors.len());
    for source in &reflection.descriptors{
        // Deliberately ignore decorations/types/global initializers:
        // the declaration is a binding *requirement* only if some reachable
        // executable instruction reads or references this original variable.
        let mut active=0;
        let mut inactive=0;
        for (function_id,body) in &functions{
            let count=body.operands.iter()
                .filter(|operand|**operand==source.id).count();
            if reachable.contains(function_id){active+=count;}
            else{inactive+=count;}
        }
        descriptors.push(NativeDescriptorUsage{
            variable_id:source.id,set:source.set,binding:source.binding,
            reachable_operand_mentions:active,
            unreachable_operand_mentions:inactive
        });
    }
    let mut frontier=NativeDescriptorUsageFrontier{
        entry_function_id,source_functions:functions.len(),
        reachable_functions:reachable.len(),
        declarations:descriptors.len(),
        referenced_declarations:descriptors.iter()
            .filter(|v|v.reachable_operand_mentions>0).count(),
        no_reachable_mentions:descriptors.iter()
            .filter(|v|v.reachable_operand_mentions==0).count(),
        original_alias_coordinates:alias_count(reflection.descriptors.iter()
            .map(|d|(d.set,d.binding))),
        reachable_alias_coordinates:alias_count(descriptors.iter()
            .filter(|v|v.reachable_operand_mentions>0)
            .map(|d|(d.set,d.binding))),
        descriptors
    };
    frontier.descriptors.sort_by_key(|d|(d.set,d.binding,d.variable_id));
    Ok(frontier)
}

#[cfg(test)]
mod tests{
    use super::*;
    use crate::vcs_spirv::SpirvEntryPoint;
    fn op(out:&mut Vec<u32>,code:u32,args:&[u32]){
        out.push((((args.len()+1) as u32)<<16)|code);out.extend_from_slice(args);
    }
    fn fixture()->(Vec<u8>,SpirvSourceReflection){
        let mut words=vec![0x07230203,0x00010500,0,100,0];
        op(&mut words,15,&[4,10,0x6e69614d,0x00007350]);
        // Helper called from MainPs uses original shader id 41.
        op(&mut words,54,&[1,10,0,2]);
        op(&mut words,57,&[1,21,11]);
        op(&mut words,56,&[]);
        op(&mut words,54,&[1,11,0,2]);
        op(&mut words,61,&[1,25,41]); // actual helper source use
        op(&mut words,56,&[]);
        // This is an unreachable helper with source variable 42 only.
        op(&mut words,54,&[1,12,0,2]);
        op(&mut words,61,&[1,26,42]);
        op(&mut words,56,&[]);
        let refl=SpirvSourceReflection{
            entry_points:vec![SpirvEntryPoint{
                stage:4,function_id:10,name:"MainPs".into()
            }],
            descriptors:vec![
                SpirvResource{id:41,type_id:1,storage_class:0,
                    set:4,binding:46,name:None},
                SpirvResource{id:42,type_id:2,storage_class:0,
                    set:4,binding:46,name:None}
            ],..Default::default()
        };
        (words.iter().flat_map(|w|w.to_le_bytes()).collect(),refl)
    }
    #[test]
    fn only_reachable_original_shader_alias_claim_is_required(){
        let (shader,reflection)=fixture();
        let audit=trace_original_entrypoint(&shader,&reflection,10).unwrap();
        assert_eq!(audit.source_functions,3);
        assert_eq!(audit.reachable_functions,2);
        assert_eq!(audit.original_alias_coordinates,1);
        assert_eq!(audit.reachable_alias_coordinates,0);
        assert_eq!(audit.referenced_declarations,1);
        assert_eq!(audit.no_reachable_mentions,1);
        assert!(audit.remaining_source_aliases().is_empty());
    }
    #[test]
    fn missing_source_entrypoint_function_is_rejected(){
        let (shader,mut reflection)=fixture();
        reflection.entry_points[0].function_id=66;
        assert!(trace_original_entrypoint(&shader,&reflection,66).is_err());
    }
    #[test]
    fn direct_source_declaration_in_same_entrypoint_is_conservative(){
        let (mut shader,reflection)=fixture();
        let mut w=shader.chunks_exact(4).map(|b|
            u32::from_le_bytes(b.try_into().unwrap())).collect::<Vec<_>>();
        // Append a referenced variable in the reachable helper (before
        // terminator would be required for valid SPIR-V). This test checks
        // strict malformed OpFunction pair rejection when added wrongly.
        op(&mut w,54,&[1,10,0,2]);
        shader=w.into_iter().flat_map(u32::to_le_bytes).collect();
        assert!(trace_original_entrypoint(&shader,&reflection,10).is_err());
    }
}
