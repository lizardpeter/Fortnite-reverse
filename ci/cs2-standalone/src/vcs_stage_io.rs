//! Source-exact Vulkan SPIR-V stage input/output reflection.
//!
//! Source2's compiled VS/PS must exchange identical typed Location lanes.
//! These are real compiler vertex/varying ABI declarations, *not* guesses
//! that POSITION/UV or a generic PBR vertex layout coincidentally match.
//! BuiltIn members are excluded; unresolved input declarations fail closed.
use std::collections::{BTreeMap,BTreeSet};
const MAGIC:u32=0x0723_0203;
const MAX_BYTES:usize=64*1024*1024;
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub enum NativeScalar { Float, Signed, Unsigned }
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct NativeStageLane{
    pub original_variable_id:u32,
    pub location:u32,
    pub component:u32,
    pub width:u32,
    pub vector_length:u32,
    pub scalar:NativeScalar,
}
#[derive(Clone,Debug,Default)]
pub struct NativeStageInterface {
    pub stage:u32,
    pub entrypoint:String,
    pub inputs:Vec<NativeStageLane>,
    pub outputs:Vec<NativeStageLane>,
    pub builtin_inputs:usize,
    pub builtin_outputs:usize,
    /// Undecodable or unlocated non-BuiltIn stage lanes. A universal
    /// Vulkan graphics pipeline cannot admit this source contract yet.
    pub unresolved_inputs:usize,
    pub unresolved_outputs:usize,
}
#[derive(Clone,Debug,Default)]
pub struct NativeVaryingCompatibility {
    pub matched_pixel_inputs:usize,
    pub missing_pixel_inputs:Vec<(u32,u32)>,
    pub mismatched_pixel_inputs:Vec<(u32,u32)>,
    pub vertex_attribute_locations:Vec<u32>,
}
impl NativeVaryingCompatibility {
    pub fn varying_abi_closed(&self)->bool{
        self.missing_pixel_inputs.is_empty() &&
        self.mismatched_pixel_inputs.is_empty()
    }
}
fn native_words(code:&[u8])->Result<Vec<u32>,String>{
    if code.len()<20||code.len()>MAX_BYTES||code.len()%4!=0 {
        return Err("native Vulkan stage is outside bounded SPIR-V byte range".into());
    }
    let words=code.chunks_exact(4).map(|w|
        u32::from_le_bytes(w.try_into().expect("source 32-bit SPIR-V word"))
    ).collect::<Vec<_>>();
    if words[0]!=MAGIC||words[3]==0||words[3]>10_000_000||words[4]!=0{
        return Err("original Vulkan SPIR-V word header is invalid".into());
    }
    Ok(words)
}
fn original_string(words:&[u32])->Result<(String,usize),String>{
    let mut bytes=Vec::new();
    for (index,word) in words.iter().enumerate(){
        bytes.extend_from_slice(&word.to_le_bytes());
        if let Some(end)=bytes.iter().position(|&v|v==0){
            let name=std::str::from_utf8(&bytes[..end])
                .map_err(|_|"invalid native SPIR-V UTF8 entry point")?;
            return Ok((name.to_owned(),index+1));
        }
        if bytes.len()>16_384{return Err("native SPIR-V string exceeds bound".into());}
    }
    Err("unterminated native SPIR-V entry point".into())
}
#[derive(Clone,Copy,Debug,Default)]
struct Decorations{
    location:Option<u32>,
    component:u32,
    builtin:bool,
}
#[derive(Clone,Debug)]
enum NativeType{
    Float(u32),
    Int(u32,bool),
    Vector(u32,u32),
    Pointer(u32,u32),
    Struct(Vec<u32>),
}
fn classify(
    mut id:u32,types:&BTreeMap<u32,NativeType>,
)->Option<(NativeScalar,u32,u32)>{
    let mut length=1;
    if let Some(NativeType::Vector(base,count))=types.get(&id){
        length=*count;
        id=*base;
    }
    if !(1..=4).contains(&length){return None;}
    match types.get(&id){
        Some(NativeType::Float(bits)) if *bits==16||*bits==32||*bits==64=>
            Some((NativeScalar::Float,*bits,length)),
        Some(NativeType::Int(bits,signed)) if *bits==16||*bits==32||*bits==64=>
            Some((if *signed{NativeScalar::Signed}else{NativeScalar::Unsigned},*bits,length)),
        _=>None,
    }
}
fn add_lane(
    output:&mut NativeStageInterface,
    stage_input:bool,
    variable:u32,
    ty:u32,
    decoration:Decorations,
    types:&BTreeMap<u32,NativeType>,
){
    if decoration.builtin {
        if stage_input{output.builtin_inputs+=1}else{output.builtin_outputs+=1;}
        return;
    }
    let maybe=decoration.location.zip(classify(ty,types));
    if let Some((location,(scalar,width,length)))=maybe{
        if decoration.component+length<=4 && width<=32 {
            let slot=NativeStageLane{
                original_variable_id:variable,
                location,component:decoration.component,width,
                vector_length:length,scalar,
            };
            if stage_input{output.inputs.push(slot)}else{output.outputs.push(slot)}
            return;
        }
    }
    if stage_input{output.unresolved_inputs+=1}else{output.unresolved_outputs+=1;}
}
/// Reflect active vertex/pixel entrypoint stage variables and built-in members,
/// preserving actual compiler Location, Component and numeric shape.
/// No source input is silently labeled TEXCOORD or POSITION.
pub fn reflect_original_stage_io(code:&[u8])->Result<NativeStageInterface,String>{
    let words=native_words(code)?;
    let mut types=BTreeMap::<u32,NativeType>::new();
    let mut vars=BTreeMap::<u32,(u32,u32)>::new();
    let mut decorations=BTreeMap::<u32,Decorations>::new();
    let mut members=BTreeMap::<(u32,u32),Decorations>::new();
    let mut entries=Vec::<(u32,String,BTreeSet<u32>)>::new();
    let mut cursor=5usize;
    while cursor<words.len(){
        let header=words[cursor];
        let size=(header>>16) as usize;
        if size==0 || cursor.checked_add(size).is_none_or(|end|end>words.len()){
            return Err("original stage IO instruction extends beyond SPIR-V code".into());
        }
        let op=header&0xffff;
        let values=&words[cursor+1..cursor+size];
        match op{
            15 if values.len()>=3=>{
                let (name,consumed)=original_string(&values[2..])?;
                entries.push((values[0],name,
                    values[2+consumed..].iter().copied().collect()));
            },
            21 if values.len()>=3=>{
                types.insert(values[0],NativeType::Int(values[1],values[2]!=0));
            },
            22 if values.len()>=2=>{
                types.insert(values[0],NativeType::Float(values[1]));
            },
            23 if values.len()>=3=>{
                types.insert(values[0],NativeType::Vector(values[1],values[2]));
            },
            30 if !values.is_empty()=>{
                types.insert(values[0],NativeType::Struct(values[1..].to_vec()));
            },
            32 if values.len()>=3=>{
                types.insert(values[0],NativeType::Pointer(values[1],values[2]));
            },
            59 if values.len()>=3&&(values[2]==1||values[2]==3)=>{
                if vars.insert(values[1],(values[0],values[2])).is_some(){
                    return Err("duplicate source Vulkan stage IO variable".into());
                }
            },
            71 if values.len()>=3=>{
                let deco=decorations.entry(values[0]).or_default();
                match values[1]{
                    30=>deco.location=Some(values[2]),
                    31=>deco.component=values[2],
                    11=>deco.builtin=true,
                    _=>{},
                }
            },
            72 if values.len()>=4=>{
                let deco=members.entry((values[0],values[1])).or_default();
                match values[2]{
                    30=>deco.location=Some(values[3]),
                    31=>deco.component=values[3],
                    11=>deco.builtin=true,
                    _=>{},
                }
            },
            _=>{},
        }
        cursor+=size;
    }
    if entries.len()!=1||!matches!(entries[0].0,0|4){
        return Err("native Vulkan graphics shader has no unique vertex/pixel entrypoint".into());
    }
    let (stage,entrypoint,interfaces)=entries.remove(0);
    let mut report=NativeStageInterface{
        stage,entrypoint,..Default::default()
    };
    for (var,(pointer,storage)) in vars{
        // In SPIR-V >=1.4 every actual stage variable must appear in
        // OpEntryPoint's interface list. Keep earlier compiler output
        // conservative when it has an empty list.
        if !interfaces.is_empty() && !interfaces.contains(&var){continue;}
        let Some(NativeType::Pointer(pointer_storage,inner))=types.get(&pointer) else{
            if storage==1{report.unresolved_inputs+=1;}else{report.unresolved_outputs+=1;}
            continue;
        };
        if *pointer_storage!=storage{
            return Err("Vulkan input/output pointer storage class mismatch".into());
        }
        let input=storage==1;
        let root=decorations.get(&var).copied().unwrap_or_default();
        if let Some(NativeType::Struct(fields))=types.get(inner){
            for (member,ty) in fields.iter().enumerate(){
                let slot=members.get(&(*inner,member as u32)).copied()
                    .unwrap_or(root);
                add_lane(&mut report,input,var,*ty,slot,&types);
            }
        }else{
            add_lane(&mut report,input,var,*inner,root,&types);
        }
    }
    report.inputs.sort_by_key(|x|(x.location,x.component,x.original_variable_id));
    report.outputs.sort_by_key(|x|(x.location,x.component,x.original_variable_id));
    for lane in [&report.inputs,&report.outputs]{
        let mut seen=BTreeSet::new();
        for slot in lane.iter(){
            if !seen.insert((slot.location,slot.component)){
                return Err("original compiled stage duplicates one IO Location/Component".into());
            }
        }
    }
    Ok(report)
}
/// Verify source-matched VS/PS varyings before even trying to build the real
/// Vulkan pipeline. Vertex input attributes remain a *separate* source ABI.
pub fn match_original_vs_ps_io(
    vertex:&NativeStageInterface,pixel:&NativeStageInterface,
)->Result<NativeVaryingCompatibility,String>{
    if vertex.stage!=0||pixel.stage!=4{
        return Err("stage interface pairing must be original VS then PS".into());
    }
    let source=vertex.outputs.iter().map(|slot|
        ((slot.location,slot.component),slot)
    ).collect::<BTreeMap<_,_>>();
    let mut matched=0;
    let mut missing=Vec::new();
    let mut mismatched=Vec::new();
    for incoming in &pixel.inputs{
        match source.get(&(incoming.location,incoming.component)){
            None=>missing.push((incoming.location,incoming.component)),
            Some(out) if out.scalar!=incoming.scalar ||
                out.width!=incoming.width ||
                out.vector_length!=incoming.vector_length=>
                    mismatched.push((incoming.location,incoming.component)),
            Some(_)=>matched+=1,
        }
    }
    Ok(NativeVaryingCompatibility{
        matched_pixel_inputs:matched,
        missing_pixel_inputs:missing,
        mismatched_pixel_inputs:mismatched,
        vertex_attribute_locations:vertex.inputs.iter().map(|x|x.location)
            .collect::<BTreeSet<_>>().into_iter().collect(),
    })
}
#[cfg(test)]
mod tests{
    use super::*;
    fn op(words:&mut Vec<u32>,code:u32,args:&[u32]){
        words.push((((args.len()+1) as u32)<<16)|code); words.extend(args);
    }
    fn fixture(stage:u32,scalar_bits:u32)->Vec<u8>{
        let mut w=vec![MAGIC,0x0001_0500,0,200,0];
        let name=u32::from_le_bytes(*b"main");
        op(&mut w,15,&[stage,10,name,0,30,31]);
        op(&mut w,22,&[1,scalar_bits]);
        op(&mut w,23,&[2,1,2]);
        op(&mut w,32,&[3,1,2]);
        op(&mut w,32,&[4,3,2]);
        op(&mut w,59,&[3,30,1]);
        op(&mut w,59,&[4,31,3]);
        op(&mut w,71,&[30,30,2]);
        op(&mut w,71,&[31,30,2]);
        w.into_iter().flat_map(|x|x.to_le_bytes()).collect()
    }
    #[test]
    fn original_stage_location_and_type_is_preserved(){
        let v=reflect_original_stage_io(&fixture(0,32)).unwrap();
        assert_eq!(v.entrypoint,"main");
        assert_eq!(v.inputs[0].location,2);
        assert_eq!(v.outputs[0].vector_length,2);
        assert_eq!(v.inputs[0].scalar,NativeScalar::Float);
    }
    #[test]
    fn typed_varying_location_pair_must_match_source_gpu_shader(){
        let vs=reflect_original_stage_io(&fixture(0,32)).unwrap();
        let ps=reflect_original_stage_io(&fixture(4,32)).unwrap();
        let io=match_original_vs_ps_io(&vs,&ps).unwrap();
        assert_eq!(io.matched_pixel_inputs,1);
        assert!(io.varying_abi_closed());
        let wrong=reflect_original_stage_io(&fixture(4,16)).unwrap();
        assert_eq!(match_original_vs_ps_io(&vs,&wrong).unwrap()
            .mismatched_pixel_inputs,vec![(2,0)]);
    }
    #[test]
    fn missing_stage_location_is_unresolved_not_guessed_from_vertex_ordinal(){
        let mut raw=fixture(0,32);
        let words=raw.chunks_exact_mut(4)
            .map(|slice|u32::from_le_bytes(slice.try_into().unwrap()))
            .collect::<Vec<_>>();
        let mut words=words;
        // Clear all OpDecorate Location: no semantic/position guessing.
        let mut i=5;
        while i<words.len(){
            let n=(words[i]>>16) as usize;
            if words[i]&0xffff==71 && words[i+2]==30{words[i+2]=777;}
            i+=n;
        }
        raw=words.into_iter().flat_map(|v|v.to_le_bytes()).collect();
        let report=reflect_original_stage_io(&raw).unwrap();
        assert_eq!(report.unresolved_inputs,1);
        assert_eq!(report.unresolved_outputs,1);
    }
}
