//! Split source-compiled mixed depth-reference and ordinary SPIR-V
//! image/sampler arrays without replacing the original sampling instructions.
//! This is source-neutral: it accepts any Vulkan SPIR-V with directly
//! identifiable image/sampler OpLoad + OpAccessChain chains.
//!
//! The new descriptor views alias the same SOURCE image/sampler arrays, but
//! require the renderer to bind two distinct legal Vulkan typed views. Source
//! descriptors are never given guessed concrete resources or contents.
use std::collections::{BTreeMap,BTreeSet};
const MAGIC:u32=0x0723_0203;
const MAX_WORDS:usize=16*1024*1024;
#[derive(Clone,Debug)]
struct Inst { op:u32,p:Vec<u32> }
impl Inst {
    fn result(&self)->Option<u32>{
        match self.op{
            25|26|27|28|29|32 if !self.p.is_empty()=>Some(self.p[0]),
            59|61|65|66|67|68|83|86 if self.p.len()>1=>Some(self.p[1]),
            _=>None,
        }
    }
    fn emit(&self,out:&mut Vec<u32>)->Result<(),String>{
        if self.p.len()>=0xffff{return Err("shader instruction length overflow".into());}
        out.push((((self.p.len()+1) as u32)<<16)|self.op);
        out.extend_from_slice(&self.p);
        Ok(())
    }
}
#[derive(Clone,Debug)]
pub struct AliasResource {
    pub original_set:u32,
    pub original_binding:u32,
    pub alias_set:u32,
    pub alias_binding:u32,
    pub original_variable_id:u32,
    pub alias_variable_id:u32,
    /// Exactly one of these for each side of original compare sampling.
    pub is_comparison_image:bool,
}
#[derive(Clone,Debug)]
pub struct LoweredMixedSampling{
    pub spirv:Vec<u8>,
    pub aliases:Vec<AliasResource>,
    pub rewritten_dref_samples:usize,
}
fn decode(code:&[u8])->Result<([u32;5],Vec<Inst>),String>{
    if code.len()<20||code.len()/4>MAX_WORDS||code.len()%4!=0{
        return Err("source SPIR-V extent outside bound".into());
    }
    let words=code.chunks_exact(4).map(|x|
        u32::from_le_bytes(x.try_into().unwrap())).collect::<Vec<_>>();
    if words[0]!=MAGIC||words[3]==0||words[4]!=0{
        return Err("original source SPIR-V header invalid".into());
    }
    let mut out=Vec::new();let mut at=5;
    while at<words.len(){
        let n=(words[at]>>16) as usize;
        if n==0||at.checked_add(n).is_none_or(|end|end>words.len()){
            return Err("source SPIR-V instruction overrun".into());
        }
        out.push(Inst{op:words[at]&65535,p:words[at+1..at+n].to_vec()});
        at+=n;
    }
    Ok(([words[0],words[1],words[2],words[3],words[4]],out))
}
fn source_root(mut id:u32,inst:&[Inst],defs:&BTreeMap<u32,usize>)->Option<u32>{
    for _ in 0..48{
        let def=inst.get(*defs.get(&id)?)?;
        match def.op{
            61|65|66|67|68|83 if def.p.len()>=3=>id=def.p[2],
            59=>return Some(id),
            _=>return None,
        }
    }
    None
}
fn loaded_source_resource(id:u32,inst:&[Inst],defs:&BTreeMap<u32,usize>)
    ->Option<(usize,usize,u32)>
{
    let load=*defs.get(&id)?;
    let d=inst.get(load)?;
    if d.op!=61||d.p.len()<3{return None;}
    let access=*defs.get(&d.p[2])?;
    let a=inst.get(access)?;
    if !matches!(a.op,65|66|67|68)||a.p.len()<3{return None;}
    let root=source_root(a.p[2],inst,defs)?;
    Some((load,access,root))
}
fn new_id(head:&mut [u32;5])->Result<u32,String>{
    let id=head[3];
    head[3]=id.checked_add(1).filter(|x|*x<=10_000_000)
        .ok_or("SPIR-V alias ID bound exceeded")?;
    Ok(id)
}
fn clone_type(
    id:u32,depth:bool,
    source:&[Inst],defs:&BTreeMap<u32,usize>,
    head:&mut [u32;5],memo:&mut BTreeMap<u32,u32>,added:&mut Vec<Inst>,
)->Result<u32,String>{
    if let Some(value)=memo.get(&id){return Ok(*value);}
    let d=source.get(*defs.get(&id).ok_or("source sampled-image type not defined")?)
        .ok_or("source sampled-image type index invalid")?;
    let mut out=d.clone();
    match out.op{
        25=>{
            if out.p.len()<8 {return Err("invalid SPIR-V source OpTypeImage".into());}
            // A Vulkan depth-reference image gets its own typed source view;
            // never reinterpret the original non-comparison color image.
            if depth && out.p[3]!=2 && out.p[3]!=1 {
                return Err("cannot shadow-sample authored non-depth image".into());
            }
            if depth{out.p[3]=1;}
        },
        27|28|29 if out.p.len()>=2=>{
            out.p[1]=clone_type(out.p[1],depth,source,defs,head,memo,added)?;
        },
        32 if out.p.len()>=3=>{
            out.p[2]=clone_type(out.p[2],depth,source,defs,head,memo,added)?;
        },
        _=>return Err(format!("source image array references unrecognized type {}",out.op)),
    }
    let next=new_id(head)?;
    out.p[0]=next;
    memo.insert(id,next);
    added.push(out);
    Ok(next)
}
pub fn split_original_mixed_comparison_arrays(code:&[u8])
    ->Result<LoweredMixedSampling,String>
{
    let (mut head,mut inst)=decode(code)?;
    let mut defs=BTreeMap::<u32,usize>::new();
    let mut set=BTreeMap::<u32,u32>::new();
    let mut binding=BTreeMap::<u32,u32>::new();
    let mut max_binding=BTreeMap::<u32,u32>::new();
    for (i,d) in inst.iter().enumerate(){
        if let Some(id)=d.result(){
            if defs.insert(id,i).is_some(){
                return Err(format!("duplicate source shader SSA ID {id}"));
            }
        }
        if d.op==71&&d.p.len()>=3{
            match d.p[1]{
                33=>{binding.insert(d.p[0],d.p[2]);},
                34=>{set.insert(d.p[0],d.p[2]);},
                _=>{}
            }
        }
    }
    for (id,&slot) in &binding{
        if let Some(&group)=set.get(id){
            let entry=max_binding.entry(group).or_insert(slot);
            *entry=(*entry).max(slot);
        }
    }
    let mut sample_users=BTreeMap::<u32,(bool,bool)>::new();
    let mut compare=Vec::new();
    for d in &inst{
        if (87..=98).contains(&d.op)&&d.p.len()>=3 {
            let used=sample_users.entry(d.p[2]).or_default();
            let dref=matches!(d.op,89|90|93|94|97);
            if dref {
                used.0=true;
                compare.push(d.p[2]);
            }else{used.1=true;}
        }
    }
    if compare.is_empty(){return Err("compiled source shader has no depth-reference sample".into());}
    for id in &compare{
        if sample_users.get(id).is_some_and(|state|state.1){
            return Err("one source OpSampledImage SSA result has both dref and ordinary users".into());
        }
    }
    let mut comparison_records=Vec::<(usize,usize,usize,usize,u32,u32)>::new();
    let mut regular_accesses=BTreeSet::new();
    for (&sampled,(_,noncmp)) in &sample_users{
        let sampled_idx=*defs.get(&sampled).ok_or("sampled image SSA not source-defined")?;
        let sampled_def=&inst[sampled_idx];
        if sampled_def.op!=86||sampled_def.p.len()<4{
            return Err("sampled image SSA has unsupported compound source origin".into());
        }
        let image=loaded_source_resource(sampled_def.p[2],&inst,&defs)
            .ok_or("shader sampled-image source not a direct array image load")?;
        let sampler=loaded_source_resource(sampled_def.p[3],&inst,&defs)
            .ok_or("shader sampled-image sampler not a direct array sampler load")?;
        if *noncmp{
            regular_accesses.insert(image.1);
            regular_accesses.insert(image.0);
            regular_accesses.insert(sampler.1);
            regular_accesses.insert(sampler.0);
        }else{
            comparison_records.push((sampled_idx,image.0,image.1,sampler.0,
                image.2,sampler.2));
        }
    }
    for (sampled,load,access,sampler_load,image_var,sampler_var) in &comparison_records{
        if regular_accesses.contains(load)||regular_accesses.contains(access)||
            regular_accesses.contains(sampler_load){
            return Err("same original access chain is shared by dref and non-comparison".into());
        }
        let sampler_pointer=inst[*sampler_load].p[2];
        let sampler_access=*defs.get(&sampler_pointer)
            .ok_or("comparison sampler pointer source absent")?;
        if regular_accesses.contains(&sampler_access){
            return Err("comparison sampler access chain also used for ordinary sampling".into());
        }
        if source_root(inst[sampler_access].p[2],&inst,&defs)!=Some(*sampler_var){
            return Err("original source comparison sampler pointer chain ambiguous".into());
        }
        if source_root(inst[*access].p[2],&inst,&defs)!=Some(*image_var)||
            inst[*sampled].op!=86 {
            return Err("source dref image origin changed during inspection".into());
        }
    }
    let mut source_alias=BTreeMap::<(u32,bool),u32>::new();
    let mut aliases=Vec::new();
    let mut additions=Vec::new();
    let mut type_cache=BTreeMap::new();
    let mut decorations=Vec::new();
    for &(_,_,_,_,image_var,sampler_var) in &comparison_records{
        for (original,is_image) in [(image_var,true),(sampler_var,false)]{
            if source_alias.contains_key(&(original,is_image)){continue;}
            let original_type=inst[*defs.get(&original).ok_or("original source resource undefined")?].p[0];
            let cloned_type=if is_image {
                clone_type(original_type,true,&inst,&defs,&mut head,
                    &mut type_cache,&mut additions)?
            }else{original_type};
            let group=*set.get(&original).ok_or("source array missing DescriptorSet")?;
            let source_binding=*binding.get(&original).ok_or("source array missing Binding")?;
            let next=max_binding.get(&group).copied().unwrap_or(source_binding)
                .checked_add(1).ok_or("source descriptor binding extent exhausted")?;
            max_binding.insert(group,next);
            let new_var=new_id(&mut head)?;
            let mut cloned=inst[*defs.get(&original).unwrap()].clone();
            if cloned.op!=59||cloned.p.len()<3{
                return Err("descriptor source must be global OpVariable".into());
            }
            cloned.p[0]=cloned_type;cloned.p[1]=new_var;
            additions.push(cloned);
            decorations.push(Inst{op:71,p:vec![new_var,34,group]});
            decorations.push(Inst{op:71,p:vec![new_var,33,next]});
            source_alias.insert((original,is_image),new_var);
            aliases.push(AliasResource{
                original_set:group,original_binding:source_binding,
                alias_set:group,alias_binding:next,
                original_variable_id:original,alias_variable_id:new_var,
                is_comparison_image:is_image,
            });
        }
    }
    // The new source-native image types and pointers must exist before
    // functions. We only patch DREF SSA operations, not ordinary samples.
    let mut cloned_type_cache=type_cache;
    let mut late_types=Vec::new();
    for (sampled,load,access,sampler_load,image_var,sampler_var) in comparison_records.iter(){
        let original_image_type=inst[*load].p[0];
        let original_access_type=inst[*access].p[0];
        let original_sampled_type=inst[*sampled].p[0];
        let new_image_type=clone_type(original_image_type,true,
            &inst,&defs,&mut head,&mut cloned_type_cache,&mut late_types)?;
        let new_access_type=clone_type(original_access_type,true,
            &inst,&defs,&mut head,&mut cloned_type_cache,&mut late_types)?;
        let new_sampled_type=clone_type(original_sampled_type,true,
            &inst,&defs,&mut head,&mut cloned_type_cache,&mut late_types)?;
        inst[*load].p[0]=new_image_type;
        inst[*access].p[0]=new_access_type;
        inst[*access].p[2]=*source_alias.get(&(*image_var,true)).unwrap();
        inst[*sampled].p[0]=new_sampled_type;
        let ptr=inst[*sampler_load].p[2];
        let samp_access=*defs.get(&ptr).unwrap();
        inst[samp_access].p[2]=*source_alias.get(&(*sampler_var,false)).unwrap();
    }
    // Keep type declaration order: recursively cloned child types before
    // each pointer, then global resource aliases after the existing globals.
    let first_type=inst.iter().position(|d|(19..=33).contains(&d.op))
        .ok_or("SPIR-V shader has no original type section")?;
    let first_function=inst.iter().position(|d|d.op==54)
        .ok_or("SPIR-V shader has no original entry function")?;
    if first_function<=first_type{
        return Err("SPIR-V sections have noncanonical order".into());
    }
    // Add type definitions before first original function; original declared
    // globals are already present. Type objects and global vars are in the
    // SPIR-V global section, so moving them before the function is legal.
    let mut out=Vec::new();
    out.extend_from_slice(&inst[..first_type]);
    out.extend(decorations);
    out.extend_from_slice(&inst[first_type..first_function]);
    // Preserve topological type dependency order produced by clone_type;
    // the source alias variables themselves must come after the types.
    out.extend(late_types);
    let mut alias_vars=Vec::new();
    let mut alias_types=Vec::new();
    for added in additions{
        if added.op==59{alias_vars.push(added)}else{alias_types.push(added)}
    }
    out.extend(alias_types);
    out.extend(alias_vars);
    out.extend_from_slice(&inst[first_function..]);
    // Append aliases to OpEntryPoint interface only when their source globals
    // were part of the original interface, preserving older Vulkan form.
    for instr in &mut out {
        if instr.op!=15{continue;}
        let original_globals=BTreeSet::<u32>::from_iter(
            aliases.iter().map(|alias|alias.original_variable_id));
        if instr.p.iter().any(|x|original_globals.contains(x)){
            for alias in &aliases{
                if instr.p.contains(&alias.original_variable_id) &&
                    !instr.p.contains(&alias.alias_variable_id) {
                    instr.p.push(alias.alias_variable_id);
                }
            }
        }
    }
    let mut output=head.to_vec();
    for d in out{d.emit(&mut output)?;}
    Ok(LoweredMixedSampling{
        spirv:output.iter().flat_map(|w|w.to_le_bytes()).collect(),
        aliases,rewritten_dref_samples:comparison_records.len(),
    })
}
