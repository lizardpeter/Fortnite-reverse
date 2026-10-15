//! Original Source 2 VCS v70-72 compiled permutation / GPU bytecode reader.
//!
//! This module handles *source-proven* static and dynamic IDs, physical frame
//! offsets and compilation hashes. Runtime selection is never inferred from
//! VMAT values, nor is raw Vulkan SPIR-V mistaken for universal SurfaceProgram
//! IR. Shader code is loaded only for an explicitly selected native combo.
//! 64-KiB original Valve shader Zstd dictionaries are external source assets,
//! never checked into the Git repository or embedded in engine source.
use std::{fs::File,io::{Read,Seek,SeekFrom},path::Path};
use crate::{kv3::{self,Value},resource::ResourceHeader,vcs_variable_contract::{self,CompilerSourceVariable}};

const MAX_NATIVE_FRAME:usize=32*1024*1024;
const MAX_NATIVE_DECOMPRESSED:usize=64*1024*1024;
const MAX_VCS_META:usize=32*1024*1024;
const ZSTD_DICTIONARY_LEN:usize=65_536;

#[derive(Clone,Debug)]
pub struct NativeCompiledCode {
    pub source_static_id:i64,
    pub source_dynamic_id:i64,
    pub compiler_hash:[u8;16],
    /// Compiler-authored VCS program hash, distinct from selected GPU blob.
    pub original_program_hashes:Vec<[u8;16]>,
    /// Source2 original variable-description ABI must match across VS/PS.
    pub original_variable_abi_hash:[u8;16],
    pub format:NativeFormat,
    /// Exact compiled GPU shader bytes, not a rewritten or universal shader.
    pub bytecode:Vec<u8>,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum NativeFormat { SpirV, Dxbc }

#[derive(Clone,Debug)]
pub struct NativeByteCodeBlock {
    /// Physical start in the original .vcs, including native compression hdr.
    pub file_offset:u64,
    pub compressed_size:usize,
    /// Source offsets in the uncompressed frame (one per original blob,
    /// including a terminal end offset).
    pub offsets:Vec<usize>,
    pub original_hashes:Vec<[u8;16]>,
}
#[derive(Clone,Debug)]
pub struct NativeStaticCombo {
    pub static_id:i64,
    pub block:Option<usize>,
    /// Original dynamic ID -> bytecode index. None = source uncompiled.
    pub dynamic:Vec<(i64,Option<usize>)>,
}
/// Original compiler-authoritative mixed-radix feature definition.
/// The nComboIndexValue comes from the actual VCS, not from a VMAT guess.
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct NativeComboParameter {
    pub name:String,
    pub min:i64,
    pub max:i64,
    pub stride:i64,
}
#[derive(Clone,Debug)]
pub struct NativeVcsIndex {
    pub declared_metadata_bytes:usize,
    pub compiler_static_ids:usize,
    pub original_program_hashes:Vec<[u8;16]>,
    pub original_variable_abi_hash:[u8;16],
    pub static_parameters:Vec<NativeComboParameter>,
    pub dynamic_parameters:Vec<NativeComboParameter>,
    pub compiler_dynamic_definitions:usize,
    pub compiler_variable_descriptions:usize,
    /// Source-authored shader variable names, provider and register metadata.
    pub variables:Vec<CompilerSourceVariable>,
    pub blocks:Vec<NativeByteCodeBlock>,
    pub static_combos:Vec<NativeStaticCombo>,
}

fn source_int(v:&Value)->Result<i64,String>{
    match v {
        Value::Int(n)=>Ok(*n),
        Value::UInt(n)=>i64::try_from(*n).map_err(|_|"VCS integer outside signed range".into()),
        Value::Flagged(_,v)=>source_int(v),
        _=>Err("VCS KV3 field is not an exact original integer".into()),
    }
}
fn field_int(v:&Value,name:&str)->Result<i64,String>{
    source_int(v.field(name).ok_or_else(||format!("VCS lacks compiler field {name}"))?)
}
fn source_array<'a>(v:&'a Value,name:&str)->Result<&'a [Value],String>{
    v.field(name).and_then(Value::as_array)
        .ok_or_else(||format!("VCS lacks compiler array {name}"))
}
fn guid(v:&Value)->Result<[u8;16],String>{
    let v=v.field("m_nHashChar").ok_or("VCS compiler hash has no bytes")?;
    match v {
        Value::Blob(bytes)=>bytes.as_slice().try_into()
            .map_err(|_|"VCS compiler GUID blob must be 16 bytes".into()),
        Value::Array(items) if items.len()==16=>{
            let mut hash=[0u8;16];
            for (dst,item) in hash.iter_mut().zip(items){
                *dst=u8::try_from(source_int(item)?)
                    .map_err(|_|"invalid compiler GUID byte")?;
            }
            Ok(hash)
        },
        _=>Err("VCS compiler GUID is not 16 exact bytes".into()),
    }
}
fn nonnegative(v:&Value,label:&str)->Result<usize,String>{
    usize::try_from(source_int(v)?).map_err(|_|format!("invalid negative {label}"))
}
fn relative(v:i64)->Result<usize,String>{
    usize::try_from(v).map_err(|_|"negative physical VCS bytecode offset".into())
}
/// Recover *only* the compiler's actual mixed-radix encoding. The caller
/// must supply every non-singleton feature value, including runtime lighting
/// choices. Unknown VMAT defaults are never implicitly set to zero.
fn compiler_parameters(root:&Value,name:&str)->Result<Vec<NativeComboParameter>,String>{
    let authored=source_array(root,name)?;
    if authored.len()>128 {return Err("VCS combo definitions exceed bounded count".into());}
    let mut parameters=Vec::with_capacity(authored.len());
    let mut expected_stride=1i64;
    let mut used=std::collections::BTreeSet::new();
    for combo in authored {
        let param=combo.field("m_szName").and_then(Value::as_text)
            .ok_or("VCS authored combo has no compiler name")?;
        if param.is_empty() || param.len()>128 || !used.insert(param) {
            return Err("duplicate/invalid original VCS feature name".into());
        }
        let min=field_int(combo,"m_nMin")?;
        let max=field_int(combo,"m_nMax")?;
        let stride=field_int(combo,"m_nComboIndexValue")?;
        let width=max.checked_sub(min).and_then(|n|n.checked_add(1))
            .ok_or("VCS feature range overflow")?;
        if width>8193 || stride!=expected_stride || stride<1 {
            return Err(format!("VCS {param} original mixed-radix stride/range inconsistent"));
        }
        parameters.push(NativeComboParameter{
            name:param.to_owned(),min,max,stride
        });
        expected_stride=expected_stride.checked_mul(width)
            .ok_or("VCS native shader combo space exceeds i64")?;
    }
    Ok(parameters)
}
/// Calculate a *compiler-indexed* combo ID. None means the author/runtime
/// has not supplied enough values, NOT that zero is a usable default.
pub fn compiler_combo_id(
    parameters:&[NativeComboParameter],
    supplied:&std::collections::BTreeMap<String,i64>,
)->Result<Option<i64>,String>{
    let mut id=0i64;
    for feature in parameters{
        let value=if let Some(value)=supplied.get(&feature.name){
            *value
        }else if feature.min==feature.max{
            feature.min
        }else{return Ok(None)};
        if value<feature.min || value>feature.max{
            return Err(format!("Source2 {}={} outside compiler range {}..{}",
                feature.name,value,feature.min,feature.max));
        }
        let digit=value.checked_sub(feature.min)
            .ok_or("Source2 native shader combo value overflow")?;
        id=id.checked_add(digit.checked_mul(feature.stride)
            .ok_or("Source2 native combo stride overflow")?)
            .ok_or("Source2 shader combo ID overflow")?;
    }
    Ok(Some(id))
}
impl NativeVcsIndex {
    /// Resolve source-authored static and dynamic features to the exact
    /// IDs that exist in the physical compiled stage. A disallowed/uncompiled
    /// combination fails, even if mixed-radix arithmetic yields an ID.
    pub fn resolve_compiler_values(
        &self,
        static_features:&std::collections::BTreeMap<String,i64>,
        dynamic_features:&std::collections::BTreeMap<String,i64>,
    )->Result<Option<(i64,i64)>,String>{
        let Some(static_id)=compiler_combo_id(&self.static_parameters,static_features)?
            else{return Ok(None)};
        let Some(dynamic_id)=compiler_combo_id(&self.dynamic_parameters,dynamic_features)?
            else{return Ok(None)};
        self.source_selection(static_id,dynamic_id)?;
        Ok(Some((static_id,dynamic_id)))
    }
    /// Parse exact compiler-authored static IDs and bytecode frame offsets.
    /// source_len is the actual file's length, not its Resource header length.
    pub fn parse(metadata:&[u8],source_len:u64)->Result<Self,String>{
        let resource=ResourceHeader::parse(metadata)?;
        if !(70..=72).contains(&(resource.resource_version as u32)){
            return Err("not a supported Source 2 VCS Resource v70-72".into());
        }
        let physical_metadata=resource.declared_file_size as usize;
        if physical_metadata!=metadata.len() || source_len<physical_metadata as u64 {
            return Err("VCS metadata extent differs from compiler Resource length".into());
        }
        let data=resource.block(metadata,b"DATA").ok_or("VCS lacks KV3 DATA")?;
        let document=kv3::decode(data)?;
        let root=if let Some(program)=document.root.field("m_programData") {
            program
        }else{&document.root};
        let variables=vcs_variable_contract::compiler_source_variables(root)?;
        let program_hashes=source_array(root,"m_programHashes")?;
        if program_hashes.len()>4096 {
            return Err("original VCS program hash inventory is unbounded".into());
        }
        // Source2 v72 stage metadata may contain multiple compiler program
        // hashes; physical VCS identity and variable-description ABI still
        // determine permissible VS/PS pairing. Preserve ALL original hashes.
        let original_program_hashes=program_hashes.iter()
            .map(guid).collect::<Result<Vec<_>,_>>()?;
        let original_variable_abi_hash=guid(
            root.field("m_variableDescriptionVersionHash")
                .ok_or("original Source2 VCS variable ABI digest missing")?
        )?;
        let static_parameters=compiler_parameters(root,"m_staticComboArray")?;
        let dynamic_parameters=compiler_parameters(root,"m_dynamicComboArray")?;
        let combos=source_array(root,"m_staticComboData")?;
        let ids=source_array(root,"m_staticComboIDs")?;
        let descriptors=source_array(root,"m_byteCodeData")?;
        if combos.len()!=ids.len() || combos.len()>100_000 || descriptors.len()>100_000 {
            return Err("original VCS static ID / source data lengths do not match".into());
        }
        let mut blocks=Vec::with_capacity(descriptors.len());
        for desc in descriptors {
            let offset=relative(field_int(desc,"m_nOffs")?)?;
            let size=relative(field_int(desc,"m_nSize")?)?;
            if size<12 || size>MAX_NATIVE_FRAME {
                return Err("VCS compressed bytecode descriptor outside bounded range".into());
            }
            let absolute=physical_metadata.checked_add(offset)
                .ok_or("VCS source bytecode offset overflow")?;
            if (absolute as u64).checked_add(size as u64)
                .is_none_or(|end|end>source_len) {
                return Err("VCS bytecode descriptor outside original physical stage".into());
            }
            let source_offsets=source_array(desc,"m_offs")?;
            let hashes=source_array(desc,"m_hash")?;
            if hashes.is_empty() || hashes.len()>65_536 || source_offsets.len()!=hashes.len()+1 {
                return Err("VCS source hash and bytecode offset tables disagree".into());
            }
            let offsets=source_offsets.iter()
                .map(|v|nonnegative(v,"shader bytecode offset"))
                .collect::<Result<Vec<_>,_>>()?;
            if offsets.first()!=Some(&0) || offsets.windows(2).any(|v|v[0]>=v[1])
               || offsets.last().copied().unwrap_or(0)>MAX_NATIVE_DECOMPRESSED {
                return Err("invalid VCS source bytecode offset boundaries".into());
            }
            let original_hashes=hashes.iter().map(guid).collect::<Result<Vec<_>,_>>()?;
            blocks.push(NativeByteCodeBlock{
                file_offset:absolute as u64,compressed_size:size,offsets,original_hashes,
            });
        }
        let mut static_combos=Vec::with_capacity(combos.len());
        let mut known=std::collections::BTreeSet::new();
        for (id,combo) in ids.iter().zip(combos) {
            let static_id=source_int(id)?;
            if !known.insert(static_id) {return Err("duplicate native VCS static ID".into());}
            let index=field_int(combo,"m_nByteCodeDataIdx")?;
            let block=if index<0 {None}else{
                let index=relative(index)?;
                if index>=blocks.len(){return Err("VCS combo references invalid code block".into());}
                Some(index)
            };
            let byte_indices=source_array(combo,"m_byteCodeIndex")?;
            let dynamic_ids=source_array(combo,"m_dynamicComboIDs")?;
            if !dynamic_ids.is_empty() && dynamic_ids.len()!=byte_indices.len(){
                return Err("VCS authored dynamic IDs / bytecode selections mismatch".into());
            }
            let mut dynamic=Vec::with_capacity(byte_indices.len());
            let mut seen_dynamic=std::collections::BTreeSet::new();
            for (n,entry) in byte_indices.iter().enumerate(){
                let id=if dynamic_ids.is_empty(){n as i64}else{source_int(&dynamic_ids[n])?};
                if !seen_dynamic.insert(id){return Err("duplicate source VCS dynamic ID".into());}
                let code=source_int(entry)?;
                let code=if code<0 {None}else{
                    let index=relative(code)?;
                    let Some(block)=block else {
                        return Err("VCS references native code without source bytecode descriptor".into());
                    };
                    if index>=blocks[block].original_hashes.len(){
                        return Err("VCS dynamic bytecode index exceeds physical source hashes".into());
                    }
                    Some(index)
                };
                dynamic.push((id,code));
            }
            static_combos.push(NativeStaticCombo{static_id,block,dynamic});
        }
        Ok(Self{
            declared_metadata_bytes:physical_metadata,
            compiler_static_ids:static_combos.len(),
            original_program_hashes,original_variable_abi_hash,
            static_parameters,dynamic_parameters,
            compiler_dynamic_definitions:source_array(root,"m_dynamicComboArray")?.len(),
            compiler_variable_descriptions:variables.len(),
            variables,blocks,static_combos,
        })
    }
    pub fn source_selection(&self,static_id:i64,dynamic_id:i64)
        ->Result<(&NativeByteCodeBlock,usize),String>{
        let record=self.static_combos.iter().find(|c|c.static_id==static_id)
            .ok_or_else(||format!("uncompiled original VCS static ID {static_id}"))?;
        let block=self.blocks.get(record.block.ok_or("source has no compiled static code")?)
            .ok_or("missing source frame")?;
        let index=record.dynamic.iter().find(|(id,_)|*id==dynamic_id)
            .ok_or_else(||format!("original VCS dynamic ID {dynamic_id} not present"))?
            .1.ok_or("original compiler omitted this dynamic shader")?;
        Ok((block,index))
    }
}

/// Decode one source frame only, with exact compressed and uncompressed bounds.
/// Source2 uses -3 for dictionary 2bc2fa87 and -5 for dictionary 255df362.
pub fn decode_native_frame(block:&[u8],dictionary:Option<&[u8]>)->Result<Vec<u8>,String>{
    if block.len()<12 || block.len()>MAX_NATIVE_FRAME {
        return Err("VCS frame exceeds bounded input size".into());
    }
    let signed=i32::from_le_bytes(block[..4].try_into().unwrap());
    if signed>=0{return Err("legacy/nonframed VCS bytecode is unsupported".into());}
    let kind=signed.checked_neg().ok_or("invalid VCS compression type")?;
    let expected=u32::from_le_bytes(block[4..8].try_into().unwrap()) as usize;
    let encoded=u32::from_le_bytes(block[8..12].try_into().unwrap()) as usize;
    if expected==0 || expected>MAX_NATIVE_DECOMPRESSED || encoded!=block.len()-12 {
        return Err("VCS source frame compressed/uncompressed size mismatch".into());
    }
    let payload=&block[12..];
    let result=match kind {
        1=>{
            if payload.len()!=expected{return Err("raw VCS size mismatch".into());}
            payload.to_vec()
        },
        2=>zstd::bulk::decompress(payload,expected)
            .map_err(|e|format!("VCS dictionary-free zstd: {e}"))?,
        3|5=>{
            let dict=dictionary.ok_or("original VCS shader dictionary not installed")?;
            let expected_id=if kind==3 {0x2bc2fa87u32}else{0x255df362u32};
            if dict.len()!=ZSTD_DICTIONARY_LEN ||
                dict.get(..4)!=Some(0xec30a437u32.to_le_bytes().as_slice()) ||
                dict.get(4..8)!=Some(expected_id.to_le_bytes().as_slice()) {
                return Err("VCS source shader dictionary magic/ID mismatch".into());
            }
            let mut decoder=zstd::bulk::Decompressor::with_dictionary(dict)
                .map_err(|e|format!("VCS source zstd dictionary load: {e}"))?;
            decoder.decompress(payload,expected)
                .map_err(|e|format!("original VCS zstd decode: {e}"))?
        },
        4=>lz4_flex::block::decompress(payload,expected)
            .map_err(|e|format!("original VCS LZ4 decode: {e}"))?,
        _=>return Err(format!("unsupported original VCS compression kind {kind}")),
    };
    if result.len()!=expected {
        return Err("VCS native decompressor returned wrong source extent".into());
    }
    Ok(result)
}

/// Extract a source compiler-selected GPU shader, never a guessed default.
pub fn source_shader_bytes<'a>(
    frame:&'a [u8],desc:&NativeByteCodeBlock,index:usize,format:NativeFormat
)->Result<&'a [u8],String>{
    if frame.len()!=desc.offsets.last().copied().unwrap_or(0) {
        return Err("VCS decoded payload disagrees with compiler bytecode offsets".into());
    }
    let (start,end)=(*desc.offsets.get(index).ok_or("bytecode index missing")?,
        *desc.offsets.get(index+1).ok_or("terminal source offset missing")?);
    let original=frame.get(start..end).ok_or("invalid original native bytecode slice")?;
    match format {
        NativeFormat::SpirV=>{
            if original.len()<28{return Err("VCS Vulkan shader is truncated".into());}
            let version=u32::from_le_bytes(original[..4].try_into().unwrap());
            let size=u32::from_le_bytes(original[4..8].try_into().unwrap()) as usize;
            if !(2..=6).contains(&version) || size<20 || size%4!=0 ||
                size>original.len()-8 || original.get(8..12)!=Some(&[3,2,35,7]) {
                return Err("invalid original Vulkan SPIR-V shader extent".into());
            }
            let words=&original[8..8+size];
            // Exact word boundaries are validated but this is not an external
            // spirv-val result nor a claim that all instructions are supported.
            let mut at=20usize;
            while at<words.len(){
                let op=u32::from_le_bytes(words[at..at+4].try_into().unwrap());
                let count=(op>>16) as usize;
                if count==0 || at.checked_add(count*4).is_none_or(|end|end>words.len()){
                    return Err("original SPIR-V instruction escapes declared bytecode".into());
                }
                at+=count*4;
            }
            Ok(words)
        },
        NativeFormat::Dxbc=>{
            if original.len()<32 || original.get(..4)!=Some(b"DXBC") {
                return Err("original D3D stage is not a DXBC container".into());
            }
            let size=u32::from_le_bytes(original[24..28].try_into().unwrap()) as usize;
            if size!=original.len() {
                return Err("original DXBC declared bytes differ from selected GPU program".into());
            }
            Ok(original)
        },
    }
}

/// Stream one native GPU program from a physically recovered VCS. Never load
/// hundreds of MiB of alternate permutations or keep an on-disk shader cache.
pub fn recover_original_gpu_program(
    source:&Path,dictionary_dir:&Path,static_id:i64,dynamic_id:i64
)->Result<NativeCompiledCode,String>{
    let mut file=File::open(source)
        .map_err(|e|format!("open original compiled VCS {}: {e}",source.display()))?;
    let file_size=file.metadata().map_err(|e|e.to_string())?.len();
    if file_size<16{return Err("source VCS too short".into());}
    let mut first=[0u8;8];
    file.read_exact(&mut first).map_err(|e|e.to_string())?;
    let length=u32::from_le_bytes(first[..4].try_into().unwrap()) as usize;
    if length<16 || length>MAX_VCS_META || length as u64>file_size{
        return Err("VCS Resource metadata size outside bounded range".into());
    }
    file.seek(SeekFrom::Start(0)).map_err(|e|e.to_string())?;
    let mut metadata=vec![0;length];
    file.read_exact(&mut metadata).map_err(|e|e.to_string())?;
    let index=NativeVcsIndex::parse(&metadata,file_size)?;
    let (block,bytecode_index)=index.source_selection(static_id,dynamic_id)?;
    file.seek(SeekFrom::Start(block.file_offset)).map_err(|e|e.to_string())?;
    let mut packed=vec![0u8;block.compressed_size];
    file.read_exact(&mut packed).map_err(|e|e.to_string())?;
    let kind=-i32::from_le_bytes(packed[..4].try_into().unwrap());
    let dictionary=match kind{
        3|5=>{
            let name=if kind==3{"vfx_zstd_2bc2fa87.bin"}else{"vfx_zstd_255df362.bin"};
            Some(std::fs::read(dictionary_dir.join(name))
                .map_err(|e|format!("original source shader dictionary {name}: {e}"))?)
        },
        _=>None,
    };
    let frame=decode_native_frame(&packed,dictionary.as_deref())?;
    let format=if source.file_name().and_then(|n|n.to_str()).is_some_and(|n|
        n.contains("_vulkan_")) {NativeFormat::SpirV}
    else if source.file_name().and_then(|n|n.to_str()).is_some_and(|n|
        n.contains("_pc_")) {NativeFormat::Dxbc}
    else{return Err("unsupported native VCS GPU target".into())};
    let bytes=source_shader_bytes(&frame,block,bytecode_index,format)?.to_vec();
    Ok(NativeCompiledCode{
        source_static_id:static_id,source_dynamic_id:dynamic_id,
        compiler_hash:block.original_hashes[bytecode_index],
        original_program_hashes:index.original_program_hashes,
        original_variable_abi_hash:index.original_variable_abi_hash,
        format,bytecode:bytes,
    })
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn source_compiler_stride_and_unprovided_lighting_modes_do_not_default(){
        use std::collections::BTreeMap;
        let definitions=vec![
            NativeComboParameter{name:"D_FROM_VERTEX".into(),min:0,max:1,stride:1},
            NativeComboParameter{name:"D_FROM_LIGHTMAP".into(),min:0,max:1,stride:2},
        ];
        let mut supplied=BTreeMap::new();
        assert_eq!(compiler_combo_id(&definitions,&supplied).unwrap(),None);
        supplied.insert("D_FROM_VERTEX".into(),0);
        supplied.insert("D_FROM_LIGHTMAP".into(),1);
        assert_eq!(compiler_combo_id(&definitions,&supplied).unwrap(),Some(2));
        supplied.insert("D_FROM_LIGHTMAP".into(),8);
        assert!(compiler_combo_id(&definitions,&supplied).is_err());
    }
    #[test]
    fn exact_native_combo_id_must_exist_and_have_compiled_bytecode(){
        use std::collections::BTreeMap;
        let index=NativeVcsIndex{
            declared_metadata_bytes:64,
            compiler_static_ids:1,
            original_program_hashes:vec![],
            original_variable_abi_hash:[0;16],
            compiler_dynamic_definitions:1,
            compiler_variable_descriptions:0,
            variables:vec![],
            static_parameters:vec![NativeComboParameter{
                name:"S_SOURCE".into(),min:0,max:1,stride:1
            }],
            dynamic_parameters:vec![NativeComboParameter{
                name:"D_LIGHTMAP".into(),min:0,max:1,stride:1
            }],
            blocks:vec![NativeByteCodeBlock{
                file_offset:64,compressed_size:16,
                offsets:vec![0,32],original_hashes:vec![[1u8;16]],
            }],
            static_combos:vec![NativeStaticCombo{
                static_id:1,block:Some(0),dynamic:vec![(1,Some(0))]
            }],
        };
        let mut static_values=BTreeMap::new();
        let mut dynamic_values=BTreeMap::new();
        static_values.insert("S_SOURCE".into(),1);
        dynamic_values.insert("D_LIGHTMAP".into(),1);
        assert_eq!(index.resolve_compiler_values(&static_values,&dynamic_values).unwrap(),
            Some((1,1)));
        static_values.insert("S_SOURCE".into(),0);
        assert!(index.resolve_compiler_values(&static_values,&dynamic_values).is_err());
        static_values.clear();
        assert_eq!(index.resolve_compiler_values(&static_values,&dynamic_values).unwrap(),None);
    }
    #[test]
    fn native_zstd_source_frame_is_exact_without_dictionary(){
        let data=b"original source frame data";
        let packed=zstd::bulk::compress(data,1).unwrap();
        let mut block=Vec::new();
        block.extend_from_slice(&(-2i32).to_le_bytes());
        block.extend_from_slice(&(data.len() as u32).to_le_bytes());
        block.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        block.extend_from_slice(&packed);
        assert_eq!(decode_native_frame(&block,None).unwrap(),data);
        block[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert!(decode_native_frame(&block,None).is_err());
    }
    #[test]
    fn exact_compiled_spirv_slice_has_native_header_and_instruction_bounds(){
        let mut spirv=Vec::new();
        for value in [0x07230203u32,0x00010500,0,16,0,(1u32<<16)|0]{
            spirv.extend_from_slice(&value.to_le_bytes());
        }
        let mut blob=Vec::new();
        blob.extend_from_slice(&6u32.to_le_bytes());
        blob.extend_from_slice(&(spirv.len() as u32).to_le_bytes());
        blob.extend_from_slice(&spirv);
        let desc=NativeByteCodeBlock{
            file_offset:0,compressed_size:0,
            offsets:vec![0,blob.len()],original_hashes:vec![[1;16]],
        };
        assert_eq!(source_shader_bytes(&blob,&desc,0,NativeFormat::SpirV).unwrap(),spirv);
        blob[8]=0;
        assert!(source_shader_bytes(&blob,&desc,0,NativeFormat::SpirV).is_err());
    }
}
