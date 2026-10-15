//! Source-backed compiled Source 2 VCS shader inventory.
//!
//! VMAT m_shaderName selects a VFX family, NOT an executable shader.
//! VCS assets carry vertex/pixel stages, static/dynamic combos and their ABI.
//! Match only actual VPK entries; never equate a guessed _pc_50_ps filename
//! with recovered shader code. For VCS2 <=69 read only the stable fixed prefix;
//! version 70+ uses KV3 Resource and requires complete bounded Resource
//! parsing. Neither counts as compiled/translated until the combo and resource
//! ABI are authenticated.
use std::collections::{BTreeMap,BTreeSet};
use crate::{material::SourcePacks,resource::ResourceHeader,kv3::{self,Value}};

const VCS_MAGIC:&[u8;4]=b"vcs2";
/// Conservative bound for legacy header probing from indexed source packages.
const VCS_HEADER_PREFIX:usize=64;
/// Limit each Source 2 v70+ VCS/KV3 Resource read during map admission.
const MAX_VCS_RESOURCE_BYTES:usize=32*1024*1024;

#[derive(Clone,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub struct VcsIdentity {
    pub family:String,
    pub platform:String,
    pub shader_model:String,
    pub stage:String,
}
/// Original static shader combination definition. The VMAT has to be
/// mapped to these compiler-authored ranges before any permutation selection.
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct VcsComboDefinition {
    pub name:String,
    pub range_min:i32,
    pub range_max:i32,
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct VcsHeader {
    pub version:u32,
    pub additional_file_flags:Option<u32>,
    /// First original program hash for backward-compatible header callers,
    /// NOT a unique compiler program/permutation identity.
    pub program_hash:Option<[u8;16]>,
    /// All original Source2 compiler program hashes in authored order. VCS
    /// v72 stages frequently declare many hashes, and rejecting those files
    /// made real VS/PS stages appear missing in the actual Christmas map.
    pub program_hashes:Vec<[u8;16]>,
    /// Variable ABI hash. No claim that the ABI is parsed.
    pub variable_description_hash:Option<[u8;16]>,
    pub variable_source_max:Option<i32>,
    pub declared_static_combo_definitions:Option<u32>,
    /// Empty for a legacy prefix-only probe; not necessarily zero combos.
    pub static_combo_definitions:Vec<VcsComboDefinition>,
}
#[derive(Clone,Debug)]
pub struct VcsSource {
    pub identity:VcsIdentity,
    pub path:String,
    pub origin:&'static str,
    pub header:Option<VcsHeader>,
    pub error:Option<String>,
}
#[derive(Clone,Debug,Default)]
pub struct VcsCensus {
    pub expected_families:usize,
    pub found_families:usize,
    pub families_with_vertex_and_pixel:usize,
    pub files_listed:usize,
    pub verified_headers:usize,
    pub missing_physical_file:usize,
    pub unsupported_headers:usize,
    pub sources:Vec<VcsSource>,
    pub missing_families:Vec<String>,
}

/// Derive only the source-native suffix, not a compiled permutation ID.
/// Supported desktop suffixes follow Valve's family_platform_model_stage.vcs.
pub fn parse_vcs_filename(path:&str)->Option<VcsIdentity>{
    let basename=path.rsplit('/').next()?.strip_suffix(".vcs")?;
    let mut parts=basename.rsplitn(4,'_');
    let stage=parts.next()?;
    let model=parts.next()?;
    let platform=parts.next()?;
    let family=parts.next()?;
    if family.is_empty() ||
        !matches!(platform,"pc"|"pcgl"|"vulkan") ||
        !matches!(model,"20"|"2b"|"30"|"31"|"40"|"41"|"50"|"60") ||
        !matches!(stage,"features"|"vs"|"ps"|"gs"|"hs"|"ds"|"cs"|"psrs"|"rtx"|"ms") {
        return None;
    }
    Some(VcsIdentity{
        family:family.to_ascii_lowercase(),
        platform:platform.to_owned(),shader_model:model.to_owned(),stage:stage.to_owned(),
    })
}

fn read_u32(bytes:&[u8],at:usize)->Result<u32,String>{
    Ok(u32::from_le_bytes(bytes.get(at..at+4)
        .ok_or("truncated VCS fixed header")?.try_into().unwrap()))
}
fn read_hash(bytes:&[u8],at:usize)->Result<[u8;16],String>{
    Ok(bytes.get(at..at+16).ok_or("truncated VCS hash")?
        .try_into().unwrap())
}
/// Inspect the fixed VCS2 prefix only. Read source program hash and variable
/// ABI hash for non-features stages; no fabricated permutation count.
/// VCS version 70+ uses Resource/KV3 and is parsed separately.
pub fn parse_vcs2_header(bytes:&[u8],stage:&str)->Result<VcsHeader,String>{
    if bytes.get(0..4)!=Some(VCS_MAGIC.as_slice()){
        return Err("not VCS2 magic (possibly VCS v70+ KV3 Resource)".into());
    }
    let version=read_u32(bytes,4)?;
    if !(58..=72).contains(&version){
        return Err(format!("unsupported original VCS version {version}"));
    }
    if version>=70 {
        return Err(format!("VCS version {version} is a KV3 Resource; do not parse it as legacy VCS2"));
    }
    let mut cursor=8;
    let additional_file_flags=if version>=64{
        let flags=read_u32(bytes,cursor)?;cursor+=4;
        if flags & !0x7!=0 {return Err(format!("unrecognized VCS additional-file flags {flags:#x}"))}
        Some(flags)
    }else{None};
    if stage=="features" {
        // Features has variable-length features header and program hash list.
        // The common prefix above is authoritative; further bytes are NOT.
        return Ok(VcsHeader{
            version,additional_file_flags,program_hash:None,
            program_hashes:Vec::new(),
            variable_description_hash:None,variable_source_max:None,
            declared_static_combo_definitions:None,
            static_combo_definitions:Vec::new(),
        });
    }
    let program_hash=read_hash(bytes,cursor)?;cursor+=16;
    let variable_description_hash=read_hash(bytes,cursor)?;cursor+=16;
    let variable_source_max=read_u32(bytes,cursor)? as i32;cursor+=4;
    let declared_static_combo_definitions=read_u32(bytes,cursor)?;
    if declared_static_combo_definitions>65_536 {
        return Err("unreasonable VCS static combo definition count".into());
    }
    Ok(VcsHeader{version,additional_file_flags,
        program_hash:Some(program_hash),
        program_hashes:vec![program_hash],
        variable_description_hash:Some(variable_description_hash),
        variable_source_max:Some(variable_source_max),
        declared_static_combo_definitions:Some(declared_static_combo_definitions),
        static_combo_definitions:Vec::new(),
    })
}
fn bounded_vcs_combo_name(bytes:&[u8],at:usize)->Result<String,String>{
    let raw=bytes.get(at..at.checked_add(64).ok_or("VCS combo string address overflow")?)
        .ok_or("truncated 64-byte VCS combo name")?;
    let end=raw.iter().position(|b|*b==0).ok_or("VCS combo name lacks NUL terminator")?;
    let name=std::str::from_utf8(&raw[..end])
        .map_err(|_|"VCS combo name is not original UTF-8")?;
    Ok(name.to_owned())
}
/// Legacy VCS2 static combos are serialized directly after the fixed stage
/// header. The source layout is 64-byte padded name, 64-byte alias, 6 i32
/// fields, optional NUL state names and (for 59+) feature comparisons.
/// No dynamic rules or selected permutation IDs are inferred here.
pub fn decode_vcs2_static_combos(bytes:&[u8],stage:&str)->Result<Vec<VcsComboDefinition>,String>{
    let hdr=parse_vcs2_header(bytes,stage)?;
    if stage=="features" {
        return Err("VCS2 features stage has a different variable-sized header".into());
    }
    let count=hdr.declared_static_combo_definitions.unwrap_or(0) as usize;
    if count>4096{return Err("VCS stage has too many static combo definitions".into());}
    let mut cursor=8+(if hdr.version>=64{4}else{0})+16+16+4+4;
    let mut combos=Vec::with_capacity(count);
    for _ in 0..count{
        let name=bounded_vcs_combo_name(bytes,cursor)?;cursor+=64;
        // Alias is a separate, equally bounded source field.
        let _alias=bounded_vcs_combo_name(bytes,cursor)?;cursor+=64;
        if name.is_empty(){return Err("VCS static combo has an empty name".into());}
        let kind=read_u32(bytes,cursor)?;cursor+=4;
        let min=read_u32(bytes,cursor)? as i32;cursor+=4;
        let max=read_u32(bytes,cursor)? as i32;cursor+=4;
        let source_type=read_u32(bytes,cursor)? as i32;cursor+=4;
        let _feature=read_u32(bytes,cursor)?;cursor+=4;
        let state_count=read_u32(bytes,cursor)? as i32;cursor+=4;
        if kind>3 || min>max || (max as i64-min as i64)>8192 || !(0..=128).contains(&state_count){
            return Err(format!("invalid VCS combo {name} kind/range/state count"));
        }
        for _ in 0..state_count {
            let tail=bytes.get(cursor..).ok_or("truncated VCS combo state name")?;
            let length=tail.iter().position(|b|*b==0)
                .ok_or("unterminated VCS combo state name")?;
            if length>256{return Err("VCS combo state name too long".into());}
            cursor=cursor.checked_add(length+1).ok_or("VCS combo state offset overflow")?;
        }
        if hdr.version>=59 && matches!(source_type,10|11){
            let _compare=read_u32(bytes,cursor)?;cursor+=4;
        }
        combos.push(VcsComboDefinition{name,range_min:min,range_max:max});
    }
    Ok(combos)
}
fn kv_hash(value:&Value)->Result<[u8;16],String>{
    let bytes=value.field("m_nHashChar")
        .ok_or("compiled VCS KV3 GUID has no m_nHashChar array")?;
    let list=match bytes {
        Value::Blob(blob) if blob.len()==16=>return Ok(blob.clone().try_into().unwrap()),
        Value::Array(list)=>list,
        _=>return Err("VCS KV3 GUID is not a 16-byte source array".into()),
    };
    if list.len()!=16{return Err("VCS KV3 GUID has wrong byte count".into());}
    let mut out=[0u8;16];
    for (index,value) in list.iter().enumerate(){
        let v=value.as_float().ok_or("non-numeric VCS GUID element")?;
        if !v.is_finite() || v<0. || v>255. || v.fract()!=0. {
            return Err("VCS GUID element outside exact source byte range".into());
        }
        out[index]=v as u8;
    }
    Ok(out)
}
/// Newer compiled VCS stages are Source 2 Resource/KV3 documents (v70+).
/// This extracts only source-declared program/ABI hashes and static combo
/// DEFINITION count. It is not evidence of any compiled selected permutation.
pub fn parse_vcs_resource_header(bytes:&[u8],stage:&str)->Result<VcsHeader,String>{
    let resource=ResourceHeader::parse(bytes)?;
    let version=resource.resource_version as u32;
    if !(70..=72).contains(&version){
        return Err(format!("VCS Resource version {version} is not supported v70-72"));
    }
    let data=resource.block(bytes,b"DATA").ok_or("VCS Resource lacks DATA")?;
    let doc=kv3::decode(data)?;
    let root=if stage=="features" {
        doc.root.field("m_programData").ok_or("VCS feature Resource missing m_programData")?
    }else{&doc.root};
    let hashes=root.field("m_programHashes").and_then(Value::as_array)
        .ok_or("VCS KV3 Resource missing m_programHashes")?;
    if hashes.is_empty() || hashes.len()>4096 {
        return Err("VCS Resource declares invalid original program hash count".into());
    }
    let program_hashes=hashes.iter().map(kv_hash)
        .collect::<Result<Vec<_>,_>>()?;
    let variable_description_hash=kv_hash(root.field("m_variableDescriptionVersionHash")
        .ok_or("VCS Resource lacks variable description hash")?)?;
    let variable_source_max=root.field("m_nVariableSourceMax")
        .and_then(Value::as_float).ok_or("VCS Resource lacks variable source range")?;
    if !variable_source_max.is_finite() || variable_source_max.fract()!=0. ||
        variable_source_max<i32::MIN as f64 || variable_source_max>i32::MAX as f64 {
        return Err("invalid VCS Resource variable source bound".into());
    }
    let static_count=root.field("m_staticComboArray").and_then(Value::as_array)
        .ok_or("VCS Resource missing static combo definitions")?.len();
    if static_count>4096{return Err("VCS Resource has unreasonable combo definition count".into());}
    let static_combo_definitions=root.field("m_staticComboArray")
        .and_then(Value::as_array).unwrap().iter().map(|combo|{
            let name=combo.field("m_szName").and_then(Value::as_text)
                .ok_or("VCS Resource static combo lacks original name")?;
            if name.is_empty()||name.len()>64{return Err("invalid VCS KV3 static combo name".into());}
            let integral=|field:&str|->Result<i32,String>{
                let v=combo.field(field).and_then(Value::as_float)
                    .ok_or_else(||format!("VCS static combo {name} lacks {field}"))?;
                if !v.is_finite() || v.fract()!=0. ||
                    v<i32::MIN as f64 || v>i32::MAX as f64 {
                    return Err(format!("VCS combo {name} invalid integer {field}"));
                }
                Ok(v as i32)
            };
            let range_min=integral("m_nMin")?;
            let range_max=integral("m_nMax")?;
            if range_min>range_max||range_max as i64-range_min as i64>8192 {
                return Err(format!("invalid VCS static combo range {name}"));
            }
            Ok(VcsComboDefinition{name:name.to_owned(),range_min,range_max})
        }).collect::<Result<Vec<_>,String>>()?;
    Ok(VcsHeader{
        version,additional_file_flags:None,
        program_hash:if stage=="features"{None}else{Some(program_hashes[0])},
        program_hashes,
        variable_description_hash:Some(variable_description_hash),
        variable_source_max:Some(variable_source_max as i32),
        declared_static_combo_definitions:Some(static_count as u32),
        static_combo_definitions,
    })
}
fn vmats_to_families<'a>(
    shader_names:impl IntoIterator<Item=&'a str>
)->BTreeSet<String>{
    shader_names.into_iter().filter_map(|shader|{
        let basename=shader.rsplit('/').next()?;
        let name=basename.strip_suffix(".vfx")?;
        (!name.is_empty()).then(||name.to_ascii_lowercase())
    }).collect()
}
/// A pair must use the same Source 2 target and agree on the
/// compiler-authored variable description hash. An unrelated VS on Vulkan
/// and PS on PC cannot be treated as a runnable pipeline.
fn source_closed_stage_pair_families(sources:&[VcsSource])->usize{
    // Each stage can occur in multiple physical source packages. Preserving
    // all ABI hashes avoids false negatives caused by last-source-wins and
    // avoids claiming a pair when no actual VS/PS ABI matches.
    let mut targets=BTreeMap::<
        (String,String,String),(BTreeSet<[u8;16]>,BTreeSet<[u8;16]>)
    >::new();
    for source in sources {
        if source.error.is_some(){continue;}
        let Some(header)=source.header.as_ref() else {continue};
        if header.program_hash.is_none(){continue;}
        let Some(abi)=header.variable_description_hash else {continue};
        let row=targets.entry((
            source.identity.family.clone(),
            source.identity.platform.clone(),
            source.identity.shader_model.clone(),
        )).or_default();
        match source.identity.stage.as_str(){
            "vs"=>{row.0.insert(abi);},
            "ps"=>{row.1.insert(abi);},
            _=>{},
        }
    }
    targets.into_iter().filter_map(|((family,_,_), (vs,ps))|
        vs.iter().any(|abi|ps.contains(abi)).then_some(family)
    ).collect::<BTreeSet<_>>().len()
}
/// Enumerate the actual VCS entries in the original VPK indices, probing
/// only matching families. A listed file in a missing physical pak is NOT
/// counted as an available compiled shader.
pub fn audit<'a>(
    packages:&SourcePacks<'_>,shader_names:impl IntoIterator<Item=&'a str>
)->VcsCensus {
    let expected=vmats_to_families(shader_names);
    let mut result=VcsCensus{expected_families:expected.len(),..Default::default()};
    // Keep source locations distinct. A path listed by the Workshop index
    // with missing archive bytes must not mask the physically available base
    // game copy of that exact stage.
    let mut seen=BTreeSet::<(VcsIdentity,String,&'static str)>::new();
    let collections=[
        ("workshop map",packages.workshop_map),
        ("workshop outer",packages.workshop_outer),
    ];
    for (origin,archive) in collections.into_iter()
        .chain(packages.base_game.into_iter().map(|archive|("base game",archive))) {
        for path in archive.entries().keys(){
            let Some(identity)=parse_vcs_filename(path) else {continue};
            if !expected.contains(&identity.family){continue;}
            if !seen.insert((identity.clone(),path.clone(),origin)){continue;}
            result.files_listed+=1;
            let mut source=VcsSource{
                identity,path:path.clone(),origin,header:None,error:None,
            };
            if !archive.available(path){
                result.missing_physical_file+=1;
                source.error=Some("VCS present in index; physical archive unavailable".into());
            }else{
                let inspected=archive.entry_prefix(path,VCS_HEADER_PREFIX)
                    .and_then(|prefix|{
                        if prefix.starts_with(VCS_MAGIC) {
                            // Read full stage only for bounded small
                            // VCS files so original packed static combo
                            // definitions and CRC can be verified together.
                            let entry=archive.entries().get(path)
                                .ok_or("VCS source stage disappeared")?;
                            if (entry.length as usize).saturating_add(entry.preload.len())
                                >MAX_VCS_RESOURCE_BYTES {
                                // Prefix only: no CRC / static combo claims.
                                return parse_vcs2_header(&prefix,&source.identity.stage);
                            }
                            let bytes=archive.read_entry(path)?;
                            let mut hdr=parse_vcs2_header(&bytes,&source.identity.stage)?;
                            if source.identity.stage!="features"{
                                hdr.static_combo_definitions=decode_vcs2_static_combos(
                                    &bytes,&source.identity.stage)?;
                            }
                            Ok(hdr)
                        }else{
                            let entry=archive.entries().get(path)
                                .ok_or("compiled VCS vanished from source archive")?;
                            if (entry.length as usize).saturating_add(entry.preload.len())
                                >MAX_VCS_RESOURCE_BYTES {
                                return Err("VCS Resource/KV3 exceeds bounded header decode budget".into());
                            }
                            let bytes=archive.read_entry(path)?;
                            parse_vcs_resource_header(&bytes,&source.identity.stage)
                        }
                    });
                match inspected {
                    Ok(header)=>{
                        result.verified_headers+=1;
                        source.header=Some(header);
                    },
                    Err(error)=>{
                        result.unsupported_headers+=1;
                        source.error=Some(error);
                    },
                }
            }
            result.sources.push(source);
        }
    }
    // The compact original Source2 shader corpus contains genuine VCS stages
    // extracted losslessly from Valve's separate shaders_pc/shaders_vulkan
    // archives. Those archives are NOT part of CS2's main pak01_dir.vpk.
    // Scan the Workshop-side loose overlay by exact original VCS filenames,
    // and read Resource-KV3 metadata only. Native shader bytecode appended
    // beyond the declared Resource header remains on disk until the actual
    // shader lowering pipeline needs it.
    for path in packages.workshop_outer.overlay_vcs_paths() {
        let Some(identity)=parse_vcs_filename(&path) else{continue};
        if !expected.contains(&identity.family){continue};
        let origin="compact original shader overlay";
        if !seen.insert((identity.clone(),path.clone(),origin)){continue};
        result.files_listed+=1;
        let inspected=packages.workshop_outer
            .read_overlay_vcs_metadata(&path,MAX_VCS_RESOURCE_BYTES)
            .and_then(|bytes|{
                if bytes.starts_with(VCS_MAGIC) {
                    let mut header=parse_vcs2_header(&bytes,&identity.stage)?;
                    if identity.stage!="features"{
                        header.static_combo_definitions=
                            decode_vcs2_static_combos(&bytes,&identity.stage)?;
                    }
                    Ok(header)
                }else{
                    parse_vcs_resource_header(&bytes,&identity.stage)
                }
            });
        let (header,error)=match inspected {
            Ok(header)=>{result.verified_headers+=1;(Some(header),None)},
            Err(error)=>{result.unsupported_headers+=1;(None,Some(error))},
        };
        result.sources.push(VcsSource{identity,path,origin,header,error});
    }
    let found=result.sources.iter().map(|s|s.identity.family.clone())
        .collect::<BTreeSet<_>>();
    result.found_families=found.len();
    result.missing_families=expected.difference(&found).cloned().collect();
    result.families_with_vertex_and_pixel=source_closed_stage_pair_families(&result.sources);
    result
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn stage_suffix_and_underscored_families_are_unambiguous(){
        let identity=parse_vcs_filename("shaders/vfx/csgo_complex_pc_50_ps.vcs").unwrap();
        assert_eq!(identity.family,"csgo_complex");
        assert_eq!(identity.shader_model,"50");
        assert_eq!(identity.stage,"ps");
        assert_eq!(parse_vcs_filename("csgo_effects_pc_50_features.vcs").unwrap().stage,"features");
        // The basename parser only validates the final three suffixes.
        // An extra token belongs to a potentially valid shader family, not
        // an inferred target platform. The audited VMAT family set filters it.
        assert_eq!(
            parse_vcs_filename("csgo_complex_android_vulkan_50_vs.vcs")
                .unwrap().family,
            "csgo_complex_android"
        );
        assert_eq!(parse_vcs_filename("csgo_complex_pc_50_ps.vcs_c"),None);
        assert_eq!(parse_vcs_filename("csgo_complex_pc_77_ps.vcs"),None);
        assert_eq!(vmats_to_families(["csgo_complex.vfx","shaders/csgo_effects.vfx"]),
            BTreeSet::from(["csgo_complex".to_owned(),"csgo_effects".to_owned()]));
    }
    #[test]
    fn legacy_fixed_header_keeps_original_program_and_abi_hashes(){
        let mut bytes=vec![0u8;64];
        bytes[0..4].copy_from_slice(b"vcs2");
        bytes[4..8].copy_from_slice(&69u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&3u32.to_le_bytes());
        bytes[12..28].copy_from_slice(&[0x11;16]);
        bytes[28..44].copy_from_slice(&[0x22;16]);
        bytes[44..48].copy_from_slice(&99u32.to_le_bytes());
        bytes[48..52].copy_from_slice(&7u32.to_le_bytes());
        let parsed=parse_vcs2_header(&bytes,"ps").unwrap();
        assert_eq!(parsed.version,69);
        assert_eq!(parsed.program_hash,Some([0x11;16]));
        assert_eq!(parsed.program_hashes,vec![[0x11;16]]);
        assert_eq!(parsed.variable_description_hash,Some([0x22;16]));
        assert_eq!(parsed.variable_source_max,Some(99));
        assert_eq!(parsed.declared_static_combo_definitions,Some(7));
        let features=parse_vcs2_header(&bytes,"features").unwrap();
        assert_eq!(features.program_hash,None);
    }
    #[test]
    fn only_same_platform_and_matching_variable_abi_counts_as_pipeline_pair(){
        let source=|stage:&str,platform:&str,abi:u8|VcsSource{
            identity:VcsIdentity{
                family:"csgo_complex".into(),platform:platform.into(),
                shader_model:"50".into(),stage:stage.into(),
            },
            path:format!("{stage}.vcs"),origin:"fixture",
            header:Some(VcsHeader{
                version:69,additional_file_flags:Some(0),
                program_hash:Some([7;16]),program_hashes:vec![[7;16]],
                variable_description_hash:Some([abi;16]),
                variable_source_max:Some(2),declared_static_combo_definitions:Some(1),
                static_combo_definitions:Vec::new(),
            }),
            error:None,
        };
        let vs=source("vs","pc",8);
        let ps_wrong_target=source("ps","vulkan",8);
        assert_eq!(source_closed_stage_pair_families(&[vs.clone(),ps_wrong_target]),0);
        let ps_wrong_abi=source("ps","pc",9);
        assert_eq!(source_closed_stage_pair_families(&[vs.clone(),ps_wrong_abi]),0);
        let ps=source("ps","pc",8);
        assert_eq!(source_closed_stage_pair_families(&[vs,ps]),1);
    }
    #[test]
    fn actual_legacy_static_combo_records_preserve_named_ranges(){
        let mut data=vec![0u8;52+152];
        data[..4].copy_from_slice(b"vcs2");
        data[4..8].copy_from_slice(&69u32.to_le_bytes());
        data[48..52].copy_from_slice(&1u32.to_le_bytes());
        data[52..57].copy_from_slice(b"F_FOG");
        data[180..184].copy_from_slice(&1u32.to_le_bytes()); // VfxComboType.Static
        data[184..188].copy_from_slice(&0u32.to_le_bytes());
        data[188..192].copy_from_slice(&3u32.to_le_bytes());
        let combos=decode_vcs2_static_combos(&data,"ps").unwrap();
        assert_eq!(combos,vec![VcsComboDefinition{
            name:"F_FOG".into(),range_min:0,range_max:3
        }]);
        let mut malformed=data;
        malformed[188..192].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_vcs2_static_combos(&malformed,"ps").is_err());
    }
    #[test]
    fn kv3_resource_guid_preserves_exact_source_bytes(){
        let value=Value::Object(vec![(
            "m_nHashChar".into(),
            Value::Array((0..16u64).map(Value::UInt).collect()),
        )]);
        let hash=kv_hash(&value).unwrap();
        assert_eq!(hash,std::array::from_fn(|i|i as u8));
        let malformed=Value::Object(vec![(
            "m_nHashChar".into(),
            Value::Array(vec![Value::UInt(256);16]),
        )]);
        assert!(kv_hash(&malformed).is_err());
        let blob=Value::Object(vec![(
            "m_nHashChar".into(),Value::Blob(vec![0x64;16]),
        )]);
        assert_eq!(kv_hash(&blob).unwrap(),[0x64;16]);
    }
    #[test]
    fn unavailable_or_new_source_bytes_never_claim_compiled_shader_abi(){
        assert!(parse_vcs2_header(b"vcs2","ps").is_err());
        let mut bytes=vec![0u8;64];bytes[0..4].copy_from_slice(b"vcs2");
        bytes[4..8].copy_from_slice(&70u32.to_le_bytes());
        assert!(parse_vcs2_header(&bytes,"ps").is_err());
        bytes[4..8].copy_from_slice(&69u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        assert!(parse_vcs2_header(&bytes,"ps").is_err());
        assert!(parse_vcs2_header(&[0;64],"ps").is_err());
    }
}
