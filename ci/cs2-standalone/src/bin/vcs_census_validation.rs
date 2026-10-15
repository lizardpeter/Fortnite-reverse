//! Audit original Valve VCS Resource headers in the recovered Vulkan corpus.
use std::{fs::File,io::Read,path::Path};
use std::collections::{BTreeMap,BTreeSet};
use cs2_importer::{vcs::{self,VcsCensus,VcsSource},vcs_selection,material::Material};
fn main()->Result<(),String>{
 let root=std::env::var("CS2_NATIVE_CORPUS")
    .map_err(|e|format!("original VCS corpus path unset: {e}"))?;
 let root=Path::new(&root);
 let shader_families=[
    "csgo_complex","csgo_effects","csgo_foliage",
    "csgo_lightmappedgeneric","csgo_vertexlitgeneric"
 ];
 let mut census=VcsCensus::default();
 let mut per_family=BTreeMap::<String,(usize,usize)>::new();
 for family in shader_families {
    for stage in ["features","vs","ps","psrs"]{
        let name=format!("{family}_vulkan_50_{stage}.vcs");
        let path=root.join(&name);
        let mut file=File::open(&path).map_err(|e|format!("missing original {name}: {e}"))?;
        let mut prefix=[0u8;4];
        file.read_exact(&mut prefix).map_err(|e|e.to_string())?;
        let declared=u32::from_le_bytes(prefix) as usize;
        if !(16..=32*1024*1024).contains(&declared) {
            return Err(format!("{name}: invalid compiler Resource bound {declared}"));
        }
        let mut source=vec![0u8;declared];
        source[..4].copy_from_slice(&prefix);
        file.read_exact(&mut source[4..]).map_err(|e|format!("{name}: {e}"))?;
        let identity=vcs::parse_vcs_filename(&name)
            .ok_or_else(||format!("invalid stage identity {name}"))?;
        let (header,error)=match vcs::parse_vcs_resource_header(&source,stage){
            Ok(header)=>(Some(header),None),
            Err(error)=>(None,Some(error)),
        };
        if let Some(h)=&header {
            if stage!="features" && h.program_hashes.is_empty() {
                return Err(format!("{name}: missing authored program hashes"));
            }
            if h.program_hashes.len()>4096 {
                return Err(format!("{name}: excessive original compiler hashes"));
            }
        }
        println!("ORIGINAL_VCS_RESOURCE_CENSUS {name} metadata={declared} parsed={} hashes={} error={:?}",
            header.is_some(),header.as_ref().map_or(0,|h|h.program_hashes.len()),error);
        census.files_listed+=1;
        if header.is_some(){census.verified_headers+=1}else{census.unsupported_headers+=1}
        census.sources.push(VcsSource{
            identity,path:name.clone(),origin:"exact Valve Vulkan binary",
            header,error,
        });
        let count=per_family.entry(family.to_owned()).or_default();
        count.0+=1;
        if census.sources.last().unwrap().header.is_some(){count.1+=1}
    }
 }
 if census.verified_headers<19 || census.files_listed!=20 {
    return Err(format!("expected >=19 recovered source VCS headers; got {}/{}; remaining errors {:?}",
        census.verified_headers,census.files_listed,
        census.sources.iter().filter_map(|s|s.error.as_ref().map(|e|format!("{}: {e}",s.path))).collect::<Vec<_>>()));
 }
 let mut pair_families=BTreeSet::new();
 for family in shader_families {
    let vm=Material {
        path:format!("materials/original-{family}.vmat_c"),
        material_name:"verified fixture".into(),
        shader:format!("{family}.vfx"),
        textures:BTreeMap::new(),scalars:BTreeMap::new(),
        switches:BTreeMap::new(),unresolved_texture_files:Vec::new(),
    };
    let candidate=vcs_selection::material_candidates(&vm,&census);
    if !candidate.pairs.is_empty(){pair_families.insert(family.to_owned());}
    println!("ORIGINAL_VCS_STAGE_PAIRS {family} candidates={} closed_static={}",
        candidate.pairs.len(),candidate.pairs.iter().filter(|p|p.static_values_closed()).count());
 }
 if pair_families.len()<4 {
    return Err(format!("expected >=4 actual Source2 VS/PS ABI-compatible families, got {pair_families:?}"));
 }
 println!("CERTIFIED_ORIGINAL_VCS_CENSUS {} / {} readable; {} VS/PS ABI-compatible families {:?}; runtime material admission still 0",
    census.verified_headers,census.files_listed,pair_families.len(),pair_families);
 Ok(())
}
