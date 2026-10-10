//! Source-authenticated recursive extraction of Fortnite 5.41 original
//! Athena terrain material functions and texture dependencies from an
//! operator-owned retail PAK. NO substitutes, no network, no game execution.
use crate::{extract,pak,material,uobject};
use sha1::{Digest,Sha1};
use std::{collections::{BTreeMap,BTreeSet},env,fs,io::Write,path::{Component,Path,PathBuf}};

const ORIGINAL_PAK_BYTES:u64=4_813_653_874;
const ORIGINAL_INDEX_SHA1:&str="fd1f4623c812f5fff47298f99cc3d0d8f2d0f11b";
const HISTORICAL_KEY:&str="81C42E03B21760A5C457C8DB7D52BA066F0633D0891FD9E37CF118F27687924A";
const MAX_PACKAGES:usize=256;
const MAX_BYTES:u64=256*1024*1024;
const ORIGINAL_TERRAIN_MATERIALS:[&str;4]=[
    "FortniteGame/Content/Athena/Environments/Landscape/Material/M_Athena_Terrain_01",
    "FortniteGame/Content/Athena/Environments/Landscape/Material/M_Athena_Terrain_Master",
    "FortniteGame/Content/Athena/Environments/Landscape/Material/M_Athena_Terrain_01_Masked",
    "FortniteGame/Content/Athena/Environments/Landscape/Material/M_Athena_Terrain_01_NoAridRock",
];
#[derive(Debug,Default)]
pub struct MaterialExtraction {
    pub source_packages:usize,
    pub authenticated_files:usize,
    pub new_files:usize,
    pub total_source_bytes:u64,
    pub unresolved_packages:BTreeSet<String>,
    pub unresolved_non_game_objects:BTreeSet<String>,
    pub inspected_material_expression_nodes:usize,
}
/// Convert a source-identified UObject path to its exact local Unreal package
/// identity without heuristics, path traversal or guessed naming.
pub fn source_game_package(object_path:&str)->Option<String>{
    let pkg=object_path.split("::").next()?;
    let game=pkg.strip_prefix("/Game/")?;
    if game.len()>512||game.is_empty()||
        game.split('/').any(|p|p.is_empty()||p=="."||p==".."||p.contains('\\')||p.contains(':')) {
        return None;
    }
    Some(format!("FortniteGame/Content/{game}"))
}
fn original_index<'a>(entries:&'a [pak::PakEntry],name:&str)->Option<&'a pak::PakEntry>{
    entries.iter().find(|e|e.path==name)
}
fn verified_cache_write(destination:&Path,entry:&pak::PakEntry,bytes:&[u8])->Result<bool,String>{
    let path=Path::new(&entry.path);
    if !entry.path.starts_with("FortniteGame/Content/")||
        !path.components().all(|c|matches!(c,Component::Normal(_))) {
        return Err(format!("unsafe original source path {}",entry.path));
    }
    let target=destination.join(path);
    if target.exists(){
        let metadata=fs::symlink_metadata(&target).map_err(|e|format!("source cache stat: {e}"))?;
        if !metadata.file_type().is_file(){return Err(format!("not a file: {}",target.display()));}
        let cached=fs::read(&target).map_err(|e|format!("read original cache: {e}"))?;
        if cached.len()!=bytes.len()||Sha1::digest(&cached).as_slice()!=entry.content_hash{
            return Err(format!("source cache is not the authenticated original: {}",target.display()));
        }
        return Ok(false);
    }
    if let Some(parent)=target.parent(){fs::create_dir_all(parent).map_err(|e|format!("source mkdir: {e}"))?;}
    let tmp=target.with_extension(format!("{}.part",target.extension().and_then(|s|s.to_str()).unwrap_or("data")));
    let mut file=fs::OpenOptions::new().write(true).create_new(true).open(&tmp)
        .map_err(|e|format!("original source temporary file: {e}"))?;
    file.write_all(bytes).map_err(|e|format!("source material write: {e}"))?;
    file.sync_all().map_err(|e|format!("source material sync: {e}"))?;
    fs::rename(&tmp,&target).map_err(|e|format!("source material commit: {e}"))?;
    Ok(true)
}
pub fn prepare_original_athena_materials(pak_path:&Path,dest:&Path)->Result<MaterialExtraction,String>{
    let key=extract::parse_aes_key(&env::var("RUST_TEST_FORTNITE_541_AES_KEY")
        .unwrap_or_else(|_|HISTORICAL_KEY.into()))?;
    let report=pak::inspect_with_key(pak_path,&key)?;
    if report.file_size!=ORIGINAL_PAK_BYTES||report.footer.version!=7||
        report.footer.index_hash.iter().map(|b|format!("{b:02x}")).collect::<String>()!=ORIGINAL_INDEX_SHA1 {
        return Err("not authenticated original Fortnite 5.41 main PAK".into());
    }
    let pak::IndexStatus::Indexed{entries,..}=&report.status else{
        return Err("original Fortnite 5.41 source index unavailable".into());
    };
    let mut report_out=MaterialExtraction::default();
    let mut pending=ORIGINAL_TERRAIN_MATERIALS.iter().map(|s|s.to_string()).collect::<BTreeSet<_>>();
    let mut visited=BTreeSet::<String>::new();
    while let Some(package)=pending.pop_first(){
        if !visited.insert(package.clone()){continue;}
        if visited.len()>MAX_PACKAGES {return Err("Athena original material dependency graph exceeds 256 unique source packages".into());}
        let Some(header)=original_index(entries,&format!("{package}.uasset")) else {
            report_out.unresolved_packages.insert(package);
            continue;
        };
        let Some(export)=original_index(entries,&format!("{package}.uexp")) else {
            report_out.unresolved_packages.insert(package);
            continue;
        };
        if [header,export].iter().any(|e|e.encrypted ||e.compression_method!=0 ||e.compressed_size!=e.uncompressed_size) {
            report_out.unresolved_packages.insert(package);
            continue;
        }
        let mut fetched=Vec::with_capacity(3);
        for entry in [header,export] {
            if entry.uncompressed_size>64*1024*1024||
                report_out.total_source_bytes+entry.uncompressed_size>MAX_BYTES{
                return Err("source material extraction exceeds authenticated file/total byte limits".into());
            }
            let bytes=pak::extract_plain_entry(pak_path,&report,entry)?;
            report_out.total_source_bytes+=entry.uncompressed_size;
            fetched.push((entry,bytes));
        }
        if let Some(bulk)=original_index(entries,&format!("{package}.ubulk")) {
            if !bulk.encrypted &&bulk.compression_method==0 &&bulk.compressed_size==bulk.uncompressed_size {
                if bulk.uncompressed_size>64*1024*1024||report_out.total_source_bytes+bulk.uncompressed_size>MAX_BYTES{
                    return Err("original source material ubulk exceeds bounded extraction".into());
                }
                let bytes=pak::extract_plain_entry(pak_path,&report,bulk)?;
                report_out.total_source_bytes+=bulk.uncompressed_size;
                fetched.push((bulk,bytes));
            } else {
                // Explicitly surface a source format gap rather than replacing
                // authored texture bulk content with a guessed image.
                report_out.unresolved_packages.insert(format!("{package}.ubulk"));
            }
        }
        if package.contains("/MaterialFunctions/")||package.contains("/Material/M_Athena_Terrain_") {
            let header_data=&fetched[0].1;
            let export_data=&fetched[1].1;
            let catalog=uobject::inspect(header_data)?;
            let graph=material::inspect(&catalog,header_data,export_data);
            if !graph.unresolved.is_empty() {
                return Err(format!("original material function source {} contains unsupported direct graph nodes {:?}",package,graph.unresolved));
            }
            report_out.inspected_material_expression_nodes+=graph.expressions.len();
            for dep in graph.external_dependencies{
                match source_game_package(&dep) {
                    Some(path)=>{if !visited.contains(&path){pending.insert(path);}},
                    None=>{report_out.unresolved_non_game_objects.insert(dep);}
                }
            }
        }
        for (entry,bytes) in fetched {
            if verified_cache_write(dest,entry,&bytes)?{report_out.new_files+=1;}
            report_out.authenticated_files+=1;
        }
        report_out.source_packages+=1;
    }
    Ok(report_out)
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn source_paths_never_escape_original_game_package_namespace(){
        assert_eq!(source_game_package("/Game/Athena/Material/Grass::Grass"),Some("FortniteGame/Content/Athena/Material/Grass".into()));
        assert!(source_game_package("/Script/Engine::Texture2D").is_none());
        assert!(source_game_package("/Game/../Private::Private").is_none());
        assert!(source_game_package("/Game/foo\\bar::bar").is_none());
    }
}
