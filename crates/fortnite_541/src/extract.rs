//! Native, source-authenticated preparation of original Fortnite 5.41
//! Athena terrain packages from an operator-owned LOCAL pak file.
//! No online fetch, no game execution, and no heuristic source stand-ins.
use crate::pak::{self,IndexStatus};
use sha1::{Digest,Sha1};
use std::{env,fs,io::Write,path::{Component,Path}};

const RETAIL_541_MAIN_PAK_SIZE:u64=4_813_653_874;
const RETAIL_541_INDEX_SHA1:&str="fd1f4623c812f5fff47298f99cc3d0d8f2d0f11b";
const HISTORICAL_541_KEY:&str="81C42E03B21760A5C457C8DB7D52BA066F0633D0891FD9E37CF118F27687924A";

pub fn parse_aes_key(hex:&str)->Result<[u8;32],String>{
    let hex=hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len()!=64||!hex.bytes().all(|c|c.is_ascii_hexdigit()){
        return Err("Fortnite 5.41 source AES key must contain 64 hexadecimal digits".into());
    }
    let mut bytes=[0u8;32];
    for i in 0..32 {
        bytes[i]=u8::from_str_radix(&hex[i*2..i*2+2],16)
            .map_err(|_|"invalid Fortnite 5.41 AES hexadecimal key")?;
    }
    Ok(bytes)
}
fn original_key()->Result<[u8;32],String>{
    parse_aes_key(&env::var("RUST_TEST_FORTNITE_541_AES_KEY")
        .unwrap_or_else(|_|HISTORICAL_541_KEY.to_owned()))
}

/// The exact retail 5.41 PakFile names whose decoded UObjects the terrain
/// scene builder consumes. Never attempt to extract arbitrary user paths.
fn desired_paths()->Vec<String>{
    let mut paths=vec![
        "/Maps/Athena_Terrain.umap".to_owned(),
        "/Maps/Athena_Terrain.uexp".to_owned(),
        "/Maps/Streaming/Sublevel_X0Y0.umap".to_owned(),
        "/Maps/Streaming/Sublevel_X0Y0.uexp".to_owned(),
        "/Maps/Background/Athena_Background.umap".to_owned(),
        "/Maps/Background/Athena_Background.uexp".to_owned(),
    ];
    for section in 0..6 {
        for ext in ["umap","uexp","ubulk"]{
            paths.push(format!("/Maps/Landscape/Athena_Terrain_LS_{section:02}.{ext}"));
        }
    }
    paths
}

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub struct PreparedLandscape {
    pub verified_files:usize,
    pub extracted_files:usize,
    pub bytes_extracted:u64,
}

/// From the full original local 5.41 pak, extract only the 24 exactly
/// referenced map package files, verifying the encrypted index, entry
/// metadata and SHA-1 of every byte, including any previously cached files.
/// All outputs remain in the ignored local work directory.
pub fn prepare_local_athena(
    pak_path:&Path,destination:&Path
)->Result<PreparedLandscape,String>{
    if !pak_path.is_file(){
        return Err(format!("original local Fortnite 5.41 pak not found: {}",pak_path.display()));
    }
    let report=pak::inspect_with_key(pak_path,&original_key()?)?;
    if report.file_size!=RETAIL_541_MAIN_PAK_SIZE||
        report.footer.version!=7||
        report.footer.index_hash.iter().map(|byte|format!("{byte:02x}")).collect::<String>()!=RETAIL_541_INDEX_SHA1 {
        return Err("local pak does not match the authenticated original 5.41 WindowsClient archive".into());
    }
    let IndexStatus::Indexed{entries,..}=&report.status else {
        return Err("local 5.41 pak encrypted index is not decoded".into());
    };
    let mut extracted=0usize;
    let mut total_bytes=0u64;
    for suffix in desired_paths(){
        let mut matches=entries.iter().filter(|entry|entry.path.ends_with(&suffix));
        let entry=matches.next().ok_or_else(||
            format!("original Fortnite 5.41 pak is missing source record {suffix}"))?;
        if matches.next().is_some(){
            return Err(format!("source pak has ambiguous original filename {suffix}"));
        }
        let relative=Path::new(&entry.path);
        if !entry.path.starts_with("FortniteGame/Content/Athena/")||
            !relative.components().all(|component|matches!(component,Component::Normal(_))){
            return Err(format!("unsafe or unexpected authenticated source path {}",entry.path));
        }
        let output=destination.join(relative);
        if output.exists() {
            let meta=fs::symlink_metadata(&output)
                .map_err(|e|format!("stat existing Athena source {}: {e}",output.display()))?;
            if !meta.file_type().is_file() {
                return Err(format!("existing Athena source path is not a regular file: {}",output.display()));
            }
            if meta.len()!=entry.uncompressed_size {
                return Err(format!("cached Athena package {} has wrong length; remove or relocate it",output.display()));
            }
            let bytes=fs::read(&output)
                .map_err(|e|format!("read previously extracted Athena source {}: {e}",output.display()))?;
            if Sha1::digest(&bytes).as_slice()!=entry.content_hash{
                return Err(format!("cached Athena package {} fails original-source SHA-1; remove or relocate it",output.display()));
            }
        }else{
            let bytes=pak::extract_plain_entry(pak_path,&report,entry)?;
            if bytes.len() as u64!=entry.uncompressed_size{
                return Err(format!("original source byte count differs for {}",entry.path));
            }
            if let Some(parent)=output.parent(){
                fs::create_dir_all(parent).map_err(|e|
                    format!("create Athena source output {}: {e}",parent.display()))?;
            }
            let temporary=output.with_extension(format!(
                "{}.part",output.extension().and_then(|e|e.to_str()).unwrap_or("bin")
            ));
            if temporary.exists(){return Err(format!("stale temporary Athena source output: {}",temporary.display()));}
            let mut writer=fs::OpenOptions::new().create_new(true).write(true).open(&temporary)
                .map_err(|e|format!("create temporary source {}: {e}",temporary.display()))?;
            writer.write_all(&bytes)
                .map_err(|e|format!("write authenticated source {}: {e}",temporary.display()))?;
            writer.sync_all().map_err(|e|format!("sync authenticated source: {e}"))?;
            fs::rename(&temporary,&output)
                .map_err(|e|format!("commit authenticated Athena source {}: {e}",output.display()))?;
            extracted+=1;
            total_bytes+=entry.uncompressed_size;
        }
    }
    Ok(PreparedLandscape{
        verified_files:desired_paths().len(),
        extracted_files:extracted,bytes_extracted:total_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn always_exactly_24_expected_terrain_files(){
        let p=desired_paths();
        assert_eq!(p.len(),24);
        assert!(p.contains(&"/Maps/Landscape/Athena_Terrain_LS_05.ubulk".into()));
        assert_eq!(p.iter().collect::<std::collections::BTreeSet<_>>().len(),24);
    }
    #[test] fn key_parsing_rejects_invalid(){
        assert_eq!(parse_aes_key(HISTORICAL_541_KEY).unwrap().len(),32);
        assert!(parse_aes_key("abcd").is_err());
        assert!(parse_aes_key(&"z".repeat(64)).is_err());
    }
}

/// Prepare the original Fortnite BR time-of-day package from its AUTHENTICATED
/// s4 retail archive. The source 5.41 main PAK does not contain this package.
/// These files remain in the ignored source cache; map admission discovers
/// the split archive automatically next to the already-discovered main PAK.
pub fn prepare_original_todm_br(main_pak:&Path,destination:&Path)->Result<PreparedLandscape,String>{
    const S4_INDEX_SHA1:&str="96a67f9eae257051576e368fdb61a6fb78b2f56a";
    const PREFIX:&str="FortniteGame/Content/TimeOfDay/TODM/BR/TODM_BR";
    let archive=main_pak.with_file_name("pakchunk0_s4-WindowsClient.pak");
    let report=pak::inspect_with_key(&archive,&original_key()?)?;
    if report.footer.version!=7 ||
        report.footer.index_hash.iter().map(|v|format!("{v:02x}")).collect::<String>()!=S4_INDEX_SHA1 {
        return Err("original Fortnite 5.41 s4 time-of-day PAK index SHA1 mismatch".into());
    }
    let IndexStatus::Indexed{entries,..}=&report.status else {
        return Err("original Fortnite split s4 source index not decoded".into());
    };
    let mut count=0;
    let mut bytes_new=0;
    for extension in [".uasset",".uexp"] {
        let suffix=format!("TimeOfDay/TODM/BR/TODM_BR{extension}");
        let mut found=entries.iter().filter(|p|p.path.replace('\\',"/").ends_with(&suffix));
        let entry=found.next().ok_or_else(||format!("missing original TODM asset {suffix}"))?;
        if found.next().is_some(){return Err(format!("ambiguous original TODM asset {suffix}"));}
        let output=destination.join(format!("{PREFIX}{extension}"));
        let original=pak::extract_plain_entry(&archive,&report,entry)?;
        if let Some(parent)=output.parent(){
            fs::create_dir_all(parent).map_err(|e|format!("original source cache directory: {e}"))?;
        }
        if output.exists(){
            let cached=fs::read(&output).map_err(|e|format!("read existing original TODM: {e}"))?;
            if cached!=original{
                return Err(format!("cached original TODM asset failed original source SHA1: {}",output.display()));
            }
        }else{
            let tmp=output.with_extension(format!("{}-auth.part",
                output.extension().and_then(|s|s.to_str()).unwrap_or("bin")));
            if tmp.exists(){return Err(format!("stale original TODM temporary file: {}",tmp.display()));}
            let mut file=fs::OpenOptions::new().create_new(true).write(true).open(&tmp)
                .map_err(|e|format!("create source TODM temp: {e}"))?;
            file.write_all(&original).map_err(|e|format!("write original TODM: {e}"))?;
            file.sync_all().map_err(|e|format!("sync original TODM: {e}"))?;
            fs::rename(&tmp,&output).map_err(|e|format!("commit original TODM cache: {e}"))?;
            count+=1;
            bytes_new+=original.len() as u64;
        }
    }
    Ok(PreparedLandscape{verified_files:2,extracted_files:count,bytes_extracted:bytes_new})
}

/// A source-verified split PAK, plus the exact original cooked package paths.
/// Source 5.41 optional archives are *not* interchangeable with the main PAK:
/// mount points differ, and each encrypted index has its own original SHA-1.
const ORIGINAL_ENVIRONMENT_ARCHIVES:[(&str,&str,&[(&str,&[&str])]);4]=[
    ("pakchunk0-WindowsClient.pak",
     "fd1f4623c812f5fff47298f99cc3d0d8f2d0f11b",
     &[("Athena/Prototype/Terrain/LF_AthenaClouds_Inst",&[".uasset",".uexp"])]),
    ("pakchunk0_s2-WindowsClient.pak",
     "42a45eee280ab70abbb5192b33a5945c119bd82c",
     &[
       ("ContentCreationTools/TextureCreation/Textures/T_BPCreated_MacroNormal_01",&[".uasset",".uexp",".ubulk"]),
       ("Environments/AutumnDecay/Terrain/Textures/T_Grass_AD_D",&[".uasset",".uexp",".ubulk"]),
     ]),
    ("pakchunk0_s3-WindowsClient.pak",
     "27376dab8f8a3488d0d2b5332a2a2da7d28fd73e",
     &[("Environments/World/Backgrounds/Transylvania/Meshes/TRV_Skybox_Mountain_04",&[".uasset",".uexp"])]),
    ("pakchunk0_s4-WindowsClient.pak",
     "96a67f9eae257051576e368fdb61a6fb78b2f56a",
     &[
       ("TimeOfDay/TODM/BR/TODM_BR",&[".uasset",".uexp"]),
       ("Packages/Fortress_Sky/TexturesHDR/T_AthenaSkylight",&[".uasset",".uexp"]),
       ("Packages/Fortress_Sky/SkyDome/MaterialInstances/SkyDomeBasic01/Morn_M_SkyDome_Inst_Basic01",&[".uasset",".uexp"]),
       ("Packages/Fortress_Sky/SkyDome/MaterialInstances/SkyDomeBasic01/Day_M_SkyDome_Inst_Basic01",&[".uasset",".uexp"]),
       ("Packages/Fortress_Sky/SkyDome/MaterialInstances/SkyDomeBasic01/Eve_M_SkyDome_Inst_Basic01",&[".uasset",".uexp"]),
       ("Packages/Fortress_Sky/SkyDome/MaterialInstances/SkyDomeBasic01/Night_M_SkyDome_Inst_Basic01",&[".uasset",".uexp"]),
     ]),
];

/// Recover the exact original environment and missing terrain material source
/// packages from every available user-owned 5.41 split PAK into the local
/// ignored source directory. The importer invokes this during map selection,
/// not in the game frame loop. Absent optional split archives remain explicit;
/// present archives must match their original SHA1 or fail closed.
pub fn prepare_original_environment_sources(
    main_pak:&Path,destination:&Path,
)->Result<PreparedLandscape,String>{
    let key=original_key()?;
    let mut ready=0usize;
    let mut extracted=0usize;
    let mut bytes_new=0u64;
    for &(archive_name,index_sha1,packages) in &ORIGINAL_ENVIRONMENT_ARCHIVES{
        let archive=main_pak.with_file_name(archive_name);
        if !archive.is_file(){continue;}
        let report=pak::inspect_with_key(&archive,&key)?;
        if report.footer.version!=7 ||
            report.footer.index_hash.iter().map(|b|format!("{b:02x}")).collect::<String>()!=index_sha1 {
            return Err(format!("original Fortnite source environment archive {archive_name} has mismatched authenticated SHA1 index"));
        }
        let IndexStatus::Indexed{entries,..}=&report.status else{
            return Err(format!("could not decode original 5.41 environment index for {archive_name}"));
        };
        for &(package,extensions) in packages {
            for &ext in extensions {
                let suffix=format!("{package}{ext}");
                let mut matches=entries.iter().filter(|e|e.path.replace('\\',"/").ends_with(&suffix));
                let original=matches.next().ok_or_else(||format!("original environment archive {archive_name} lacks {suffix}"))?;
                if matches.next().is_some(){
                    return Err(format!("ambiguous source environment asset {suffix} in {archive_name}"));
                }
                let output=destination.join("FortniteGame/Content").join(&suffix);
                if let Some(parent)=output.parent(){
                    fs::create_dir_all(parent).map_err(|e|format!("create original source cache: {e}"))?;
                }
                if output.exists(){
                    let meta=fs::symlink_metadata(&output).map_err(|e|format!("source asset stat: {e}"))?;
                    if !meta.file_type().is_file(){return Err(format!("original source cache not regular file: {}",output.display()));}
                    let cached=fs::read(&output).map_err(|e|format!("source asset cache read: {e}"))?;
                    if cached.len() as u64!=original.uncompressed_size||
                        Sha1::digest(&cached).as_slice()!=original.content_hash {
                        return Err(format!("cached original source asset is not verified: {}",output.display()));
                    }
                } else {
                    let bytes=pak::extract_plain_entry(&archive,&report,original)?;
                    let tmp=output.with_extension(format!("{}-auth.part",ext.trim_start_matches('.')));
                    if tmp.exists(){return Err(format!("stale original source temp file: {}",tmp.display()));}
                    let mut file=fs::OpenOptions::new().create_new(true).write(true).open(&tmp)
                        .map_err(|e|format!("original source temp create: {e}"))?;
                    file.write_all(&bytes).map_err(|e|format!("write original source: {e}"))?;
                    file.sync_all().map_err(|e|format!("sync original source: {e}"))?;
                    fs::rename(&tmp,&output).map_err(|e|format!("commit original source file: {e}"))?;
                    extracted+=1;
                    bytes_new+=bytes.len() as u64;
                }
                ready+=1;
            }
        }
    }
    Ok(PreparedLandscape{verified_files:ready,extracted_files:extracted,bytes_extracted:bytes_new})
}
#[cfg(test)]
mod environment_tests {
    use super::*;
    #[test]fn recovered_environment_has_22_exact_source_files(){
        let all=ORIGINAL_ENVIRONMENT_ARCHIVES.iter()
            .flat_map(|(_,_,p)|p.iter().flat_map(|(_,exts)|exts.iter())).count();
        assert_eq!(all,22);
        assert_eq!(ORIGINAL_ENVIRONMENT_ARCHIVES.len(),4);
    }
}
