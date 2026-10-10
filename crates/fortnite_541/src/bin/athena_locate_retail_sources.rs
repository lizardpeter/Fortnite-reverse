//! Search original operator-owned Fortnite 5.41 PAK indexes for missing
//! source lighting, skybox mesh, and terrain material assets. The archives'
//! own SHA1 authenticated indexes are verified; no fabricated source data,
//! network calls, or map-rendering side effects. Use local original install.
use std::{collections::{BTreeMap,BTreeSet},env,fs,path::{Path,PathBuf},process::ExitCode};
use fortnite_541_importer::{extract,locate_source_root,pak};
const ORIGINAL_DEPS:&[&str]=&[
 "FortniteGame/Content/TimeOfDay/TODM/BR/TODM_BR",
 "FortniteGame/Content/Environments/World/Backgrounds/Transylvania/Meshes/TRV_Skybox_Mountain_04",
 "FortniteGame/Content/ContentCreationTools/TextureCreation/Textures/T_BPCreated_MacroNormal_01",
 "FortniteGame/Content/Environments/AutumnDecay/Terrain/Textures/T_Grass_AD_D",
];
fn run()->Result<(),String>{
    let root=if let Some(arg)=env::args_os().nth(1){PathBuf::from(arg)}
        else{locate_source_root().ok_or("cannot find owned Fortnite 5.41 install; pass its root path")?};
    if !root.join("FortniteGame").is_dir()||!root.join("Engine").is_dir(){
        return Err(format!("{} is not the original Fortnite installation root",root.display()));
    }
    let key=extract::parse_aes_key(&env::var("RUST_TEST_FORTNITE_541_AES_KEY").unwrap_or_else(|_|"81C42E03B21760A5C457C8DB7D52BA066F0633D0891FD9E37CF118F27687924A".into()))?;
    let mut archives=BTreeSet::<PathBuf>::new();
    for directory in [root.join("FortniteGame/Content/Paks"),root.join("Engine/Content/Paks")] {
        if !directory.is_dir(){continue;}
        for item in fs::read_dir(directory).map_err(|e|format!("source archive list: {e}"))? {
            let item=item.map_err(|e|format!("source archive entry: {e}"))?;
            if !item.file_type().map_err(|e|format!("source archive stat: {e}"))?.is_file(){continue;}
            let path=item.path();
            if path.extension().is_some_and(|ext|ext.eq_ignore_ascii_case("pak")){archives.insert(path);}
            if archives.len()>128 {return Err("refusing to scan >128 original source PAK files".into());}
        }
    }
    if archives.is_empty(){return Err("no original PAK files in source FortniteGame/Content/Paks or Engine/Content/Paks".into());}
    let mut found=BTreeMap::<String,Vec<(String,u64,u64,u32,bool)>>::new();
    let mut inspected=0usize;
    for archive in archives {
        let report=match pak::inspect_with_key(&archive,&key){
            Ok(v)=>v,
            Err(e)=>{
                println!("AUTHENTICATED_PAK_SCAN_UNSUPPORTED archive={} reason={e}",archive.display());
                continue;
            }
        };
        let pak::IndexStatus::Indexed{entries,..}=&report.status else{
            println!("AUTHENTICATED_PAK_SCAN_INDEX_UNSUPPORTED archive={}",archive.display());
            continue;
        };
        inspected+=1;
        println!("AUTHENTICATED_PAK_INDEX archive={} version={} file_bytes={} entries={}",
            archive.display(),report.footer.version,report.file_size,entries.len());
        for original in ORIGINAL_DEPS{
            for ext in [".uasset",".uexp",".ubulk"]{
                let exact=format!("{original}{ext}");
                // The asset path comes from Unreal's cooked FPackageIndex and
                // SoftObjectPath; retain source archive identity, don't guess.
                for entry in entries.iter().filter(|record|record.path==exact){
                    found.entry(exact.clone()).or_default().push((
                        archive.display().to_string(),
                        entry.offset,entry.uncompressed_size,
                        entry.compression_method,entry.encrypted,
                    ));
                }
            }
        }
    }
    for (path,records) in &found {
        for (archive,offset,bytes,compression,encrypted) in records {
            println!("ORIGINAL_FORTNITE_SOURCE_FOUND file={path} archive={archive} archive_offset={offset} source_unpacked_bytes={bytes} compression={compression} encrypted={encrypted}");
        }
    }
    for original in ORIGINAL_DEPS {
        let missing=[".uasset",".uexp"].iter()
            .filter(|ext|!found.contains_key(&format!("{original}{ext}"))).collect::<Vec<_>>();
        if !missing.is_empty(){
            println!("ORIGINAL_FORTNITE_SOURCE_MISSING original_package={original} extensions={missing:?}");
        }
    }
    println!("ORIGINAL_FORTNITE_SOURCE_INDEX_CENSUS inspected_paks={inspected} found_source_entries={} unique_original_targets={}",
        found.values().map(Vec::len).sum::<usize>(),ORIGINAL_DEPS.len());
    Ok(())
}
fn main()->ExitCode{match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("ORIGINAL_FORTNITE_ASSET_LOCATOR_FAILED: {e}");ExitCode::FAILURE}}}
