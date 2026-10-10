//! Exact Fortnite 5.41 original master-terrain material function/package
//! dependency census. Source-only, no renderer shader guesses.
//!
//! With the original local PAK, verifies the authentic encrypted index and
//! reports whether each referenced original material package is available,
//! compressed, encrypted, or missing from pakchunk0. No content is extracted.
use std::{collections::{BTreeMap,BTreeSet},env,fs,path::PathBuf,process::ExitCode};
use fortnite_541_importer::{material,pak,extract,uobject};

fn raw_material_package(path:&str)->Option<String>{
    let package=path.split("::").next()?;
    let suffix=package.strip_prefix("/Game/")?;
    if suffix.is_empty()||suffix.split('/').any(|part|part.is_empty()||part=="."||part=="..") {
        return None;
    }
    Some(format!("FortniteGame/Content/{suffix}"))
}
fn run()->Result<(),String>{
    let mut args=env::args_os().skip(1);
    let root=PathBuf::from(args.next().ok_or("usage: athena_material_dependencies ORIGINAL_SOURCE_ROOT [ORIGINAL_MAIN_PAK]")?);
    let base=root.join("FortniteGame/Content/Athena/Environments/Landscape/Material/M_Athena_Terrain_Master");
    let uasset=fs::read(base.with_extension("uasset")).map_err(|e|format!("original master material .uasset: {e}"))?;
    let uexp=fs::read(base.with_extension("uexp")).map_err(|e|format!("original master material .uexp: {e}"))?;
    let catalog=uobject::inspect(&uasset)?;
    let graph=material::inspect(&catalog,&uasset,&uexp);
    if !graph.unresolved.is_empty(){return Err(format!("original master material exports unresolved: {:?}",graph.unresolved));}
    if graph.expressions.len()!=271 {return Err(format!("expected 271 source-authenticated master expression nodes; got {}",graph.expressions.len()));}
    let mut packages=BTreeSet::new();
    let mut external_non_game=BTreeSet::new();
    let mut paths=BTreeMap::<String,Vec<String>>::new();
    for object in &graph.external_dependencies {
        match raw_material_package(object){
            Some(file)=>{
                packages.insert(file.clone());
                paths.entry(file).or_default().push(object.clone());
            },
            None=>{external_non_game.insert(object.clone());}
        }
    }
    println!("ATHENA_MASTER_MATERIAL_DISCOVERY nodes={} external_object_refs={} game_source_packages={} other_object_refs={} unresolved={}",
        graph.expressions.len(),graph.external_dependencies.len(),
        packages.len(),external_non_game.len(),graph.unresolved.len());
    for (package,objects) in &paths {
        println!("ATHENA_MASTER_DEP_PACKAGE {} source_objects={objects:?}",package);
    }
    for object in &external_non_game {
        println!("ATHENA_MASTER_NON_GAME_IMPORT {object}");
    }

    if let Some(archive)=args.next(){
        let key=extract::parse_aes_key(&env::var("RUST_TEST_FORTNITE_541_AES_KEY")
            .unwrap_or_else(|_|"81C42E03B21760A5C457C8DB7D52BA066F0633D0891FD9E37CF118F27687924A".into()))?;
        let report=pak::inspect_with_key(&PathBuf::from(archive),&key)?;
        if report.file_size!=4_813_653_874||report.footer.version!=7||
            report.footer.index_hash.iter().map(|b|format!("{b:02x}")).collect::<String>()
                !="fd1f4623c812f5fff47298f99cc3d0d8f2d0f11b"{
            return Err("source PAK index does not identify authenticated 5.41 WindowsClient archive".into());
        }
        let pak::IndexStatus::Indexed{entries,..}=report.status else{
            return Err("cannot resolve original source PAK index".into());
        };
        let index=BTreeMap::from_iter(entries.iter().map(|e|(e.path.as_str(),e)));
        let mut complete=0usize;let mut missing=0usize;let mut unsupported=0usize;
        let mut total_bytes=0u64;
        for path in &packages {
            let mut missing_ext=Vec::new();
            let mut entries_ok=Vec::new();
            for ext in [".uasset",".uexp"] {
                let file=format!("{path}{ext}");
                match index.get(file.as_str()){
                    Some(p) if !p.encrypted && p.compression_method==0 && p.compressed_size==p.uncompressed_size=>{
                        entries_ok.push((file,p.uncompressed_size));
                        total_bytes+=p.uncompressed_size;
                    },
                    Some(p)=>{
                        unsupported+=1;
                        println!("ATHENA_MASTER_DEP_UNSUPPORTED file={file} compression={} encrypted={} compressed_bytes={} unpacked={}",
                            p.compression_method,p.encrypted,p.compressed_size,p.uncompressed_size);
                    },
                    None=>{missing_ext.push(file);}
                }
            }
            if !missing_ext.is_empty(){
                missing+=1;
                println!("ATHENA_MASTER_DEP_MISSING package={path} missing={missing_ext:?}");
            } else if entries_ok.len()==2{
                complete+=1;
                println!("ATHENA_MASTER_DEP_ARCHIVE_READY package={path} uncompressed={entries_ok:?}");
            }
        }
        println!("ATHENA_MASTER_PAK_CENSUS game_packages={} complete_uncompressed={} missing_package_records={} unsupported_entry_records={} ready_bytes={} (header-only metadata, no asset extraction)",
            packages.len(),complete,missing,unsupported,total_bytes);
    }
    Ok(())
}
fn main()->ExitCode{
    match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("ATHENA_MASTER_DEPENDENCIES_FAILED: {e}");ExitCode::FAILURE}}
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn only_exact_game_content_package_paths_are_admitted(){
        assert_eq!(raw_material_package("/Game/Athena/Foo::Foo"),Some("FortniteGame/Content/Athena/Foo".into()));
        assert!(raw_material_package("/Script/Engine::MaterialFunction").is_none());
        assert!(raw_material_package("/Game/../Secret::Secret").is_none());
    }
}
