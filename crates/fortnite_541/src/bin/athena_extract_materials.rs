//! Extract original Fortnite 5.41 Athena material/function/texture source
//! packages from the operator's local, SHA-1-authenticated retail main PAK.
//! All recovered bytes remain in the ignored local source working directory.
use std::{env,path::PathBuf,process::ExitCode};
use fortnite_541_importer::{locate_source_root,material_extract};

fn run()->Result<(),String>{
    let mut args=env::args_os().skip(1);
    let archive=if let Some(arg)=args.next(){PathBuf::from(arg)}else{
        locate_source_root()
            .ok_or("Fortnite 5.41 source root not found; supply original pak path")?
            .join("FortniteGame/Content/Paks/pakchunk0-WindowsClient.pak")
    };
    let source=if let Some(arg)=args.next(){PathBuf::from(arg)}else{
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../work/fortnite_541/athena/source")
    };
    let direct_only=args.next().is_some_and(|flag|flag=="--direct-only");
    // Only the direct dependencies are tested by a sparse original-byte PAK
    // fixture; the actual user-owned 5.41 PAK can supply recursive closure.
    let result=if direct_only{
        material_extract::prepare_original_athena_materials_up_to(&archive,&source,1)?
    }else{
        material_extract::prepare_original_athena_materials(&archive,&source)?
    };
    println!("ATHENA_EXTRACTED_ORIGINAL_MATERIAL_SOURCES packages={} authenticated_files={} newly_written={} bytes={} expression_nodes={} missing_or_unhandled_packages={:?} other_engine_dependencies={:?} deferred_packages={:?}",
        result.source_packages,result.authenticated_files,result.new_files,
        result.total_source_bytes,result.inspected_material_expression_nodes,
        result.unresolved_packages,result.unresolved_non_game_objects,result.deferred_packages);
    Ok(())
}
fn main()->ExitCode{
    match run(){Ok(())=>ExitCode::SUCCESS,Err(error)=>{
        eprintln!("FORTNITE_541_ORIGINAL_MATERIAL_EXTRACT_FAILED: {error}");ExitCode::FAILURE
    }}
}
