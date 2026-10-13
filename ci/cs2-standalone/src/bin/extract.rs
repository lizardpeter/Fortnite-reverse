//! Extract a precisely named original resource for offline format research.
//! No content transformation, source synthesis, caching or renderer dependency.
//! Usage: cs2_source_extract <workshop_dir.vpk> <inner_map.vpk> <resource_path> <output_path>
use cs2_importer::vpk::VpkArchive;
use std::{env,path::PathBuf,process::ExitCode};
fn run()->Result<(),String>{
    let args=env::args_os().skip(1).collect::<Vec<_>>();
    if args.len()!=4{return Err("expected <outer_dir.vpk> <nested_map_path> <entry_path> <output_file>".into());}
    let outer=VpkArchive::open_directory(&PathBuf::from(&args[0]))?;
    let nested=outer.open_nested(&args[1].to_string_lossy())?;
    let bytes=nested.read_entry(&args[2].to_string_lossy())?;
    let output=PathBuf::from(&args[3]);
    if let Some(parent)=output.parent(){std::fs::create_dir_all(parent).map_err(|e|e.to_string())?;}
    std::fs::write(&output,&bytes).map_err(|e|format!("write original resource {}: {e}",output.display()))?;
    println!("Wrote exact source resource {} ({} bytes)",output.display(),bytes.len());
    Ok(())
}
fn main()->ExitCode{match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("{e}");ExitCode::FAILURE}}}
