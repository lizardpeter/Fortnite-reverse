//! Reproduce the actual Rust-test automatic environment source extraction
//! from authenticated original retail Fortnite 5.41 PAK bytes. No network
//! fetch or game-specific renderer.
use std::{env,path::PathBuf,process::ExitCode};
use fortnite_541_importer::extract;
fn run()->Result<(),String>{
    let mut a=env::args_os().skip(1);
    let pak=PathBuf::from(a.next().ok_or("usage: athena_extract_environment ORIGINAL_MAIN_PAK OUTPUT_CACHE")?);
    let cache=PathBuf::from(a.next().ok_or("missing ignored source cache path")?);
    let out=extract::prepare_original_environment_sources(&pak,&cache)?;
    println!("FORTNITE_541_AUTHENTIC_ENVIRONMENT_SOURCE_CLOSURE verified_files={} newly_extracted={} original_bytes_new={}",
        out.verified_files,out.extracted_files,out.bytes_extracted);
    if out.verified_files!=22{return Err(format!("expected 22 authenticated original sky/material source files, got {}",out.verified_files));}
    Ok(())
}
fn main()->ExitCode{match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{
    eprintln!("FORTNITE_541_AUTHENTIC_ENVIRONMENT_SOURCE_FAILED: {e}");ExitCode::FAILURE
}}}
