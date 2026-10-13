use std::{env,path::PathBuf,process::ExitCode};
fn run()->Result<(),String>{
    let src=env::args_os().nth(1).map(PathBuf::from)
        .ok_or("expected original Workshop _dir.vpk path")?;
    for map in ["maps/de_dust2_christmas.vpk","maps/de_dust2_winter.vpk"]{
        let started=std::time::Instant::now();
        let scene=cs2_importer::scene::import_workshop_preview(&src,map)?;
        let triangles=scene.meshes.iter().map(|m|m.indices.len()/3).sum::<usize>();
        println!("SOURCE_GEOMETRY_SCENE {map}: meshes={} instances={} materials={} triangles={} elapsed_seconds={:.2}",
            scene.meshes.len(),scene.instances.len(),scene.materials.len(),triangles,started.elapsed().as_secs_f32());
        for line in &scene.report.lines{println!("SOURCE_SCENE_REPORT {line}");}
        if triangles==0||scene.instances.is_empty(){return Err(format!("{map}: no source triangles admitted"));}
    }
    Ok(())
}
fn main()->ExitCode{match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("SOURCE SCENE ERROR: {e}");ExitCode::FAILURE}}}
