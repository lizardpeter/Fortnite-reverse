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
        // Source-trace visually oversized/corrupted triangles. No guesses or
        // changes to the source geometry; report the actual material/model.
        let mut largest=Vec::<(f32,String,usize,[f32;3],[f32;3],[f32;3])>::new();
        let mut sample_count=0usize;
        let mut over_20m=0usize;
        let mut over_80m=0usize;
        for (mesh_idx,mesh) in scene.meshes.iter().enumerate(){
            for tri in mesh.indices.chunks_exact(3){
                let (Some(a),Some(b),Some(c))=(
                    mesh.vertices.get(tri[0] as usize),
                    mesh.vertices.get(tri[1] as usize),
                    mesh.vertices.get(tri[2] as usize)) else {continue};
                let dist=|x:[f32;3],y:[f32;3]|->f32{
                    ((x[0]-y[0]).powi(2)+(x[1]-y[1]).powi(2)+(x[2]-y[2]).powi(2)).sqrt()
                };
                let max=dist(a.position,b.position).max(dist(b.position,c.position)).max(dist(c.position,a.position));
                if max>20. {over_20m+=1}
                if max>80. {over_80m+=1}
                if max>5. && max.is_finite(){
                    let name=scene.materials.get(mesh.material).map(|m|m.name.clone()).unwrap_or_default();
                    largest.push((max,name,mesh_idx,a.position,b.position,c.position));
                    if largest.len()>1000{
                        largest.sort_by(|a,b|b.0.total_cmp(&a.0));
                        largest.truncate(40);
                    }
                }
                sample_count+=1;
            }
        }
        largest.sort_by(|a,b|b.0.total_cmp(&a.0));
        println!("CS2_TRIANGLE_SOURCE_AUDIT map={map} triangles={sample_count} edges_over_20m={over_20m} edges_over_80m={over_80m}");
        for (dist,mat,idx,a,b,c) in largest.iter().take(24) {
            println!("CS2_LARGE_TRIANGLE edge_m={dist:.2} mesh={idx} material={mat} points={a:?} {b:?} {c:?} mesh_name={}",scene.meshes[*idx].name);
        }

        if triangles==0||scene.instances.is_empty(){return Err(format!("{map}: no source triangles admitted"));}
    }
    Ok(())
}
fn main()->ExitCode{match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("SOURCE SCENE ERROR: {e}");ExitCode::FAILURE}}}
