use std::{env,path::Path,process::ExitCode};
fn dist(a:[f32;3],b:[f32;3])->f32{((a[0]-b[0]).powi(2)+(a[1]-b[1]).powi(2)+(a[2]-b[2]).powi(2)).sqrt()}
fn run()->Result<(),String>{
 let input=env::args().nth(1).ok_or("expect original Workshop _dir.vpk")?;
 for map in ["maps/de_dust2_christmas.vpk","maps/de_dust2_winter.vpk"] {
  let scene=cs2_importer::scene::import_workshop_preview(Path::new(&input),map)?;
  let mut triangles=Vec::<(f32,usize,[f32;3],[f32;3],[f32;3])>::new();
  let mut top_height=Vec::<(f32,f32,usize)>::new();
  let mut bad=0usize;
  for (idx,m) in scene.meshes.iter().enumerate() {
   if !scene.materials[m.material].visible {continue;}
   let mut maxlen=0f32;let mut h=0f32;
   for tri in m.indices.chunks_exact(3) {
     let (Some(a),Some(b),Some(c))=(m.vertices.get(tri[0] as usize),m.vertices.get(tri[1] as usize),m.vertices.get(tri[2] as usize)) else {continue};
     let edge=dist(a.position,b.position).max(dist(b.position,c.position)).max(dist(c.position,a.position));
     maxlen=maxlen.max(edge);
     let mx=a.position[1].max(b.position[1]).max(c.position[1]);h=h.max(mx);
     if edge>12. && edge.is_finite() {
       triangles.push((edge,idx,a.position,b.position,c.position));
       if edge>20. {bad+=1;}
     }
   }
   if maxlen>10. || h>30. {top_height.push((h,maxlen,idx));}
  }
  triangles.sort_by(|a,b|b.0.total_cmp(&a.0));top_height.sort_by(|a,b|b.0.total_cmp(&a.0));
  println!("CS2_VISIBLE_GIANT_TRIANGLES map={map} edges_over_20={bad}");
  for (edge,idx,a,b,c) in triangles.iter().take(32) {
    let m=&scene.meshes[*idx];
    println!("CS2_VISIBLE_GIANT map={map} edge={edge:.3} mesh={idx} material={} name={} vertices={a:?}|{b:?}|{c:?}",scene.materials[m.material].name,m.name);
  }
  for (h,edge,idx) in top_height.iter().take(16) {
    let m=&scene.meshes[*idx];
    println!("CS2_SKYLINE_GEOMETRY map={map} height={h:.2} edge={edge:.2} material={} name={}",scene.materials[m.material].name,m.name);
  }
  let outer=cs2_importer::vpk::VpkArchive::open_directory(Path::new(&input))?;
  let inner=outer.open_nested(map)?;
  let packs=cs2_importer::material::SourcePacks{
     workshop_outer:&outer,workshop_map:&inner,base_game:None
  };
  for path in ["materials/effects/smoke/steam_001.vmat",
      "materials/ground/snow01_expensive.vmat",
      "materials/de_dust/hr_dust/hr_dust_blend_plaster01b_rough01.vmat"] {
    match packs.describe(path) {
      Ok(m)=>println!("CS2_SKYLINE_VMATERIAL map={map} path={path} shader={} textures={:?} scalars={:?} switches={:?}",
         m.shader,m.textures,m.scalars,m.switches),
      Err(e)=>println!("CS2_SKYLINE_VMATERIAL_MISSING map={map} path={path} error={e}")
    }
  }
  if let Some(sky)=scene.sky{
    for (i,face) in sky.faces.iter().enumerate() {
      let n=face.rgba.chunks_exact(4).len();
      let mut sums=[0u64;3];let mut white=0usize;let mut pale=0usize;let mut blue=0usize;let mut black=0usize;
      let mut min=[255u8;3];let mut max=[0u8;3];
      for p in face.rgba.chunks_exact(4){for ch in 0..3{sums[ch]+=p[ch] as u64;min[ch]=min[ch].min(p[ch]);max[ch]=max[ch].max(p[ch]);}
        if p[0]>=245 && p[1]>=245 && p[2]>=245{white+=1;}
        if p[0]>=215 && p[1]>=215 && p[2]>=215 {pale+=1;}
        if p[2]>p[0].saturating_add(10) && p[2]>p[1].saturating_add(3) {blue+=1;}
        if p[0]<20 && p[1]<20 && p[2]<20{black+=1;}
      }
      println!("CS2_SKY_FACE map={map} face={i} name={} dimensions={}x{} mean={:?} min={min:?} max={max:?} white={} pale={} blue={} black={} pixel_count={n}",
        face.name,face.width,face.height,sums.map(|s|s as f64/n as f64),white,pale,blue,black);
    }
  }
 }
 Ok(())
}
fn main()->ExitCode{match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("CS2 DIAG FAILED {e}");ExitCode::FAILURE}}}
