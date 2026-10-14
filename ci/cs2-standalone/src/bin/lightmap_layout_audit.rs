use std::{env,collections::BTreeMap,path::Path,process::ExitCode};
fn run()->Result<(),String>{
 let arg=env::args().nth(1).ok_or("expected Workshop _dir.vpk")?;
 let outer=cs2_importer::vpk::VpkArchive::open_directory(Path::new(&arg))?;
 for path in ["maps/de_dust2_christmas.vpk","maps/de_dust2_winter.vpk"]{
  let inner=outer.open_nested(path)?;
  let graph=cs2_importer::world::from_archive(&outer,path)?;
  println!("CS2_SOURCE_LIGHTMAP_WORLD map={path} version={:?} uv_scale={:?} resources={:?}",
     graph.lightmap_version,graph.lightmap_uv_scale,graph.lighting_textures);
  let models:Vec<String>=graph.nodes.iter().flat_map(|n|
    n.scene_objects.iter().map(|p|p.model.clone()).chain(n.aggregates.iter().map(|a|a.model.clone()))
  ).collect();
  let mut seen=std::collections::BTreeSet::new();
  let mut lightmap_count=0usize;
  let mut examined=0usize;
  let mut types=BTreeMap::<String,usize>::new();
  for model in models{
   if !seen.insert(model.clone()){continue;}
   let file=if inner.available(&model){inner.read_entry(&model)?}
    else if outer.available(&model){outer.read_entry(&model)?} else {continue;};
   let Ok(data)=cs2_importer::draw::decode_model(&file,&model) else{continue;};
   examined+=1;
   for draw in &data.draws{
    if !draw.lightmapped{continue;}
    lightmap_count+=1;
    let mut attrs=Vec::new();
    for &i in &draw.vertex_buffers{
      if let Some(buffer)=data.buffers.vertices.get(i){
       for a in &buffer.attributes{
        if a.semantic.contains("TEXCOORD") || a.semantic.contains("LIGHT") {
         let id=format!("{}#{}:DXGI{}@{}",a.semantic,a.semantic_index,a.dxgi_format,a.offset);
         *types.entry(id.clone()).or_default()+=1;
         attrs.push(id);
        }
       }
      }
    }
    if lightmap_count<=12 {
     let lowered=cs2_importer::surface::lower_draw(&data,draw)?;
     let mut uvmin=[f32::INFINITY;2];let mut uvmax=[f32::NEG_INFINITY;2];let mut sec=0usize;
     for v in &lowered.vertices{if let Some(uv)=v.secondary_uv{sec+=1;
      for k in 0..2{uvmin[k]=uvmin[k].min(uv[k]);uvmax[k]=uvmax[k].max(uv[k]);}
     }}
     println!("CS2_LIGHTMAP_DRAW map={path} model={model} shader={} attrs={attrs:?} vertices={} secondary_uv_count={sec} uv_min={uvmin:?} uv_max={uvmax:?}",
         draw.material,lowered.vertices.len());
    }
   }
   if examined>=400 || lightmap_count>=18 {break;}
  }
  println!("CS2_LIGHTMAP_VERTEX_CENSUS map={path} models_examined={examined} lightmapped_draws={lightmap_count} attribute_ids={types:?}");
 }
 Ok(())
}
fn main()->ExitCode{match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("CS2 LIGHTMAP AUDIT ERROR {e}");ExitCode::FAILURE}}}
