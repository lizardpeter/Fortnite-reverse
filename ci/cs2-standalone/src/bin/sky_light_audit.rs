use std::{path::Path,process::ExitCode};
fn run()->Result<(),String>{
 let root=std::env::args().nth(1).ok_or("expected compact original CS2 resource root")?;
 let root=Path::new(&root).join("cs2-base-resources");
 let mut paths=Vec::new();
 fn walk(dir:&Path,paths:&mut Vec<std::path::PathBuf>)->Result<(),String>{
  for file in std::fs::read_dir(dir).map_err(|e|e.to_string())?{
   let path=file.map_err(|e|e.to_string())?.path();
   if path.is_dir(){walk(&path,paths)?;}else if path.extension().is_some_and(|e|e=="vtex_c")
    &&(path.to_string_lossy().contains("sky")||path.to_string_lossy().contains("lightmap")||
      path.to_string_lossy().contains("baked")) {paths.push(path);}
  }
  Ok(())
 }
 walk(&root,&mut paths)?;
 for path in &paths {
   let bytes=std::fs::read(path).map_err(|e|e.to_string())?;
   println!("CS2_SOURCE_LIGHT_SKY_PATH {} bytes {}",path.display(),bytes.len());
   match cs2_importer::texture::inspect(&bytes){
    Ok(meta)=>println!("CS2_SOURCE_LIGHT_SKY_FORMAT {} width={} height={} depth={} format={} mips={} mip_compression={} flags={} disk_sizes={:?}",
      path.display(),meta.width,meta.height,meta.depth,meta.format,meta.mips,meta.mip_compression,meta.flags,meta.mip_disk_sizes),
    Err(e)=>println!("CS2_SOURCE_LIGHT_SKY_FORMAT_ERROR {} {e}",path.display()),
   }
 }
 let sky=root.join("materials/skybox/sky_de_dust2vmat.vmat_c");
 if sky.exists(){
  let m=cs2_importer::material::material_bytes(&std::fs::read(&sky).map_err(|e|e.to_string())?,"materials/skybox/sky_de_dust2vmat.vmat_c")?;
  println!("CS2_SOURCE_SKY_VMATERIAL shader={} textures={:?} scalars={:?}",m.shader,m.textures,m.scalars);
 }
 println!("CS2_SKY_AUDIT_FILE_COUNT {}",paths.len());
 Ok(())
}
fn main()->ExitCode {match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("{e}");ExitCode::FAILURE}}}
