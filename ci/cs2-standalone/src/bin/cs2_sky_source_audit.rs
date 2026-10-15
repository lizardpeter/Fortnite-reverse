use std::{fs,path::Path,io::Write};
fn main()->Result<(),String>{
 let root=std::env::var("CS2_SKY_SOURCE").map_err(|e|e.to_string())?;
 let out=std::env::var("CS2_SKY_OUTPUT").map_err(|e|e.to_string())?;
 let source=Path::new(&root).join("cs2-base-resources/materials/skybox/sky_de_mirage_exr_71e5f2a1.vtex_c");
 let data=fs::read(&source).map_err(|e|format!("{}: {e}",source.display()))?;
 let faces=cs2_importer::texture::decode_hdr_cube_faces(&data,
     "materials/skybox/sky_de_mirage_exr_71e5f2a1.vtex_c",0.0)?;
 fs::create_dir_all(&out).map_err(|e|e.to_string())?;
 let mut stats=String::new();
 for (i,face) in faces.iter().enumerate(){
     let image_path=Path::new(&out).join(format!("face_{i}.ppm"));
     let mut file=fs::File::create(&image_path).map_err(|e|e.to_string())?;
     file.write_all(format!("P6\n{} {}\n255\n",face.width,face.height).as_bytes()).map_err(|e|e.to_string())?;
     let mut rgb=Vec::with_capacity(face.rgba.len()/4*3);
     let mut sums=[0u64;3];let mut mins=[255u8;3];let mut maxs=[0u8;3];
     for pixel in face.rgba.chunks_exact(4) {
         rgb.extend_from_slice(&pixel[..3]);
         for channel in 0..3{
             sums[channel]+=pixel[channel] as u64;
             mins[channel]=mins[channel].min(pixel[channel]);
             maxs[channel]=maxs[channel].max(pixel[channel]);
         }
     }
     file.write_all(&rgb).map_err(|e|e.to_string())?;
     let count=face.width as u64*face.height as u64;
     let row=format!("face {i} {}x{} means {:?} min {:?} max {:?}\n",face.width,face.height,
          sums.map(|x|x as f64/count as f64),mins,maxs);
     print!("ORIGINAL_CS2_SKY_FACE {row}");
     stats.push_str(&row);
 }
 fs::write(Path::new(&out).join("sky_source_stats.txt"),stats).map_err(|e|e.to_string())?;
 Ok(())
}
