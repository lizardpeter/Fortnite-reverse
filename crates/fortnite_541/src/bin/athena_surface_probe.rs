//! Original UE4.21 Athena surface and transform evidence probe.
//! This is a READ-ONLY source assay, not an approximation of materials.
use std::{collections::BTreeMap,env,fs,path::PathBuf,process::ExitCode};
use fortnite_541_importer::{landscape,properties,uobject,texture,weightmap};

fn f32_triplet(data:&[u8])->Option<[f32;3]> {
    if data.len()!=12{return None;}
    let v=std::array::from_fn(|i|f32::from_le_bytes(data[i*4..i*4+4].try_into().unwrap()));
    v.iter().all(|x|x.is_finite()).then_some(v)
}
fn run()->Result<(),String>{
    let root=PathBuf::from(env::args_os().nth(1).ok_or("usage: athena_surface_probe ORIGINAL_EXTRACTED_SOURCE_ROOT")?);
    let mut all_weightmaps=0usize;
    let mut source_allocations=0usize;
    let mut allocation_shapes=BTreeMap::<String,usize>::new();
    let mut normal_bins=[0usize;4];
    let mut adjacent_height_delta_max=0i32;
    let mut adjacent_height_delta_gt_512=0u64;
    let mut total_height_pairs=0u64;
    let mut root_transform_fields=BTreeMap::<String,usize>::new();
    let mut source_sections=0usize;
    for section in 0..6{
        let base=root.join(format!("FortniteGame/Content/Athena/Maps/Landscape/Athena_Terrain_LS_{section:02}"));
        let umap=fs::read(base.with_extension("umap")).map_err(|e|format!("LS_{section:02} .umap: {e}"))?;
        let uexp=fs::read(base.with_extension("uexp")).map_err(|e|format!("LS_{section:02} .uexp: {e}"))?;
        let ubulk=fs::read(base.with_extension("ubulk")).map_err(|e|format!("LS_{section:02} .ubulk: {e}"))?;
        let cat=uobject::inspect(&umap)?;
        let mut roots=0usize;
        let mut components=0usize;
        let mut allocations_section=0usize;
        let mut weightmap_ref_count=0usize;
        let mut formats=BTreeMap::<String,usize>::new();
        for (i,export) in cat.exports.iter().enumerate(){
            let class=cat.export_class_name(export).unwrap_or("");
            if class=="LandscapeStreamingProxy"{
                let bytes=cat.export_data(&umap,&uexp,export)?;
                let props=properties::scan(&cat,bytes)?;
                if let Some(root_prop)=props.fields.iter().find(|p|p.name=="RootComponent"){
                    let r=&bytes[root_prop.payload.clone()];
                    if r.len()!=4{return Err("root component ref does not contain i32".into());}
                    let idx=i32::from_le_bytes(r.try_into().unwrap());
                    if idx>0{
                        let target=cat.exports.get(idx as usize-1).ok_or("source proxy root ref invalid")?;
                        let root_bytes=cat.export_data(&umap,&uexp,target)?;
                        let root_fields=properties::scan(&cat,root_bytes)?;
                        let mut transform=Vec::new();
                        for p in &root_fields.fields {
                            if p.name=="RelativeLocation" || p.name=="RelativeRotation" || p.name=="RelativeScale3D" || p.name=="Mobility" || p.name=="AttachParent" {
                                let raw=&root_bytes[p.payload.clone()];
                                let parsed=f32_triplet(raw).map(|x|format!("{x:?}")).unwrap_or_else(||format!("{:02x?}",raw));
                                transform.push(format!("{}={parsed}",p.name));
                                *root_transform_fields.entry(p.name.clone()).or_default()+=1;
                            }
                        }
                        println!("ATHENA_PROXY_ROOT LS_{section:02} export={} root_ref={idx} class={:?} transform={transform:?}",
                            i+1,cat.export_class_name(target));
                        roots+=1;
                    }
                }
            } else if class=="LandscapeComponent" {
                components+=1;
                let bytes=cat.export_data(&umap,&uexp,export)?;
                let props=properties::scan(&cat,bytes)?;
                let component=landscape::inspect(&cat,bytes)?;
                weightmap_ref_count+=component.weightmap_texture_refs.len();
                // Fail the real retail test on any missing/misaddressed source
                // layer, and print the exact authored LayerInfo reference.
                let decoded=weightmap::decode_layer_allocations(
                    &cat,bytes,&component.weightmap_texture_refs)?;
                if components<=2{
                    println!("ATHENA_DECODED_PAINT LS_{section:02} component={} layers={decoded:?}",i+1);
                }

                let allocations=props.fields.iter().find(|p|p.name=="WeightmapLayerAllocations");
                if let Some(p)=allocations{
                    let raw=&bytes[p.payload.clone()];
                    let key=format!("{}:{}:{}",p.kind,p.metadata.join(","),raw.len());
                    *allocation_shapes.entry(key).or_default()+=1;
                    if raw.len()<4{return Err("weightmap allocations payload too short".into());}
                    let count=u32::from_le_bytes(raw[0..4].try_into().unwrap()) as usize;
                    if count>256{return Err(format!("LS_{section:02} component {} has {count} weightmap entries",i+1));}
                    allocations_section+=count;
                    source_allocations+=count;
                    if components<=2 {
                        for (off,len) in [(4usize,8usize),(12,8),(28,8),(52,8),(60,8),(80,8),(88,8),(104,8),(114,8),(122,8),(138,8),(148,8)] {
                            if off+len<=raw.len() {
                                let i=u32::from_le_bytes(raw[off..off+4].try_into().unwrap()) as usize;
                                println!("ATHENA_WEIGHT_FIELD LS_{section:02} component={} offset={} name_idx={} name={:?} bytes={:02x?}",
                                    i+1,off,i,cat.names.get(i),&raw[off..off+len]);
                            }
                        }
                        println!("ATHENA_WEIGHT_FULL_HEX LS_{section:02} component={} data={}",i+1,raw.iter().map(|b|format!("{b:02x}")).collect::<String>());
                    }
                    if components<=2{
                        let hex=raw.iter().take(176).map(|x|format!("{x:02x}")).collect::<String>();
                        println!("ATHENA_WEIGHT_ALLOCATIONS LS_{section:02} component={} count={count} data_bytes={} kind={} inner={:?} raw_hex={hex}",
                            i+1,raw.len(),p.kind,p.metadata);
                    }
                }
                if let Some(&refer)=component.weightmap_texture_refs.first(){
                    if refer<=0{return Err(format!("LS_{section:02} weightmap texture ref not local: {refer}"));}
                    let tex=cat.exports.get(refer as usize-1).ok_or("source weightmap ref missing")?;
                    let tex_data=cat.export_data(&umap,&uexp,tex)?;
                    let tex_props=properties::scan(&cat,tex_data)?;
                    let cooked=&tex_data[tex_props.bytes_consumed..];
                    let string=String::from_utf8_lossy(cooked);
                    let fmt=if string.contains("PF_B8G8R8A8"){"PF_B8G8R8A8"}else if string.contains("PF_G8"){"PF_G8"}else{"OTHER"};
                    *formats.entry(fmt.to_string()).or_default()+=1;
                    if fmt=="PF_B8G8R8A8"{
                        // The verified parser also checks byte offsets and SHA-1.
                        if let Ok(mip)=texture::first_mip_bgra8(&cat,&umap,&uexp,&ubulk,tex){
                            if components==1{println!("ATHENA_WEIGHT_FIRST_MIP LS_{section:02} size={}x{} flags=0x{:x} first_bgra={:02x?}",mip.width,mip.height,mip.source_bulk_flags,&mip.bgra8[..16]);}
                        }
                    }
                }
                let h_ref=component.heightmap_texture_ref;
                let ht=cat.exports.get((h_ref-1) as usize).ok_or("source heightmap missing")?;
                let mip=texture::first_mip_bgra8(&cat,&umap,&uexp,&ubulk,ht)?;
                let n=component.component_size_quads as usize+1;
                for y in 0..n{for x in 0..n {
                    let h=mip.height_u16(x as u32,y as u32)? as i32;
                    let px=&mip.bgra8[(y*mip.width as usize+x)*4..(y*mip.width as usize+x)*4+4];
                    normal_bins[usize::from(px[0]>127)+2*usize::from(px[3]>127)]+=1;
                    if x>0 {
                        let other=mip.height_u16(x as u32-1,y as u32)? as i32;
                        let delta=(h-other).abs();
                        adjacent_height_delta_max=adjacent_height_delta_max.max(delta);
                        adjacent_height_delta_gt_512+=(delta>512) as u64;
                        total_height_pairs+=1;
                    }
                    if y>0 {
                        let other=mip.height_u16(x as u32,y as u32-1)? as i32;
                        let delta=(h-other).abs();
                        adjacent_height_delta_max=adjacent_height_delta_max.max(delta);
                        adjacent_height_delta_gt_512+=(delta>512) as u64;
                        total_height_pairs+=1;
                    }
                }}
            }
        }
        println!("ATHENA_SOURCE_SURFACE LS_{section:02} root_actors={roots} landscape_components={components} weightmap_texture_refs={weightmap_ref_count} layer_allocations={allocations_section} texture_format_samples={formats:?}");
        all_weightmaps+=weightmap_ref_count;
        source_sections+=1;
    }
    println!("ATHENA_SURFACE_AUDIT sections={source_sections} weightmap_texture_refs={all_weightmaps} source_layer_allocations={source_allocations} allocation_property_shapes={allocation_shapes:?} proxy_root_transform_fields={root_transform_fields:?} height_adjacent_pairs={total_height_pairs} height_max_delta_raw={adjacent_height_delta_max} height_delta_gt_512={adjacent_height_delta_gt_512} normal_channel_sign_bins={normal_bins:?}");
    Ok(())
}
fn main()->ExitCode{
    match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("ATHENA_SOURCE_AUDIT_FAILED: {e}");ExitCode::FAILURE}}
}
