//! Offline, source-only Source 2 package verification tool.
//! Run: cargo run --manifest-path asset_import/importers/cs2/Cargo.toml
//!      --bin cs2_source_audit -- /path/to/3620630831_dir.vpk
use cs2_importer::{inspect_workshop, resource::ResourceHeader, vpk::VpkArchive};
use std::{env,path::PathBuf,process::ExitCode};

fn run() -> Result<(),String> {
    let path=env::args_os().nth(1).map(PathBuf::from)
        .or_else(||env::var_os("RUST_TEST_CS2_VPK_DIR").map(PathBuf::from))
        .ok_or("pass path to Workshop _dir.vpk or set RUST_TEST_CS2_VPK_DIR")?;
    let report=inspect_workshop(&path)?;
    println!("CS2 outer VPK: {} entries, {:?}",
        report.outer.file_count,report.outer.by_extension);
    for map in &report.maps {
        println!("Nested {}: {} entries, {:?}",
            map.label,map.file_count,map.by_extension);
        for p in &map.world_files { println!("  world resource: {p}"); }
    }
    for warning in &report.nested_errors { eprintln!("Nested VPK unavailable: {warning}"); }
    if report.maps.is_empty() {
        return Err("No nested Source 2 map packages could be indexed".into());
    }
    for map in &report.maps {
        let graph=cs2_importer::world::from_workshop(&path,&map.label)?;
        println!("  SOURCE WORLD graph {}: nodes={}, placements={}, aggregate groups={}, aggregate draws={}, lightmaps={}, entity lumps={}, unresolved source model references={}",
            map.label,graph.nodes.len(),
            graph.nodes.iter().map(|n|n.scene_objects.len()).sum::<usize>(),
            graph.nodes.iter().map(|n|n.aggregate_groups).sum::<usize>(),
            graph.nodes.iter().map(|n|n.aggregate_draws).sum::<usize>(),
            graph.lighting_textures.len(),graph.entity_lumps.len(),
            graph.unresolved_placements.len());
        for node in &graph.nodes {
            println!("    world node {} placements={} aggregates={}",node.path,node.scene_objects.len(),node.aggregate_draws);
            for obj in node.scene_objects.iter().take(4) {
                println!("    placement {} translation=[{}, {}, {}]",obj.model,obj.rows[0][3],obj.rows[1][3],obj.rows[2][3]);
            }
        }
    }
    let outer=VpkArchive::open_directory(&path)?;
    let mut good_resources=0usize;
    for map_report in &report.maps {
        let nested=outer.open_nested(&map_report.label)?;
        let mut found_world=false;
        for entry in &map_report.world_files {
            if !entry.ends_with(".vwrld_c") && !entry.ends_with(".vmap_c") && !entry.ends_with(".vwnod_c") { continue; }
            let bytes=nested.read_entry(entry)?;
            let header=ResourceHeader::parse(&bytes).map_err(|e|format!("{entry}: {e}"))?;
            let kinds=header.blocks.iter().map(|b|b.name()).collect::<Vec<_>>();
            println!("  decoded Source 2 resource {entry}: version {}, blocks {kinds:?}",
                header.resource_version);
            let dependencies=header.external_references(&bytes)?;
            if let Some(data)=header.block(&bytes,b"DATA") {
                let head=data.iter().take(48).map(|b|format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                let magic=data.get(0..4).map(|x| u32::from_le_bytes(x.try_into().unwrap())).unwrap_or(0);
                let compression=data.get(20..24).map(|x|u32::from_le_bytes(x.try_into().unwrap())).unwrap_or(0);
                println!("    KV3 DATA bytes={} magic=0x{magic:08x} compression={compression} prefix={head}",data.len());
            }
            if let Some(data)=header.block(&bytes,b"DATA") {
                match cs2_importer::kv3::decode(data) {
                    Ok(doc)=>{
                        println!("    decoded KV3 version={} compression={} strings={} values={}",
                            doc.header.version,doc.header.compression,doc.string_count,doc.nodes);
                        if let cs2_importer::kv3::Value::Object(fields)=&doc.root {
                            println!("    root fields: {:?}",fields.iter().take(36).map(|(k,_)|k).collect::<Vec<_>>());
                            for (name,field) in fields.iter().take(12) {
                                let repr=format!("{field:?}");
                                println!("    field {name}: {}",repr.chars().take(1700).collect::<String>());
                            }
                        }
                    },
                    Err(error)=>println!("    KV3 pending: {error}"),
                }
            }
            println!("    exact resource dependencies: {}",dependencies.len());
            for dep in dependencies.iter().take(12) {
                println!("    RERL {:016x} -> {}",dep.id,dep.path);
            }
            good_resources+=1;
            if entry.ends_with(".vwrld_c") { found_world=true; }
        }
        if !found_world { return Err(format!("{} has no valid world.vwrld_c",map_report.label)); }
        for model in nested.entries().keys().filter(|p|p.ends_with(".vmdl_c") && p.contains("/worldnodes/")).take(2) {
            let bytes=nested.read_entry(model)?;
            let header=ResourceHeader::parse(&bytes)?;
            let kind=header.blocks.iter().map(|b|b.name()).collect::<Vec<_>>();
            println!("  source model {model}: {} bytes blocks {kind:?}",bytes.len());
            if let Some(mbuf)=header.block(&bytes,b"MBUF") {
                match cs2_importer::vbib::decode(mbuf) {
                    Ok(geometry)=>{
                        println!("    DECODED SOURCE MODEL: vertex buffers={}, index buffers={}",
                            geometry.vertices.len(),geometry.indices.len());
                        for buffer in geometry.vertices.iter().take(4) {
                            println!("    vertex count={} stride={} attrs={:?}",
                                buffer.count,buffer.stride,
                                buffer.attributes.iter().map(|a|format!("{}:{}@{}",a.semantic,a.dxgi_format,a.offset)).collect::<Vec<_>>());
                        }
                        for buffer in geometry.indices.iter().take(4) {
                            println!("    triangles index count={} stride={}",buffer.count,buffer.stride);
                        }
                    },
                    Err(e)=>println!("    model MBUF decoder pending: {e}"),
                }
            }
            if let Some(data)=header.block(&bytes,b"DATA") {
                match cs2_importer::kv3::decode(data) {
                    Ok(doc)=> {
                        if let cs2_importer::kv3::Value::Object(fields)=doc.root {
                            println!("    model fields: {:?}",fields.iter().map(|(k,_)|k).collect::<Vec<_>>());
                        }
                    },
                    Err(error)=>println!("    model DATA pending: {error}"),
                }
            }
        }
    }
    println!("CS2 original-resource verification: {good_resources} compiled map/world files parsed");
    Ok(())
}
fn main()->ExitCode{
    match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{eprintln!("CS2 audit failed: {e}");ExitCode::FAILURE}}
}
