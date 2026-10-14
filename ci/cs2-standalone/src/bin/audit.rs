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
        let src=VpkArchive::open_directory(&path)?;
        let sub=src.open_nested(&map.label)?;
        for ent in sub.entries().keys().filter(|p|p.ends_with(".vents_c")).take(2) {
            let data=sub.read_entry(ent)?;
            let h=ResourceHeader::parse(&data)?;
            println!("  ENTITY SOURCE {ent} blocks {:?}",h.blocks.iter().map(|x|x.name()).collect::<Vec<_>>());
            if let Some(bin)=h.block(&data,b"DATA") {
                match cs2_importer::kv3::decode(bin) {
                    Ok(doc)=> {println!("  ENTITY ROOT {}",format!("{:?}",doc.root).chars().take(4000).collect::<String>());}
                    Err(e)=>println!("  ENTITY DECODE pending {e}"),
                }
            }
        }
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
    {
        let outer=VpkArchive::open_directory(&path)?;
        for map in &report.maps {
            let nested=outer.open_nested(&map.label)?;
            let lumps=cs2_importer::entity::from_nested_map(&nested)?;
            let types=cs2_importer::entity::class_counts(&lumps);
            let spawns=cs2_importer::entity::team_spawns(&lumps);
            println!("CS2 ENTITY CENSUS {}: entities={} classes={} spawns={} sky={:?}",
                map.label,lumps.iter().map(|l|l.entities.len()).sum::<usize>(),
                types.len(),spawns.len(),cs2_importer::entity::sky_name(&lumps));
            for (name,count) in &types {
                if name.contains("spawn") || name.contains("player") || name.contains("sky") || name.contains("light") {
                    println!("CS2 ENTITY CLASS {name} = {count}");
                }
            }
            for spawn in spawns.iter().take(5){
                println!("CS2 AUTHORED SPAWN {} origin={:?} angles={:?}",
                    spawn.classname,spawn.source_origin,spawn.source_angles);
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
                            if let Some(first)=doc.root.field("m_aggregateSceneObjects").and_then(cs2_importer::kv3::Value::as_array).and_then(|a|a.first()){
                                if let cs2_importer::kv3::Value::Object(kvs)=first {
                                    println!("    AGGREGATE fields: {:?}",kvs.iter().map(|(k,_)|k).collect::<Vec<_>>());
                                    for (k,v) in kvs {if k!="m_aggregateMeshes" {println!("    AGGREGATE {k}={}",format!("{v:?}").chars().take(1200).collect::<String>());}}
                                }
                            }
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
            match cs2_importer::draw::decode_model(&bytes,model) {
                Ok(decoded) => {
                    println!("    authored Source 2 draw calls={}",decoded.draws.len());
                    for draw in decoded.draws.iter().take(3) {
                        match cs2_importer::surface::lower_draw(&decoded,draw) {
                            Ok(surface)=>println!("    SOURCE TRIANGLES material={} triangles={} unique_vertices={} source_tint={:?} source_lightmap={}",
                                surface.material,surface.indices.len()/3,surface.vertices.len(),
                                surface.tint,surface.lightmapped),
                            Err(e)=>println!("    SOURCE TRIANGLES blocked {}: {e}",draw.material),
                        }
                    }
                },
                Err(e)=>println!("    ORIGINAL MATERIAL DRAW decode blocked {e}"),
            }
            if let Some(mdat)=header.block(&bytes,b"MDAT") {
                match cs2_importer::kv3::decode(mdat) {
                    Ok(doc)=>{
                        if let cs2_importer::kv3::Value::Object(fields)=doc.root{
                            println!("    MDAT fields {:?}",fields.iter().map(|(k,_)|k).collect::<Vec<_>>());
                            for (k,v) in fields.iter().take(7) {
                                let s=format!("{v:?}");
                                println!("    MDAT {k}: {}",s.chars().take(1600).collect::<String>());
                            }
                        }
                    },
                    Err(e)=>println!("    MDAT decode pending: {e}"),
                }
            }
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
