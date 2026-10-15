//! Verify Source2 real Workshop original entity KV3 decoding before runtime.
use std::path::Path;
use cs2_importer::{entity, vpk::VpkArchive};

fn main() -> Result<(),String> {
    let directory=std::env::var("ORIGINAL_CS2_WORKSHOP_DIR")
        .map_err(|_|"missing exact original Workshop VPK directory".to_owned())?;
    let source=Path::new(&directory).join("3620630831_dir.vpk");
    let outer=VpkArchive::open_directory(&source)?;
    for (name,expected_bytes) in [
        ("maps/de_dust2_christmas.vpk",340_042_954u32),
        ("maps/de_dust2_winter.vpk",224_520_795u32),
    ] {
        let entry=outer.entries().get(name)
            .ok_or_else(||format!("missing original source workshop map {name}"))?;
        if entry.length!=expected_bytes{
            return Err(format!("source Workshop physical map extent differs for {name}: {}",entry.length));
        }
        let nested=outer.open_nested(name)?;
        let source_lumps=entity::from_nested_map(&nested)?;
        let spawns=entity::team_spawns(&source_lumps);
        if source_lumps.is_empty()||spawns.len()<20 {
            return Err(format!("{name}: original KV3 source entity decomp incomplete, spawn count {}",spawns.len()));
        }
        println!("CERTIFIED_SOURCE2_WORKSHOP_BOOTSTRAP {name} compiled_lumps={} native_team_spawns={} exact_map_bytes={expected_bytes}",
            source_lumps.len(),spawns.len());
    }
    Ok(())
}
