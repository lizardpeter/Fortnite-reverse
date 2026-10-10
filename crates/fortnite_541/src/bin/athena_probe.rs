//! Read-only proof against real Fortnite 5.41 retail files.
//! Requires a local original PakFile (full or sparse, range-populated) and a
//! historical AES key supplied by the operator. Never runs game code.
use fortnite_541_importer::pak::{self, IndexStatus};
use std::{collections::{BTreeMap, BTreeSet}, env, path::PathBuf, process::ExitCode};

fn parse_key(value: &str) -> Result<[u8; 32], String> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    if hex.len() != 64 || !hex.bytes().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("AES key must have exactly 64 hexadecimal digits".into());
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "invalid AES key hex")?;
    }
    Ok(key)
}

fn run() -> Result<(), String> {
    let path = env::args_os().nth(1).map(PathBuf::from)
        .ok_or("usage: fortnite_541_athena_probe PATH_TO_PAK (set RUST_TEST_FORTNITE_541_AES_KEY)")?;
    let key = parse_key(&env::var("RUST_TEST_FORTNITE_541_AES_KEY")
        .map_err(|_| "missing RUST_TEST_FORTNITE_541_AES_KEY")?)?;
    let report = pak::inspect_with_key(&path, &key)?;
    let IndexStatus::Indexed { mount_point, entries } = &report.status else {
        return Err(format!("Fortnite source index not decoded: {:?}", report.status));
    };
    println!("UE4 PAK v{} original source: {} entries, mount={mount_point:?}",
        report.footer.version, entries.len());
    let map_names = entries.iter().filter(|entry| entry.path.ends_with(".umap")).count();
    println!("Source-backed UMAP packages: {map_names}");
    let mut downloaded = BTreeMap::<String, Vec<u8>>::new();
    for path_suffix in [
        "/Maps/Athena_Terrain.umap",
        "/Maps/Athena_Terrain.uexp",
        "/Maps/Landscape/Athena_Terrain_LS_00.umap",
        "/Maps/Landscape/Athena_Terrain_LS_00.uexp",
        "/Maps/Streaming/Sublevel_X0Y0.umap",
        "/Maps/Streaming/Sublevel_X0Y0.uexp",
        "/Maps/Background/Athena_Background.umap",
        "/Maps/Background/Athena_Background.uexp",
    ] {
        let entry = entries.iter().find(|entry| entry.path.ends_with(path_suffix))
            .ok_or_else(|| format!("missing exact source record {path_suffix}"))?;
        let data = pak::extract_plain_entry(&path, &report, entry)?;
        if entry.path.ends_with(".umap") && !data.starts_with(&0x9E2A_83C1u32.to_le_bytes()) {
            return Err(format!("invalid UE4 package file signature {:?}", entry.path));
        }
        if entry.path.ends_with(".umap") {
            let catalog = fortnite_541_importer::uobject::inspect(&data)?;
            println!("PACKAGE {} names={} imports={} exports={} name_offset={} import_offset={} export_offset={} sample={:?}",
                entry.path,
                catalog.summary.name_count,
                catalog.summary.import_count,
                catalog.summary.export_count,
                catalog.summary.name_offset,
                catalog.summary.import_offset,
                catalog.summary.export_offset,
                catalog.names.iter().take(5).collect::<Vec<_>>());
        }
        println!("VERIFIED {} ({} bytes, SHA-1 matches source entry)",
            entry.path, data.len());
        downloaded.insert(entry.path.clone(), data);
    }
    for (name, header) in &downloaded {
        let Some(base) = name.strip_suffix(".umap") else { continue };
        let companion = downloaded.get(&format!("{base}.uexp"))
            .ok_or_else(|| format!("missing companion UEXP for source {name}"))?;
        let catalog = fortnite_541_importer::uobject::inspect(header)?;
        let mut classes = BTreeMap::<String, usize>::new();
        let mut resolved = 0usize;
        let mut payloads_ok = 0usize;
        let mut payloads_invalid = 0usize;
        let mut bad_examples = BTreeSet::new();
        for export in &catalog.exports {
            let class_name = catalog.export_class_name(export).unwrap_or("<unresolved>");
            if class_name != "<unresolved>" { resolved += 1; }
            *classes.entry(class_name.to_owned()).or_insert(0) += 1;
            if export.serialized_size == 0 { continue; }
            match catalog.export_data(header, companion, export) {
                Ok(_) => payloads_ok += 1,
                Err(error) => {
                    payloads_invalid += 1;
                    bad_examples.insert(format!("offset={} len={} {error}",
                        export.serialized_offset, export.serialized_size));
                }
            }
        }
        let mut class_samples = BTreeSet::new();
        for export in &catalog.exports {
            let class_name = catalog.export_class_name(export).unwrap_or("<unresolved>");
            if !matches!(class_name,
                "LandscapeComponent" | "LandscapeHeightfieldCollisionComponent" |
                "Texture2D" | "LandscapeMaterialInstanceConstant" |
                "World" | "Level" | "StaticMeshComponent" |
                "FortHLODSMActor" | "FortStaticMeshActor" | "InstancedFoliageActor") ||
                !class_samples.insert(class_name.to_owned()) {
                continue;
            }
            if let Ok(bytes) = catalog.export_data(header, companion, export) {
                let count = bytes.len().min(128);
                let mut first = String::new();
                for byte in &bytes[..count] {
                    use std::fmt::Write;
                    let _ = write!(&mut first, "{byte:02x}");
                }
                let first_property = if bytes.len() >= 24 {
                    let get = |off: usize| u32::from_le_bytes(bytes[off..off+4].try_into().unwrap()) as usize;
                    let prop_name = catalog.names.get(get(0)).map(String::as_str).unwrap_or("<invalid>");
                    let prop_type = catalog.names.get(get(8)).map(String::as_str).unwrap_or("<invalid>");
                    let prop_size = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
                    format!("{prop_name}:{prop_type} size={prop_size}")
                } else { "<not enough data>".to_owned() };
                println!("EXPORT_SAMPLE {name} class={class_name} object={} offset={} bytes={} first_property={first_property} head={first}",
                    catalog.names.get(export.object_name.name_index as usize).map_or("?", String::as_str),
                    export.serialized_offset, bytes.len());
                match fortnite_541_importer::properties::scan(&catalog, bytes) {
                    Ok(properties) => {
                        let preview = properties.fields.iter().take(16)
                            .map(|f| format!("{}:{}:{}:{:?}",f.name,f.kind,f.payload.len(),f.metadata))
                            .collect::<Vec<_>>();
                        println!("PROPERTY_SCAN {class_name} properties={} stopped_at={} previews={preview:?}",
                            properties.fields.len(), properties.bytes_consumed);
                    }
                    Err(error) => {
                        println!("PROPERTY_UNPROVEN {class_name}: {error}");
                    }
                }
            }
        }
        let mut sorted = classes.into_iter().collect::<Vec<_>>();
        sorted.sort_by(|a,b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        println!("OBJECT_GRAPH {} exports={} class_resolved={} payloads_in_uexp={} payloads_invalid={} top_classes={:?} failures={:?}",
            name, catalog.exports.len(), resolved, payloads_ok, payloads_invalid,
            sorted.iter().take(14).collect::<Vec<_>>(),
            bad_examples.iter().take(3).collect::<Vec<_>>());
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("Fortnite Athena retail import proof failed: {message}");
            ExitCode::FAILURE
        }
    }
}
