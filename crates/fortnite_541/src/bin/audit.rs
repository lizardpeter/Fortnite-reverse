use fortnite_541_importer::{inspect_source, locate_source_root, pak::IndexStatus};
use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let root = env::args_os().nth(1).map(PathBuf::from).or_else(locate_source_root);
    let Some(root) = root else {
        eprintln!("Fortnite 5.41 source not found. Set RUST_TEST_FORTNITE_541_ROOT to the directory containing Engine/ and FortniteGame/.");
        return ExitCode::FAILURE;
    };
    let audit = match inspect_source(&root) {
        Ok(audit) => audit,
        Err(e) => {
            eprintln!("Fortnite 5.41 audit failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("Fortnite 5.41 source: {}", audit.root.display());
    println!("Visited {} files; {} PAKs, {} UMAPs, {} UASSETs, {} UEXPs, {} UBULKs, {} INIs",
        audit.visited_files, audit.archives.len(), audit.loose.umap,
        audit.loose.uasset, audit.loose.uexp, audit.loose.ubulk, audit.loose.ini);
    for archive in &audit.archives {
        match &archive.result {
            Ok(report) => {
                let state = match &report.status {
                    IndexStatus::Encrypted => "encrypted index".to_owned(),
                    IndexStatus::UnsupportedVersion(v) => format!("unsupported index version {v}"),
                    IndexStatus::Indexed { entries, .. } => format!("{} verified index entries", entries.len()),
                };
                println!("PAK {}: v{}; {} ({} bytes)",
                    archive.relative_path.display(), report.footer.version, state, report.file_size);
            }
            Err(error) => println!("PAK {}: ERROR: {error}", archive.relative_path.display()),
        }
    }
    println!("{} UMAP candidates found (not yet playable):", audit.candidate_maps.len());
    for map in audit.candidate_maps.iter().take(100) {
        println!("  {map}");
    }
    if audit.candidate_maps.len() > 100 {
        println!("  ... {} additional candidates", audit.candidate_maps.len() - 100);
    }
    for warning in &audit.warnings {
        eprintln!("WARNING: {warning}");
    }
    if audit.warnings.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
