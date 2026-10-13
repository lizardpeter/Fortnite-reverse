//! Counter-Strike 2 / Source 2 original content importer.
//!
//! Reads Valve VPK v2 and nested map VPK files directly. Never creates
//! placeholder meshes, approximate materials or inferred gameplay geometry.
//! Native renderer integration will be enabled only as compiled Source 2
//! resource and material semantics acquire source-backed decoding.
pub mod kv3;
pub mod vbib;
pub mod world;
pub mod draw;
pub mod surface;
pub mod resource;
pub mod vpk;

use std::{collections::BTreeMap, path::Path};
use vpk::VpkArchive;

#[derive(Clone, Debug)]
pub struct PackageReport {
    pub label: String,
    pub file_count: usize,
    pub by_extension: BTreeMap<String, usize>,
    pub world_files: Vec<String>,
    pub material_files: usize,
    pub texture_files: usize,
    pub model_files: usize,
}

pub fn inspect_package(label: &str, package: &VpkArchive) -> PackageReport {
    let mut by_extension = BTreeMap::<String, usize>::new();
    let mut world_files = Vec::new();
    for path in package.entries().keys() {
        let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        *by_extension.entry(ext.clone()).or_default() += 1;
        if matches!(ext.as_str(), "vwrld_c" | "vwnod_c" | "vmap_c" | "vrman_c" | "vvis_c") {
            world_files.push(path.clone());
        }
    }
    PackageReport {
        label: label.into(),
        file_count: package.entries().len(),
        material_files: *by_extension.get("vmat_c").unwrap_or(&0),
        texture_files: *by_extension.get("vtex_c").unwrap_or(&0),
        model_files: *by_extension.get("vmdl_c").unwrap_or(&0),
        by_extension,
        world_files,
    }
}

#[derive(Clone, Debug)]
pub struct WorkshopReport {
    pub outer: PackageReport,
    pub maps: Vec<PackageReport>,
    pub nested_errors: Vec<String>,
}

pub fn inspect_workshop(directory_vpk: &Path) -> Result<WorkshopReport, String> {
    let outer = VpkArchive::open_directory(directory_vpk)?;
    let outer_report = inspect_package("workshop", &outer);
    let mut maps = Vec::new();
    let mut nested_errors = Vec::new();
    for path in outer.entries().keys().filter(|p| p.starts_with("maps/") && p.ends_with(".vpk")) {
        match outer.open_nested(path) {
            Ok(map) => maps.push(inspect_package(path, &map)),
            Err(error) => nested_errors.push(format!("{path}: {error}")),
        }
    }
    Ok(WorkshopReport { outer: outer_report, maps, nested_errors })
}
