//! Fortnite 5.41 source-private importer foundation.
//!
//! The source catalog is read-only. It does not synthesize geometry, lighting,
//! collision, materials, world spawns or map-readiness from filenames.
pub mod pak;
pub mod uobject;
pub mod properties;
pub mod landscape;
pub mod weightmap;
pub mod texture;
pub mod terrain;
pub mod material;
pub mod athena;
pub mod extract;

use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
};

const MAX_VISITED_FILES: usize = 1_000_000;
const MAX_WALK_DEPTH: usize = 48;

#[derive(Debug, Clone, Default)]
pub struct LooseCounts {
    pub uasset: usize,
    pub uexp: usize,
    pub ubulk: usize,
    pub umap: usize,
    pub ini: usize,
    pub other: usize,
}

#[derive(Debug)]
pub struct ArchiveAudit {
    pub relative_path: PathBuf,
    pub result: Result<pak::PakReport, String>,
}

#[derive(Debug)]
pub struct SourceAudit {
    pub root: PathBuf,
    pub loose: LooseCounts,
    pub archives: Vec<ArchiveAudit>,
    /// Only source-backed package identities. These are NOT playable map IDs.
    pub candidate_maps: Vec<String>,
    pub visited_files: usize,
    pub warnings: Vec<String>,
}

/// Find an already-mounted/extracted source root. The R2 dashboard URL is
/// not an anonymously listable filesystem and is never treated as one.
pub fn locate_source_root() -> Option<PathBuf> {
    if let Some(configured) = env::var_os("RUST_TEST_FORTNITE_541_ROOT") {
        let configured = PathBuf::from(configured);
        return is_source_root(&configured).then_some(configured);
    }
    let mut candidates = vec![
        PathBuf::from("imports/fortnite/5.41"),
        PathBuf::from("imports/Fortnite/5.41"),
        PathBuf::from("Fortnite/5.41"),
    ];
    if let Some(profile) = env::var_os("USERPROFILE").or_else(|| env::var_os("HOME")) {
        let downloads = PathBuf::from(profile).join("Downloads");
        candidates.push(downloads.join("5.41/5.41"));
        candidates.push(downloads.join("5.41"));
    }
    candidates.into_iter().find(|p| is_source_root(p))
}

fn is_source_root(root: &Path) -> bool {
    root.join("Engine").is_dir() && root.join("FortniteGame").is_dir()
}

pub fn inspect_source(root: &Path) -> Result<SourceAudit, String> {
    if !is_source_root(root) {
        return Err(format!(
            "{} is not a Fortnite 5.41 source root (expected Engine/ and FortniteGame/)",
            root.display()
        ));
    }
    let mut audit = SourceAudit {
        root: root.to_path_buf(),
        loose: LooseCounts::default(),
        archives: Vec::new(),
        candidate_maps: Vec::new(),
        visited_files: 0,
        warnings: Vec::new(),
    };
    let mut maps = BTreeSet::<String>::new();
    let mut stack = vec![
        (root.join("Engine"), 0usize),
        (root.join("FortniteGame"), 0usize),
    ];
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_WALK_DEPTH {
            return Err(format!("Fortnite source directory exceeds {MAX_WALK_DEPTH} levels: {}",
                dir.display()));
        }
        let iterator = fs::read_dir(&dir)
            .map_err(|e| format!("Fortnite source directory {}: {e}", dir.display()))?;
        for item in iterator {
            let item = item.map_err(|e| format!("Fortnite source entry: {e}"))?;
            let path = item.path();
            let kind = item.file_type()
                .map_err(|e| format!("Fortnite source entry {}: {e}", path.display()))?;
            if kind.is_symlink() { continue; }
            if kind.is_dir() {
                stack.push((path, depth + 1));
                continue;
            }
            if !kind.is_file() { continue; }
            audit.visited_files += 1;
            if audit.visited_files > MAX_VISITED_FILES {
                return Err(format!("Fortnite source exceeds {MAX_VISITED_FILES} file audit limit"));
            }
            let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext.eq_ignore_ascii_case("pak") {
                let result = pak::inspect(&path);
                match &result {
                    Ok(report) => {
                        if let pak::IndexStatus::Indexed { mount_point, entries } = &report.status {
                            for entry in entries {
                                if entry.path.to_ascii_lowercase().ends_with(".umap") {
                                    maps.insert(format!("{mount_point}{}", entry.path).replace('\\', "/"));
                                }
                            }
                        }
                    }
                    Err(error) => audit.warnings.push(format!("{}: {error}", rel.display())),
                }
                audit.archives.push(ArchiveAudit { relative_path: rel, result });
            } else if ext.eq_ignore_ascii_case("umap") {
                audit.loose.umap += 1;
                maps.insert(rel.to_string_lossy().replace('\\', "/"));
            } else if ext.eq_ignore_ascii_case("uasset") {
                audit.loose.uasset += 1;
            } else if ext.eq_ignore_ascii_case("uexp") {
                audit.loose.uexp += 1;
            } else if ext.eq_ignore_ascii_case("ubulk") {
                audit.loose.ubulk += 1;
            } else if ext.eq_ignore_ascii_case("ini") {
                audit.loose.ini += 1;
            } else {
                audit.loose.other += 1;
            }
        }
    }
    audit.archives.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    audit.candidate_maps = maps.into_iter().collect();
    Ok(audit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_unrelated_directory() {
        let dir = std::env::temp_dir().join(format!("fn541_empty_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert!(inspect_source(&dir).unwrap_err().contains("Engine/ and FortniteGame/"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn discovers_loose_map_without_claiming_playability() {
        let dir = std::env::temp_dir().join(format!("fn541_map_{}", std::process::id()));
        fs::create_dir_all(dir.join("Engine")).unwrap();
        fs::create_dir_all(dir.join("FortniteGame/Content/Maps")).unwrap();
        fs::write(dir.join("FortniteGame/Content/Maps/Test.umap"), b"fixture").unwrap();
        let result = inspect_source(&dir).unwrap();
        assert_eq!(result.candidate_maps, vec!["FortniteGame/Content/Maps/Test.umap"]);
        assert_eq!(result.loose.umap, 1);
        fs::remove_dir_all(dir).unwrap();
    }
}
