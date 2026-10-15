//! Conservative bridge between a source VMAT and compiler-authored VCS stages.
//!
//! This is *not* executable shader selection. A VMAT parameter with the exact
//! compiler combo name and a valid value can constrain a static combination;
//! absent values, defaults, dynamic combos, bytecode blocks and source shader
//! runtime bindings must still be recovered before SurfaceProgram admission.
use std::collections::{BTreeMap, BTreeSet};
use crate::{material::Material, vcs::{VcsCensus, VcsHeader, VcsSource}};

const MAX_PAIRS_PER_MATERIAL: usize = 128;
const MAX_REPORT_EXAMPLES: usize = 8;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StageStaticChoice {
    /// These are values constrained by the actual VMAT or a compiler singleton,
    /// not a VCS packed/static combo ID.
    pub known: BTreeMap<String, i32>,
    pub unresolved: Vec<String>,
    pub invalid: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct StagePairCandidate {
    pub vertex_path: String,
    pub pixel_path: String,
    pub platform: String,
    pub shader_model: String,
    pub abi_hash: [u8; 16],
    pub vertex_static: StageStaticChoice,
    pub pixel_static: StageStaticChoice,
}

impl StagePairCandidate {
    /// A fully *constrained set of named static feature values*, not a
    /// successfully selected or decoded executable shader permutation.
    pub fn static_values_closed(&self) -> bool {
        self.vertex_static.unresolved.is_empty()
            && self.pixel_static.unresolved.is_empty()
            && self.vertex_static.invalid.is_empty()
            && self.pixel_static.invalid.is_empty()
    }

    pub fn has_invalid_values(&self) -> bool {
        !self.vertex_static.invalid.is_empty() || !self.pixel_static.invalid.is_empty()
    }

    pub fn unresolved_count(&self) -> usize {
        self.vertex_static.unresolved.len() + self.pixel_static.unresolved.len()
    }
}

#[derive(Clone, Debug, Default)]
pub struct MaterialVcsFrontier {
    pub shader_family: String,
    /// Stage matches are source/ABI compatible, not certified runtime programs.
    pub pairs: Vec<StagePairCandidate>,
    pub truncated_pairs: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SelectionCensus {
    pub vmats_checked: usize,
    pub vmats_with_abi_pair: usize,
    pub vmats_with_closed_static_values: usize,
    pub vmats_with_unresolved_values: usize,
    pub vmats_with_invalid_values: usize,
    pub compatible_pairs: usize,
    pub candidate_pairs_truncated: usize,
    pub missing_examples: Vec<String>,
    pub examples: Vec<String>,
}

fn shader_family(shader: &str) -> Option<String> {
    let base = shader.rsplit('/').next()?.strip_suffix(".vfx")?;
    if base.is_empty() { None } else { Some(base.to_ascii_lowercase()) }
}

/// Stage ABI matches must consider *all* physical sources, not a single
/// arbitrary last-seen VS and PS for each (family, platform, model).
fn stages_compatible(vertex: &VcsSource, pixel: &VcsSource) -> Option<[u8; 16]> {
    if vertex.error.is_some() || pixel.error.is_some()
        || vertex.identity.stage != "vs" || pixel.identity.stage != "ps"
        || vertex.identity.family != pixel.identity.family
        || vertex.identity.platform != pixel.identity.platform
        || vertex.identity.shader_model != pixel.identity.shader_model {
        return None;
    }
    let vertex_hdr = vertex.header.as_ref()?;
    let pixel_hdr = pixel.header.as_ref()?;
    // Do not infer unique executable IDs from a single header hash.
    // Source v72 often declares multiple program hashes for one compiler
    // stage. Both VS and PS must have a verified nonempty original list.
    if vertex_hdr.program_hashes.is_empty() || pixel_hdr.program_hashes.is_empty(){
        return None;
    }
    let abi = vertex_hdr.variable_description_hash?;
    (pixel_hdr.variable_description_hash == Some(abi)).then_some(abi)
}

/// No fabricated value zero/default for a compiler feature absent in a VMAT.
/// Identically named compiler and authored VMAT integer parameters provide a
/// constraint, not proof that the VCS permutation exists.
pub fn constrain_stage_static(header: &VcsHeader, material: &Material) -> StageStaticChoice {
    let mut result = StageStaticChoice::default();
    let Some(declared) = header.declared_static_combo_definitions else {
        result.unresolved.push("no compiler static-definition count".into());
        return result;
    };
    if declared as usize != header.static_combo_definitions.len() {
        result.unresolved.push(format!(
            "compiler definitions incomplete: decoded {}, declared {}",
            header.static_combo_definitions.len(), declared
        ));
        return result;
    }
    let mut seen = BTreeSet::new();
    for combo in &header.static_combo_definitions {
        if !seen.insert(combo.name.as_str()) {
            result.invalid.push(format!("duplicate compiler combo {}", combo.name));
            continue;
        }
        if combo.range_min > combo.range_max {
            result.invalid.push(format!("invalid compiler range {}", combo.name));
            continue;
        }
        if let Some(&value) = material.switches.get(&combo.name) {
            if value < i64::from(combo.range_min) || value > i64::from(combo.range_max) {
                result.invalid.push(format!(
                    "{}={} outside compiler range {}..{}",
                    combo.name, value, combo.range_min, combo.range_max
                ));
            } else {
                result.known.insert(combo.name.clone(), value as i32);
            }
        } else if combo.range_min == combo.range_max {
            // A singleton requires no source default inference.
            result.known.insert(combo.name.clone(), combo.range_min);
        } else {
            result.unresolved.push(format!(
                "{}: no VMAT value for compiler range {}..{}",
                combo.name, combo.range_min, combo.range_max
            ));
        }
    }
    result
}

pub fn material_candidates(material: &Material, shaders: &VcsCensus) -> MaterialVcsFrontier {
    let Some(family) = shader_family(&material.shader) else {
        return MaterialVcsFrontier::default();
    };
    let mut result = MaterialVcsFrontier { shader_family: family.clone(), ..Default::default() };
    // A distinct archive copy is not silently overwritten, even if another
    // original VCS file has the same family/stage/ABI.
    let vertex = shaders.sources.iter().filter(|s|
        s.identity.family == family && s.identity.stage == "vs"
    ).collect::<Vec<_>>();
    let pixel = shaders.sources.iter().filter(|s|
        s.identity.family == family && s.identity.stage == "ps"
    ).collect::<Vec<_>>();
    for vs in &vertex {
        for ps in &pixel {
            let Some(abi_hash) = stages_compatible(vs, ps) else { continue };
            if result.pairs.len() >= MAX_PAIRS_PER_MATERIAL {
                result.truncated_pairs = true;
                return result;
            }
            let vs_header = vs.header.as_ref().expect("verified source VS");
            let ps_header = ps.header.as_ref().expect("verified source PS");
            result.pairs.push(StagePairCandidate {
                vertex_path: format!("{} [{}]", vs.path, vs.origin),
                pixel_path: format!("{} [{}]", ps.path, ps.origin),
                platform: vs.identity.platform.clone(),
                shader_model: vs.identity.shader_model.clone(),
                abi_hash,
                vertex_static: constrain_stage_static(vs_header, material),
                pixel_static: constrain_stage_static(ps_header, material),
            });
        }
    }
    result
}

/// This diagnostic is intentionally separate from the universal renderer's
/// SurfaceProgram admission counter, which remains zero until native code and
/// bindings are decoded, lowered and executed.
pub fn audit_materials<'a>(
    materials: impl IntoIterator<Item = &'a Material>, shaders: &VcsCensus
) -> SelectionCensus {
    let mut result = SelectionCensus::default();
    for material in materials {
        result.vmats_checked += 1;
        let candidates = material_candidates(material, shaders);
        result.compatible_pairs += candidates.pairs.len();
        result.candidate_pairs_truncated += usize::from(candidates.truncated_pairs);
        if candidates.pairs.is_empty() {
            if result.missing_examples.len() < MAX_REPORT_EXAMPLES {
                result.missing_examples.push(format!(
                    "{} ({}) has no matching readable original VS/PS program-ABI pair",
                    material.path, material.shader
                ));
            }
            continue;
        }
        result.vmats_with_abi_pair += 1;
        let closed = candidates.pairs.iter().any(StagePairCandidate::static_values_closed);
        let invalid = candidates.pairs.iter().all(StagePairCandidate::has_invalid_values);
        result.vmats_with_closed_static_values += usize::from(closed);
        result.vmats_with_invalid_values += usize::from(invalid);
        result.vmats_with_unresolved_values += usize::from(!closed && !invalid);
        if result.examples.len() < MAX_REPORT_EXAMPLES {
            let best = candidates.pairs.iter()
                .min_by(|a,b| {
                    (a.has_invalid_values(), a.unresolved_count(),
                        a.platform.as_str(), a.shader_model.as_str())
                    .cmp(&(b.has_invalid_values(), b.unresolved_count(),
                        b.platform.as_str(), b.shader_model.as_str()))
                })
                .expect("nonempty candidate pairs");
            result.examples.push(format!(
                "{}: {}_{} VS={} PS={} static closed={} unresolved={} invalid={}",
                material.path, best.platform, best.shader_model, best.vertex_path,
                best.pixel_path, best.static_values_closed(),
                best.unresolved_count(), best.has_invalid_values()
            ));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vcs::{VcsComboDefinition, VcsIdentity};
    fn material() -> Material {
        Material {
            path: "materials/test.vmat_c".into(),
            material_name: "test".into(),
            shader: "csgo_complex.vfx".into(),
            textures: BTreeMap::new(),
            scalars: BTreeMap::new(),
            switches: BTreeMap::from([("F_FOG".into(), 2)]),
            unresolved_texture_files: Vec::new(),
        }
    }
    fn source(stage: &str, abi: u8, origin: &'static str) -> VcsSource {
        VcsSource {
            identity: VcsIdentity { family: "csgo_complex".into(),
                platform: "pc".into(), shader_model: "50".into(), stage: stage.into() },
            path: format!("csgo_complex_pc_50_{stage}.vcs"),
            origin,
            header: Some(VcsHeader {
                version: 69, additional_file_flags: Some(0),
                program_hash: Some([0x33; 16]),
                program_hashes: vec![[0x33; 16]],
                variable_description_hash: Some([abi; 16]),
                variable_source_max: Some(1),
                declared_static_combo_definitions: Some(1),
                static_combo_definitions: vec![VcsComboDefinition {
                    name: "F_FOG".into(), range_min: 0, range_max: 3
                }],
            }),
            error: None,
        }
    }
    #[test]
    fn exact_named_vmats_constrain_but_do_not_admit_native_bytecode() {
        let vs = source("vs", 1, "workshop");
        let ps = source("ps", 1, "base");
        let census = VcsCensus { sources: vec![vs, ps], ..Default::default() };
        let choice = material_candidates(&material(), &census);
        assert_eq!(choice.pairs.len(), 1);
        assert!(choice.pairs[0].static_values_closed());
        assert_eq!(choice.pairs[0].vertex_static.known["F_FOG"], 2);
        let summary = audit_materials([&material()], &census);
        assert_eq!(summary.vmats_with_closed_static_values, 1);
    }
    #[test]
    fn source_v72_multiple_program_hashes_do_not_hide_authentic_stage_pairs() {
        let mut vs=source("vs",8,"original v72 source");
        let mut ps=source("ps",8,"original v72 source");
        vs.header.as_mut().unwrap().program_hashes=vec![[0x11;16],[0x22;16]];
        ps.header.as_mut().unwrap().program_hashes=vec![[0x33;16],[0x44;16]];
        // The stage ABI is authenticated independent of static permutation
        // hashes; equal per-stage program hashes are NOT required.
        let c=VcsCensus{sources:vec![vs,ps],..Default::default()};
        assert_eq!(material_candidates(&material(),&c).pairs.len(),1);
        let mut missing=c.clone();
        missing.sources[0].header.as_mut().unwrap().program_hashes.clear();
        assert!(material_candidates(&material(),&missing).pairs.is_empty());
    }
    #[test]
    fn stage_pairing_preserves_valid_alternatives_instead_of_overwriting() {
        let census = VcsCensus { sources: vec![
            source("vs", 1, "workshop"),
            source("vs", 2, "base"),
            source("ps", 1, "workshop"),
            source("ps", 3, "base"),
        ], ..Default::default() };
        let candidates = material_candidates(&material(), &census);
        assert_eq!(candidates.pairs.len(), 1);
        assert_eq!(candidates.pairs[0].abi_hash, [1; 16]);
    }
    #[test]
    fn unprovided_multivalue_features_never_default_to_zero() {
        let mut mat = material();
        mat.switches.clear();
        let vcs = source("ps", 4, "base");
        let choice = constrain_stage_static(vcs.header.as_ref().unwrap(), &mat);
        assert!(choice.known.is_empty());
        assert_eq!(choice.unresolved.len(), 1);
    }
    #[test]
    fn out_of_range_and_missing_definitions_are_not_selected() {
        let mut mat = material();
        mat.switches.insert("F_FOG".into(), 99);
        let vcs = source("ps", 4, "base");
        let mut hdr = vcs.header.unwrap();
        assert_eq!(constrain_stage_static(&hdr, &mat).invalid.len(), 1);
        hdr.static_combo_definitions.clear();
        let choice = constrain_stage_static(&hdr, &mat);
        assert!(!choice.unresolved.is_empty());
        assert!(choice.known.is_empty());
    }
    #[test]
    fn singleton_compiler_ranges_are_exact_without_vmats() {
        let mut mat = material();
        mat.switches.clear();
        let vcs = source("ps", 4, "base");
        let mut hdr = vcs.header.unwrap();
        hdr.static_combo_definitions[0].range_min = 3;
        hdr.static_combo_definitions[0].range_max = 3;
        let choice = constrain_stage_static(&hdr, &mat);
        assert_eq!(choice.known["F_FOG"], 3);
        assert!(choice.unresolved.is_empty());
    }
}
