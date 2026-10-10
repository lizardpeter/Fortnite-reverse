//! Bounded source-authored UE4.21 cooked package name/TOC recovery.
//! Fortnite 5.41 packages are commonly unversioned (-7 legacy summary).
//! This module does not guess actors, meshes, transforms or physics.
use std::str;

const MAGIC: u32 = 0x9E2A_83C1;
const MAX_NAME_COUNT: usize = 250_000;
const MAX_TEXT_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSummary {
    pub total_header_size: u32,
    pub folder_name: String,
    pub flags: u32,
    pub unversioned: bool,
    pub name_count: u32,
    pub name_offset: u32,
    pub export_count: u32,
    pub export_offset: u32,
    pub import_count: u32,
    pub import_offset: u32,
    pub depends_offset: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceName {
    pub name_index: u32,
    pub instance_number: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageImport {
    pub class_package: SourceName,
    pub class_name: SourceName,
    pub outer_index: i32,
    pub object_name: SourceName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageExport {
    pub class_index: i32,
    pub super_index: i32,
    pub template_index: i32,
    pub outer_index: i32,
    pub object_name: SourceName,
    pub object_flags: u32,
    pub serialized_size: i64,
    pub serialized_offset: i64,
}

#[derive(Debug, Clone)]
pub struct PackageCatalog {
    pub summary: PackageSummary,
    pub names: Vec<String>,
    pub imports: Vec<PackageImport>,
    pub exports: Vec<PackageExport>,
}

impl PackageCatalog {
    /// Resolve UE4 FPackageIndex semantics into a source table name.
    ///  0 is null, negative is -(import index+1), positive is export index+1.
    pub fn resolve_package_name(&self, reference: i32) -> Option<&str> {
        if reference == 0 {
            return None;
        }
        let name_index = if reference < 0 {
            let index = usize::try_from(i64::from(reference).checked_neg()?.checked_sub(1)?).ok()?;
            self.imports.get(index)?.object_name.name_index
        } else {
            let index = usize::try_from(reference - 1).ok()?;
            self.exports.get(index)?.object_name.name_index
        };
        self.names.get(name_index as usize).map(String::as_str)
    }

    /// Follow the original UE4 FPackageIndex Outer chain, preserving each
    /// exact source FName and instance number rather than flattening distinct
    /// texture/material/object records into generic class names.
    pub fn source_object_chain(&self, reference: i32) -> Result<Vec<(String,u32)>, String> {
        let mut reference=reference;
        let mut chain=Vec::<(String,u32)>::new();
        let mut visited=std::collections::HashSet::<i32>::new();
        while reference!=0 {
            if chain.len()>1024 || !visited.insert(reference) {
                return Err("cyclic or excessive UE4 source UObject outer chain".into());
            }
            let (name,outer)=if reference<0 {
                let n=i64::from(reference).checked_neg().and_then(|v|v.checked_sub(1))
                    .ok_or("invalid negative UObject import reference")?;
                let index=usize::try_from(n).map_err(|_| "UObject import index overflow")?;
                let source=self.imports.get(index).ok_or("unresolved UObject import in outer chain")?;
                (source.object_name,source.outer_index)
            } else {
                let index=usize::try_from(reference-1).map_err(|_| "UObject export index overflow")?;
                let source=self.exports.get(index).ok_or("unresolved UObject export in outer chain")?;
                (source.object_name,source.outer_index)
            };
            let name_text=self.names.get(name.name_index as usize)
                .ok_or("UObject outer chain references missing original FName")?;
            chain.push((name_text.clone(),name.instance_number));
            reference=outer;
        }
        chain.reverse();
        Ok(chain)
    }

    pub fn source_object_path(&self,reference:i32)->Result<String,String> {
        let chain=self.source_object_chain(reference)?;
        Ok(chain.iter().map(|(name,number)|{
            if *number==0 {name.clone()} else {format!("{name}#{}",number)}
        }).collect::<Vec<_>>().join("::"))
    }

    /// Resolve an export class by source-authored package reference; never
    /// assume an unreferenced actor or material class.
    pub fn export_class_name(&self, export: &PackageExport) -> Option<&str> {
        self.resolve_package_name(export.class_index)
    }

    /// A split cooked UE4 package stores exported data in the companion .uexp.
    /// SerialOffset is relative to the logical concatenation of .umap and
    /// .uexp; this function uses the actual header length, not a heuristic.
    pub fn export_data<'a>(
        &self,
        package_file: &[u8],
        companion_uexp: &'a [u8],
        export: &PackageExport,
    ) -> Result<&'a [u8], String> {
        let file_header = i64::try_from(package_file.len()).map_err(|_| "header too large")?;
        let source_offset = export.serialized_offset.checked_sub(file_header)
            .ok_or("UE4 export serial offset underflow")?;
        let start = usize::try_from(source_offset)
            .map_err(|_| "source export serial offset predates .uexp")?;
        let len = usize::try_from(export.serialized_size)
            .map_err(|_| "source export has invalid serialization length")?;
        let end = start.checked_add(len).ok_or("UE4 export serial span overflow")?;
        companion_uexp.get(start..end).ok_or_else(||
            "UE4 source export escapes companion .uexp bytes".to_owned())
    }
}

struct Reader<'a> { data: &'a [u8], pos: usize }
impl<'a> Reader<'a> {
    fn at(data: &'a [u8], pos: usize) -> Result<Self, String> {
        if pos > data.len() { return Err("package offset exceeds source file".into()); }
        Ok(Self { data, pos })
    }
    fn bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(len).ok_or("package field offset overflow")?;
        let bytes = self.data.get(self.pos..end).ok_or("truncated cooked package field")?;
        self.pos = end;
        Ok(bytes)
    }
    fn i32(&mut self) -> Result<i32, String> {
        Ok(i32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, String> {
        Ok(i64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }
    fn name(&mut self) -> Result<SourceName, String> {
        Ok(SourceName {
            name_index: self.u32()?,
            instance_number: self.u32()?,
        })
    }
    fn string(&mut self) -> Result<String, String> {
        let count = self.i32()?;
        if count == 0 { return Ok(String::new()); }
        if count > 0 {
            let length = usize::try_from(count).map_err(|_| "invalid name string length")?;
            if length > MAX_TEXT_BYTES { return Err("source name exceeds byte limit".into()); }
            let raw = self.bytes(length)?;
            if raw.last() != Some(&0) { return Err("non-terminated source name".into()); }
            return str::from_utf8(&raw[..length - 1])
                .map(|s| s.to_owned()).map_err(|_| "non-UTF8 source name".into());
        }
        let length = usize::try_from(count.checked_neg().ok_or("invalid UTF16 name length")?)
            .map_err(|_| "invalid UTF16 name length")?;
        if length > MAX_TEXT_BYTES / 2 { return Err("source UTF16 name exceeds byte limit".into()); }
        let raw = self.bytes(length.checked_mul(2).ok_or("UTF16 length overflow")?)?;
        if !raw.ends_with(&[0, 0]) { return Err("non-terminated UTF16 source name".into()); }
        let utf16 = raw[..raw.len() - 2].chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&utf16).map_err(|_| "invalid UTF16 source name".into())
    }
}

/// Recover source-authored package summaries and FName map for Fortnite 5.41.
/// The imported game uses UE4.21 unversioned cooked packages; FName serialized
/// entries contain an FString plus a pair of source hashing u16 fields.
pub fn inspect(bytes: &[u8]) -> Result<PackageCatalog, String> {
    let mut r = Reader::at(bytes, 0)?;
    if r.u32()? != MAGIC { return Err("not a little-endian UE4 package".into()); }
    let legacy = r.i32()?;
    if legacy != -7 {
        return Err(format!("unsupported UE4 package legacy summary {legacy}, expected -7"));
    }
    let _legacy_ue3 = r.i32()?;
    let file_ue4 = r.i32()?;
    let file_licensee = r.i32()?;
    let versions = r.i32()?;
    if versions != 0 {
        return Err(format!("UE4 custom-version table (count={versions}) not yet supported"));
    }
    let total_header_size = r.u32()?;
    if total_header_size as usize > bytes.len() {
        return Err("UE4 total header size escapes source .umap".into());
    }
    let folder_name = r.string()?;
    let flags = r.u32()?;
    let name_count = r.u32()?;
    let name_offset = r.u32()?;
    let _gatherable_text_count = r.u32()?;
    let _gatherable_text_offset = r.u32()?;
    let export_count = r.u32()?;
    let export_offset = r.u32()?;
    let import_count = r.u32()?;
    let import_offset = r.u32()?;
    let depends_offset = r.u32()?;
    let summary = PackageSummary {
        total_header_size, folder_name, flags,
        unversioned: file_ue4 == 0 && file_licensee == 0,
        name_count, name_offset, export_count, export_offset,
        import_count, import_offset, depends_offset,
    };
    if name_count as usize > MAX_NAME_COUNT ||
        [name_offset, export_offset, import_offset].iter().any(|v| *v as usize > bytes.len()) {
        return Err("invalid cooked name/import/export table limits".into());
    }
    let mut names_reader = Reader::at(bytes, name_offset as usize)?;
    let mut names = Vec::with_capacity(name_count as usize);
    for _ in 0..name_count {
        names.push(names_reader.string()?);
        names_reader.bytes(4)?; // FNameEntrySerialized non-case/case hash pair.
    }
    if (import_count != 0 && names_reader.pos > import_offset as usize) ||
        (export_count != 0 && names_reader.pos > export_offset as usize) {
        return Err("name map crosses source import/export table".into());
    }
    // This build's cooked FObjectImport records are exactly 28 bytes:
    // two FNames, FPackageIndex, and the object FName. FObjectExport records
    // occupy 104 bytes up to DependsOffset. Fail closed if a different
    // version/layout is encountered instead of inventing actor relationships.
    const IMPORT_BYTES: usize = 28;
    const EXPORT_BYTES: usize = 104;
    let count_i = usize::try_from(import_count).map_err(|_| "import count too large")?;
    let count_e = usize::try_from(export_count).map_err(|_| "export count too large")?;
    let expected_import_end = (import_offset as usize)
        .checked_add(count_i.checked_mul(IMPORT_BYTES).ok_or("import size overflow")?)
        .ok_or("import end overflow")?;
    let expected_export_end = (export_offset as usize)
        .checked_add(count_e.checked_mul(EXPORT_BYTES).ok_or("export size overflow")?)
        .ok_or("export end overflow")?;
    if expected_import_end != export_offset as usize ||
        expected_export_end != depends_offset as usize ||
        expected_export_end > bytes.len() {
        return Err("unsupported UE4.21 cooked import/export record stride".into());
    }

    let mut r_import = Reader::at(bytes, import_offset as usize)?;
    let mut imports = Vec::with_capacity(count_i);
    for _ in 0..count_i {
        let class_package = r_import.name()?;
        let class_name = r_import.name()?;
        let outer_index = r_import.i32()?;
        let object_name = r_import.name()?;
        for value in [class_package, class_name, object_name] {
            if value.name_index >= name_count {
                return Err("source import FName index out of bounds".into());
            }
        }
        imports.push(PackageImport { class_package, class_name, outer_index, object_name });
    }
    let mut r_export = Reader::at(bytes, export_offset as usize)?;
    let mut exports = Vec::with_capacity(count_e);
    for _ in 0..count_e {
        let class_index = r_export.i32()?;
        let super_index = r_export.i32()?;
        let template_index = r_export.i32()?;
        let outer_index = r_export.i32()?;
        let object_name = r_export.name()?;
        if object_name.name_index >= name_count {
            return Err("source export FName index out of bounds".into());
        }
        let object_flags = r_export.u32()?;
        let serialized_size = r_export.i64()?;
        let serialized_offset = r_export.i64()?;
        if serialized_size < 0 || serialized_offset < 0 {
            return Err("invalid negative source export length or offset".into());
        }
        // Preserve the remaining version-specific flags, GUID and dependency
        // metadata for later precise lowering; do not pretend to interpret it.
        r_export.bytes(EXPORT_BYTES - 44)?;
        exports.push(PackageExport {
            class_index, super_index, template_index, outer_index,
            object_name, object_flags, serialized_size, serialized_offset,
        });
    }
    Ok(PackageCatalog { summary, names, imports, exports })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_truncated_and_wrong_magic_packages() {
        assert!(inspect(&[]).is_err());
        assert!(inspect(&[0u8; 200]).is_err());
    }
    #[test]
    fn rejects_oversized_name_map() {
        let mut package = vec![0u8; 193];
        package[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        package[4..8].copy_from_slice(&(-7i32).to_le_bytes());
        package[24..28].copy_from_slice(&193u32.to_le_bytes());
        package[28..32].copy_from_slice(&5i32.to_le_bytes());
        package[32..37].copy_from_slice(b"None\0");
        package[41..45].copy_from_slice(&u32::MAX.to_le_bytes());
        package[45..49].copy_from_slice(&193u32.to_le_bytes());
        assert!(inspect(&package).unwrap_err().contains("invalid cooked name"));
    }
}
