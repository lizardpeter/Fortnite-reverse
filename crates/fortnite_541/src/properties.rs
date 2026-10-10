//! Conservative UE4.21 source-authored UObject FPropertyTag reader.
//! No property names/values are synthesized. Unknown tag types or malformed
//! type-specific metadata fail closed, preserving original export bytes.
use crate::uobject::PackageCatalog;
use std::ops::Range;

const MAX_PROPERTIES: usize = 20_000;
const MAX_EXPORT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    pub name: String,
    pub kind: String,
    pub array_index: i32,
    /// Byte positions inside this exact source UObject's serialized bytes.
    pub payload: Range<usize>,
    pub metadata: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Properties {
    pub fields: Vec<Property>,
    /// First byte after the source-defined `None` terminator.
    pub bytes_consumed: usize,
}

fn u32_at(bytes: &[u8], pos: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(bytes.get(pos..pos+4)
        .ok_or("truncated FPropertyTag metadata")?.try_into().unwrap()))
}
fn i32_at(bytes: &[u8], pos: usize) -> Result<i32, String> {
    Ok(i32::from_le_bytes(bytes.get(pos..pos+4)
        .ok_or("truncated FPropertyTag metadata")?.try_into().unwrap()))
}
fn next(pos: &mut usize, len: usize, total: usize) -> Result<(), String> {
    *pos = pos.checked_add(len).ok_or("FPropertyTag offset overflow")?;
    if *pos > total { return Err("FPropertyTag byte span exits object".into()); }
    Ok(())
}
fn name<'a>(catalog: &'a PackageCatalog, bytes: &[u8], pos: &mut usize)
    -> Result<&'a str, String> {
    let index = u32_at(bytes, *pos)?;
    let _instance = u32_at(bytes, *pos + 4)?;
    next(pos, 8, bytes.len())?;
    catalog.names.get(index as usize).map(String::as_str)
        .ok_or_else(|| format!("FPropertyTag references missing source FName {index}"))
}

/// Read a stream of UE4 tagged properties; `None` terminates tagged fields.
/// Return exact byte offsets and original type data only (no PBR fallback).
pub fn scan(catalog: &PackageCatalog, bytes: &[u8]) -> Result<Properties, String> {
    if bytes.len() > MAX_EXPORT_BYTES { return Err("source object exceeds property audit limit".into()); }
    let mut pos = 0;
    let mut fields = Vec::new();
    for _ in 0..MAX_PROPERTIES {
        let property = name(catalog, bytes, &mut pos)?;
        if property == "None" {
            return Ok(Properties { fields, bytes_consumed: pos });
        }
        let property = property.to_owned();
        let kind = name(catalog, bytes, &mut pos)?.to_owned();
        let size = i32_at(bytes, pos)?;
        let array_index = i32_at(bytes, pos + 4)?;
        if size < 0 || array_index < 0 { return Err("invalid UE4 property value size or array index".into()); }
        next(&mut pos, 8, bytes.len())?;
        let mut metadata = Vec::new();
        match kind.as_str() {
            "StructProperty" => {
                metadata.push(name(catalog, bytes, &mut pos)?.to_owned());
                next(&mut pos, 16, bytes.len())?; // source StructGuid
            }
            "BoolProperty" => {
                metadata.push(format!("bool_value={}", bytes.get(pos)
                    .ok_or("truncated BoolProperty tag")?));
                next(&mut pos, 1, bytes.len())?;
            }
            "ByteProperty" | "EnumProperty" | "ArrayProperty" | "SetProperty" => {
                metadata.push(name(catalog, bytes, &mut pos)?.to_owned());
            }
            "MapProperty" => {
                metadata.push(name(catalog, bytes, &mut pos)?.to_owned());
                metadata.push(name(catalog, bytes, &mut pos)?.to_owned());
            }
            "ObjectProperty" | "WeakObjectProperty" | "LazyObjectProperty" |
            "SoftObjectProperty" | "AssetObjectProperty" | "ClassProperty" |
            "IntProperty" | "Int8Property" | "Int16Property" | "Int64Property" |
            "UInt16Property" | "UInt32Property" | "UInt64Property" |
            "FloatProperty" | "DoubleProperty" | "StrProperty" |
            "NameProperty" | "TextProperty" | "InterfaceProperty" |
            "MulticastDelegateProperty" | "DelegateProperty" => {}
            _ => return Err(format!("unproven UE4 FPropertyTag type {kind:?}")),
        }
        // UE4.21 serializes a source-authored bHasPropertyGuid byte on each
        // cooked FPropertyTag, following any type-specific tag metadata.
        // Its absence caused a one-byte desync on real Athena components.
        let has_guid = *bytes.get(pos).ok_or("missing property GUID flag")?;
        if has_guid > 1 { return Err("invalid property GUID presence flag".into()); }
        next(&mut pos, 1, bytes.len())?;
        if has_guid == 1 {
            next(&mut pos, 16, bytes.len())?;
        }
        let start = pos;
        next(&mut pos, size as usize, bytes.len())?;
        fields.push(Property {name: property, kind, array_index, payload: start..pos, metadata});
    }
    Err("source UObject property count exceeds validated bound".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uobject::{PackageCatalog,PackageSummary};
    fn tiny(names: &[&str]) -> PackageCatalog {
        PackageCatalog {
            summary: PackageSummary {
                total_header_size: 0, folder_name: String::new(),
                flags: 0, unversioned: true, name_count: names.len() as u32,
                name_offset: 0, export_count: 0, export_offset: 0,
                import_count: 0, import_offset: 0, depends_offset: 0,
            },
            names: names.iter().map(|s| s.to_string()).collect(),
            imports: Vec::new(), exports: Vec::new(),
        }
    }
    #[test]
    fn reads_exact_int_property_and_none() {
        let names = tiny(&["None","SectionBaseX","IntProperty"]);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.push(0); // bHasPropertyGuid is false in retail UE4.21 tags.
        bytes.extend_from_slice(&127u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        let result = scan(&names, &bytes).unwrap();
        assert_eq!(result.fields.len(),1);
        assert_eq!(result.fields[0].name,"SectionBaseX");
        assert_eq!(&bytes[result.fields[0].payload.clone()], &127u32.to_le_bytes());
        assert_eq!(result.bytes_consumed,37);
    }
    #[test]
    fn rejects_invalid_property_name_index() {
        let names = tiny(&["None"]);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert!(scan(&names, &bytes).unwrap_err().contains("missing source FName"));
    }
}
