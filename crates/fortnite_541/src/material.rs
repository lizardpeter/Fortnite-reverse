//! Source-authored UE4 material expression dependency graph.
//!
//! MaterialExpression classes, FPackageIndex references, parameter FNames,
//! and tagged FExpressionInput links are retained as source data. This is NOT
//! a shader translator and does not claim SurfaceProgram admission.
use crate::{properties, uobject::PackageCatalog};
use std::collections::{BTreeMap,BTreeSet};

#[derive(Debug,Clone)]
pub struct MaterialReference {
    pub property: String,
    pub target: i32,
    pub source_path: String,
}
#[derive(Debug,Clone)]
pub struct MaterialExpression {
    pub export_index: i32,
    pub class_name: String,
    pub object_name: String,
    pub parameters: Vec<(String,String)>,
    pub references: Vec<MaterialReference>,
    pub expression_inputs: Vec<MaterialReference>,
    pub properties: Vec<(String,String,usize)>,
    /// Original nested LandscapeLayerBlend records, not synthesized layer
    /// colors or approximated shader operations.
    pub landscape_layers: Vec<LandscapeBlendLayer>,
}

/// Exact cooked FExpressionInput reference plus all 40 uninterpreted source
/// bytes: output selectors, channel mask and legacy flags remain available.
#[derive(Debug,Clone)]
pub struct SourceExpressionInput {
    pub target: i32,
    pub source_path: String,
    pub serialized: [u8;40],
}
#[derive(Debug,Clone)]
pub struct LandscapeBlendLayer {
    pub name: String,
    pub blend_type: String,
    pub layer_input: SourceExpressionInput,
    pub height_input: SourceExpressionInput,
    pub preview_weight: f32,
    pub constant_layer_input: [f32;3],
    pub constant_height_input: f32,
}
#[derive(Debug,Default,Clone)]
pub struct MaterialGraph {
    pub expressions: Vec<MaterialExpression>,
    pub class_counts: BTreeMap<String,usize>,
    pub external_dependencies: BTreeSet<String>,
    pub unresolved: Vec<String>,
}

fn ref_name(catalog:&PackageCatalog,reference:i32)->Result<String,String>{
    catalog.source_object_path(reference)
}
fn name_value(catalog:&PackageCatalog,source:&[u8])->Result<String,String>{
    if source.len()!=8{return Err("FName property data not eight bytes".into());}
    let name=u32::from_le_bytes(source[0..4].try_into().unwrap()) as usize;
    let number=u32::from_le_bytes(source[4..8].try_into().unwrap());
    let text=catalog.names.get(name).ok_or("material parameter has bad FName index")?;
    Ok(if number==0{text.to_owned()}else{format!("{text}#{number}")})
}
fn reference(catalog:&PackageCatalog,prop:&str,raw:&[u8])->Result<MaterialReference,String>{
    if raw.len()<4 {return Err(format!("source material property {prop} has short UObject ref"));}
    let target=i32::from_le_bytes(raw[0..4].try_into().unwrap());
    Ok(MaterialReference{
        property:prop.to_owned(),target,
        source_path:ref_name(catalog,target)?,
    })
}


fn f_name(catalog:&PackageCatalog,data:&[u8])->Result<String,String>{
    if data.len()!=8 {return Err("source FName must be 8 bytes".into());}
    name_value(catalog,data)
}
fn typed_field<'a>(
    p:&'a properties::Properties,
    bytes:&'a [u8],
    name:&str,kind:&str,length:usize,
)->Result<&'a [u8],String>{
    let f=p.fields.iter().filter(|field|field.name==name).collect::<Vec<_>>();
    if f.len()!=1 ||f[0].kind!=kind ||f[0].payload.len()!=length {
        return Err(format!("source LandscapeLayerBlend field {name} not exact {kind}[{length}]"));
    }
    Ok(&bytes[f[0].payload.clone()])
}
fn source_link(catalog:&PackageCatalog,data:&[u8])->Result<SourceExpressionInput,String>{
    if data.len()!=40{return Err("original FExpressionInput must be 40 bytes".into());}
    let serialized:[u8;40]=data.try_into().unwrap();
    let target=i32::from_le_bytes(serialized[..4].try_into().unwrap());
    Ok(SourceExpressionInput{
        target,source_path:catalog.source_object_path(target)?,serialized,
    })
}

/// Decode all original landscape blend names, blend types, constants, and
/// author-defined expression references from the cooked nested array. This
/// is a source shader AST layer; it does not claim full shader execution.
pub fn decode_landscape_blend_layers(
    catalog:&PackageCatalog,
    bytes:&[u8],
)->Result<Vec<LandscapeBlendLayer>,String>{
    const HEADER:usize=53; // FScriptArray count + 49-byte StructProperty tag
    const RECORD:usize=379; // UE4.21 serialized LandscapeLayerBlendInput
    if bytes.len()<HEADER {return Err("source LayerBlend array truncated".into());}
    let count=u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    if count==0 ||count>32 ||bytes.len()!=HEADER+count*RECORD {
        return Err(format!("original LayerBlend nested array count {count} vs {} bytes",bytes.len()));
    }
    let hdr=&bytes[4..HEADER];
    if f_name(catalog,&hdr[0..8])?!="Layers"||
        f_name(catalog,&hdr[8..16])?!="StructProperty" ||
        u32::from_le_bytes(hdr[16..20].try_into().unwrap()) as usize !=count*RECORD ||
        u32::from_le_bytes(hdr[20..24].try_into().unwrap())!=0 ||
        hdr[32..48].iter().any(|x|*x!=0)||hdr[48]!=0{
        return Err("cooked LayerBlend inner struct tag inconsistent with source".into());
    }
    let source_struct_name=f_name(catalog,&hdr[24..32])?;
    if !source_struct_name.contains("LayerBlend") {
        return Err(format!("unexpected nested blend input struct type {source_struct_name}"));
    }
    let mut out=Vec::with_capacity(count);
    for (i,serialized) in bytes[HEADER..].chunks_exact(RECORD).enumerate(){
        let props=properties::scan(catalog,serialized)?;
        if props.bytes_consumed!=RECORD||props.fields.len()!=7{
            return Err(format!("source LayerBlend layer {i} expected 7 tagged fields in {RECORD} bytes"));
        }
        let layer_name=f_name(catalog,typed_field(&props,serialized,"LayerName","NameProperty",8)?)?;
        let field=props.fields.iter().find(|p|p.name=="BlendType")
            .ok_or("LayerBlend BlendType missing")?;
        if field.metadata.first().map(String::as_str)!=Some("ELandscapeLayerBlendType"){
            return Err("original LayerBlend enum type mismatch".into());
        }
        let blend_type=f_name(catalog,typed_field(&props,serialized,"BlendType","ByteProperty",8)?)?;
        // There are three original UE4 landscape blend operators; unknown
        // variants must be investigated instead of silently misinterpreted.
        if !matches!(blend_type.as_str(),"LB_WeightBlend"|"LB_AlphaBlend"|"LB_HeightBlend"){
            return Err(format!("unsupported source LayerBlend blend type {blend_type}"));
        }
        let layer_input=source_link(catalog,typed_field(&props,serialized,"LayerInput","StructProperty",40)?)?;
        let height_input=source_link(catalog,typed_field(&props,serialized,"HeightInput","StructProperty",40)?)?;
        let weight_raw=typed_field(&props,serialized,"PreviewWeight","FloatProperty",4)?;
        let preview_weight=f32::from_le_bytes(weight_raw.try_into().unwrap());
        let input_raw=typed_field(&props,serialized,"ConstLayerInput","StructProperty",12)?;
        let mut constant_layer_input=[0f32;3];
        for j in 0..3 {
            constant_layer_input[j]=f32::from_le_bytes(input_raw[j*4..j*4+4].try_into().unwrap());
        }
        let height_raw=typed_field(&props,serialized,"ConstHeightInput","FloatProperty",4)?;
        let constant_height_input=f32::from_le_bytes(height_raw.try_into().unwrap());
        if !preview_weight.is_finite()||!constant_height_input.is_finite()||
            constant_layer_input.iter().any(|v|!v.is_finite()){
            return Err("original landscape layer has non-finite authored constants".into());
        }
        out.push(LandscapeBlendLayer {
            name:layer_name,blend_type,layer_input,height_input,
            preview_weight,constant_layer_input,constant_height_input,
        });
    }
    Ok(out)
}

/// Extract the exact references in a cooked material's original UObject
/// export stream, including a conservative 40-byte FExpressionInput link
/// when its StructProperty source metadata explicitly proves that type.
pub fn inspect(catalog:&PackageCatalog,package:&[u8],companion:&[u8])->MaterialGraph{
    let mut graph=MaterialGraph::default();
    for (ordinal,export) in catalog.exports.iter().enumerate(){
        let Some(class)=catalog.export_class_name(export) else {
            graph.unresolved.push(format!("export {} class unresolved",ordinal+1));
            continue
        };
        if !class.starts_with("MaterialExpression"){continue}
        let source=match catalog.export_data(package,companion,export){
            Ok(v)=>v,Err(e)=>{
                graph.unresolved.push(format!("export {} serialized bytes: {e}",ordinal+1));
                continue
            }
        };
        let fields=match properties::scan(catalog,source){
            Ok(v)=>v,Err(e)=>{
                graph.unresolved.push(format!("export {} tagged data: {e}",ordinal+1));
                continue
            }
        };
        let mut node=MaterialExpression{
            export_index:ordinal as i32+1,
            class_name:class.to_owned(),
            object_name:catalog.names.get(export.object_name.name_index as usize)
                .cloned().unwrap_or_else(||"<unresolved>".into()),
            parameters:Vec::new(),references:Vec::new(),
            expression_inputs:Vec::new(),properties:Vec::new(),
            landscape_layers:Vec::new(),
        };
        for field in fields.fields{
            let raw=&source[field.payload.clone()];
            node.properties.push((field.name.clone(),field.kind.clone(),raw.len()));
            match field.kind.as_str(){
                "ArrayProperty" if class=="MaterialExpressionLandscapeLayerBlend"
                    &&field.name=="Layers" =>{
                    match decode_landscape_blend_layers(catalog,raw){
                        Ok(layers)=>node.landscape_layers=layers,
                        Err(e)=>graph.unresolved.push(format!("export {} nested Layers: {e}",ordinal+1)),
                    }
                },
                "NameProperty" if raw.len()==8=>{
                    match name_value(catalog,raw){
                        Ok(n)=>node.parameters.push((field.name.clone(),n)),
                        Err(e)=>graph.unresolved.push(format!("export {} FName {}: {e}",ordinal+1,field.name)),
                    }
                },
                "ObjectProperty" | "ClassProperty" if raw.len()==4=>{
                    match reference(catalog,&field.name,raw){
                        Ok(r)=>{
                            if r.target<0{graph.external_dependencies.insert(r.source_path.clone());}
                            node.references.push(r);
                        }
                        Err(e)=>graph.unresolved.push(format!("export {} property {}: {e}",ordinal+1,field.name)),
                    }
                },
                "StructProperty" if field.metadata.first().map(String::as_str)==Some("ExpressionInput")=>{
                    if raw.len()==40{
                        match reference(catalog,&field.name,raw){
                            Ok(r)=>node.expression_inputs.push(r),
                            Err(e)=>graph.unresolved.push(format!("export {} expression input {}: {e}",ordinal+1,field.name)),
                        }
                    }else{
                        graph.unresolved.push(format!("export {} unexpected input {} size {}",ordinal+1,field.name,raw.len()));
                    }
                },
                _=>{}
            }
        }
        *graph.class_counts.entry(class.to_owned()).or_default()+=1;
        graph.expressions.push(node);
    }
    graph
}
