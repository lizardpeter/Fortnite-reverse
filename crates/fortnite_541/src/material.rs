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
        };
        for field in fields.fields{
            let raw=&source[field.payload.clone()];
            node.properties.push((field.name.clone(),field.kind.clone(),raw.len()));
            match field.kind.as_str(){
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
