//! Compiled Source 2 render mesh draw calls and their original buffer/material
//! bindings. This module never supplies fallback names, default materials, or
//! invented indices: a primitive is admitted only with an authored draw call.
use crate::{kv3::{self,Value},resource::ResourceHeader,vbib::{self,MeshBuffers}};

#[derive(Clone,Debug)]
pub struct SourceDraw {
    pub material: String,
    pub vertex_buffers: Vec<usize>,
    pub index_buffer:usize,
    pub start_index:usize,
    pub index_count:usize,
    pub base_vertex:i64,
    pub tint: Option<[f32;3]>,
    pub alpha: Option<f32>,
    pub lightmapped:bool,
}
#[derive(Clone,Debug)]
pub struct SourceModel {
    pub draws:Vec<SourceDraw>,
    pub buffers:MeshBuffers,
    pub name: String,
}
fn integer(value:&Value,name:&str)->Result<i64,String>{
    let f=value.as_float().ok_or_else(||format!("source draw missing numeric {name}"))?;
    if !f.is_finite()||f.fract()!=0.||f.abs()>9_007_199_254_740_992. {
        return Err(format!("invalid Source 2 {name}={f}"));
    }
    Ok(f as i64)
}
fn required<'a>(obj:&'a Value,name:&str)->Result<&'a Value,String>{
    obj.field(name).ok_or_else(||format!("source draw missing {name}"))
}
fn positive(v:&Value,name:&str)->Result<usize,String>{
    usize::try_from(integer(v,name)?).map_err(|_|format!("invalid negative source {name}"))
}
fn buffer_handle(obj:&Value)->Result<usize,String>{
    positive(required(obj,"m_hBuffer")?,"m_hBuffer")
}
pub fn source_draws(root:&Value)->Result<Vec<SourceDraw>,String>{
    let scenes=required(root,"m_sceneObjects")?.as_array()
        .ok_or("Source 2 MDAT m_sceneObjects not array")?;
    let mut out=Vec::new();
    for scene in scenes {
        let draw_calls=required(scene,"m_drawCalls")?.as_array().ok_or("Source 2 m_drawCalls not array")?;
        for draw in draw_calls {
            let typ=required(draw,"m_nPrimitiveType")?.as_text()
                .ok_or("missing Source 2 primitive type")?;
            if typ!="RENDER_PRIM_TRIANGLES" {return Err(format!("unsupported Source 2 primitive {typ}"));}
            let material=required(draw,"m_material")?.as_text()
                .ok_or("Source 2 draw has no original material reference")?.to_owned();
            if !material.ends_with(".vmat") || material.contains("..") || material.contains('\\') {
                return Err(format!("invalid Source 2 material path {material}"));
            }
            let handles=required(draw,"m_vertexBuffers")?.as_array().ok_or("draw vertex buffers not array")?;
            let mut vertex_buffers=Vec::with_capacity(handles.len());
            for b in handles {vertex_buffers.push(buffer_handle(b)?);}
            if vertex_buffers.is_empty(){return Err("draw has no vertex buffers".into());}
            let index_buffer=buffer_handle(required(draw,"m_indexBuffer")?)?;
            let start_index=positive(required(draw,"m_nStartIndex")?,"m_nStartIndex")?;
            let index_count=positive(required(draw,"m_nIndexCount")?,"m_nIndexCount")?;
            let base_vertex=integer(required(draw,"m_nBaseVertex")?,"m_nBaseVertex")?;
            if index_count==0 || index_count%3!=0 {return Err("source triangle draw index count is not divisible by three".into());}
            let tint=draw.field("m_vTintColor").and_then(Value::as_array).and_then(|a|{
                if a.len()!=3 {return None}
                let v=[a[0].as_float()? as f32,a[1].as_float()? as f32,a[2].as_float()? as f32];
                v.iter().all(|x|x.is_finite()).then_some(v)
            });
            let alpha=draw.field("m_flAlpha").and_then(Value::as_float).map(|v|v as f32);
            let lightmapped=matches!(draw.field("m_bHasBakedLightingFromLightMap"),Some(Value::Bool(true)));
            out.push(SourceDraw{material,vertex_buffers,index_buffer,start_index,index_count,base_vertex,tint,alpha,lightmapped});
            if out.len()>250_000{return Err("Source 2 model draw count exceeds limit".into());}
        }
    }
    Ok(out)
}
pub fn decode_model(file:&[u8],name:&str)->Result<SourceModel,String>{
    let header=ResourceHeader::parse(file)?;
    let mdat=header.block(file,b"MDAT").ok_or("Source 2 model missing original MDAT mesh metadata")?;
    let buffers=header.block(file,b"MBUF").ok_or("Source 2 model missing MBUF geometry")?;
    let source=kv3::decode(mdat)?.root;
    let draws=source_draws(&source)?;
    let buffers=vbib::decode(buffers)?;
    for (i,draw) in draws.iter().enumerate(){
        for v in &draw.vertex_buffers {
            if *v>=buffers.vertices.len() {
                return Err(format!("{name} draw {i}: authored vertex buffer {v} unavailable"));
            }
        }
        let index=buffers.indices.get(draw.index_buffer)
            .ok_or_else(||format!("{name} draw {i}: index buffer {} unavailable",draw.index_buffer))?;
        if draw.start_index.checked_add(draw.index_count).ok_or("draw index range overflow")?>index.count{
            return Err(format!("{name} draw {i}: index range extends beyond source stream"));
        }
    }
    Ok(SourceModel{name:name.to_owned(),draws,buffers})
}

#[cfg(test)]
mod tests{
    use super::*;
    fn num(i:i64)->Value{Value::Int(i)}
    fn obj(v:Vec<(&str,Value)>)->Value{Value::Object(v.into_iter().map(|(k,v)|(k.to_owned(),v)).collect())}
    #[test]
    fn original_material_and_triangle_bounds_are_required(){
        let draw=obj(vec![
            ("m_nPrimitiveType",Value::Text("RENDER_PRIM_TRIANGLES".into())),
            ("m_material",Value::Text("materials/source/test.vmat".into())),
            ("m_indexBuffer",obj(vec![("m_hBuffer",num(0))])),
            ("m_vertexBuffers",Value::Array(vec![obj(vec![("m_hBuffer",num(0))])])),
            ("m_nStartIndex",num(6)),("m_nIndexCount",num(12)),("m_nBaseVertex",num(0))
        ]);
        let root=obj(vec![("m_sceneObjects",Value::Array(vec![obj(vec![("m_drawCalls",Value::Array(vec![draw]))])]))]);
        let d=source_draws(&root).unwrap();
        assert_eq!(d[0].index_count,12);
        assert_eq!(d[0].material,"materials/source/test.vmat");
    }
    #[test]
    fn non_triangles_are_rejected(){
        let root=obj(vec![("m_sceneObjects",Value::Array(vec![obj(vec![("m_drawCalls",Value::Array(vec![
            obj(vec![("m_nPrimitiveType",Value::Text("RENDER_PRIM_LINES".into()))])
        ]))])]))]);
        assert!(source_draws(&root).is_err());
    }
}
