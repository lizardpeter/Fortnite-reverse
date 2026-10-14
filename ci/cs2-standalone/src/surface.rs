//! Exact CS2 vertex streams and triangle-range lowering, preserving Source 2
//! draw-call material provenance. Engine-space transform is performed only in
//! the optional neutral-scene layer, never by the source stream decoder.
use std::collections::HashMap;
use crate::{draw::{SourceDraw,SourceModel},vbib::{Attribute,Buffer}};

#[derive(Clone,Copy,Debug,PartialEq)]
pub struct SurfaceVertex {
    pub position:[f32;3],
    pub normal:[f32;3],
    pub tangent:[f32;4],
    pub uv:[f32;2],
    pub secondary_uv:Option<[f32;2]>,
    /// Authored Source2 TEXCOORD semantic index 3, the vLightmapUV channel,
    /// distinct from TEXCOORD1 (layer UV). This is unscaled atlas UV.
    pub lightmap_uv:Option<[f32;2]>,
    /// Authored Source 2 vertex colour. Defaults to white when no COLOR
    /// attribute exists; never synthesize paint/blend-layer weights.
    pub color:[f32;4],
}
impl Default for SurfaceVertex {
    fn default()->Self {
        Self {position:[0.;3],normal:[0.;3],tangent:[0.;4],uv:[0.;2],
            secondary_uv:None,lightmap_uv:None,color:[1.;4]}
    }
}
#[derive(Clone,Debug)]
pub struct SourceSurface{
    pub material:String,
    pub vertices:Vec<SurfaceVertex>,
    pub indices:Vec<u32>,
    pub tint:Option<[f32;3]>,
    pub alpha:Option<f32>,
    pub lightmapped:bool,
}

fn read<T:TryFrom<[u8;4]>>(v:&[u8],at:usize)->Result<[u8;4],String>{
    let b=v.get(at..at.checked_add(4).ok_or("vertex byte offset overflow")?)
        .ok_or("vertex component out of bounds")?;
    Ok(b.try_into().unwrap())
}
fn f32_component(v:&[u8],at:usize)->Result<f32,String>{
    let f=f32::from_le_bytes(read::<[u8;4]>(v,at)?);
    if f.is_finite() {Ok(f)} else{Err("non-finite Source 2 vertex component".into())}
}
fn u32_component(v:&[u8],at:usize)->Result<u32,String>{
    Ok(u32::from_le_bytes(read::<[u8;4]>(v,at)?))
}
fn u16_component(v:&[u8],at:usize)->Result<u16,String>{
    let b=v.get(at..at.checked_add(2).ok_or("vertex byte offset overflow")?)
        .ok_or("vertex component out of bounds")?;
    Ok(u16::from_le_bytes(b.try_into().unwrap()))
}
fn normalize(v:[f32;3])->[f32;3]{
    let sq=v[0]*v[0]+v[1]*v[1]+v[2]*v[2];
    if sq>1e-20 {let inv=sq.sqrt().recip();[v[0]*inv,v[1]*inv,v[2]*inv]}else{[0.,0.,1.]}
}
/// Original Source 2 compressed R32_UINT normal+tangent frame (0 sign, 11
/// tangent-angle bits, 10+10 octahedral XY). Matches the upstream unpack math.
pub fn decode_packed_normal(frame:u32)->([f32;3],[f32;4]){
    let sign=frame&1;
    let angle=((frame>>1)&0x7ff) as f32/2047.*std::f32::consts::TAU;
    let x=((frame>>12)&0x3ff) as f32/1023.*2.-1.;
    let y=((frame>>22)&0x3ff) as f32/1023.*2.-1.;
    let z=1.-x.abs()-y.abs();
    let delta=(-z).clamp(0.,1.);
    let n=normalize([x+if x>=0.{-delta}else{delta},y+if y>=0.{-delta}else{delta},z]);
    let s=if n[2]>=0.{1.}else{-1.};
    let rcp=1./(s+n[2]);
    let tx=1.-s*n[0]*n[0]*rcp;
    let ty=-s*n[0]*n[1]*rcp;
    let tz=-s*n[0];
    let cos=angle.cos();
    let sin=angle.sin();
    let cross=[n[1]*tz-n[2]*ty,n[2]*tx-n[0]*tz,n[0]*ty-n[1]*tx];
    let tangent=[tx*cos+cross[0]*sin,ty*cos+cross[1]*sin,tz*cos+cross[2]*sin,
        if sign==0{-1.}else{1.}];
    (n,tangent)
}
fn vector2(v:&[u8],at:usize,format:u32)->Result<[f32;2],String>{
    match format {
        16=>Ok([f32_component(v,at)?,f32_component(v,at+4)?]), // R32G32_FLOAT
        28=>Ok([v.get(at).copied().ok_or("truncated RGBA8 UV")? as f32/255.,
                v.get(at+1).copied().ok_or("truncated RGBA8 UV")? as f32/255.]), // Source2 RGBA8 UNORM vec4; xy retained
        34=>Ok([half::f16::from_bits(u16_component(v,at)?).to_f32(),
                 half::f16::from_bits(u16_component(v,at+2)?).to_f32()]),
        35=>Ok([u16_component(v,at)? as f32/65535.,u16_component(v,at+2)? as f32/65535.]),
        37=>Ok([((u16_component(v,at)? as i16) as f32/32767.).clamp(-1.,1.),
                 ((u16_component(v,at+2)? as i16) as f32/32767.).clamp(-1.,1.)]),
        _=>Err(format!("unimplemented Source 2 TEXCOORD DXGI format {format}")),
    }
}
fn source_color(v:&[u8],at:usize,format:u32)->Result<Option<[f32;4]>,String>{
    match format {
        28=> {
            let raw=v.get(at..at.checked_add(4).ok_or("Source2 COLOR offset overflow")?)
                .ok_or("truncated source RGBA8 vertex color")?;
            Ok(Some([raw[0] as f32/255.,raw[1] as f32/255.,
                raw[2] as f32/255.,raw[3] as f32/255.]))
        },
        2=>Ok(Some([f32_component(v,at)?,f32_component(v,at+4)?,
                    f32_component(v,at+8)?,f32_component(v,at+12)?])),
        // Other authored formats require exact VDATA format translation. Do
        // not reinterpret these as blend-mask weights or drop the geometry.
        _=>Ok(None),
    }
}
fn base_vertex<'a>(stream:&'a Buffer,idx:usize)->Result<&'a [u8],String>{
    let start=idx.checked_mul(stream.stride).ok_or("vertex stride overflow")?;
    stream.bytes.get(start..start.checked_add(stream.stride).ok_or("vertex slice overflow")?)
        .ok_or_else(||format!("vertex index {idx} outside buffer"))
}
fn vertex_attributes(model:&SourceModel,draw:&SourceDraw,index:usize)->Result<SurfaceVertex,String>{
    let mut result=SurfaceVertex::default();
    let mut position=false;
    let mut normal=false;
    let mut normal_attr:Option<(&Buffer,&Attribute)>=None;
    for handle in &draw.vertex_buffers{
        let buffer=model.buffers.vertices.get(*handle).ok_or("bad source vertex stream")?;
        let bytes=base_vertex(buffer,index)?;
        for attr in &buffer.attributes{
            let at=attr.offset as usize;
            match attr.semantic.as_str(){
                "POSITION" if attr.dxgi_format==6 => {
                    result.position=[f32_component(bytes,at)?,f32_component(bytes,at+4)?,f32_component(bytes,at+8)?];
                    position=true;
                },
                "NORMAL" if attr.dxgi_format==42 => {
                    let (n,t)=decode_packed_normal(u32_component(bytes,at)?);
                    result.normal=n;result.tangent=t;normal=true;normal_attr=Some((buffer,attr));
                },
                "NORMAL" if attr.dxgi_format==6 => {
                    result.normal=normalize([f32_component(bytes,at)?,f32_component(bytes,at+4)?,f32_component(bytes,at+8)?]);
                    normal=true;normal_attr=Some((buffer,attr));
                },
                "COLOR"=>{
                    if let Some(color)=source_color(bytes,at,attr.dxgi_format)? {
                        if color.iter().all(|f|f.is_finite()){
                            result.color=color;
                        }
                    }
                },
                "TEXCOORD"=>{
                    // Do not interpret semantic index 3 as an ordinary
                    // second UV simply because it is the second buffer attr.
                    // The original Source2 CS2 v8.2 mesh layouts have
                    // TEXCOORD0 = material UV, TEXCOORD3 = baked atlas UV.
                    let uv=vector2(bytes,at,attr.dxgi_format)?;
                    match attr.semantic_index {
                        0=>{
                            result.uv=uv;
                            if attr.dxgi_format==28 {
                                let b=bytes.get(at+2..at+4)
                                    .ok_or("truncated RGBA8 source UV")?;
                                result.secondary_uv=Some([b[0] as f32/255.,b[1] as f32/255.]);
                            }
                        },
                        1=>result.secondary_uv=Some(uv),
                        3=>result.lightmap_uv=Some(uv),
                        _=>{}, // preserve geometry; other semantics still need shader binding
                    }
                },
                _=>{},
            }
        }
    }
    if !position || !normal {return Err(format!("vertex missing exact POSITION or NORMAL; normal attribute seen={}",normal_attr.is_some()));}
    Ok(result)
}
fn source_index(stream:&Buffer,index:usize)->Result<usize,String>{
    let at=index.checked_mul(stream.stride).ok_or("index offset overflow")?;
    let val=match stream.stride {
        2=>u16_component(&stream.bytes,at)? as usize,
        4=>u32_component(&stream.bytes,at)? as usize,
        _=>return Err("unsupported index stride".into()),
    };
    Ok(val)
}
pub fn lower_draw(model:&SourceModel,draw:&SourceDraw)->Result<SourceSurface,String>{
    let indices=model.buffers.indices.get(draw.index_buffer).ok_or("draw index buffer unavailable")?;
    let end=draw.start_index.checked_add(draw.index_count).ok_or("draw source index overflow")?;
    if end>indices.count || draw.index_count%3!=0{return Err("draw invalid source index range".into());}
    let primary=model.buffers.vertices.get(*draw.vertex_buffers.first().ok_or("no vertex buffer")?)
        .ok_or("source vertex buffer not found")?;
    let mut reverse=HashMap::<usize,u32>::new();
    let mut vertices=Vec::new();
    let mut output=Vec::with_capacity(draw.index_count);
    for index in draw.start_index..end {
        let raw=source_index(indices,index)?;
        let actual=(raw as i64).checked_add(draw.base_vertex).ok_or("base vertex overflow")?;
        let src=usize::try_from(actual).map_err(|_|format!("negative Source 2 vertex index {actual}"))?;
        if src>=primary.count{return Err(format!("source vertex index {src} outside {}",primary.count));}
        if let Some(i)=reverse.get(&src){output.push(*i);continue}
        let vertex=vertex_attributes(model,draw,src)?;
        let local=u32::try_from(vertices.len()).map_err(|_|"Source 2 draw exceeds u32 vertex count")?;
        vertices.push(vertex);
        reverse.insert(src,local);
        output.push(local);
    }
    Ok(SourceSurface {material:draw.material.clone(),vertices,indices:output,
        tint:draw.tint,alpha:draw.alpha,lightmapped:draw.lightmapped})
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn packed_normal_bits_produce_finite_orthogonal_tangent(){
        for source in [0,1,u32::MAX,0xab76cd13]{
            let (n,t)=decode_packed_normal(source);
            let len=(n[0]*n[0]+n[1]*n[1]+n[2]*n[2]).sqrt();
            assert!((len-1.).abs()<1e-3);
            assert!(t.iter().all(|x|x.is_finite()));
            assert!((n[0]*t[0]+n[1]*t[1]+n[2]*t[2]).abs()<1e-3);
        }
    }
    #[test]
    fn original_rgba8_vertex_tint_not_replaced_with_white(){
        let raw=[128,64,255,192];
        let c=source_color(&raw,0,28).unwrap().unwrap();
        assert!((c[0]-128./255.).abs()<1e-5);
        assert_eq!(c[2],1.);
        assert!((c[3]-192./255.).abs()<1e-5);
        assert_eq!(SurfaceVertex::default().color,[1.;4]);
        assert!(source_color(&raw,0,999).unwrap().is_none());
    }
    #[test]
    fn original_texcoord3_is_lightmap_even_if_it_precedes_texcoord0(){
        use crate::vbib::MeshBuffers;
        let mut bytes=Vec::new();
        for v in [1.0f32,2.0,3.0,0.0,0.0,1.0] {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        bytes.extend_from_slice(&[0,128,0,64]); // uv3: 0.5,0.25 R16G16_UNORM
        bytes.extend_from_slice(&[255,127,0,0]); // uv0: 1,0 R16G16_SNORM
        assert_eq!(bytes.len(),32);
        let attr=|semantic:&str,semantic_index,dxgi_format,offset|Attribute{
            semantic:semantic.into(),semantic_index,dxgi_format,offset,
            slot:0,slot_type:0,instance_step:0
        };
        let mesh=SourceModel{name:"authored.vmdl_c".into(),draws:Vec::new(),buffers:MeshBuffers{
            vertices:vec![Buffer{count:1,stride:32,bytes,meshopt_compressed:false,zstd_compressed:false,
                attributes:vec![
                    attr("POSITION",0,6,0),attr("NORMAL",0,6,12),
                    attr("TEXCOORD",3,35,24),attr("TEXCOORD",0,37,28),
                ]}],
            indices:Vec::new(),
        }};
        let draw=SourceDraw{
            material:"materials/test.vmat".into(),vertex_buffers:vec![0],
            index_buffer:0,start_index:0,index_count:0,base_vertex:0,
            tint:None,alpha:None,lightmapped:true
        };
        let vertex=vertex_attributes(&mesh,&draw,0).unwrap();
        assert!((vertex.uv[0]-1.).abs()<0.001);
        let lm=vertex.lightmap_uv.expect("authored atlas uv");
        assert!((lm[0]-0.5).abs()<0.001 && (lm[1]-0.25).abs()<0.001);
        assert!(vertex.secondary_uv.is_none());
    }
    #[test]
    fn source_lightmap_uv_is_a_separate_authored_attribute(){
        let source=SurfaceVertex::default();
        assert_eq!(source.uv,[0.;2]);
        assert_eq!(source.secondary_uv,None);
        assert_eq!(source.lightmap_uv,None);
        // Source2 TEXCOORD3 DXGI35 is R16G16_UNORM.
        let bytes=[0xff,0x7f,0,0x80];
        let uv=vector2(&bytes,0,35).unwrap();
        assert!((uv[0]-0.5).abs()<0.00003);
        assert!((uv[1]-0.5).abs()<0.00003);
    }
    #[test]
    fn signed_uvs_decode_negative_source_values(){
        let b=[0x01,0x80,0xff,0x7f];
        let uv=vector2(&b,0,37).unwrap();
        assert!((uv[0]+1.).abs()<1e-2&&uv[1]>0.999);
    }
}
