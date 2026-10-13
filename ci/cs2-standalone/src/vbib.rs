//! Source 2 VBIB / MBUF model vertex/index streams.
//! Source fields and compressed bitstream decode mirror compiled buffer metadata.
//! Nothing here guesses vertex attributes or material assignments.

const MAX_BUFFER_BYTES: usize=256*1024*1024;
const MAX_BUFFERS: usize=65536;
const MAX_FIELDS: usize=64;

fn u32_at(b:&[u8],i:usize)->Result<u32,String>{
    Ok(u32::from_le_bytes(b.get(i..i.checked_add(4).ok_or("VBIB integer overflow")?)
        .ok_or("truncated VBIB u32")?.try_into().unwrap()))
}
fn i32_at(b:&[u8],i:usize)->Result<i32,String>{Ok(u32_at(b,i)? as i32)}
fn checked_i32(i:i32,name:&str)->Result<usize,String>{
    if i<0{Err(format!("invalid negative VBIB {name}: {i}"))}else{Ok(i as usize)}
}
fn relative(base:usize,off:usize,end:usize)->Result<usize,String>{
    let at=base.checked_add(off).ok_or("VBIB offset overflow")?;
    if at>end{Err("VBIB relative range exceeds source block".into())}else{Ok(at)}
}

#[derive(Clone,Debug)]
pub struct Attribute {
    pub semantic:String,
    pub semantic_index:i32,
    pub dxgi_format:u32,
    pub offset:u32,
    pub slot:i32,
    pub slot_type:u32,
    pub instance_step:i32,
}
#[derive(Clone,Debug)]
pub struct Buffer {
    pub count:usize,
    pub stride:usize,
    pub attributes:Vec<Attribute>,
    pub bytes:Vec<u8>,
    pub meshopt_compressed:bool,
    pub zstd_compressed:bool,
}
#[derive(Clone,Debug,Default)]
pub struct MeshBuffers {
    pub vertices:Vec<Buffer>,
    pub indices:Vec<Buffer>,
}
#[derive(Clone,Copy)]
enum Kind { Vertex, Index }
fn read_buffer(bytes:&[u8],base:usize,kind:Kind)->Result<Buffer,String>{
    let count=u32_at(bytes,base)? as usize;
    let word=u32_at(bytes,base+4)?;
    let stride=(word & 0x03ffffff) as usize;
    let meshopt=(word & 0x04000000)==0;
    let zstd=(word & 0x08000000)!=0;
    if count==0 || stride==0 || stride>4096 {
        return Err(format!("invalid VBIB geometry count={count} stride={stride}"));
    }
    if matches!(kind,Kind::Index) && stride!=2 && stride!=4 {
        return Err(format!("unsupported VBIB index size {stride}"));
    }
    let raw_size=count.checked_mul(stride).ok_or("VBIB vertex byte count overflow")?;
    if raw_size>MAX_BUFFER_BYTES {return Err("VBIB geometry stream larger than allowed".into());}
    let layout_start=relative(base+8,u32_at(bytes,base+8)? as usize,bytes.len())?;
    let attribute_count=u32_at(bytes,base+12)? as usize;
    if attribute_count>MAX_FIELDS{return Err("too many VBIB attributes".into());}
    let data_start=relative(base+16,u32_at(bytes,base+16)? as usize,bytes.len())?;
    let input_size=checked_i32(i32_at(bytes,base+20)?,"stored buffer byte size")?;
    if input_size>MAX_BUFFER_BYTES{return Err("oversized compressed VBIB stream".into());}
    let input=bytes.get(data_start..data_start.checked_add(input_size).ok_or("VBIB data size overflow")?)
        .ok_or("VBIB data truncated")?;
    let mut attributes=Vec::with_capacity(attribute_count);
    for index in 0..attribute_count {
        let at=layout_start.checked_add(index.checked_mul(56).ok_or("VBIB attribute overflow")?)
            .ok_or("VBIB attribute overflow")?;
        let name=bytes.get(at..at+32).ok_or("truncated VBIB attribute name")?;
        let len=name.iter().position(|&b|b==0).unwrap_or(32);
        let semantic=std::str::from_utf8(&name[..len]).map_err(|_|"non-utf8 VBIB semantic")?.to_ascii_uppercase();
        let field=Attribute {
            semantic, semantic_index:i32_at(bytes,at+32)?,dxgi_format:u32_at(bytes,at+36)?,
            offset:u32_at(bytes,at+40)?,slot:i32_at(bytes,at+44)?,
            slot_type:u32_at(bytes,at+48)?,instance_step:i32_at(bytes,at+52)?,
        };
        if field.offset as usize >= stride {
            return Err(format!("VBIB {} offset {} outside stride {stride}",field.semantic,field.offset));
        }
        attributes.push(field);
    }
    let source=if zstd {
        zstd::bulk::decompress(input,raw_size)
            .map_err(|e|format!("VBIB zstd decompress failed: {e}"))?
    }else{input.to_vec()};
    let output=if source.len()==raw_size {source} else if meshopt {
        let mut result=vec![0u8;raw_size];
        let code=unsafe {
            match kind {
                Kind::Vertex=>meshopt::ffi::meshopt_decodeVertexBuffer(
                    result.as_mut_ptr().cast(),count,stride,source.as_ptr(),source.len()),
                Kind::Index=>meshopt::ffi::meshopt_decodeIndexBuffer(
                    result.as_mut_ptr().cast(),count,stride,source.as_ptr(),source.len()),
            }
        };
        if code!=0 {return Err(format!("VBIB meshoptimizer decoder status {code}"));}
        result
    }else{
        return Err(format!("VBIB stored {} bytes, expected {} (not meshopt)",source.len(),raw_size));
    };
    Ok(Buffer{count,stride,attributes,bytes:output,meshopt_compressed:meshopt,zstd_compressed:zstd})
}
pub fn decode(bytes:&[u8])->Result<MeshBuffers,String>{
    if bytes.len()<16 {return Err("truncated Source 2 VBIB header".into());}
    let vertex_offset=u32_at(bytes,0)? as usize;
    let vertex_count=u32_at(bytes,4)? as usize;
    let index_offset=u32_at(bytes,8)? as usize;
    let index_count=u32_at(bytes,12)? as usize;
    if vertex_count>MAX_BUFFERS || index_count>MAX_BUFFERS {
        return Err("unreasonable number of Source 2 vertex/index streams".into());
    }
    // Valve's on-disk VBIB block addresses the vertex table from the
    // start of the block, and index table relative to the word at offset 8.
    let vertex_start=relative(0,vertex_offset,bytes.len())?;
    let index_start=relative(8,index_offset,bytes.len())?;
    let mut result=MeshBuffers::default();
    for i in 0..vertex_count{
        let base=vertex_start.checked_add(i.checked_mul(24).ok_or("vertex table offset overflow")?)
            .ok_or("vertex table offset overflow")?;
        result.vertices.push(read_buffer(bytes,base,Kind::Vertex)?);
    }
    for i in 0..index_count{
        let base=index_start.checked_add(i.checked_mul(24).ok_or("index table offset overflow")?)
            .ok_or("index table offset overflow")?;
        result.indices.push(read_buffer(bytes,base,Kind::Index)?);
    }
    Ok(result)
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn raw_vertex_buffer_fields_from_source_descriptor(){
        let mut bytes=vec![0u8;256];
        let put=|b:&mut Vec<u8>,i:usize,v:u32|b[i..i+4].copy_from_slice(&v.to_le_bytes());
        put(&mut bytes,0,16);put(&mut bytes,4,1);
        let base=16;
        put(&mut bytes,base,1);put(&mut bytes,base+4,12|0x04000000);
        put(&mut bytes,base+8,16);put(&mut bytes,base+12,1);
        put(&mut bytes,base+16,80);put(&mut bytes,base+20,12);
        let attrib=base+8+16;
        bytes[attrib..attrib+8].copy_from_slice(b"POSITION");
        put(&mut bytes,attrib+36,6);
        let data=base+16+80;
        for (i,v) in [1f32,2f32,3f32].iter().enumerate(){
            bytes[data+i*4..data+i*4+4].copy_from_slice(&v.to_le_bytes());
        }
        let result=decode(&bytes).unwrap();
        assert_eq!(result.vertices.len(),1);
        assert_eq!(result.vertices[0].attributes[0].semantic,"POSITION");
        assert_eq!(result.vertices[0].count,1);
        assert_eq!(result.vertices[0].bytes.len(),12);
    }
}
