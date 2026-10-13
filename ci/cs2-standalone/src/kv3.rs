//! Source 2 binary KeyValues3 v5, with bounded buffer decompression and
//! source-faithful typed lanes. No guessed strings, scene defaults or geometry.
//! Future render lowering consumes the parsed values, not exported glTF.
//!
//! Unsupported encodings fail closed rather than returning an empty world.
const KV3_V5: u32 = 0x4b563305;
const TRAILER: u32 = 0xffeedd00;
const MAX_PAYLOAD: usize = 256 * 1024 * 1024;
const MAX_VALUES: usize = 2_000_000;
const MAX_DEPTH: usize = 96;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    Text(String),
    Blob(Vec<u8>),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
    Flagged(u8, Box<Value>),
}
impl Value {
    pub fn field(&self, name: &str) -> Option<&Value> {
        match self {
            Self::Object(fields) => fields.iter().rev().find(|(key,_)| key==name).map(|(_,v)|v),
            Self::Flagged(_,x) => x.field(name),
            _ => None,
        }
    }
    pub fn as_array(&self)->Option<&[Value]> {
        match self { Self::Array(a)=>Some(a),Self::Flagged(_,v)=>v.as_array(),_=>None }
    }
    pub fn as_text(&self)->Option<&str> {
        match self { Self::Text(t)=>Some(t),Self::Flagged(_,v)=>v.as_text(),_=>None }
    }
    pub fn as_float(&self)->Option<f64> {
        match self { Self::Float(v)=>Some(*v),Self::Int(v)=>Some(*v as f64),Self::UInt(v)=>Some(*v as f64),
        Self::Flagged(_,v)=>v.as_float(),_=>None }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub version: u8,
    pub compression: u32,
    pub format_id: [u8;16],
    pub count_types: usize,
    pub count_strings_buffer1: usize,
    pub buffer1_uncompressed: usize,
    pub buffer2_uncompressed: usize,
    pub binary_blob_bytes: usize,
    pub block_count: usize,
}

fn uint(bytes:&[u8],at:usize)->Result<u32,String>{
    let b=bytes.get(at..at.checked_add(4).ok_or("KV3 offset overflow")?).ok_or("truncated KV3 u32")?;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}
fn signed(bytes:&[u8],at:usize)->Result<i32,String>{ Ok(uint(bytes,at)? as i32) }
fn small(bytes:&[u8],at:usize)->Result<u16,String>{
    let b=bytes.get(at..at.checked_add(2).ok_or("KV3 offset overflow")?).ok_or("truncated KV3 u16")?;
    Ok(u16::from_le_bytes(b.try_into().unwrap()))
}
fn checked(value:i32,label:&str)->Result<usize,String>{
    if value<0 { Err(format!("negative KV3 {label}: {value}")) } else { Ok(value as usize) }
}
fn align(n:usize,b:usize)->Result<usize,String>{
    n.checked_add(b-1).map(|x|x & !(b-1)).ok_or("KV3 alignment overflow".into())
}
#[derive(Clone)]
struct Lane<'a>{ bytes:&'a [u8], at:usize }
impl<'a> Lane<'a>{
    fn take(&mut self,size:usize)->Result<&'a [u8],String>{
        let end=self.at.checked_add(size).ok_or("KV3 lane offset overflow")?;
        let result=self.bytes.get(self.at..end).ok_or_else(||format!("KV3 lane overrun ({}+{} > {})",self.at,size,self.bytes.len()))?;
        self.at=end;
        Ok(result)
    }
    fn byte(&mut self)->Result<u8,String>{ Ok(self.take(1)?[0]) }
    fn i32(&mut self)->Result<i32,String>{ Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    fn u32(&mut self)->Result<u32,String>{ Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    fn i64(&mut self)->Result<i64,String>{ Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    fn u64(&mut self)->Result<u64,String>{ Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    fn f32(&mut self)->Result<f32,String>{ Ok(f32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    fn f64(&mut self)->Result<f64,String>{ Ok(f64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    fn u16(&mut self)->Result<u16,String>{ Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap())) }
    fn i16(&mut self)->Result<i16,String>{ Ok(i16::from_le_bytes(self.take(2)?.try_into().unwrap())) }
    fn remaining(&self)->usize { self.bytes.len()-self.at }
}
#[derive(Clone)]
struct Lanes<'a> { b1:Lane<'a>, b2:Lane<'a>, b4:Lane<'a>, b8:Lane<'a> }
impl<'a> Lanes<'a>{
    fn new()->Self{
        let e=Lane { bytes:&[],at:0 };
        Self{b1:e.clone(),b2:e.clone(),b4:e.clone(),b8:e}
    }
}
struct Reader<'a> {
    types: Lane<'a>,
    names: Vec<String>,
    main: Lanes<'a>,
    auxiliary: Lanes<'a>,
    objects: Lane<'a>,
    blobs: Lane<'a>,
    lengths: Lane<'a>,
    visited: usize,
    legacy_object_lengths: bool,
}

fn read_type(reader:&mut Reader<'_>)->Result<(u8,u8),String>{
    let tag=reader.types.byte()?;
    let flag=if tag & 0x80!=0 {reader.types.byte()?}else{0};
    if tag & 0x40!=0 {let _=reader.types.byte()?;}
    let kind=tag & 0x3f;
    if kind==0 || kind>25 {return Err(format!("unsupported KV3 scalar kind {kind}"));}
    Ok((kind,flag))
}
fn read_text(reader:&mut Reader<'_>)->Result<String,String>{
    let id=reader.main.b4.i32()?;
    if id==-1{return Ok(String::new());}
    reader.names.get(checked(id,"string reference")?).cloned()
        .ok_or_else(||format!("KV3 unresolved source string id {id}"))
}
fn read_value(reader:&mut Reader<'_>,kind:u8,flag:u8,auxiliary:bool,depth:usize)->Result<Value,String>{
    if depth>MAX_DEPTH{return Err("KV3 exceeds recursion depth".into());}
    reader.visited+=1;
    if reader.visited>MAX_VALUES{return Err("KV3 exceeds node-count limit".into());}
    let value=match kind {
        1=>Value::Null,
        2=>Value::Bool(if auxiliary {reader.auxiliary.b1.byte()?} else {reader.main.b1.byte()?}!=0),
        3=>Value::Int(if auxiliary {reader.auxiliary.b8.i64()?} else {reader.main.b8.i64()?}),
        4=>Value::UInt(if auxiliary {reader.auxiliary.b8.u64()?} else {reader.main.b8.u64()?}),
        5=>Value::Float(if auxiliary {reader.auxiliary.b8.f64()?} else {reader.main.b8.f64()?}),
        6=>Value::Text(read_text(reader)?),
        7=>{
            let length=checked(reader.lengths.i32()?,"binary blob size")?;
            if length>MAX_PAYLOAD{return Err("KV3 binary blob too large".into());}
            Value::Blob(reader.blobs.take(length)?.to_vec())
        },
        8=>{
            let count=checked(reader.main.b4.i32()?,"array size")?;
            if count>MAX_VALUES{return Err("KV3 array exceeds node-count bound".into());}
            let mut items=Vec::with_capacity(count);
            for _ in 0..count {
                let (kind,flag)=read_type(reader)?;
                items.push(read_value(reader,kind,flag,false,depth+1)?);
            }
            Value::Array(items)
        },
        9=>{
            let count=checked(if reader.legacy_object_lengths { reader.main.b4.i32()? } else { reader.objects.i32()? },"object size")?;
            if count>MAX_VALUES{return Err("KV3 object exceeds node-count bound".into());}
            let mut members=Vec::with_capacity(count);
            for _ in 0..count {
                let (kind,flag)=read_type(reader)?;
                let name=read_text(reader)?;
                let value=read_value(reader,kind,flag,false,depth+1)?;
                members.push((name,value));
            }
            Value::Object(members)
        },
        10|24|25=>{
            let count=if kind==10 {checked(reader.main.b4.i32()?,"typed array size")?} else {reader.main.b1.byte()? as usize};
            if count==0 || count>MAX_VALUES {return Err("invalid KV3 typed-array length".into());}
            let (element,eflag)=read_type(reader)?;
            let mut result=Vec::with_capacity(count);
            for _ in 0..count{
                result.push(read_value(reader,element,eflag,kind==25,depth+1)?);
            }
            Value::Array(result)
        },
        11=>Value::Int(if auxiliary {reader.auxiliary.b4.i32()?}else{reader.main.b4.i32()?} as i64),
        12=>Value::UInt(if auxiliary {reader.auxiliary.b4.u32()?}else{reader.main.b4.u32()?} as u64),
        13=>Value::Bool(true), 14=>Value::Bool(false),
        15=>Value::Int(0),16=>Value::Int(1),
        17=>Value::Float(0.0),18=>Value::Float(1.0),
        19=>Value::Float(if auxiliary {reader.auxiliary.b4.f32()?}else{reader.main.b4.f32()?} as f64),
        20=>Value::Int(if auxiliary {reader.auxiliary.b2.i16()?}else{reader.main.b2.i16()?} as i64),
        21=>Value::UInt(if auxiliary {reader.auxiliary.b2.u16()?}else{reader.main.b2.u16()?} as u64),
        22=>Value::Int(if auxiliary {reader.auxiliary.b1.byte()?}else{reader.main.b1.byte()?} as i8 as i64),
        23=>Value::UInt(if auxiliary {reader.auxiliary.b1.byte()?}else{reader.main.b1.byte()?} as u64),
        _=>return Err(format!("unknown binary KV3 type {kind}")),
    };
    Ok(if flag==0 {value}else{Value::Flagged(flag,Box::new(value))})
}
fn decoded(compression:u32,bytes:&[u8],uncompressed:usize,compressed:usize)->Result<Vec<u8>,String>{
    if uncompressed>MAX_PAYLOAD{return Err("KV3 decompressed buffer exceeds hard size limit".into());}
    match compression {
        0=>{
            if bytes.len()<uncompressed {return Err("truncated uncompressed KV3 buffer".into());}
            Ok(bytes[..uncompressed].to_vec())
        },
        1=>{
            let buf=bytes.get(..compressed).ok_or("truncated LZ4 KV3 buffer")?;
            lz4_flex::block::decompress(buf,uncompressed)
                .map_err(|e|format!("KV3 LZ4 decompress failed: {e}"))
        },
        2=>{
            let buf=bytes.get(..compressed).ok_or("truncated Zstd KV3 buffer")?;
            zstd::bulk::decompress(buf,uncompressed)
                .map_err(|e|format!("KV3 zstd decompress failed: {e}"))
                .and_then(|out|if out.len()==uncompressed {Ok(out)}else{Err("KV3 zstd output size mismatch".into())})
        },
        _=>Err(format!("unknown KV3 compression {compression}")),
    }
}
#[derive(Debug)]
pub struct Document {pub header: Header,pub root: Value,pub nodes:usize,pub string_count:usize}
pub fn decode(bytes:&[u8])->Result<Document,String>{
    if uint(bytes,0)?==0x4b563304 {return decode_v4(bytes);}
    if uint(bytes,0)?!=KV3_V5{return Err("unsupported Source 2 KV3 format".into());}
    if bytes.len()<120 {return Err("truncated KV3 version 5 header".into());}
    let mut format_id=[0;16];format_id.copy_from_slice(&bytes[4..20]);
    let compression=uint(bytes,20)?;
    let dict=small(bytes,24)?;
    let frame=small(bytes,26)?;
    if dict!=0 {return Err(format!("KV3 dictionary {dict} unsupported"));}
    if compression==0 && frame!=0 {return Err("invalid uncompressed KV3 frame".into());}
    let count1=checked(signed(bytes,28)?,"bytes1")?;
    let count4=checked(signed(bytes,32)?,"bytes4")?;
    let count8=checked(signed(bytes,36)?,"bytes8")?;
    let types_count=checked(signed(bytes,40)?,"types")?;
    let _objects1=small(bytes,44)? as usize;
    let _arrays1=small(bytes,46)? as usize;
    let total=checked(signed(bytes,48)?,"total uncompressed")?;
    let compressed_total=checked(signed(bytes,52)?,"total compressed")?;
    let blocks=checked(signed(bytes,56)?,"blobs count")?;
    let binary_blob_bytes=checked(signed(bytes,60)?,"blob byte size")?;
    let count2=checked(signed(bytes,64)?,"bytes2")?;
    let _compressed_table=checked(signed(bytes,68)?,"block sizes")?;
    let u1=checked(signed(bytes,72)?,"uncompressed buffer 1")?;
    let c1=checked(signed(bytes,76)?,"compressed buffer 1")?;
    let u2=checked(signed(bytes,80)?,"uncompressed buffer 2")?;
    let c2=checked(signed(bytes,84)?,"compressed buffer 2")?;
    let b1_2=checked(signed(bytes,88)?,"buffer 2 bytes1")?;
    let b2_2=checked(signed(bytes,92)?,"buffer 2 bytes2")?;
    let b4_2=checked(signed(bytes,96)?,"buffer 2 bytes4")?;
    let b8_2=checked(signed(bytes,100)?,"buffer 2 bytes8")?;
    let _node_hint=checked(signed(bytes,104)?,"node hint")?;
    let objects2=checked(signed(bytes,108)?,"buffer 2 objects")?;
    let _arrays2=checked(signed(bytes,112)?,"buffer 2 arrays")?;
    let _array_elements=checked(signed(bytes,116)?,"buffer 2 array elements")?;
    if total!=u1+u2 || u1>MAX_PAYLOAD || u2>MAX_PAYLOAD || compressed_total>MAX_PAYLOAD {
        return Err("invalid KV3 advertised buffer extent".into());
    }
    if types_count>MAX_VALUES || objects2>MAX_VALUES || blocks>MAX_VALUES {
        return Err("KV3 advertised value counts exceed limits".into());
    }
    if blocks!=0 {
        return Err(format!("KV3 external binary blobs ({blocks} blocks, {binary_blob_bytes} bytes) not yet supported"));
    }
    let consumed1=if compression==0 {u1}else{c1};
    let consumed2=if compression==0 {u2}else{c2};
    let end1=120usize.checked_add(consumed1).ok_or("KV3 extent overflow")?;
    let end2=end1.checked_add(consumed2).ok_or("KV3 extent overflow")?;
    if end2>bytes.len() {return Err("truncated KV3 compressed buffers".into());}
    let bytes1=decoded(compression,&bytes[120..end1],u1,c1)?;
    let bytes2=decoded(compression,&bytes[end1..end2],u2,c2)?;
    let mut first=Lanes::new();
    let mut cursor=0;
    first.b1=Lane{bytes:bytes1.get(cursor..count1).ok_or("KV3 first bytes1 range")?,at:0};
    cursor=count1;
    cursor=align(cursor,2)?;
    let size2=count2.checked_mul(2).ok_or("KV3 first bytes2 overflow")?;
    first.b2=Lane{bytes:bytes1.get(cursor..cursor.checked_add(size2).ok_or("KV3 offset overflow")?).ok_or("KV3 first bytes2 range")?,at:0};
    cursor+=size2;
    cursor=align(cursor,4)?;
    let size4=count4.checked_mul(4).ok_or("KV3 first bytes4 overflow")?;
    first.b4=Lane{bytes:bytes1.get(cursor..cursor.checked_add(size4).ok_or("KV3 offset overflow")?).ok_or("KV3 first bytes4 range")?,at:0};
    cursor+=size4;
    if count8>0 { cursor=align(cursor,8)?; }
    let size8=count8.checked_mul(8).ok_or("KV3 first bytes8 overflow")?;
    first.b8=Lane{bytes:bytes1.get(cursor..cursor.checked_add(size8).ok_or("KV3 offset overflow")?).ok_or("KV3 first bytes8 range")?,at:0};
    cursor+=size8;
    if cursor!=bytes1.len(){return Err(format!("KV3 buffer 1 lane mismatch: {cursor} vs {}",bytes1.len()));}
    let strings=checked(first.b4.i32()?,"string count")?;
    if strings>MAX_VALUES {return Err("KV3 string count exceeds maximum".into());}
    let mut names=Vec::with_capacity(strings);
    for _ in 0..strings{
        let rest=&first.b1.bytes[first.b1.at..];
        let end=rest.iter().position(|b|*b==0).ok_or("unterminated KV3 string")?;
        if end>65536 {return Err("KV3 source string too long".into());}
        names.push(std::str::from_utf8(&rest[..end]).map_err(|_|"invalid KV3 UTF-8")?.to_owned());
        first.b1.at+=end+1;
    }
    let mut second=Lanes::new();
    let mut cursor2=0;
    let object_length_bytes=objects2.checked_mul(4).ok_or("KV3 object lengths overflow")?;
    let objects=Lane{bytes:bytes2.get(0..object_length_bytes).ok_or("KV3 object length lane overrun")?,at:0};
    cursor2+=object_length_bytes;
    second.b1=Lane{bytes:bytes2.get(cursor2..cursor2.checked_add(b1_2).ok_or("KV3 offset overflow")?).ok_or("KV3 second bytes1 range")?,at:0};
    cursor2+=b1_2;
    cursor2=align(cursor2,2)?;
    let size2b=b2_2.checked_mul(2).ok_or("KV3 buffer 2 bytes2 overflow")?;
    second.b2=Lane{bytes:bytes2.get(cursor2..cursor2.checked_add(size2b).ok_or("KV3 offset overflow")?).ok_or("KV3 second bytes2 range")?,at:0};
    cursor2+=size2b;
    cursor2=align(cursor2,4)?;
    let size4b=b4_2.checked_mul(4).ok_or("KV3 buffer 2 bytes4 overflow")?;
    second.b4=Lane{bytes:bytes2.get(cursor2..cursor2.checked_add(size4b).ok_or("KV3 offset overflow")?).ok_or("KV3 second bytes4 range")?,at:0};
    cursor2+=size4b;
    if b8_2>0 { cursor2=align(cursor2,8)?; }
    let size8b=b8_2.checked_mul(8).ok_or("KV3 buffer 2 bytes8 overflow")?;
    second.b8=Lane{bytes:bytes2.get(cursor2..cursor2.checked_add(size8b).ok_or("KV3 offset overflow")?).ok_or("KV3 second bytes8 range")?,at:0};
    cursor2+=size8b;
    let type_end=cursor2.checked_add(types_count).ok_or("KV3 type byte overflow")?;
    let type_bytes=bytes2.get(cursor2..type_end).ok_or("KV3 type byte lane overrun")?;
    let marker=uint(&bytes2,type_end)?;
    if marker!=TRAILER{return Err(format!("invalid KV3 trailer 0x{marker:08x}"));}
    let mut reader=Reader{
        types:Lane{bytes:type_bytes,at:0},names,
        main:second,auxiliary:first,objects,
        blobs:Lane{bytes:&[],at:0}, lengths:Lane{bytes:&[],at:0},
        visited:0,legacy_object_lengths:false,
    };
    let (kind,flag)=read_type(&mut reader)?;
    let root=read_value(&mut reader,kind,flag,false,0)?;
    if reader.types.remaining()!=0 || reader.objects.remaining()!=0 {
        return Err(format!("KV3 trailing types={} object lengths={}",reader.types.remaining(),reader.objects.remaining()));
    }
    Ok(Document{
        header:Header{version:5,compression,format_id,count_types:types_count,
            count_strings_buffer1:strings,buffer1_uncompressed:u1,buffer2_uncompressed:u2,
            binary_blob_bytes,block_count:blocks},
        root,nodes:reader.visited,string_count:reader.names.len()
    })
}
/// Version 4 encodes interned strings and the type stream in the same
/// compressed buffer. Object lengths are read from the 4-byte lane.
fn decode_v4(bytes:&[u8])->Result<Document,String>{
    if bytes.len()<72 {return Err("truncated binary KV3 v4 header".into());}
    let mut format_id=[0;16];format_id.copy_from_slice(&bytes[4..20]);
    let compression=uint(bytes,20)?;
    let dict=small(bytes,24)?;
    let frame=small(bytes,26)?;
    if dict!=0 {return Err(format!("KV3 dictionary {dict} unsupported"));}
    if compression==0 && frame!=0 {return Err("invalid KV3 compression frame".into());}
    let n1=checked(signed(bytes,28)?,"v4 byte1")?;
    let n4=checked(signed(bytes,32)?,"v4 byte4")?;
    let n8=checked(signed(bytes,36)?,"v4 byte8")?;
    let types_total=checked(signed(bytes,40)?,"v4 type section")?;
    let _objects_hint=small(bytes,44)?;
    let _arrays_hint=small(bytes,46)?;
    let uncompressed=checked(signed(bytes,48)?,"v4 uncompressed buffer")?;
    let compressed=checked(signed(bytes,52)?,"v4 compressed buffer")?;
    let blocks=checked(signed(bytes,56)?,"v4 blobs")?;
    let binary_blob_bytes=checked(signed(bytes,60)?,"v4 blob bytes")?;
    let n2=checked(signed(bytes,64)?,"v4 byte2")?;
    let _block_sizes=checked(signed(bytes,68)?,"v4 block compressed sizes")?;
    if blocks!=0 {return Err(format!("KV3 v4 binary blob support pending ({blocks} blocks)"));}
    let take=if compression==0 {uncompressed}else{compressed};
    let end=72usize.checked_add(take).ok_or("KV3 v4 byte offset overflow")?;
    if end>bytes.len(){return Err("truncated KV3 v4 payload".into());}
    let decompressed=decoded(compression,&bytes[72..end],uncompressed,compressed)?;
    let mut lanes=Lanes::new();
    let mut cursor=0usize;
    lanes.b1=Lane{bytes:decompressed.get(0..n1).ok_or("short v4 bytes1")?,at:0};
    cursor+=n1;
    cursor=align(cursor,2)?;
    let len2=n2.checked_mul(2).ok_or("v4 bytes2 overflow")?;
    lanes.b2=Lane{bytes:decompressed.get(cursor..cursor.checked_add(len2).ok_or("v4 range overflow")?).ok_or("short v4 bytes2")?,at:0};
    cursor+=len2;
    cursor=align(cursor,4)?;
    let len4=n4.checked_mul(4).ok_or("v4 bytes4 overflow")?;
    lanes.b4=Lane{bytes:decompressed.get(cursor..cursor.checked_add(len4).ok_or("v4 range overflow")?).ok_or("short v4 bytes4")?,at:0};
    cursor+=len4;
    cursor=align(cursor,8)?;
    let len8=n8.checked_mul(8).ok_or("v4 bytes8 overflow")?;
    lanes.b8=Lane{bytes:decompressed.get(cursor..cursor.checked_add(len8).ok_or("v4 range overflow")?).ok_or("short v4 bytes8")?,at:0};
    cursor+=len8;
    cursor=align(cursor,8)?;
    let strings_start=cursor;
    let num_strings=checked(lanes.b4.i32()?,"v4 strings")?;
    if num_strings>MAX_VALUES {return Err("KV3 v4 string count excessive".into());}
    let mut names=Vec::with_capacity(num_strings);
    for _ in 0..num_strings {
        let rest=decompressed.get(cursor..).ok_or("v4 string cursor out of bounds")?;
        let endstr=rest.iter().position(|b|*b==0).ok_or("unterminated KV3 v4 string")?;
        if endstr>65536{return Err("KV3 v4 source string too long".into());}
        names.push(std::str::from_utf8(&rest[..endstr]).map_err(|_|"invalid UTF-8 v4 source string")?.to_owned());
        cursor+=endstr+1;
    }
    let type_end=strings_start.checked_add(types_total).ok_or("KV3 v4 type range overflow")?;
    if type_end<cursor {return Err("KV3 v4 types overlap strings".into());}
    let types=decompressed.get(cursor..type_end).ok_or("truncated KV3 v4 types")?;
    let trailer=uint(&decompressed,type_end)?;
    if trailer!=TRAILER{return Err(format!("invalid KV3 v4 trailer 0x{trailer:08x}"));}
    let mut reader=Reader{
        types:Lane{bytes:types,at:0},names,main:lanes.clone(),auxiliary:lanes,
        objects:Lane{bytes:&[],at:0},blobs:Lane{bytes:&[],at:0},lengths:Lane{bytes:&[],at:0},
        visited:0,legacy_object_lengths:true,
    };
    let (kind,flag)=read_type(&mut reader)?;
    let root=read_value(&mut reader,kind,flag,false,0)?;
    if reader.types.remaining()!=0 {return Err("KV3 v4 unread type tokens".into());}
    Ok(Document{
        header:Header{version:4,compression,format_id,count_types:types.len(),
            count_strings_buffer1:num_strings,buffer1_uncompressed:uncompressed,
            buffer2_uncompressed:0,binary_blob_bytes,block_count:blocks},
        root,nodes:reader.visited,string_count:reader.names.len()
    })
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn uncompressed_v5_source_object(){
        // Strings: "model", "props/box.vmdl". One source object with a string.
        let strings=b"model\0props/box.vmdl\0";
        let mut lane1=strings.to_vec();
        lane1.resize(align(lane1.len(),4).unwrap(),0);
        lane1.extend_from_slice(&2i32.to_le_bytes()); // number of interned strings
        let mut lane2=Vec::new();
        lane2.extend_from_slice(&1i32.to_le_bytes()); // root object field count
        lane2.extend_from_slice(&0i32.to_le_bytes()); // name id
        lane2.extend_from_slice(&1i32.to_le_bytes()); // value string id
        lane2.extend_from_slice(&[9,6]); // root object and member string
        lane2.extend_from_slice(&TRAILER.to_le_bytes());
        let mut bytes=vec![0;120];
        bytes[0..4].copy_from_slice(&KV3_V5.to_le_bytes());
        let set=|b:&mut Vec<u8>,at:usize,v:i32|b[at..at+4].copy_from_slice(&v.to_le_bytes());
        set(&mut bytes,20,0);
        set(&mut bytes,28,strings.len() as i32);
        set(&mut bytes,32,1);
        set(&mut bytes,40,2);
        set(&mut bytes,48,(lane1.len()+lane2.len()) as i32);
        set(&mut bytes,72,lane1.len() as i32);
        set(&mut bytes,80,lane2.len() as i32);
        set(&mut bytes,96,2);
        set(&mut bytes,104,2);
        set(&mut bytes,108,1);
        bytes.extend_from_slice(&lane1);
        bytes.extend_from_slice(&lane2);
        let doc=decode(&bytes).unwrap();
        assert_eq!(doc.string_count,2);
        assert_eq!(doc.root.field("model").unwrap().as_text(),Some("props/box.vmdl"));
    }
}
