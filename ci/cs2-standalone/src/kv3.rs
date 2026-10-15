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
/// Valve's compiled Source 2 KV3 v4/v5 DATA blocks are raw LZ4 *blocks*,
/// not an LZ4 frame and not a length-prefixed block. Consume precisely the
/// compressed buffer advertised by the KV3 header and accept a final
/// literals-only sequence as the terminator. The output size is an external
/// signed header value already checked against MAX_PAYLOAD.
fn decode_source2_lz4_block(input:&[u8],expected:usize)->Result<Vec<u8>,String>{
    if expected>MAX_PAYLOAD {return Err("KV3 LZ4 decoded size exceeds limit".into());}
    let mut result=Vec::with_capacity(expected);
    let mut cursor=0usize;
    let extended=|start:usize,source:&[u8],cursor:&mut usize|->Result<usize,String>{
        let mut length=start;
        if start==15 {
            loop {
                let extra=*source.get(*cursor).ok_or(
                    "truncated KV3 LZ4 extended length"
                )? as usize;
                *cursor+=1;
                length=length.checked_add(extra)
                    .ok_or("KV3 LZ4 length overflow")?;
                if extra!=255 {break;}
            }
        }
        Ok(length)
    };
    while cursor<input.len(){
        let token=input[cursor];
        cursor+=1;
        let literal_length=extended((token>>4) as usize,input,&mut cursor)?;
        let end=cursor.checked_add(literal_length)
            .ok_or("KV3 LZ4 literal extent overflow")?;
        let literal=input.get(cursor..end)
            .ok_or("KV3 LZ4 literals exceed compressed input")?;
        if result.len().checked_add(literal_length)
            .is_none_or(|length|length>expected){
            return Err("KV3 LZ4 literals exceed declared output".into());
        }
        result.extend_from_slice(literal);
        cursor=end;
        // LZ4 raw blocks terminate with a literals-only sequence; do not
        // attempt to read an offset after the final source literal.
        if cursor==input.len() {break;}
        let offset_end=cursor.checked_add(2)
            .ok_or("KV3 LZ4 offset overflow")?;
        let offset_bytes=input.get(cursor..offset_end)
            .ok_or("KV3 LZ4 match offset truncated")?;
        let offset=u16::from_le_bytes([offset_bytes[0],offset_bytes[1]]) as usize;
        cursor=offset_end;
        if offset==0 || offset>result.len(){
            return Err("KV3 LZ4 invalid match offset".into());
        }
        let length=extended((token&15) as usize,input,&mut cursor)?
            .checked_add(4).ok_or("KV3 LZ4 match length overflow")?;
        if result.len().checked_add(length)
            .is_none_or(|size|size>expected){
            return Err("KV3 LZ4 match exceeds declared output".into());
        }
        // The source format explicitly permits overlapping match copies.
        for _ in 0..length {
            let value=result[result.len()-offset];
            result.push(value);
        }
    }
    if result.len()!=expected || cursor!=input.len(){
        return Err(format!(
            "KV3 LZ4 output size mismatch: {} decoded vs {expected} advertised",
            result.len()
        ));
    }
    Ok(result)
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
            decode_source2_lz4_block(buf,uncompressed)
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
    // Compiled CS2 entity lumps often contain hundreds of *zero-length*
    // binary attributes. Their lengths still occupy the KV3 trailer lane.
    // Preserve these authored binary slots rather than rejecting the lump.
    if blocks==0 && binary_blob_bytes!=0 {
        return Err("KV3 has a binary payload without binary blob descriptors".into());
    }
    // The third v5 buffer is a separate compressed blob stream; the first two
    // buffers contain the typed nodes and blob length descriptors. Source 2
    // VCS v72 shaders use real nonempty blobs for shader properties, hashes,
    // combo tables and variable metadata. Rejecting them loses the entire
    // original compiled shader even when its KV3 prefix is valid.
    if blocks>0 && binary_blob_bytes>MAX_PAYLOAD {
        return Err("KV3 external blob bytes exceed size limit".into());
    }
    let consumed1=if compression==0 {u1}else{c1};
    let consumed2=if compression==0 {u2}else{c2};
    let end1=120usize.checked_add(consumed1).ok_or("KV3 extent overflow")?;
    let end2=end1.checked_add(consumed2).ok_or("KV3 extent overflow")?;
    if end2>bytes.len() {return Err("truncated KV3 compressed buffers".into());}
    let consumed1=if compression==0 {u1}else{c1};
    let consumed2=if compression==0 {u2}else{c2};
    // Some older uncompressed Source 2 KV3 producers leave this
    // compressed-size aggregate unset. Their raw third lane is still fully
    // determined by source blob lengths. Compressed Resources MUST provide
    // the encoded aggregate; never guess missing Zstd/LZ4 byte extents.
    let aggregate=if compression==0 && compressed_total==0 {
        consumed1.checked_add(consumed2)
            .and_then(|n|n.checked_add(binary_blob_bytes))
            .ok_or("KV3 uncompressed lane extent overflow")?
    } else {compressed_total};
    let remaining_compressed=aggregate.checked_sub(consumed1)
        .and_then(|v|v.checked_sub(consumed2))
        .ok_or("KV3 advertised compressed buffers exceed total")?;
    if blocks==0 && remaining_compressed!=0 {
        return Err("KV3 has a compressed blob stream but no blob descriptors".into());
    }
    let end3=end2.checked_add(remaining_compressed)
        .ok_or("KV3 binary blob offset overflow")?;
    if end3>bytes.len() {return Err("KV3 binary blob stream is truncated".into());}
    let bytes1=decoded(compression,&bytes[120..end1],u1,c1)?;
    let bytes2=decoded(compression,&bytes[end1..end2],u2,c2)?;
    let bytes3=if blocks==0 {Vec::new()} else {
        decoded(compression,&bytes[end2..end3],binary_blob_bytes,remaining_compressed)?
    };
    // Real v5 Source2 resources append an outer trailer after the three
    // compressed buffers. Permit header-only synthetic test fixtures that
    // omit the optional outer marker, but never accept a different marker.
    if bytes.len()>end3 {
        if bytes.len()<end3+4 || uint(bytes,end3)?!=TRAILER {
            return Err("KV3 outer blob trailer is invalid".into());
        }
    }
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
    let lengths_end=type_end.checked_add(blocks.checked_mul(4).ok_or("KV3 binary length lane overflow")?)
        .ok_or("KV3 length lane overflow")?;
    let lengths=bytes2.get(type_end..lengths_end).ok_or("truncated KV3 external blob lengths")?;
    let summed=lengths.chunks_exact(4).try_fold(0usize,|sum,bytes|{
        sum.checked_add(u32::from_le_bytes(bytes.try_into().unwrap()) as usize)
            .ok_or("KV3 external blob length sum overflow")
    })?;
    if summed!=binary_blob_bytes {
        return Err(format!("KV3 external blob sizes total {summed}, expected {binary_blob_bytes}"));
    }
    let marker=uint(&bytes2,lengths_end)?;
    if marker!=TRAILER{return Err(format!("invalid KV3 trailer 0x{marker:08x}"));}
    let mut reader=Reader{
        types:Lane{bytes:type_bytes,at:0},names,
        main:second,auxiliary:first,objects,
        blobs:Lane{bytes:&bytes3,at:0}, lengths:Lane{bytes:lengths,at:0},
        visited:0,legacy_object_lengths:false,
    };
    let (kind,flag)=read_type(&mut reader)?;
    let root=read_value(&mut reader,kind,flag,false,0)?;
    if reader.types.remaining()!=0 || reader.objects.remaining()!=0 ||
       reader.blobs.remaining()!=0 || reader.lengths.remaining()!=0 {
        return Err(format!(
            "KV3 trailing types={} object lengths={} blob data={} blob lengths={}",
            reader.types.remaining(),reader.objects.remaining(),
            reader.blobs.remaining(),reader.lengths.remaining()
        ));
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
    if blocks!=0 && binary_blob_bytes!=0 {
        return Err(format!("KV3 v4 nonempty external binary blobs unsupported ({blocks} blocks, {binary_blob_bytes} bytes)"));
    }
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
    let lengths_end=type_end.checked_add(blocks.checked_mul(4).ok_or("v4 blob lengths overflow")?)
        .ok_or("v4 blob address overflow")?;
    let lengths=decompressed.get(type_end..lengths_end).ok_or("truncated KV3 v4 blob lengths")?;
    if lengths.chunks_exact(4).any(|b|u32::from_le_bytes(b.try_into().unwrap())!=0) {
        return Err("KV3 v4 blob lengths declare nonzero values but blob payload unavailable".into());
    }
    let trailer=uint(&decompressed,lengths_end)?;
    if trailer!=TRAILER{return Err(format!("invalid KV3 v4 trailer 0x{trailer:08x}"));}
    let mut reader=Reader{
        types:Lane{bytes:types,at:0},names,main:lanes.clone(),auxiliary:lanes,
        objects:Lane{bytes:&[],at:0},blobs:Lane{bytes:&[],at:0},lengths:Lane{bytes:lengths,at:0},
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
    /// Real compiled VCS v72 KV3 documents place nonempty binary members in
    /// a third separately compressed buffer. Preserve the exact source blobs
    /// rather than treating their presence as an unsupported shader version.
    #[test]
    fn source2_raw_lz4_literals_and_overlapping_matches(){
        // Literal 'A', then a back-reference of length 18 from offset 1,
        // and a legal source-final five-literal sequence.
        let source=[0x1e,b'A',1,0,0x50,b'B',b'C',b'D',b'E',b'F'];
        let decoded=decode_source2_lz4_block(&source,24).unwrap();
        assert_eq!(&decoded[..19],&[b'A';19]);
        assert_eq!(&decoded[19..],b"BCDEF");
    }
    #[test]
    fn source2_raw_lz4_bounds_and_truncated_lengths_rejected(){
        assert_eq!(decode_source2_lz4_block(&[0x00],0).unwrap(),b"");
        assert!(decode_source2_lz4_block(&[0xf0],15).is_err());
        assert!(decode_source2_lz4_block(&[0x00,1],4).is_err());
        assert!(decode_source2_lz4_block(&[0x00,0,0],4).is_err());
        assert!(decode_source2_lz4_block(&[0x10,b'A'],2).is_err());
        assert!(decode_source2_lz4_block(&[0x10,b'A'],1).is_ok());
        assert!(decode_source2_lz4_block(&[0x10,b'A'],0).is_err());
    }
    #[test]
    fn source2_lz4_roundtrip_matches_existing_encoder(){
        let plain=b"Valve Source2 original KV3 entity arrays + more KV3 entity arrays";
        let compressed=lz4_flex::block::compress(plain);
        let decoded=decode_source2_lz4_block(&compressed,plain.len()).unwrap();
        assert_eq!(decoded,plain);
    }
    #[test]
    fn v5_nonempty_external_shader_blob_roundtrip_and_bad_lengths(){
        let strings=b"shader_blob\0";
        let mut lane1=strings.to_vec();
        lane1.resize(align(lane1.len(),4).unwrap(),0);
        lane1.extend_from_slice(&1i32.to_le_bytes());
        let mut lane2=Vec::new();
        lane2.extend_from_slice(&1i32.to_le_bytes()); // object count
        lane2.extend_from_slice(&0i32.to_le_bytes()); // property name ID
        lane2.extend_from_slice(&[9,7]); // object containing binary
        lane2.extend_from_slice(&3i32.to_le_bytes()); // blob size
        lane2.extend_from_slice(&TRAILER.to_le_bytes());
        let blob=[0x03,0x02,0x23];
        let mut bytes=vec![0u8;120];
        bytes[..4].copy_from_slice(&KV3_V5.to_le_bytes());
        let set=|b:&mut Vec<u8>,at:usize,v:i32|b[at..at+4].copy_from_slice(&v.to_le_bytes());
        set(&mut bytes,20,0);
        set(&mut bytes,28,strings.len() as i32);
        set(&mut bytes,32,1);
        set(&mut bytes,40,2);
        set(&mut bytes,48,(lane1.len()+lane2.len()) as i32);
        set(&mut bytes,52,(lane1.len()+lane2.len()+blob.len()) as i32);
        set(&mut bytes,56,1);
        set(&mut bytes,60,3);
        set(&mut bytes,72,lane1.len() as i32);
        set(&mut bytes,80,lane2.len() as i32);
        set(&mut bytes,96,1);
        set(&mut bytes,104,2);
        set(&mut bytes,108,1);
        bytes.extend_from_slice(&lane1);
        bytes.extend_from_slice(&lane2);
        bytes.extend_from_slice(&blob);
        bytes.extend_from_slice(&TRAILER.to_le_bytes());
        let doc=decode(&bytes).expect("external Source2 binary blob");
        assert_eq!(doc.header.binary_blob_bytes,3);
        assert_eq!(doc.root.field("shader_blob"),Some(&Value::Blob(blob.to_vec())));
        // Corrupted advertised binary extent must fail, never truncate silently.
        let mut malformed=bytes;
        malformed[60..64].copy_from_slice(&4u32.to_le_bytes());
        assert!(decode(&malformed).is_err());
    }
    #[test]
    fn v5_zstd_compressed_shader_blob_is_source_exact(){
        // Distinctly compressed buffer1, buffer2, and external blob stream.
        let strings=b"shader_blob\0";
        let mut lane1=strings.to_vec();
        lane1.resize(align(lane1.len(),4).unwrap(),0);
        lane1.extend_from_slice(&1i32.to_le_bytes());
        let mut lane2=Vec::new();
        lane2.extend_from_slice(&1i32.to_le_bytes());
        lane2.extend_from_slice(&0i32.to_le_bytes());
        lane2.extend_from_slice(&[9,7]);
        lane2.extend_from_slice(&4i32.to_le_bytes());
        lane2.extend_from_slice(&TRAILER.to_le_bytes());
        let blob=b"SPIR".to_vec();
        let comp1=zstd::bulk::compress(&lane1,1).unwrap();
        let comp2=zstd::bulk::compress(&lane2,1).unwrap();
        let comp3=zstd::bulk::compress(&blob,1).unwrap();
        let mut bytes=vec![0u8;120];
        bytes[..4].copy_from_slice(&KV3_V5.to_le_bytes());
        let set=|b:&mut Vec<u8>,at:usize,v:i32|b[at..at+4].copy_from_slice(&v.to_le_bytes());
        set(&mut bytes,20,2);
        set(&mut bytes,28,strings.len() as i32);
        set(&mut bytes,32,1);
        set(&mut bytes,40,2);
        set(&mut bytes,48,(lane1.len()+lane2.len()) as i32);
        set(&mut bytes,52,(comp1.len()+comp2.len()+comp3.len()) as i32);
        set(&mut bytes,56,1);
        set(&mut bytes,60,4);
        set(&mut bytes,72,lane1.len() as i32);
        set(&mut bytes,76,comp1.len() as i32);
        set(&mut bytes,80,lane2.len() as i32);
        set(&mut bytes,84,comp2.len() as i32);
        set(&mut bytes,96,1);
        set(&mut bytes,104,2);
        set(&mut bytes,108,1);
        bytes.extend_from_slice(&comp1);
        bytes.extend_from_slice(&comp2);
        bytes.extend_from_slice(&comp3);
        bytes.extend_from_slice(&TRAILER.to_le_bytes());
        let doc=decode(&bytes).unwrap();
        assert_eq!(doc.root.field("shader_blob"),Some(&Value::Blob(blob)));
    }
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
