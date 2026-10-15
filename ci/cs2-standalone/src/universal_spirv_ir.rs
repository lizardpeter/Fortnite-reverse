//! Universal, game-agnostic imported SPIR-V shader IR.
 //!
 //! The original bytes are consumed by Naga's typed SPIR-V frontend, the
 //! same IR used by our shared material shader compiler. Shader output is
 //! validated as WGSL and recompiled as Vulkan SPIR-V. No guessing original
 //! UBO offsets, texture identities or ambient equations is allowed.
use naga::{self,back,front,valid};
const MAX_SOURCE_SPV:usize=64*1024*1024;
pub struct TranslatedSourceShader {
    /// Source-neutral validated code which can be compiled by the shared
    /// Vulkan shader module backend after provider/descriptor admission.
    pub generated_spirv:Vec<u32>,
    /// Debug/reference form of the exact typed source-neutral shader IR.
    pub generated_wgsl:String,
    pub stage:naga::ShaderStage,
    pub source_entrypoint:String,
    pub translated_globals:usize,
    pub translated_functions:usize,
}
/// Translate executable GPU instructions into validated Naga IR and back to
/// executable SPIR-V, not a metadata census or an approximate PBR substitute.
/// Fail closed if Naga cannot represent source scalar UBO packing or mixed
/// compare/noncompare sampling.
pub fn translate_source_spirv(input:&[u8])->Result<TranslatedSourceShader,String>{
    if input.len()<20 || input.len()>MAX_SOURCE_SPV || input.len()%4!=0 {
        return Err("original SPIR-V code outside source-neutral byte limit".into());
    }
    let source=front::spv::parse_u8_slice(
        input,&front::spv::Options::default()
    ).map_err(|e|format!("SPIR-V to universal Naga IR failed: {e:?}"))?;
    if source.entry_points.len()!=1 {
        return Err("source shader must expose one unambiguous entrypoint".into());
    }
    let stage=source.entry_points[0].stage;
    let name=source.entry_points[0].name.clone();
    let globals=source.global_variables.len();
    let functions=source.functions.len();
    let info=valid::Validator::new(
        valid::ValidationFlags::all(),valid::Capabilities::all()
    ).validate(&source)
        .map_err(|e|format!("source shader IR is not universally valid: {e:?}"))?;
    let wgsl=back::wgsl::write_string(
        &source,&info,back::wgsl::WriterFlags::empty()
    ).map_err(|e|format!("universal shader WGSL lowering failed: {e:?}"))?;
    // Ensure the generated textual shader is itself a valid cross-backend
    // intermediate, not just Naga's best-effort printed representation.
    let canonical=front::wgsl::parse_str(&wgsl)
        .map_err(|e|format!("universal WGSL shader cannot be reparsed: {}",
            e.emit_to_string(&wgsl)))?;
    if canonical.entry_points.len()!=1 ||
        canonical.entry_points[0].stage!=stage{
        return Err("SPIR-V shader stage changed during universal WGSL lowering".into());
    }
    let canonical_info=valid::Validator::new(
        valid::ValidationFlags::all(),valid::Capabilities::all()
    ).validate(&canonical)
        .map_err(|e|format!("translated universal WGSL IR invalid: {e:?}"))?;
    let pipeline=back::spv::PipelineOptions{
        shader_stage:stage,entry_point:canonical.entry_points[0].name.clone()
    };
    let spirv=back::spv::write_vec(
        &canonical,&canonical_info,
        &back::spv::Options::default(),Some(&pipeline)
    ).map_err(|e|format!("universal IR -> Vulkan SPIR-V codegen failed: {e:?}"))?;
    if spirv.len()<5 || spirv[0]!=0x0723_0203{
        return Err("translated Vulkan shader is not executable SPIR-V".into());
    }
    Ok(TranslatedSourceShader{
        generated_spirv:spirv,generated_wgsl:wgsl,stage,
        source_entrypoint:name,translated_globals:globals,
        translated_functions:functions,
    })
}
/// An original shader's uniform structure may use a scalar/relaxed-block
/// source layout rather than WGSL's stricter uniform-buffer layout. We retain
/// the ORIGINAL member offsets and the generated canonical offsets together:
/// renderer uniform upload is not admissible until the provider supplies the
/// source-owned bytes and applies this mapping, including array/matrix stride.
#[derive(Clone,Debug)]
pub struct UniformLayoutRebase{
    pub group:u32,
    pub binding:u32,
    pub original_offsets:Vec<u32>,
    pub canonical_offsets:Vec<u32>,
    pub original_bytes:u32,
    pub canonical_bytes:u32,
    /// Only 32-bit/16-bit scalar or vector fields can currently be byte-
    /// copied automatically. Matrix, nested struct or array strides must
    /// be source-certified before their runtime providers are enabled.
    pub field_widths:Vec<Option<u32>>,
    /// Original Vulkan shader MatrixStride and RowMajor/ColMajor metadata,
    /// combined with typed canonical WGSL matrix layout. Never inferred from
    /// raw material names or guessed from a screenshot.
    pub matrix_fields:Vec<OriginalMatrixFieldRebase>,
}
#[derive(Clone,Debug)]
pub struct OriginalMatrixFieldRebase{
    pub member_index:usize,
    pub columns:u32,
    pub rows:u32,
    pub scalar_bytes:u32,
    pub original_stride:u32,
    pub original_row_major:bool,
    pub canonical_stride:u32,
}
impl OriginalMatrixFieldRebase {
    fn repack(&self, original:&[u8],source_at:usize,
        target:&mut[u8],target_at:usize)->Result<(),String>{
        if !(2..=4).contains(&self.columns) ||
            !(2..=4).contains(&self.rows) ||
            !matches!(self.scalar_bytes,2|4|8){
            return Err("source matrix has unsupported dimensions or scalar size".into());
        }
        let original_major=if self.original_row_major{self.rows}else{self.columns};
        let original_minor=if self.original_row_major{self.columns}else{self.rows};
        if self.original_stride<original_minor*self.scalar_bytes ||
            self.canonical_stride<self.rows*self.scalar_bytes{
            return Err("original shader matrix stride overlaps active elements".into());
        }
        for column in 0..self.columns{
            for row in 0..self.rows{
                let (major,minor)=if self.original_row_major{
                    (row,column)
                }else{
                    (column,row)
                };
                // The original SPIR-V MatrixStride is untrusted and may be
                // close to u32::MAX. Check arithmetic before addressing bytes:
                // release-mode wraparound must never silently copy the wrong
                // source value into a light matrix.
                let source_slot=(major as usize)
                    .checked_mul(self.original_stride as usize)
                    .and_then(|offset|offset.checked_add(
                        minor as usize*self.scalar_bytes as usize))
                    .ok_or("source Vulkan matrix stride address overflow")?;
                let target_slot=(column as usize)
                    .checked_mul(self.canonical_stride as usize)
                    .and_then(|offset|offset.checked_add(
                        row as usize*self.scalar_bytes as usize))
                    .ok_or("universal matrix stride address overflow")?;
                let start=source_at.checked_add(source_slot)
                    .ok_or("source matrix address overflow")?;
                let dst=target_at.checked_add(target_slot)
                    .ok_or("canonical matrix address overflow")?;
                let size=self.scalar_bytes as usize;
                let input_end=start.checked_add(size)
                    .ok_or("source matrix active scalar address overflow")?;
                let target_end=dst.checked_add(size)
                    .ok_or("canonical matrix active scalar address overflow")?;
                let input=original.get(start..input_end)
                    .ok_or("source Vulkan matrix field extent unavailable")?;
                let output=target.get_mut(dst..target_end)
                    .ok_or("canonical matrix field extent unavailable")?;
                output.copy_from_slice(input);
            }
        }
        if original_major==0{return Err("original matrix dimension empty".into());}
        Ok(())
    }
}
impl UniformLayoutRebase{
    pub fn requires_repack(&self)->bool{
        self.original_offsets!=self.canonical_offsets ||
        self.original_bytes!=self.canonical_bytes ||
        // Identical buffer extents and field offsets do NOT mean identical
        // bytes when Source2 authored RowMajor or noncanonical MatrixStride.
        self.matrix_fields.iter().any(|m|
            m.original_row_major || m.original_stride!=m.canonical_stride
        ) ||
        // An unrecognized aggregate or array is never ABI-certified just
        // because its original and canonical struct spans happen to match.
        self.field_widths.iter().enumerate().any(|(index,width)|
            width.is_none() &&
            !self.matrix_fields.iter().any(|m|m.member_index==index)
        )
    }
    /// Copy proven byte-level fields from original source UBO packing into
    /// the generated universal shader's canonical buffer layout. Unknown
    /// matrix/array/nested structure strides are rejected rather than
    /// silently producing plausible but incorrect lighting.
    pub fn repack_original_bytes(&self,source:&[u8])->Result<Vec<u8>,String>{
        if source.len()<self.original_bytes as usize{
            return Err("source shader uniform upload lacks original buffer extent".into());
        }
        if self.original_offsets.len()!=self.canonical_offsets.len() ||
            self.field_widths.len()!=self.original_offsets.len(){
            return Err("source/native UBO member identities changed".into());
        }
        let mut output=vec![0u8;self.canonical_bytes as usize];
        for (i,((&from,&to),width)) in self.original_offsets.iter()
            .zip(&self.canonical_offsets).zip(&self.field_widths).enumerate(){
            if let Some(matrix)=self.matrix_fields.iter().find(|m|m.member_index==i){
                if width.is_some(){
                    return Err("scalar/vector field conflicts with original matrix type".into());
                }
                matrix.repack(source,from as usize,&mut output,to as usize)?;
                continue;
            }
            let bytes=width.ok_or_else(||format!(
                "source uniform member {i} uses an unresolved array/matrix/struct stride"
            ))? as usize;
            let source_start=from as usize;
            let target_start=to as usize;
            let input_slice=source.get(source_start..source_start.saturating_add(bytes))
                .ok_or("source shader UBO field extends beyond original range")?;
            let target=output.get_mut(target_start..target_start.saturating_add(bytes))
                .ok_or("canonical shader UBO field extends beyond destination range")?;
            target.copy_from_slice(input_slice);
        }
        Ok(output)
    }
}
pub struct RebasedUnboundShader{
    pub shader:TranslatedSourceShader,
    /// Shader source is now syntactically valid and executable, but this
    /// preserves original source byte-layout mismatch, not a made-up default
    /// GPU uniform value. This is not a binding admission certificate.
    pub uniform_layouts:Vec<UniformLayoutRebase>,
    pub original_abi_closed:bool,
}
fn plain_member_width(module:&naga::Module,ty:naga::Handle<naga::Type>)->Option<u32>{
    match &module.types[ty].inner{
        naga::TypeInner::Scalar(scalar)=>Some(scalar.width as u32),
        naga::TypeInner::Vector{size,scalar}=>{
            let count=match size{
                naga::VectorSize::Bi=>2,
                naga::VectorSize::Tri=>3,
                naga::VectorSize::Quad=>4
            };
            Some(count*scalar.width as u32)
        },
        _=>None,
    }
}
fn uniform_structs(module:&naga::Module)
    ->Result<std::collections::BTreeMap<(u32,u32),(Vec<u32>,u32,Vec<Option<u32>>)>,String>
{
    let mut out=std::collections::BTreeMap::new();
    for (_,var) in module.global_variables.iter(){
        if var.space!=naga::AddressSpace::Uniform{continue;}
        let binding=var.binding.as_ref()
            .ok_or("source uniform buffer has no physical group/binding")?;
        let (members,span)=match &module.types[var.ty].inner{
            naga::TypeInner::Struct{members,span}=>(members,span),
            _=>return Err("original source uniform payload is not a typed struct".into()),
        };
        if members.len()>4096{return Err("source UBO member array exceeds safe limit".into())}
        let offsets=members.iter().map(|m|m.offset).collect::<Vec<_>>();
        let widths=members.iter().map(|m|plain_member_width(module,m.ty))
            .collect::<Vec<_>>();
        let key=(binding.group,binding.binding);
        if out.insert(key,(offsets,*span,widths)).is_some(){
            return Err("ambiguous duplicate source uniform descriptor coordinate".into())
        }
    }
    Ok(out)
}
/// Decode the ORIGINAL compiled SPIR-V MatrixStride and RowMajor/ColMajor
/// OpMemberDecorate declarations. Absent decorations stay absent: the shader
/// compiler is not permitted to fill missing matrix ABI details from defaults.
fn original_spirv_matrix_decorations(
    code:&[u8]
)->Result<std::collections::BTreeMap<(u32,u32,usize),(u32,bool)>,String>{
    use std::collections::BTreeMap;
    if code.len()<20||code.len()%4!=0||code.len()>MAX_SOURCE_SPV{
        return Err("original SPIR-V matrix metadata input outside bound".into());
    }
    let words=code.chunks_exact(4).map(|w|
        u32::from_le_bytes(w.try_into().unwrap())).collect::<Vec<_>>();
    if words[0]!=0x0723_0203{return Err("source matrix decorations lack SPIR-V header".into());}
    let mut groups=BTreeMap::new();
    let mut bindings=BTreeMap::new();
    let mut member_abi=BTreeMap::<(u32,u32),(Option<u32>,Option<bool>)>::new();
    let mut structs=BTreeMap::<u32,Vec<u32>>::new();
    let mut matrices=BTreeMap::<u32,()>::new();
    let mut pointers=BTreeMap::<u32,(u32,u32)>::new();
    let mut vars=Vec::<(u32,u32,u32)>::new();
    let mut at=5;
    while at<words.len(){
        let op=words[at]&0xffff;
        let size=(words[at]>>16) as usize;
        if size==0||at.checked_add(size).is_none_or(|end|end>words.len()){
            return Err("source matrix decorations contain truncated SPIR-V op".into());
        }
        let p=&words[at+1..at+size];
        match op{
            71 if p.len()>=3=>match p[1]{
                33=>{bindings.insert(p[0],p[2]);},
                34=>{groups.insert(p[0],p[2]);},
                _=>{}
            },
            72 if p.len()>=3=>{
                let slot=member_abi.entry((p[0],p[1])).or_default();
                match p[2]{
                    4=>slot.1=Some(true),  // RowMajor
                    5=>slot.1=Some(false), // ColMajor
                    7 if p.len()>=4=>slot.0=Some(p[3]), // MatrixStride
                    _=>{}
                }
            },
            24 if !p.is_empty()=>{matrices.insert(p[0],());},
            30 if !p.is_empty()=>{structs.insert(p[0],p[1..].to_vec());},
            32 if p.len()>=3=>{pointers.insert(p[0],(p[1],p[2]));},
            59 if p.len()>=3=>vars.push((p[0],p[1],p[2])),
            _=>{}
        }
        at+=size;
    }
    let mut result=BTreeMap::new();
    for (ptr,var,storage) in vars{
        if storage!=2{continue;} // Uniform only
        let Some((ptr_storage,structure))=pointers.get(&ptr).copied() else{continue;};
        if ptr_storage!=2{continue;}
        let Some(members)=structs.get(&structure) else{continue;};
        let (Some(&group),Some(&binding))=(groups.get(&var),bindings.get(&var))
            else{continue;};
        for (index,&ty) in members.iter().enumerate(){
            if !matrices.contains_key(&ty){continue;}
            let Some((Some(stride),Some(rowmajor)))=
                member_abi.get(&(structure,index as u32)).copied()
                else{continue;};
            if stride==0{return Err("source matrix stride cannot be zero".into());}
            if result.insert((group,binding,index),(stride,rowmajor)).is_some(){
                return Err("ambiguous authored matrix stride for source descriptor".into());
            }
        }
    }
    Ok(result)
}
/// Extract only direct matrix members. Nested structs and matrix arrays are
/// intentionally excluded pending recursive source ABI evidence.
fn original_ir_matrix_shapes(module:&naga::Module)
    ->Result<std::collections::BTreeMap<(u32,u32,usize),(u32,u32,u32)>,String>{
    use naga::TypeInner;
    let mut result=std::collections::BTreeMap::new();
    let vecsize=|v:naga::VectorSize|->u32{
        match v{naga::VectorSize::Bi=>2,naga::VectorSize::Tri=>3,naga::VectorSize::Quad=>4}
    };
    for (_,var) in module.global_variables.iter(){
        if var.space!=naga::AddressSpace::Uniform{continue;}
        let Some(location)=var.binding.as_ref() else{continue;};
        let TypeInner::Struct{members,..}=&module.types[var.ty].inner else{continue;};
        for (index,member) in members.iter().enumerate(){
            if let TypeInner::Matrix{columns,rows,scalar}=&module.types[member.ty].inner{
                result.insert(
                    (location.group,location.binding,index),
                    (vecsize(*columns),vecsize(*rows),scalar.width as u32)
                );
            }
        }
    }
    Ok(result)
}

/// Some source compilers deliberately overlay multiple uniform fields
/// in one address span. Naga's WGSL type system cannot represent those
/// overlapping members directly. Expand their *IR* offsets into disjoint
/// regions while the source-byte offsets remain recorded in UniformLayoutRebase.
/// Shader operations keep their original field indices, never flattened to
/// guessed constants. Host providers must still explicitly rebase the data.
fn normalize_overlapping_source_structs(module:&mut naga::Module)
    ->Result<usize,String>
{
    let originals=module.types.iter().map(|(h,t)|(h,t.clone()))
        .collect::<Vec<_>>();
    let mut corrected=0usize;
    for (handle,mut type_copy) in originals{
        let naga::TypeInner::Struct{ref mut members,ref mut span}=
            type_copy.inner else{continue;};
        let mut end=0u32;
        let mut changed=false;
        for member in members{
            let size=module.types[member.ty].inner.try_size(naga::proc::GlobalCtx{
                types:&module.types,
                constants:&module.constants,
                overrides:&module.overrides,
                global_expressions:&module.global_expressions,
            }).ok_or("source struct member exceeds universal compiler size limit")?;
            if member.offset<end{
                member.offset=end;
                corrected+=1;
                changed=true;
            }
            end=member.offset.checked_add(size)
                .ok_or("source compiler struct rebase size overflow")?;
        }
        if end>*span {*span=end;changed=true;}
        if changed{
            if module.types.get(&type_copy).is_some_and(|existing|existing!=handle){
                return Err("source struct rebase collides with existing Naga type identity".into());
            }
            module.types.replace(handle,type_copy);
        }
    }
    Ok(corrected)
}

/// Recover a matrix multiply obscured by Naga's row-major input-load
/// transpose. Restrict the adjustment to a provably invalid matrix * vector
/// whose *original pre-transpose* matrix columns match the vector size.
/// This keeps the exact source instruction's vector cardinality and every
/// matrix element intact. Original row-major upload still requires a
/// source-backed matrix stride and transpose provider before runtime use.
fn repair_source_row_major_matrix_multiply(
    module:&mut naga::Module
)->Result<usize,String>{
    use naga::{Expression as E,TypeInner as T,BinaryOperator as B,MathFunction as M};
    fn fix_one(
        module:&naga::Module,
        function:&naga::Function,
    )->Result<Vec<(naga::Handle<naga::Expression>,naga::Handle<naga::Expression>)>,String>{
        let ctx=naga::proc::ResolveContext::with_locals(
            module,&function.local_variables,&function.arguments);
        let mut typer=naga::front::Typifier::new();
        let mut candidates=Vec::new();
        for (handle,expression) in function.expressions.iter(){
            let E::Binary{op:B::Multiply,left,right}=expression else{continue;};
            let E::Math{fun:M::Transpose,arg,arg1:None,arg2:None,arg3:None}=
                &function.expressions[*left] else{continue;};
            let (left,right,arg)=(*left,*right,*arg);
            typer.grow(right,&function.expressions,&ctx)
                .map_err(|e|format!("original source vector type unresolved: {e:?}"))?;
            typer.grow(arg,&function.expressions,&ctx)
                .map_err(|e|format!("original source matrix type unresolved: {e:?}"))?;
            let (T::Matrix{columns,rows,..},T::Vector{size,..})=
                (typer.get(arg,&module.types),typer.get(right,&module.types))
            else{continue;};
            // In the already transposed expression, columns==rows(original)
            // and the multiply is invalid if the vec length differs from the
            // new columns. Only repair when the pre-transpose matrix was
            // the exact vector-compatible type.
            if columns!=size && rows!=size{
                continue;
            }
            if columns==size && rows!=size {
                candidates.push((handle,arg));
            }
        }
        Ok(candidates)
    }
    let original=module.clone();
    let mut count=0;
    for (handle,func) in original.functions.iter(){
        let corrections=fix_one(&original,func)?;
        let target=&mut module.functions[handle];
        for (expr,arg) in corrections{
            if let E::Binary{ref mut left,..}=target.expressions[expr]{
                *left=arg;count+=1;
            }
        }
    }
    for (idx,entry) in original.entry_points.iter().enumerate(){
        let corrections=fix_one(&original,&entry.function)?;
        let target=&mut module.entry_points[idx].function;
        for (expr,arg) in corrections{
            if let E::Binary{ref mut left,..}=target.expressions[expr]{
                *left=arg;count+=1;
            }
        }
    }
    Ok(count)
}

/// IMPORTS the original shader operations into the common Naga IR and uses
/// the ordinary WGSL writer to canonicalize layout. Unlike the strict path,
/// this returns the *original and translated* UBO member offsets, so the
/// runtime can repack real source data before admitting the generated code.
///
/// Deliberately does NOT silently supply zero UBO values or claim the
/// generated code is equivalent with the *original* un-repacked buffer.
pub fn translate_source_spirv_with_ubo_rebase(
    input:&[u8]
)->Result<RebasedUnboundShader,String>{
    if input.len()<20 || input.len()>MAX_SOURCE_SPV || input.len()%4!=0{
        return Err("source shader outside universal bounded SPIR-V range".into());
    }
    let mut source=front::spv::parse_u8_slice(
        input,&front::spv::Options::default()
    ).map_err(|e|format!("source SPIR-V instruction import failed: {e:?}"))?;
    if source.entry_points.len()!=1 {
        return Err("ambiguous source-native shader entrypoint".into());
    }
    let layouts=uniform_structs(&source)?;
    let authored_matrix_abi=original_spirv_matrix_decorations(input)?;
    let source_matrix_types=original_ir_matrix_shapes(&source)?;
    let _rewritten_overlapping_members=normalize_overlapping_source_structs(&mut source)?;
    let _repaired_row_major_multiplications=repair_source_row_major_matrix_multiply(&mut source)?;
    // Naga cannot validate some author-approved Vulkan scalar-block
    // packing as WebGPU Uniform. Relax ONLY host-shareable struct layout
    // for THIS import. The canonical WGSL is strictly revalidated below.
    let relaxed=valid::ValidationFlags::all() &
        !valid::ValidationFlags::STRUCT_LAYOUTS;
    let info=match valid::Validator::new(relaxed,valid::Capabilities::all())
        .validate(&source){
        Ok(info)=>info,
        Err(e)=>{
            let mut context=Vec::new();
            for (_,function) in source.functions.iter(){
                for (id,op) in function.expressions.iter(){
                    if (740..=750).contains(&id.index()){
                        context.push(format!("expr{}={op:?}",id.index()));
                    }
                }
            }
            return Err(format!(
                "source shader invalid outside source UBO layout: {e:?}; nearby original IR={context:?}"
            ));
        }
    };
    let wgsl=back::wgsl::write_string(
        &source,&info,back::wgsl::WriterFlags::empty()
    ).map_err(|e|format!("source shader IR canonicalization failed: {e:?}"))?;
    let normalized=front::wgsl::parse_str(&wgsl)
        .map_err(|e|format!("canonical shader WGSL cannot parse: {}",
            e.emit_to_string(&wgsl)))?;
    if normalized.entry_points.len()!=1 ||
        normalized.entry_points[0].stage!=source.entry_points[0].stage {
        return Err("source shader stage changed during canonicalization".into());
    }
    let normalized_info=valid::Validator::new(
        valid::ValidationFlags::all(),valid::Capabilities::all()
    ).validate(&normalized)
        .map_err(|e|format!("canonical shader layout still invalid: {e:?}"))?;
    let normalized_layouts=uniform_structs(&normalized)?;
    let canonical_matrix_types=original_ir_matrix_shapes(&normalized)?;
    if layouts.len()!=normalized_layouts.len() ||
        layouts.keys().any(|key|!normalized_layouts.contains_key(key)){
        return Err("canonical shader changed a source uniform descriptor identity".into());
    }
    let mut original_abi_closed=true;
    let mut changes=Vec::new();
    for ((group,binding),(source_offsets,source_bytes,source_widths)) in layouts{
        let (target_offsets,target_bytes,target_widths)=normalized_layouts
            .get(&(group,binding)).ok_or("canonical uniform lost descriptor")?;
        if source_offsets.len()!=target_offsets.len() ||
            source_widths.len()!=target_widths.len() ||
            source_widths.iter().zip(target_widths).any(|(a,b)|a!=b){
            return Err("canonical shader changed source uniform field type/width identity".into());
        }
        let mut matrix_fields=Vec::new();
        for (&(set,slot,index),&(source_cols,source_rows,source_width)) in
            source_matrix_types.iter()
        {
            if (set,slot)!=(group,binding){continue;}
            let Some(&(stride,row_major))=authored_matrix_abi.get(&(set,slot,index))
                else{continue;};
            let Some(&(target_cols,target_rows,target_width))=
                canonical_matrix_types.get(&(set,slot,index)) else{
                    return Err("source Vulkan matrix member missing from canonical shader".into());
                };
            if (source_cols,source_rows,source_width)!=
                (target_cols,target_rows,target_width){
                return Err("canonical matrix type changed original shader dimensions".into());
            }
            let canonical_stride=if target_rows==2{
                2*target_width
            }else{4*target_width};
            matrix_fields.push(OriginalMatrixFieldRebase{
                member_index:index,
                columns:source_cols,rows:source_rows,scalar_bytes:source_width,
                original_stride:stride,original_row_major:row_major,
                canonical_stride,
            });
        }
        let change=UniformLayoutRebase{
            group,binding,
            original_offsets:source_offsets,
            canonical_offsets:target_offsets.clone(),
            original_bytes:source_bytes,canonical_bytes:*target_bytes,
            field_widths:source_widths,
            matrix_fields, // only compiled SPIR-V-authored MatrixStride + major order
        };
        original_abi_closed &= !change.requires_repack();
        changes.push(change);
    }
    let options=back::spv::PipelineOptions{
        shader_stage:normalized.entry_points[0].stage,
        entry_point:normalized.entry_points[0].name.clone(),
    };
    let spirv=back::spv::write_vec(
        &normalized,&normalized_info,
        &back::spv::Options::default(),Some(&options)
    ).map_err(|e|format!("canonical shader Vulkan code generation failed: {e:?}"))?;
    if spirv.len()<5 || spirv[0]!=0x0723_0203 {
        return Err("rebased source shader did not generate actual Vulkan SPIR-V".into());
    }
    Ok(RebasedUnboundShader{
        shader:TranslatedSourceShader{
            generated_spirv:spirv,generated_wgsl:wgsl,
            stage:source.entry_points[0].stage,
            source_entrypoint:source.entry_points[0].name.clone(),
            translated_globals:source.global_variables.len(),
            translated_functions:source.functions.len(),
        },
        uniform_layouts:changes,original_abi_closed
    })
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn source_uniform_repack_copies_verified_scalar_fields_without_guessing_padding(){
        let layout=UniformLayoutRebase{
            group:2,binding:7,
            original_offsets:vec![0,4,8],
            canonical_offsets:vec![0,16,20],
            original_bytes:12,canonical_bytes:32,
            field_widths:vec![Some(4),Some(4),Some(4)],
            matrix_fields:Vec::new(),
        };
        let source=(0u8..12).collect::<Vec<_>>();
        let target=layout.repack_original_bytes(&source).unwrap();
        assert_eq!(&target[0..4],&source[0..4]);
        assert_eq!(&target[16..20],&source[4..8]);
        assert_eq!(&target[20..24],&source[8..12]);
        assert!(target[4..16].iter().all(|&b|b==0));
        assert!(layout.repack_original_bytes(&source[0..11]).is_err());
        let unknown=UniformLayoutRebase{
            field_widths:vec![None,Some(4),Some(4)],..layout
        };
        assert!(unknown.repack_original_bytes(&source).is_err());
    }
    #[test]
    fn source_rowmajor_mat4x3_upload_retains_every_authored_element(){
        // Source uses row-major 3 rows of 4 floats. Canonical WGSL uses
        // mat4x3 as four padded columns, stride 16 bytes per column.
        let mut input=Vec::new();
        for row in 0..3u32{
            for column in 0..4u32 {
                input.extend_from_slice(&(row*10+column+1).to_le_bytes());
            }
        }
        let spec=OriginalMatrixFieldRebase{
            member_index:0,columns:4,rows:3,scalar_bytes:4,
            original_stride:16,original_row_major:true,canonical_stride:16,
        };
        let plan=UniformLayoutRebase{
            group:0,binding:3,
            original_offsets:vec![0],canonical_offsets:vec![0],
            original_bytes:48,canonical_bytes:64,
            field_widths:vec![None],matrix_fields:vec![spec],
        };
        let data=plan.repack_original_bytes(&input).unwrap();
        for row in 0..3usize {
            for column in 0..4usize {
                let actual=u32::from_le_bytes(data[column*16+row*4..column*16+row*4+4]
                    .try_into().unwrap());
                assert_eq!(actual,row as u32*10+column as u32+1);
            }
        }
        assert_eq!(data.len(),64);
        assert_eq!(&data[12..16],&[0,0,0,0]);
        assert!(plan.repack_original_bytes(&input[..47]).is_err());
    }
    #[test]
    fn row_major_matrix_requires_repack_even_when_byte_size_and_offsets_match(){
        let plan=UniformLayoutRebase{
            group:1,binding:7,
            original_offsets:vec![0],canonical_offsets:vec![0],
            original_bytes:64,canonical_bytes:64,
            field_widths:vec![None],
            matrix_fields:vec![OriginalMatrixFieldRebase{
                member_index:0,columns:4,rows:4,scalar_bytes:4,
                original_stride:16,original_row_major:true,canonical_stride:16,
            }],
        };
        assert!(plan.requires_repack());
        let bytes=(0u8..64).collect::<Vec<_>>();
        let fixed=plan.repack_original_bytes(&bytes).unwrap();
        assert_eq!(&fixed[..4],&bytes[..4]);
        assert_eq!(&fixed[16..20],&bytes[4..8]);
        assert_eq!(&fixed[4..8],&bytes[16..20]);
        let canonical=UniformLayoutRebase{
            matrix_fields:vec![OriginalMatrixFieldRebase{
                original_row_major:false,..plan.matrix_fields[0].clone()
            }],..plan
        };
        assert!(!canonical.requires_repack());
    }
    #[test]
    fn unresolved_original_uniform_aggregate_must_not_be_certified(){
        let plan=UniformLayoutRebase{
            group:0,binding:0,
            original_offsets:vec![0],canonical_offsets:vec![0],
            original_bytes:64,canonical_bytes:64,
            field_widths:vec![None],matrix_fields:vec![],
        };
        assert!(plan.requires_repack());
        assert!(plan.repack_original_bytes(&[0u8;64]).is_err());
    }
    #[test]
    fn malicious_original_matrix_stride_never_wraps_into_valid_data(){
        let matrix=OriginalMatrixFieldRebase{
            member_index:0,columns:4,rows:4,scalar_bytes:4,
            original_stride:u32::MAX,original_row_major:true,
            canonical_stride:16,
        };
        let plan=UniformLayoutRebase{
            group:0,binding:0,
            original_offsets:vec![0],canonical_offsets:vec![0],
            original_bytes:64,canonical_bytes:64,
            field_widths:vec![None],matrix_fields:vec![matrix],
        };
        assert!(plan.repack_original_bytes(&[0u8;64]).is_err());
    }
    #[test]
    fn source_matrix_stride_is_never_invented(){
        let plan=UniformLayoutRebase{
            group:0,binding:0,
            original_offsets:vec![0],canonical_offsets:vec![0],
            original_bytes:32,canonical_bytes:64,
            field_widths:vec![None],matrix_fields:vec![],
        };
        assert!(plan.repack_original_bytes(&[0u8;32]).is_err());
        let bad=OriginalMatrixFieldRebase{
            member_index:0,columns:4,rows:3,scalar_bytes:4,
            original_stride:8,original_row_major:true,canonical_stride:16,
        };
        let incorrect=UniformLayoutRebase{matrix_fields:vec![bad],..plan};
        assert!(incorrect.repack_original_bytes(&[0u8;32]).is_err());
    }
    #[test]
    fn input_bounds_reject_truncated_source_shader(){
        assert!(translate_source_spirv(&[]).is_err());
        assert!(translate_source_spirv(&[0;20]).is_err());
    }
    #[test]
    fn original_wgsl_instruction_roundtrip_produces_executable_universal_spirv(){
        let source=r#"
            @vertex
            fn vs(@location(0) position:vec3<f32>) -> @builtin(position) vec4<f32>{
                return vec4<f32>(position,1.0);
            }
        "#;
        let module=front::wgsl::parse_str(source).unwrap();
        let info=valid::Validator::new(
            valid::ValidationFlags::all(),valid::Capabilities::all()
        ).validate(&module).unwrap();
        let binary=back::spv::write_vec(
            &module,&info,&back::spv::Options::default(),
            Some(&back::spv::PipelineOptions{
                shader_stage:naga::ShaderStage::Vertex,entry_point:"vs".into(),
            })
        ).unwrap();
        let bytes=binary.iter().flat_map(|w|w.to_le_bytes()).collect::<Vec<_>>();
        let translated=translate_source_spirv(&bytes).unwrap();
        assert_eq!(translated.stage,naga::ShaderStage::Vertex);
        assert!(translated.generated_spirv.len()>5);
        assert!(!translated.generated_wgsl.is_empty());
    }
}
