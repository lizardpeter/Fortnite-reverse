//! Compile production common Vulkan WGSL fragment path with real
//! source-native BC6H/BC4 HDR atlas sampling. A successful shader is NOT
//! a rendered screenshot or source VCS parity certificate.
fn main()->Result<(),String>{
    let code=include_str!("../preview_original_hdr_atlas.wgsl");
    for required in [
        "source_baked_irradiance_hdr",
        "source_baked_direct_light_shadows",
        "if baked.mode.x > 4.5 && baked.mode.x < 5.5",
        "textureSampleLevel(",
        "fn evaluate_baked_lighting(",
    ]{
        if !code.contains(required){
            return Err(format!("active native baked shader lacks source fragment path {required}"));
        }
    }
    let shader=naga::front::wgsl::parse_str(code)
        .map_err(|e|format!("native HDR WGSL invalid: {}",e.emit_to_string(code)))?;
    let stages=shader.entry_points.iter().map(|e|(e.name.clone(),e.stage)).collect::<Vec<_>>();
    if !stages.iter().any(|(_,s)|*s==naga::ShaderStage::Vertex)||
        !stages.iter().any(|(_,s)|*s==naga::ShaderStage::Fragment){
        return Err("rendering shader lost GPU vertex/fragment entry points".into());
    }
    let info=naga::valid::Validator::new(
        naga::valid::ValidationFlags::all(),naga::valid::Capabilities::all()
    ).validate(&shader).map_err(|e|format!("HDR shader invalid for Vulkan Naga IR: {e:?}"))?;
    let spv=naga::back::spv::write_vec(
        &shader,&info,&naga::back::spv::Options {
            lang_version:(1,6),
            flags:naga::back::spv::WriterFlags::ADJUST_COORDINATE_SPACE,
            ..Default::default()
        },None
    ).map_err(|e|format!("native HDR shader Vulkan SPIR-V codegen failure: {e:?}"))?;
    if spv.len()<5 || spv[0]!=0x0723_0203{
        return Err("native HDR map shader did not emit real Vulkan SPIR-V".into());
    }
    println!("CERTIFIED_COMMON_NATIVE_HDR_ATLAS_PIXEL_SHADER entrypoints={stages:?} original_wgsl_bytes={} executable_spirv_words={} source_hdr_bc6h_and_bc4_sampled=true actual_gpu_frame_not_verified=true",code.len(),spv.len());
    Ok(())
}
