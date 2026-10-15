use std::path::Path;
use cs2_importer::{
    vpk::VpkArchive, material::SourcePacks,
    lightmap,
    vtex_native_array::SourceNativeGpuBlockFormat,
};
fn main()->Result<(),String>{
    let root=std::env::var("ORIGINAL_CS2_WORKSHOP_DIR")
        .map_err(|_|"original CS2 Workshop files unavailable".to_owned())?;
    let archive=VpkArchive::open_directory(
        &Path::new(&root).join("3620630831_dir.vpk"))?;
    for (map,expected) in [
        ("de_dust2_christmas",3usize),
        ("de_dust2_winter",3usize),
    ] {
        let nested=archive.open_nested(&format!("maps/{map}.vpk"))?;
        let packs=SourcePacks{
            workshop_outer:&archive,workshop_map:&nested,base_game:None
        };
        let channel_names=["irradiance","directional_irradiance","direct_light_shadows"];
        let paths=channel_names.iter().map(|name|
            format!("maps/{map}/lightmaps/{name}.vtex_c")
        ).collect::<Vec<_>>();
        let audit=lightmap::audit(&packs,&paths,[8,2]);
        if !audit.complete || audit.channels.len()!=expected {
            return Err(format!("{map}: authored atlas incomplete: {:?}",audit.errors));
        }
        let atlas=lightmap::decode_native_atlas(&packs,&audit)?;
        if (atlas.width,atlas.height,atlas.layers)!=(4096,4096,1) ||
            atlas.total_native_gpu_bytes!=33_554_432 ||
            atlas.channels.len()!=3 {
            return Err(format!("{map}: source native atlas dimensions/bytes invalid"));
        }
        for (slot,fmt,expected_bytes) in [
            ("g_tIrradiance",SourceNativeGpuBlockFormat::Bc6hUnsignedFloat,16_777_216usize),
            ("g_tDirectionalIrradiance",SourceNativeGpuBlockFormat::Bc1Unorm,8_388_608usize),
            ("g_tDirectLightShadows",SourceNativeGpuBlockFormat::Bc4Unorm,8_388_608usize),
        ] {
            let channel=atlas.channels.get(slot).ok_or(
                format!("{map}: missing {slot} GPU native channel"))?;
            if channel.format!=fmt || channel.original_gpu_bytes()!=expected_bytes {
                return Err(format!("{map}: source-native channel {slot} changed format or GPU size"));
            }
            println!("SOURCE2_GPU_NATIVE_ATLAS_CHANNEL {map} {slot} {} bytes={} first16={:02x?}",
                fmt.vulkan_format_name(),channel.original_gpu_bytes(),
                &channel.mips[0].bytes[..16]);
        }
        println!("CERTIFIED_NATIVE_SOURCE2_ATLAS {map} {}x{} layers={} gpu_bytes={} channels={}",
            atlas.width,atlas.height,atlas.layers,atlas.total_native_gpu_bytes,
            atlas.channels.len());
    }
    Ok(())
}
