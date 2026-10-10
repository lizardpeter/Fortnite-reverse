//! Real retail regression for the *typed* source-brightness/fog/sky-phase
//! decoder. It does not render unsupported sunlight directions or sky shaders.
use std::{env,path::PathBuf,process::ExitCode};
use fortnite_541_importer::timeofday;
fn run()->Result<(),String>{
    let root=PathBuf::from(env::args_os().nth(1).ok_or("usage: athena_phase_probe VERIFIED_ORIGINAL_REMOTE_ROOT")?);
    let data=timeofday::from_source_root(&root)?;
    let expected_brightness=[3.5,3.0,3.5,8.0];
    let expected_fog=[0.004,0.004,0.003,0.009];
    let expected_colors=[[1.0,0.63408,0.663958,0.7],
        [0.61144,0.780079,1.1,0.8],
        [1.0,0.560073,0.530209,0.8],
        [0.58,0.69915,1.0,0.75]];
    for (i,p) in data.phases.iter().enumerate(){
        if p.slot!=i ||(p.directional_light_brightness-expected_brightness[i]).abs()>1e-5
            ||(p.fog_density-expected_fog[i]).abs()>1e-5||
            p.skylight_linear_rgba.iter().zip(expected_colors[i].iter())
                .any(|(a,b)|(a-b).abs()>1e-5){
            return Err(format!("original source phase {i} changed or misparsed: {p:?}"));
        }
        println!("ORIGINAL_FORTNITE_PHASE_VERIFIED slot={i} source_time={:?} sun_brightness={} sun_source_bgra={:?} skylight={:?} fog_color={:?} fog_density={} fog_height_falloff={}",
            p.time_phase_begins,p.directional_light_brightness,p.directional_light_bgra,
            p.skylight_linear_rgba,p.fog_color_linear_rgba,p.fog_density,p.fog_height_falloff);
    }
    if data.phases[1].time_phase_begins!=Some(7.0)||
        data.phases[1].phase_length_hours!=Some(12.0){
        return Err("source daylight phase time range is not exact 7..19".into());
    }
    println!("ORIGINAL_FORTNITE_541_TODM_PHASE_TYPED_SOURCE_OK");
    Ok(())
}
fn main()->ExitCode{match run(){Ok(())=>ExitCode::SUCCESS,Err(e)=>{
    eprintln!("ORIGINAL_FORTNITE_541_TODM_PHASE_TYPED_SOURCE_FAILED: {e}");ExitCode::FAILURE
}}}
