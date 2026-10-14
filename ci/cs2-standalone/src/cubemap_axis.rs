//! Exact rigid cubemap change of basis from Source 2 Z-up to renderer Y-up.
//! A face permutation alone preserves six directions at their centers, but
//! ROTATES the image axes incorrectly on all side faces. The generic Vulkan
//! cube sampler uses D3D/Vulkan +X,-X,+Y,-Y,+Z,-Z with u right, v down.
use neutral_scene::NeutralTexture;
/// Direction corresponding to a texel (u, v in [-1,1]) on a Vulkan cube.
fn face_direction(face:usize,u:f32,v:f32)->[f32;3]{
    match face {
        0=>[1.,-v,-u], 1=>[-1.,-v,u],
        2=>[u,1.,v], 3=>[u,-1.,-v],
        4=>[u,-v,1.], 5=>[-u,-v,-1.],
        _=>unreachable!("only six cubemap faces"),
    }
}
fn source_cube_face_uv(d:[f32;3])->(usize,f32,f32){
    let [x,y,z]=d;
    let [ax,ay,az]=[x.abs(),y.abs(),z.abs()];
    if ax>=ay && ax>=az {
        if x>=0. {(0,-z/ax,-y/ax)} else {(1,z/ax,-y/ax)}
    } else if ay>=az {
        if y>=0. {(2,x/ay,z/ay)} else {(3,x/ay,-z/ay)}
    } else if z>=0. {(4,x/az,-y/az)} else {(5,-x/az,-y/az)}
}
/// Reorient authentic compiled source face pixels without changing RGB values.
pub fn source_z_up_to_engine_y_up(faces:[NeutralTexture;6])->Result<[NeutralTexture;6],String>{
    let side=faces[0].width;
    if side==0||side>4096||faces.iter().any(|x|x.width!=side||x.height!=side||
        x.rgba.len()!=side as usize*side as usize*4){
        return Err("source cubemap has invalid/inconsistent face dimensions".into());
    }
    let side=side as usize;
    let converted=std::array::from_fn(|engine_face|{
        let mut rgba=vec![0u8;side*side*4];
        for y in 0..side {
            for x in 0..side {
                let u=(x as f32+0.5)/side as f32*2.-1.;
                let v=(y as f32+0.5)/side as f32*2.-1.;
                let e=face_direction(engine_face,u,v);
                let d=[e[0],-e[2],e[1]];
                let (sf,su,sv)=source_cube_face_uv(d);
                let sx=((su+1.)*0.5*side as f32).floor().clamp(0.,(side-1) as f32) as usize;
                let sy=((sv+1.)*0.5*side as f32).floor().clamp(0.,(side-1) as f32) as usize;
                rgba[(y*side+x)*4..(y*side+x)*4+4]
                    .copy_from_slice(&faces[sf].rgba[(sy*side+sx)*4..(sy*side+sx)*4+4]);
            }
        }
        NeutralTexture{
            name:format!("{}#engine_face_{engine_face}",faces[engine_face].name),
            width:side as u32,height:side as u32,
            rgba,mips:Vec::new(),compressed:None,
        }
    });
    Ok(converted)
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn face_direction_change_rotates_pixels_not_only_faces(){
        // For an engine +X face, image LEFT must sample the original +X
        // face's vertical texel coordinate; a face-only permutation does not.
        let side=8u32;
        let make=|face:usize|NeutralTexture{name:format!("{face}"),width:side,height:side,
            rgba:(0..side*side).flat_map(|i|[
                face as u8,(i%side) as u8,(i/side) as u8,255
            ]).collect(),mips:Vec::new(),compressed:None};
        let source=std::array::from_fn(make);
        let cube=source_z_up_to_engine_y_up(source).unwrap();
        let at=|face:usize,x:usize,y:usize|->[u8;4]{
            cube[face].rgba[(y*side as usize+x)*4..(y*side as usize+x)*4+4]
                .try_into().unwrap()
        };
        assert_eq!(at(0,0,side as usize/2)[0],0);
        // Left/right in engine become source face vertical directions.
        assert_ne!(at(0,0,side as usize/2)[2],at(0,side as usize-1,side as usize/2)[2]);
        assert_ne!(at(0,0,side as usize/2)[1],0);
        // Face centers preserve exact coordinate change.
        let faces=[0usize,1,4,5,3,2];
        for (target,&source_id) in faces.iter().enumerate(){
            let p=at(target,side as usize/2,side as usize/2);
            assert_eq!(p[0] as usize,source_id);
        }
    }
}
