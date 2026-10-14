//! CI-only minimal ABI/type compatibility contract for the isolated CS2 crate.
//! Production Rust-test uses its actual neutral_scene package, never this stub.
//! No renderer and no fabricated scene data is implemented here.
#[derive(Clone,Debug,Default)]
pub struct NeutralReport{pub lines:Vec<String>}
#[derive(Clone,Debug,Default)]
pub struct NeutralScene{
    pub meshes:Vec<NeutralMesh>,
    pub materials:Vec<NeutralMaterial>,
    pub textures:Vec<NeutralTexture>,
    pub instances:Vec<NeutralInstance>,
    pub report:NeutralReport,
    pub sun:Option<NeutralSun>,
    pub sky:Option<NeutralSky>,
    pub local_lights:Vec<NeutralLocalLight>,
}
#[derive(Clone,Copy,Debug,Default)]
pub struct NeutralVertex{
    pub position:[f32;3],
    pub normal:[f32;3],
    pub tangent:[f32;4],
    pub uv:[f32;2],
    pub color:[f32;4],
    pub lightmap_uv:[f32;2],
}
#[derive(Clone,Copy,Debug,Default)]
pub enum NeutralAlpha {#[default] Opaque,Blend}
#[derive(Clone,Copy,Debug,Default)]
pub struct NeutralLayer;
#[derive(Clone,Debug)]
pub struct NeutralMaterial{
    pub name:String,
    pub base_color_texture:Option<usize>,
    pub normal_texture:Option<usize>,
    pub specular_texture:Option<usize>,
    pub metallic_roughness_texture:Option<usize>,
    pub emissive_texture:Option<usize>,
    pub metallic:f32,
    pub emissive:[f32;3],
    pub roughness:f32,
    pub point_sampled:bool,
    pub gloss_from_color_alpha:bool,
    pub alpha:NeutralAlpha,
    pub double_sided:bool,
    pub front_culled:bool,
    pub unlit:bool,
    pub emissive_scale:f32,
    pub layers:[NeutralLayer;2],
    pub visible:bool,
    pub collides:bool,
    pub program:Option<()>,
}
#[derive(Clone,Debug)]
pub struct NeutralMesh{
    pub name:String,
    pub material:usize,
    pub vertices:Vec<NeutralVertex>,
    pub indices:Vec<u32>,
    pub lightmap:Option<usize>,
    pub model_vertex_base:u32,
    pub vertex_light:Option<Vec<[f32;4]>>,
    pub source_vertices:Option<()>,
}
#[derive(Clone,Copy,Debug)]
pub struct NeutralInstance{
    pub mesh:usize,
    pub rows:[[f32;4];3],
    pub motion:Option<()>,
    pub camera_relative:bool,
    pub irradiance_sh:Option<[[f32;3];9]>,
    pub reflection_probe:Option<usize>,
    pub source_reflection_probe:Option<usize>,
    pub sun_visibility:Option<f32>,
    pub program_data:[[f32;4];8],
    pub program_data_valid_rows:u8,
    pub vertex_data_override:Option<u32>,
}

#[derive(Clone,Copy,Debug)]
pub struct NeutralSun{
    pub direction_to_light:[f32;3],
    pub color:[f32;3],
    pub intensity:f32,
}
#[derive(Clone,Copy,Debug)]
pub enum NeutralLocalLightKind{Point,Spot}
#[derive(Clone,Copy,Debug)]
pub struct NeutralLocalLight{
    pub kind:NeutralLocalLightKind,
    pub position:[f32;3],
    pub direction:[f32;3],
    pub color:[f32;3],
    pub intensity:f32,
    pub radius:f32,
    pub inner_angle_degrees:f32,
    pub outer_angle_degrees:f32,
    pub specular_strength:f32,
}

#[derive(Clone,Debug)]
pub struct NeutralTexture{pub name:String,pub width:u32,pub height:u32,pub rgba:Vec<u8>,pub mips:Vec<NeutralTextureMip>,pub compressed:Option<NeutralCompressedTexture>}
#[derive(Clone,Copy,Debug)]
pub enum NeutralBlockFormat {Bc1,Bc3,Bc5,Bc7}
#[derive(Clone,Debug)]
pub struct NeutralCompressedLevel {pub width:u32,pub height:u32,pub blocks:Vec<u8>}
#[derive(Clone,Debug)]
pub struct NeutralCompressedTexture {pub format:NeutralBlockFormat,pub levels:Vec<NeutralCompressedLevel>}
#[derive(Clone,Debug)]
pub struct NeutralTextureMip{pub width:u32,pub height:u32,pub rgba:Vec<u8>}

#[derive(Clone,Debug)]
pub struct NeutralSky {pub faces:[NeutralTexture;6],pub intensity:f32,pub cycle:Option<()>}
