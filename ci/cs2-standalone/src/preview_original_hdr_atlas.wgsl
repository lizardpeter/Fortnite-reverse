struct Frame {
    view_proj: mat4x4<f32>,
    camera_position: vec4<f32>,
    render_fog: vec4<f32>,
    render_params: vec4<f32>,
    ibl_params: vec4<f32>,
};

var<immediate> frame: Frame;

struct RigidVertexInput {
    @location(0) position: vec3<f32>,
    @location(1) normal: vec3<f32>,
    @location(2) tangent: vec4<f32>,
    @location(3) uv: vec2<f32>,
    @location(4) color: vec4<f32>,
    // Second vertex stream: baked-lightmap UVs (zero when a mesh has none),
    // then the UVs of blend layers 1 and 2.
    @location(5) lightmap_uv: vec2<f32>,
    @location(6) layer1_uv: vec2<f32>,
    @location(7) layer2_uv: vec2<f32>,
    // Per-vertex baked light (rgb) and directional-light visibility (a).
    @location(8) vertex_light: vec4<f32>,
    // Source-defined per-vertex values read by surface programs.
    @location(9) vertex_data: vec4<f32>,
};

struct EnvironmentInstance {
    transform: array<vec4<f32>, 3>,
    bounds_sphere: vec4<f32>,
    mesh: u32,
    material: u32,
    flags: u32,
    object_id: u32,
    // Stepped: xyz = local axis * source steps/second, w = degrees/step.
    // Continuous flag: xyz = unit local axis, w = authored degrees/second.
    // Dual sine: x/y = wave amplitudes, z/w = local-grid-recenter UV
    // gains (local Z -> U, local X -> V), in UV units per metre.
    motion: vec4<f32>,
    // Timed translation: accel_ms, decel_ms, start_delay_ms, unused.
    // Dual-sine surface: k0x, k0z, k1x, k1z.
    motion_aux: vec4<f32>,
    // Dual-sine surface: phase_per_step, steps_per_second, recenter_step, unused.
    motion_extra: vec4<f32>,
};

const INSTANCE_FLAG_CAMERA_RELATIVE: u32 = 1u << 4u;
const INSTANCE_FLAG_BILLBOARD: u32 = 1u << 5u;
const INSTANCE_FLAG_BILLBOARD_Y: u32 = 1u << 6u;
const INSTANCE_FLAG_CONTINUOUS_ROTATION: u32 = 1u << 7u;
const INSTANCE_FLAG_TIMED_TRANSLATION: u32 = 1u << 8u;
const INSTANCE_FLAG_TIMED_ROTATION: u32 = 1u << 9u;
const INSTANCE_FLAG_DUAL_SINE_HEIGHT_FIELD: u32 = 1u << 10u;
const INSTANCE_FLAG_UV_SCROLL: u32 = 1u << 11u;
const INSTANCE_FLAG_HARMONIC_ROTATION: u32 = 1u << 12u;
const INSTANCE_FLAG_ATLAS_CYCLE: u32 = 1u << 13u;
const INSTANCE_FLAG_REPEATING_WORLD_TILE: u32 = 1u << 14u;
const INSTANCE_FLAG_DYNAMIC_SKY_VERTEX_LIGHT: u32 = 1u << 15u;
const INSTANCE_FLAG_KEYFRAMED_ROTATION: u32 = 1u << 16u;
// A source-lit static surface may carry nonzero motion.xyz/w containing
// lighting coefficients. Only explicitly authored stepped rotation uses
// this flag; do not interpret arbitrary material payloads as a rotation.
const INSTANCE_FLAG_STEPPED_ROTATION: u32 = 1u << 18u;

struct PbrMaterial {
    base_color: vec4<f32>,
    emissive_occlusion: vec4<f32>,
    metallic_roughness_normal_alpha: vec4<f32>,
    // x = blend equation: 0 normal, 1 additive, 2 multiply.
    // y = texture-array slot per semantic layer, 3 bits each (7 = absent).
    params: vec4<f32>,
};

struct SceneLight {
    position_radius: vec4<f32>,
    color_intensity: vec4<f32>,
    direction_inner: vec4<f32>,
    params: vec4<f32>,
};

struct SceneLightBuffer {
    ambient: vec4<f32>,
    counts: vec4<u32>,
    lights: array<SceneLight>,
};

struct ShadowGlobals {
    light_view_proj: array<mat4x4<f32>, 16>,
    shadow_params: vec4<f32>,
    // xy = minimum world X/Z, zw = world X/Z tile step.
    shadow_grid: vec4<f32>,
    // x = tile columns or cascades, y = tile rows (>0) or cascade mode
    // sentinel (-1), z = active layers, w = positive authored shadow
    // range (>=1m) or zero when disabled.
    shadow_meta: vec4<f32>,
};

struct IblGlobals {
    // x = authored cubemap enabled, y = maximum roughness mip,
    // z = visible-sky intensity, w = source-neutral studio-shaping strength.
    params: vec4<f32>,
    sh0: vec4<f32>,
    sh1: vec4<f32>,
    sh2: vec4<f32>,
    sh3: vec4<f32>,
    sh4: vec4<f32>,
    sh5: vec4<f32>,
    sh6: vec4<f32>,
    sh7: vec4<f32>,
    sh8: vec4<f32>,
    // x = graded display transform (0 = ACES, 2 = linear-HDR scene: the
    // composite applies it), y = encode gamma, z = shoulder knee,
    // w = display colour table present.
    grade: vec4<f32>,
    // Fog shape: x = cos(outer), y = cos(inner) of the directional fog cone,
    // z = maximum fog opacity (1 = fog can fully cover).
    fog_shape: vec4<f32>,
    // Directional (sun) fog: rgb colour, w = its maximum opacity.
    sun_fog_color: vec4<f32>,
    // xyz = direction toward the sun fog, w = enabled.
    sun_fog_direction: vec4<f32>,
    // (initial ticks, ticks/second, cycle ticks, enabled).
    sky_cycle: vec4<f32>,
    sky_zenith_stops: array<vec4<f32>, 16>,
    sky_horizon_stops: array<vec4<f32>, 16>,
    // (zenith count, horizon count, source-phase offset, unused).
    sky_color_meta: vec4<f32>,
    // Original Mojang 0..1 keyframe phases and scalar values.
    sky_blend_min: array<vec4<f32>, 16>,
    sky_blend_start: array<vec4<f32>, 16>,
    sky_blend_max: array<vec4<f32>, 16>,
    sky_blend_mie_start: array<vec4<f32>, 16>,
    sky_blend_meta: vec4<f32>,
    // x = last specular IBL record (0..2), y = blend (0..1),
    // z = 3 independent authored history records available, w reserved.
    specular_record_controls: vec4<f32>,
};

@group(0) @binding(0)
var<storage, read> instances: array<EnvironmentInstance>;

@group(0) @binding(1)
var<storage, read> materials: array<PbrMaterial>;

// Each material descriptor set binds one UNORM texture array holding only the
// layers the material supplies; `PbrMaterial.params.y` maps each semantic to
// its slot: 0 base-color(sRGB), 1 tangent-space normal(linear),
// 2 metallic-roughness(linear, B=metallic/G=roughness),
// 3 occlusion(linear, R=AO), 4 emissive(sRGB). Absent layers use neutral values.
@group(0) @binding(2)
var material_textures: texture_2d_array<f32>;

@group(0) @binding(3)
var material_sampler: sampler;

// Set 1 is the per-scene set: lights (bindings 0-2), directional shadow (3-5),
// environment lighting (6-8) and baked lighting (9-14). Keeping them in one
// set keeps the pipeline within Vulkan's guaranteed four descriptor sets.
// Lights: binding 0 owns all authored lights; 1/2 are the forward+ view
// clusters (ranges per cluster, then the light indices they reference).
@group(1) @binding(0)
var<storage, read> scene_lights: SceneLightBuffer;

@group(1) @binding(1)
var<storage, read> scene_light_clusters: array<vec2<u32>>;

@group(1) @binding(2)
var<storage, read> scene_light_indices: array<u32>;

// Scene set bindings 3-5: source-neutral shadow state. Authored static scenery uses a cached
// world-space tile array so large maps retain directional-shadow coverage with
// no per-frame shadow rendering.
@group(1) @binding(3)
var<uniform> shadow_globals: ShadowGlobals;

@group(1) @binding(4)
var environment_shadow: texture_depth_2d_array;

@group(1) @binding(5)
var environment_shadow_sampler: sampler_comparison;

// Scene set bindings 6-8: source-neutral authored environment lighting. The cubemap is SRGB,
// so Vulkan returns linear values to the shader. Roughness selects a prefiltered
// mip, while diffuse irradiance comes from map-load-time cosine-convolved SH9.
@group(1) @binding(6)
var<uniform> ibl_globals: IblGlobals;

@group(1) @binding(7)
var environment_cube: texture_cube<f32>;

@group(1) @binding(8)
var environment_cube_sampler: sampler;

// Scene set bindings 9-14: source-neutral baked lighting. Each instance may carry a directional
// lightmap (three layers of `lightmap_textures`: ambient RGBM, directional RGBM,
// direction) or a 9-coefficient irradiance SH probe. Baked diffuse replaces the
// scene ambient and diffuse environment light; direct lights still add on top.
struct BakedInstance {
    // x = mode (0 none, 1 lightmap, 2 probe SH, 3 per-vertex light with SH
    // detail), y = first layer, zw = UV scale (lightmap); z = directional
    // visibility (probe SH).
    mode: vec4<f32>,
    // x = generic PBR reflection probe slot (-1 = none), y = its highest mip,
    // z = mean luminance the generic probe captured (0 = unknown),
    // w = exact source cube-array slot (-1 = unavailable).
    probe: vec4<f32>,
    sh: array<vec4<f32>, 9>,
    // Opaque source-defined values read only by universal SurfacePrograms.
    program_data: array<vec4<f32>, 8>,
    // x = base word in source_vertex_words, y = stride bytes,
    // z = vertex count, w = 1 when an exact source stream is present.
    source_vertex: vec4<u32>,
    // Per-instance vertex-data lane override in source_vertex_words: x = base
    // word, y = first lane | lanes << 8, z = vertex count, w = present.
    instance_vertex: vec4<u32>,
};

const LIGHTMAP_RGBM_RANGE: f32 = 8.0;

@group(1) @binding(9)
var<storage, read> baked_instances: array<BakedInstance>;

@group(1) @binding(15)
var<storage, read> source_vertex_words: array<u32>;

// Optional source-native baked-lighting payload retained for universal shader
// replay. One array layer corresponds to one scene lightmap; the per-instance
// baked record supplies its layer and UV scale. Generic PBR lighting does not
// read this resource.
@group(1) @binding(16)
var source_lightmap_textures: texture_2d_array<f32>;

// Optional exact source-owned 3D RGBA8 scene texture retained for universal
// shader replay. Generic environment lighting does not interpret it.
@group(1) @binding(17)
var source_volume_texture: texture_3d<f32>;

// Exact source-owned reflection cubemaps. Unlike probe_textures, these retain
// source face order, BC format, authored mips and source colour-space format.
@group(1) @binding(18)
var source_reflection_probes: texture_cube_array<f32>;

@group(1) @binding(19)
var source_reflection_sampler: sampler;

// Generic per-scene runtime values shared by source-neutral procedural
// environment geometry. row0.xyz = local-player world position,
// row0.w = 1 when a current player position is available.
@group(1) @binding(20)
var<storage, read> scene_runtime: array<vec4<f32>>;

// Snapshot of the already-rendered scene used by late refractive/composite
// SurfacePrograms. The renderer refreshes it only when at least one active
// program explicitly requests ProgramSceneTexture::SceneColorSnapshot.
@group(1) @binding(21)
var scene_color_snapshot: texture_2d<f32>;

@group(1) @binding(22)
var scene_color_sampler: sampler;

// Scene depth copied with the snapshot (linear-HDR scenes), for late
// SurfacePrograms reading ProgramSceneTexture::SceneViewDepth.
@group(1) @binding(23)
var scene_depth_snapshot: texture_depth_2d;

// Exact source-authored native BCn baked-lighting inputs, kept separate from
// the generic 3-layer RGBM baked lightmap. These are device-local image2DArray
// resources, with original BC6H HDR, BC1 directional and BC4 shadow blocks.
// No Source 2-specific lighting equation is presumed by this interface.
// Material admission must verify all three source compiler semantic roles
// and the original lightmap UV/primitive contract before shader sampling.
@group(1) @binding(24)
var source_baked_irradiance_hdr: texture_2d_array<f32>;

@group(1) @binding(25)
var source_baked_directional_irradiance: texture_2d_array<f32>;

@group(1) @binding(26)
var source_baked_direct_light_shadows: texture_2d_array<f32>;

// Optional preintegrated two-channel GGX split-sum coefficients, uploaded
// once at scene creation. The original client s_BrdfLUT pixels are not
// available: this is an engine-generated linear lookup compatible with
// the recovered sample coordinates and A*F0+B reconstruction.
@group(1) @binding(27)
var environment_brdf_lut: texture_2d<f32>;

@group(1) @binding(28)
var environment_brdf_sampler: sampler;

// Actual independently authored three-record specular IBL history.
// The descriptor always points to a valid cubemap-array view, but the
// source history sampling path is admitted only if the manifest supplied
// three compatible cubemaps. No fake history is synthesized from the sky.
@group(1) @binding(29)
var environment_specular_records: texture_cube_array<f32>;

// Distance along the view axis (engine metres) of the snapshot depth at a
// normalized screen UV. The reversed perspective's z/w rows are recovered from
// the frame's view-projection: clip.w = -view_z and clip.z = P22 view_z + P32,
// so depth d gives distance P32 / (d + P22).
fn program_scene_view_depth(uv: vec2<f32>) -> f32 {
    let size = vec2<i32>(textureDimensions(scene_depth_snapshot));
    let texel = clamp(vec2<i32>(floor(uv * vec2<f32>(size))), vec2<i32>(0), size - vec2<i32>(1));
    let d = textureLoad(scene_depth_snapshot, texel, 0);
    let m = frame.view_proj;
    let row2 = vec4<f32>(m[0][2], m[1][2], m[2][2], m[3][2]);
    let row3 = vec4<f32>(m[0][3], m[1][3], m[2][3], m[3][3]);
    let a = abs(row3.xyz);
    var k = 0;
    if a.y > a.x && a.y >= a.z {
        k = 1;
    } else if a.z > a.x && a.z > a.y {
        k = 2;
    }
    let p22 = -row2[k] / row3[k];
    let p32 = row2.w + p22 * row3.w;
    return p32 / max(d + p22, 1.0e-7);
}

@group(1) @binding(10)
var lightmap_textures: texture_2d_array<f32>;

@group(1) @binding(11)
var lightmap_sampler: sampler;

// Reflection probes: six layers per probe (+X, -X, +Y, -Y, +Z, -Z), RGBM,
// with a roughness mip chain.
@group(1) @binding(12)
var probe_textures: texture_2d_array<f32>;

@group(1) @binding(13)
var probe_sampler: sampler;

// Display colour table: 32 layers (blue slices) of 32x32 (red across, green
// down), display-encoded. Sampled with the clamped linear lightmap sampler.
@group(1) @binding(14)
var display_lut: texture_2d_array<f32>;

fn sample_reflection_probe(probe: vec4<f32>, direction: vec3<f32>, lod: f32) -> vec3<f32> {
    let a = abs(direction);
    var face = 0;
    var sc = 0.0;
    var tc = 0.0;
    var ma = 1.0;
    if a.x >= a.y && a.x >= a.z {
        ma = a.x;
        tc = -direction.y;
        if direction.x > 0.0 { face = 0; sc = -direction.z; } else { face = 1; sc = direction.z; }
    } else if a.y >= a.z {
        ma = a.y;
        sc = direction.x;
        if direction.y > 0.0 { face = 2; tc = direction.z; } else { face = 3; tc = -direction.z; }
    } else {
        ma = a.z;
        tc = -direction.y;
        if direction.z > 0.0 { face = 4; sc = direction.x; } else { face = 5; sc = -direction.x; }
    }
    let uv = vec2<f32>(sc, tc) / max(ma, 0.000001) * 0.5 + vec2<f32>(0.5);
    let layer = i32(probe.x + 0.5) * 6 + face;
    let texel = textureSampleLevel(probe_textures, probe_sampler, uv, layer, lod);
    return texel.rgb * texel.a * LIGHTMAP_RGBM_RANGE;
}

struct VertexOutput {
    @builtin(position) position: vec4<f32>,
    @location(0) world_position: vec3<f32>,
    @location(1) world_normal: vec3<f32>,
    @location(2) world_tangent: vec4<f32>,
    @location(3) color: vec4<f32>,
    @location(4) uv: vec2<f32>,
    @location(5) @interpolate(flat) material_index: u32,
    @location(6) @interpolate(flat) instance_index: u32,
    @location(7) lightmap_uv: vec2<f32>,
    @location(8) layer_uvs: vec4<f32>,
    @location(9) vertex_light: vec4<f32>,
    @location(10) vertex_data: vec4<f32>,
};

fn affine_point(rows: array<vec4<f32>, 3>, point: vec3<f32>) -> vec3<f32> {
    let p = vec4<f32>(point, 1.0);
    return vec3<f32>(dot(rows[0], p), dot(rows[1], p), dot(rows[2], p));
}

fn affine_direction(rows: array<vec4<f32>, 3>, direction: vec3<f32>) -> vec3<f32> {
    let d = vec4<f32>(direction, 0.0);
    return vec3<f32>(dot(rows[0], d), dot(rows[1], d), dot(rows[2], d));
}

fn timed_trajectory_progress(
    total_millis: f32,
    accel_millis: f32,
    decel_millis: f32,
    start_delay_millis: f32,
) -> f32 {
    let total = max(total_millis, 1.0);
    let accel = clamp(accel_millis, 0.0, total);
    let decel = clamp(decel_millis, 0.0, total - accel);
    let linear = max(total - accel - decel, 0.0);
    let delay = max(start_delay_millis, 0.0);
    let elapsed_ms = max(frame.camera_position.w * 1000.0 - delay, 0.0);
    if elapsed_ms >= total {
        return 1.0;
    }

    // Unit-distance trapezoid. This is the same profile as
    // neutral_scene::trajectory::NeutralTrajectoryTiming::sample_progress.
    let denominator = total - 0.5 * (accel + decel);
    if denominator <= 0.000001 {
        return 0.0;
    }
    let peak = 1.0 / denominator;
    var progress = 0.0;
    if accel > 0.0 && elapsed_ms < accel {
        let acceleration = peak / accel;
        progress = 0.5 * acceleration * elapsed_ms * elapsed_ms;
    } else {
        let accel_distance = 0.5 * peak * accel;
        let after_accel = elapsed_ms - accel;
        if after_accel < linear {
            progress = accel_distance + peak * after_accel;
        } else if decel > 0.0 {
            let decel_t = clamp(after_accel - linear, 0.0, decel);
            let before_decel = accel_distance + peak * linear;
            let deceleration = peak / decel;
            progress = before_decel
                + peak * decel_t
                - 0.5 * deceleration * decel_t * decel_t;
        } else {
            progress = accel_distance + peak * after_accel;
        }
    }
    return clamp(progress, 0.0, 1.0);
}

fn timed_rotation_progress(instance: EnvironmentInstance) -> f32 {
    if (instance.flags & INSTANCE_FLAG_TIMED_ROTATION) == 0u {
        return 0.0;
    }
    return timed_trajectory_progress(
        instance.motion_aux.x,
        instance.motion_aux.y,
        instance.motion_aux.z,
        instance.motion_aux.w,
    );
}

fn instance_has_rigid_rotation(instance: EnvironmentInstance) -> bool {
    return (instance.flags & (
        INSTANCE_FLAG_STEPPED_ROTATION |
        INSTANCE_FLAG_CONTINUOUS_ROTATION |
        INSTANCE_FLAG_TIMED_ROTATION |
        INSTANCE_FLAG_HARMONIC_ROTATION |
        INSTANCE_FLAG_KEYFRAMED_ROTATION
    )) != 0u;
}

fn instance_motion_angle(instance: EnvironmentInstance) -> f32 {
    // Previously the fallthrough stepped-rotation path ran for EVERY
    // instance with nonzero motion.xyz, including static Bedrock terrain:
    // (night_irradiance, PCF_width, GGX_k, roughness_floor) were treated
    // as an angular axis/rate and rotated the whole world over time.
    if !instance_has_rigid_rotation(instance) {
        return 0.0;
    }
    let axis_scale = length(instance.motion.xyz);
    if axis_scale <= 0.000001 {
        return 0.0;
    }
    if (instance.flags & INSTANCE_FLAG_TIMED_ROTATION) != 0u {
        return timed_rotation_progress(instance)
            * instance.motion.w
            * 0.017453292519943295;
    }
    let elapsed = max(frame.camera_position.w, 0.0);
    if (instance.flags & INSTANCE_FLAG_KEYFRAMED_ROTATION) != 0u {
        let times = instance.motion_aux.xyz;
        let length = instance.motion_aux.w;
        var t = min(elapsed, length);
        if (instance.motion_extra.w >= 0.5) {
            t = fract(elapsed / length) * length;
        }
        var degrees = instance.motion.w;
        if (t > times.x) {
            let alpha = clamp((t-times.x) / max(times.y-times.x, 0.000001), 0.0, 1.0);
            degrees = mix(instance.motion.w, instance.motion_extra.x, alpha);
        }
        if (t > times.y && instance.motion_extra.z >= 2.5) {
            let alpha = clamp((t-times.y) / max(times.z-times.y, 0.000001), 0.0, 1.0);
            degrees = mix(instance.motion_extra.x, instance.motion_extra.y, alpha);
        }
        return degrees * 0.017453292519943295;
    }
    if (instance.flags & INSTANCE_FLAG_HARMONIC_ROTATION) != 0u {
        return sin(elapsed * instance.motion_aux.x + instance.motion_aux.y)
            * instance.motion.w * 0.017453292519943295;
    }
    if (instance.flags & INSTANCE_FLAG_CONTINUOUS_ROTATION) != 0u {
        return elapsed * instance.motion.w * 0.017453292519943295;
    }
    // Preserve source runtimes that advance once per fixed game tick instead
    // of replacing them with a continuously interpolated host rotation.
    let steps = floor(elapsed * axis_scale);
    return steps * instance.motion.w * 0.017453292519943295;
}

fn rotate_axis_angle(value: vec3<f32>, axis: vec3<f32>, angle: f32) -> vec3<f32> {
    if abs(angle) <= 0.0000001 {
        return value;
    }
    let c = cos(angle);
    let s = sin(angle);
    return value * c
        + cross(axis, value) * s
        + axis * dot(axis, value) * (1.0 - c);
}

fn motion_local_direction(instance: EnvironmentInstance, value: vec3<f32>) -> vec3<f32> {
    // Prevent stray motion payloads from rotating geometry or normals.
    // This also skips costly normalization for millions of static vertices.
    if !instance_has_rigid_rotation(instance) {
        return value;
    }
    let axis_scale = length(instance.motion.xyz);
    if axis_scale <= 0.000001 {
        return value;
    }
    return rotate_axis_angle(
        value,
        instance.motion.xyz / axis_scale,
        instance_motion_angle(instance),
    );
}

fn timed_translation_progress(instance: EnvironmentInstance) -> f32 {
    if (instance.flags & INSTANCE_FLAG_TIMED_TRANSLATION) == 0u {
        return 0.0;
    }
    return timed_trajectory_progress(
        instance.motion.w,
        instance.motion_aux.x,
        instance.motion_aux.y,
        instance.motion_aux.z,
    );
}

fn instance_translation_delta(instance: EnvironmentInstance) -> vec3<f32> {
    var delta = vec3<f32>(0.0);
    if (instance.flags & INSTANCE_FLAG_TIMED_TRANSLATION) != 0u {
        delta += instance.motion.xyz * timed_translation_progress(instance);
    }
    if (instance.flags & INSTANCE_FLAG_REPEATING_WORLD_TILE) != 0u {
        // Every instance in a repeated tile field has the same origin and
        // period. Recenter the entire group as the viewer crosses tile
        // boundaries, retaining physically extruded world geometry.
        let periods = max(instance.motion_aux.zw, vec2<f32>(1.0));
        let anchor = instance.motion_aux.xy;
        let shift = floor((frame.camera_position.xz - anchor) / periods) * periods;
        let drift = fract(max(frame.camera_position.w, 0.0)
            * instance.motion.xz / periods) * periods;
        delta += vec3<f32>(shift.x + drift.x, 0.0, shift.y + drift.y);
    }
    if (instance.flags & INSTANCE_FLAG_CAMERA_RELATIVE) != 0u {
        delta += frame.camera_position.xyz;
    }
    return delta;
}

fn instance_translation(instance: EnvironmentInstance) -> vec3<f32> {
    var center = vec3<f32>(
        instance.transform[0].w,
        instance.transform[1].w,
        instance.transform[2].w,
    );
    center += instance_translation_delta(instance);
    return center;
}

fn instance_linear_scale(instance: EnvironmentInstance) -> vec3<f32> {
    let c0 = vec3<f32>(instance.transform[0].x, instance.transform[1].x, instance.transform[2].x);
    let c1 = vec3<f32>(instance.transform[0].y, instance.transform[1].y, instance.transform[2].y);
    let c2 = vec3<f32>(instance.transform[0].z, instance.transform[1].z, instance.transform[2].z);
    return vec3<f32>(length(c0), length(c1), length(c2));
}

fn instance_billboard_basis(instance: EnvironmentInstance) -> mat3x3<f32> {
    let center = instance_translation(instance);
    var forward = frame.camera_position.xyz - center;
    if dot(forward, forward) <= 0.0000001 {
        forward = vec3<f32>(0.0, 0.0, 1.0);
    } else {
        forward = normalize(forward);
    }

    let world_up = vec3<f32>(0.0, 1.0, 0.0);
    var right = cross(world_up, forward);
    if dot(right, right) <= 0.0000001 {
        right = vec3<f32>(1.0, 0.0, 0.0);
    } else {
        right = normalize(right);
    }

    var up = normalize(cross(forward, right));
    if (instance.flags & INSTANCE_FLAG_BILLBOARD_Y) != 0u {
        up = world_up;
        forward = normalize(cross(right, up));
    }

    let scale = instance_linear_scale(instance);
    return mat3x3<f32>(
        right * max(scale.x, 0.000001),
        up * max(scale.y, 0.000001),
        forward * max(scale.z, 0.000001),
    );
}

fn dual_sine_grid_local_position(
    instance: EnvironmentInstance,
    position: vec3<f32>,
) -> vec3<f32> {
    if (instance.flags & INSTANCE_FLAG_DUAL_SINE_HEIGHT_FIELD) == 0u {
        return position;
    }
    let quantum = max(instance.motion_extra.z, 0.0);
    if quantum <= 0.000001 || scene_runtime[0].w < 0.5 {
        return position;
    }

    // Convert the player delta into the instance's orthogonal SRT basis.
    // This preserves local side/front recentering while wave phase itself
    // remains world-XZ below.
    let center = vec3<f32>(
        instance.transform[0].w,
        instance.transform[1].w,
        instance.transform[2].w,
    );
    let delta = scene_runtime[0].xyz - center;
    let axis_x = vec3<f32>(
        instance.transform[0].x,
        instance.transform[1].x,
        instance.transform[2].x,
    );
    let axis_z = vec3<f32>(
        instance.transform[0].z,
        instance.transform[1].z,
        instance.transform[2].z,
    );
    let x_denom = max(dot(axis_x, axis_x), 0.000001);
    let z_denom = max(dot(axis_z, axis_z), 0.000001);
    let local_player_x = dot(delta, axis_x) / x_denom;
    let local_player_z = dot(delta, axis_z) / z_denom;
    let shift_x = round(local_player_x / quantum) * quantum;
    let shift_z = round(local_player_z / quantum) * quantum;
    return position + vec3<f32>(shift_x, 0.0, shift_z);
}

fn dual_sine_world_height(
    instance: EnvironmentInstance,
    world_xz: vec2<f32>,
) -> f32 {
    if (instance.flags & INSTANCE_FLAG_DUAL_SINE_HEIGHT_FIELD) == 0u {
        return 0.0;
    }
    let steps = floor(max(frame.camera_position.w, 0.0) * max(instance.motion_extra.y, 0.0));
    let phase = steps * instance.motion_extra.x;
    let p0 = dot(world_xz, instance.motion_aux.xy) + phase;
    let p1 = dot(world_xz, instance.motion_aux.zw) + phase;
    return sin(p0) * instance.motion.x + sin(p1) * instance.motion.y;
}

fn dual_sine_world_normal(
    instance: EnvironmentInstance,
    world_xz: vec2<f32>,
) -> vec3<f32> {
    if (instance.flags & INSTANCE_FLAG_DUAL_SINE_HEIGHT_FIELD) == 0u {
        return vec3<f32>(0.0, 1.0, 0.0);
    }
    let steps = floor(max(frame.camera_position.w, 0.0) * max(instance.motion_extra.y, 0.0));
    let phase = steps * instance.motion_extra.x;
    let p0 = dot(world_xz, instance.motion_aux.xy) + phase;
    let p1 = dot(world_xz, instance.motion_aux.zw) + phase;
    let slope_x =
        cos(p0) * instance.motion.x * instance.motion_aux.x
        + cos(p1) * instance.motion.y * instance.motion_aux.z;
    let slope_z =
        cos(p0) * instance.motion.x * instance.motion_aux.y
        + cos(p1) * instance.motion.y * instance.motion_aux.w;
    return normalize(vec3<f32>(-slope_x, 1.0, -slope_z));
}

fn instance_world_position(instance: EnvironmentInstance, position: vec3<f32>) -> vec3<f32> {
    if (instance.flags & INSTANCE_FLAG_BILLBOARD) != 0u {
        return instance_translation(instance) + instance_billboard_basis(instance) * position;
    }
    if (instance.flags & INSTANCE_FLAG_DUAL_SINE_HEIGHT_FIELD) != 0u {
        let local = dual_sine_grid_local_position(instance, position);
        var world = affine_point(instance.transform, local);
        world.y += dual_sine_world_height(instance, world.xz);
        world += instance_translation_delta(instance);
        return world;
    }
    let local = motion_local_direction(instance, position);
    var world = affine_point(instance.transform, local);
    world += instance_translation_delta(instance);
    return world;
}

fn normal_direction(rows: array<vec4<f32>, 3>, direction: vec3<f32>) -> vec3<f32> {
    let c0 = vec3<f32>(rows[0].x, rows[1].x, rows[2].x);
    let c1 = vec3<f32>(rows[0].y, rows[1].y, rows[2].y);
    let c2 = vec3<f32>(rows[0].z, rows[1].z, rows[2].z);
    let cof0 = cross(c1, c2);
    let cof1 = cross(c2, c0);
    let cof2 = cross(c0, c1);
    return normalize(cof0 * direction.x + cof1 * direction.y + cof2 * direction.z);
}

fn instance_world_normal(
    instance: EnvironmentInstance,
    direction: vec3<f32>,
    world_position: vec3<f32>,
) -> vec3<f32> {
    if (instance.flags & INSTANCE_FLAG_BILLBOARD) != 0u {
        return normalize(instance_billboard_basis(instance) * direction);
    }
    if (instance.flags & INSTANCE_FLAG_DUAL_SINE_HEIGHT_FIELD) != 0u {
        // The wave slope varies per vertex. Sampling it at the instance center
        // made every OceanBowl-style height field carry one constant normal
        // across the entire 48 m grid even while its vertices moved correctly.
        return dual_sine_world_normal(instance, world_position.xz);
    }
    return normal_direction(instance.transform, motion_local_direction(instance, direction));
}

fn instance_world_tangent(instance: EnvironmentInstance, direction: vec3<f32>) -> vec3<f32> {
    if (instance.flags & INSTANCE_FLAG_BILLBOARD) != 0u {
        return instance_billboard_basis(instance) * direction;
    }
    return affine_direction(instance.transform, motion_local_direction(instance, direction));
}

fn program_object_to_world(instance_index: u32, row: u32) -> vec4<f32> {
    let instance = instances[instance_index];
    if (instance.flags & INSTANCE_FLAG_BILLBOARD) != 0u {
        let basis = instance_billboard_basis(instance);
        let center = instance_translation(instance);
        if row == 0u {
            return vec4<f32>(basis[0].x, basis[1].x, basis[2].x, center.x);
        }
        if row == 1u {
            return vec4<f32>(basis[0].y, basis[1].y, basis[2].y, center.y);
        }
        return vec4<f32>(basis[0].z, basis[1].z, basis[2].z, center.z);
    }

    let base = instance.transform[row];
    let translation_delta = instance_translation_delta(instance);
    // SurfacePrograms must see the exact same non-rotating object-to-world
    // transform as the regular vertex shader, normals and shadow geometry.
    if !instance_has_rigid_rotation(instance) {
        return vec4<f32>(base.xyz, base.w + translation_delta[row]);
    }
    let axis_scale = length(instance.motion.xyz);
    if axis_scale <= 0.000001 {
        return vec4<f32>(base.xyz, base.w + translation_delta[row]);
    }
    // Effective object-to-world is static_affine * local_rotation. For a
    // row-vector of the affine linear block this is R^T * row, hence -angle.
    let rotated_row = rotate_axis_angle(
        base.xyz,
        instance.motion.xyz / axis_scale,
        -instance_motion_angle(instance),
    );
    return vec4<f32>(rotated_row, base.w + translation_delta[row]);
}

fn program_instance_data(instance_index: u32, row: u32) -> vec4<f32> {
    return baked_instances[instance_index].program_data[row];
}

fn fallback_tangent(n: vec3<f32>) -> vec3<f32> {
    var axis = vec3<f32>(1.0, 0.0, 0.0);
    if abs(n.x) > 0.9 {
        axis = vec3<f32>(0.0, 1.0, 0.0);
    }
    return normalize(cross(axis, n));
}

// The mesh vertex's `vertex_data` with this instance's per-vertex unorm8
// lanes (if any) substituted. Mesh draws use vertex offset 0, so
// `vertex_index` is the mesh-local vertex.
fn instance_vertex_data(instance_index: u32, vertex_index: u32, base: vec4<f32>) -> vec4<f32> {
    let record = baked_instances[instance_index].instance_vertex;
    var data = base;
    if record.w == 0u || vertex_index >= record.z {
        return data;
    }
    let first = record.y & 0xffu;
    let lanes = (record.y >> 8u) & 0xffu;
    for (var i = 0u; i < lanes; i = i + 1u) {
        let byte_index = vertex_index * lanes + i;
        let word = source_vertex_words[record.x + byte_index / 4u];
        data[first + i] = f32((word >> (8u * (byte_index % 4u))) & 0xffu) / 255.0;
    }
    return data;
}

@vertex
fn vs_main(
    input: RigidVertexInput,
    @builtin(instance_index) instance_index: u32,
    @builtin(vertex_index) vertex_index: u32,
) -> VertexOutput {
    let instance = instances[instance_index];
    let world_position = instance_world_position(instance, input.position);
    let world_normal = instance_world_normal(instance, input.normal, world_position);
    let tangent_raw = instance_world_tangent(instance, input.tangent.xyz);
    let tangent_orthogonal = tangent_raw - world_normal * dot(world_normal, tangent_raw);
    var world_tangent = fallback_tangent(world_normal);
    if dot(tangent_orthogonal, tangent_orthogonal) > 0.000001 {
        world_tangent = normalize(tangent_orthogonal);
    }

    var out: VertexOutput;
    out.position = frame.view_proj * vec4<f32>(world_position, 1.0);
    out.world_position = world_position;
    out.world_normal = world_normal;
    out.world_tangent = vec4<f32>(world_tangent, input.tangent.w);
    out.color = input.color;
    out.uv = input.uv;
    if (instance.flags & INSTANCE_FLAG_ATLAS_CYCLE) != 0u {
        // Frame selection is discrete, but the authored quad and angular
        // motion are continuous. Per-vertex UV mapping keeps texture sampling
        // derivatives stable within each source atlas tile.
        let columns = max(u32(instance.motion_aux.x + 0.5), 1u);
        let rows = max(u32(instance.motion_aux.y + 0.5), 1u);
        let total = min(columns * rows, 256u);
        // initial phase is fractional: loading the map at sunset must
        // advance the phase at the NEXT midnight, not after a whole day.
        let phase = max(frame.camera_position.w, 0.0)
            * max(instance.motion_aux.z, 0.0)
            + max(instance.motion_aux.w, 0.0);
        let tile = u32(floor(phase)) % total;
        out.uv = (input.uv + vec2<f32>(
            f32(tile % columns), f32(tile / columns)
        )) / vec2<f32>(f32(columns), f32(rows));
    }
    if (instance.flags & INSTANCE_FLAG_UV_SCROLL) != 0u {
        // Source-neutral texture flow; sampler addressing performs wrap.
        // Keep the scroll in the vertex stage so fragment sampling remains
        // derivative-correct and no material/shader specialization is needed.
        out.uv += instance.motion.xy * max(frame.camera_position.w, 0.0);
    }
    if (instance.flags & INSTANCE_FLAG_DUAL_SINE_HEIGHT_FIELD) != 0u {
        // The mesh follows the player in quantized cells, but the water
        // texture remains fixed in the underlying world/grid coordinate
        // system. Without compensating the snapped grid translation,
        // texture features visibly chase the moving player.
        let recentered_origin = dual_sine_grid_local_position(
            instance, vec3<f32>(0.0));
        out.uv += vec2<f32>(
            recentered_origin.z * instance.motion.z,
            recentered_origin.x * instance.motion.w,
        );
    }
    out.lightmap_uv = input.lightmap_uv;
    out.layer_uvs = vec4<f32>(input.layer1_uv, input.layer2_uv);
    out.vertex_light = input.vertex_light;
    out.vertex_data = instance_vertex_data(instance_index, vertex_index, input.vertex_data);
    out.material_index = instance.material;
    out.instance_index = instance_index;
    return out;
}

const PI: f32 = 3.14159265358979323846;

fn srgb_channel_to_linear(value: f32) -> f32 {
    if value <= 0.04045 {
        return value / 12.92;
    }
    return pow((value + 0.055) / 1.055, 2.4);
}

fn srgb_to_linear(value: vec3<f32>) -> vec3<f32> {
    return vec3<f32>(
        srgb_channel_to_linear(value.x),
        srgb_channel_to_linear(value.y),
        srgb_channel_to_linear(value.z),
    );
}

// Texture-array slot of a semantic layer, or -1 when the material has none.
// Semantics 0-4 are packed in params.y; blend-layer slots 5-8 in params.z.
fn material_layer(material: PbrMaterial, semantic: u32) -> i32 {
    var packed = u32(material.params.y + 0.5);
    var shift = semantic * 3u;
    if semantic >= 5u {
        packed = u32(material.params.z + 0.5);
        shift = (semantic - 5u) * 3u;
    }
    let code = (packed >> shift) & 7u;
    if code == 7u {
        return -1;
    }
    return i32(code);
}

struct MaterialSampling {
    source_grad_x: vec2<f32>,
    source_grad_y: vec2<f32>,
    offset0: vec2<f32>,
    offset1: vec2<f32>,
    offset2: vec2<f32>,
    offset3: vec2<f32>,
    grad_x: vec2<f32>,
    grad_y: vec2<f32>,
};

// Capture derivatives only in uniform fragment control flow, BEFORE any
// alpha-cutout discard. The expensive footprint calculations themselves do
// not use derivatives and can be deferred for layers actually sampled.
struct MaterialGradients {
    dx: vec2<f32>,
    dy: vec2<f32>,
};

fn capture_material_gradients(uv: vec2<f32>) -> MaterialGradients {
    return MaterialGradients(dpdx(uv), dpdy(uv));
}

fn build_material_sampling_from_gradients(gradients: MaterialGradients) -> MaterialSampling {
    let dx = gradients.dx;
    let dy = gradients.dy;
    let dx_len = max(length(dx), 0.0000001);
    let dy_len = max(length(dy), 0.0000001);
    var major = dx;
    var minor = dy;
    var major_len = dx_len;
    var minor_len = dy_len;
    var major_is_x = true;
    if dy_len > dx_len {
        major = dy;
        minor = dx;
        major_len = dy_len;
        minor_len = dx_len;
        major_is_x = false;
    }
    // Lengths belong to the same selected major/minor gradients. Reusing
    // them saves two length/sqrt operations while retaining even the prior
    // NaN-dependent branch selection (unlike sorting via max/min).
    let ratio = clamp(major_len / minor_len, 1.0, 4.0);
    let span = major * (1.0 - 1.0 / ratio);
    let reduced_major = major / ratio;
    var grad_x = minor;
    var grad_y = reduced_major;
    if major_is_x {
        grad_x = reduced_major;
        grad_y = minor;
    }

    var sampling: MaterialSampling;
    sampling.source_grad_x = dx;
    sampling.source_grad_y = dy;
    sampling.offset0 = -span * 0.375;
    sampling.offset1 = -span * 0.125;
    sampling.offset2 = span * 0.125;
    sampling.offset3 = span * 0.375;
    sampling.grad_x = grad_x;
    sampling.grad_y = grad_y;
    return sampling;
}

fn build_material_sampling(uv: vec2<f32>, point_sampled: bool) -> MaterialSampling {
    // Capture derivatives in uniform fragment control flow before alpha
    // discard. For point-sampled source art (including Bedrock's authored
    // pixel textures), sample_material_layer uses only the original gradients
    // and exactly one tap. Building the 4-tap anisotropic footprint here was
    // wasted GPU work on every opaque pixel.
    let gradients = capture_material_gradients(uv);
    if point_sampled {
        var sampling: MaterialSampling;
        sampling.source_grad_x = gradients.dx;
        sampling.source_grad_y = gradients.dy;
        return sampling;
    }
    return build_material_sampling_from_gradients(gradients);
}

fn sample_material_layer(
    uv: vec2<f32>,
    layer: i32,
    sampling: MaterialSampling,
    point_sampled: bool,
) -> vec4<f32> {
    // A source-authored point-sampled material must not be blurred by the
    // four-tap anisotropic floor. The bound sampler is nearest for this
    // material, and one derivative-aware fetch retains appropriate mip LOD.
    if point_sampled {
        return textureSampleGrad(
            material_textures,
            material_sampler,
            uv,
            layer,
            sampling.source_grad_x,
            sampling.source_grad_y,
        );
    }
    let s0 = textureSampleGrad(
        material_textures,
        material_sampler,
        uv + sampling.offset0,
        layer,
        sampling.grad_x,
        sampling.grad_y,
    );
    let s1 = textureSampleGrad(
        material_textures,
        material_sampler,
        uv + sampling.offset1,
        layer,
        sampling.grad_x,
        sampling.grad_y,
    );
    let s2 = textureSampleGrad(
        material_textures,
        material_sampler,
        uv + sampling.offset2,
        layer,
        sampling.grad_x,
        sampling.grad_y,
    );
    let s3 = textureSampleGrad(
        material_textures,
        material_sampler,
        uv + sampling.offset3,
        layer,
        sampling.grad_x,
        sampling.grad_y,
    );
    return (s0 + s1 + s2 + s3) * 0.25;
}

// Source-neutral parallax occlusion for heightmap-derived tangent normals.
// A has unmodified linear height, RGB has the derived normal. The material
// opts in using a quantized UV depth; no UV displacement changes geometry,
// collision, depth testing, shadows or silhouettes.
fn parallax_height_uv(
    uv: vec2<f32>,
    input: VertexOutput,
    normal_layer: i32,
    sampling: MaterialSampling,
    depth_scale: f32,
) -> vec2<f32> {
    let n = normalize(input.world_normal);
    let t = normalize(input.world_tangent.xyz);
    let b = normalize(cross(n, t)) * input.world_tangent.w;
    let view = normalize(frame.camera_position.xyz - input.world_position);
    let tangent_view = vec3<f32>(dot(view, t), dot(view, b), dot(view, n));
    let ray = (tangent_view.xy / max(abs(tangent_view.z), 0.25)) * depth_scale;
    let step_uv = ray * 0.125;
    var current_uv = uv;
    var previous_uv = uv;
    var layer_depth = 0.0;
    // Bedrock authors height, not depth: 1 is the raised surface and
    // maps to zero ray depth, 0 is recessed and maps to full depth.
    var previous_depth = 1.0 - textureSampleGrad(
        material_textures, material_sampler, current_uv, normal_layer,
        sampling.source_grad_x, sampling.source_grad_y
    ).a;
    var sampled_depth = previous_depth;
    // Bounded eight-layer occlusion approximation. Source texels and
    // material gradients are unchanged; a second PBR texture is unnecessary.
    for (var i = 0u; i < 8u; i += 1u) {
        if layer_depth >= sampled_depth {
            break;
        }
        previous_uv = current_uv;
        previous_depth = sampled_depth;
        current_uv -= step_uv;
        layer_depth += 0.125;
        sampled_depth = 1.0 - textureSampleGrad(
            material_textures, material_sampler, current_uv, normal_layer,
            sampling.source_grad_x, sampling.source_grad_y
        ).a;
    }
    let previous_gap = previous_depth - (layer_depth - 0.125);
    let current_gap = sampled_depth - layer_depth;
    let denom = previous_gap - current_gap;
    let fraction = clamp(previous_gap / max(abs(denom), 0.000001), 0.0, 1.0);
    return mix(previous_uv, current_uv, fraction);
}

fn fresnel_schlick(cos_theta: f32, f0: vec3<f32>) -> vec3<f32> {
    return f0 + (vec3<f32>(1.0) - f0) * pow(clamp(1.0 - cos_theta, 0.0, 1.0), 5.0);
}

fn fresnel_schlick_roughness(cos_theta: f32, f0: vec3<f32>, roughness: f32) -> vec3<f32> {
    let grazing = max(vec3<f32>(1.0 - roughness), f0);
    return f0 + (grazing - f0) * pow(clamp(1.0 - cos_theta, 0.0, 1.0), 5.0);
}

fn direct_pbr_precomputed(
    n: vec3<f32>,
    v: vec3<f32>,
    l: vec3<f32>,
    radiance: vec3<f32>,
    diffuse_color: vec3<f32>,
    f0: vec3<f32>,
    roughness_a2: f32,
    geometry_k: f32,
    geometry_v: f32,
    subsurface: f32,
    source_direct_ggx: bool,
    specular_strength: f32,
) -> vec3<f32> {
    let signed_n_dot_l = dot(n, l);
    let n_dot_l = max(signed_n_dot_l, 0.0);
    // Cheap source-neutral thin-sheet transmission. Back illumination
    // affects the diffuse lobe only; it never creates back-facing GGX
    // highlights. The material explicitly opts in through the GPU flags
    // and a per-pixel, linear transmission factor.
    var transmitted = vec3<f32>(0.0);
    if subsurface > 0.000001 && signed_n_dot_l < 0.0 {
        transmitted = diffuse_color * radiance
            * (subsurface * 0.35 * (-signed_n_dot_l) / PI);
    }
    if n_dot_l <= 0.000001 {
        return transmitted;
    }

    let h = normalize(v + l);
    let n_dot_h = max(dot(n, h), 0.0);
    let n_dot_h2 = n_dot_h * n_dot_h;
    let distribution_denominator = n_dot_h2 * (roughness_a2 - 1.0) + 1.0;
    let exact_ndf_denominator = PI * distribution_denominator * distribution_denominator;
    // Recovered RenderChunkForwardPBR direct-light NDF has no 1e-6
    // denominator floor (source lines 870-881). With its authored
    // roughness >= 0.05 the denominator stays finite. That old generic
    // floor can suppress very smooth specular highlights by thousands
    // of times. Do not change any importer without this source contract.
    let ndf_denominator = select(
        max(exact_ndf_denominator, 0.000001),
        exact_ndf_denominator,
        source_direct_ggx,
    );
    let ndf = roughness_a2 / ndf_denominator;
    let geometry_l_base = n_dot_l * (1.0 - geometry_k) + geometry_k;
    // Source Smith-GGX adds 1e-4 to each visibility denominator;
    // the generic shader instead guards it with max(...,1e-6).
    let geometry_l_denominator = select(
        max(geometry_l_base, 0.000001),
        geometry_l_base + 0.0001,
        source_direct_ggx,
    );
    let geometry_l = n_dot_l / geometry_l_denominator;
    let geometry = geometry_v * geometry_l;
    let fresnel = fresnel_schlick(max(dot(h, v), 0.0), f0);
    let numerator = fresnel * ndf * geometry;
    let specular_base = 4.0 * max(dot(n, v), 0.0) * n_dot_l;
    let denominator = select(
        max(specular_base, 0.0001),
        specular_base + 0.0001,
        source_direct_ggx,
    );
    // Authored specular strength belongs only to the specular lobe.
    // Previously the GPU uploaded light.params.z but this BRDF ignored it,
    // making lights with specular_strength=0 still create highlights.
    let specular = (numerator / denominator) * max(specular_strength, 0.0);
    let k_s = fresnel;
    let k_d = vec3<f32>(1.0) - k_s;
    return (k_d * diffuse_color / PI + specular) * radiance * n_dot_l
        + transmitted;
}

// The original RenderChunk cascade shader admits a candidate only when
// its projected coordinate lies inside the source projection volume.
// This neutral equivalent also checks Vulkan's 0..1 depth convention.
fn shadow_projected_volume_contains(clip: vec4<f32>) -> bool {
    if clip.w <= 0.000001 {
        return false;
    }
    let projected = clip.xyz / clip.w;
    return abs(projected.x) < 1.0 && abs(projected.y) < 1.0
        && projected.z > 0.0 && projected.z < 1.0;
}

fn sample_directional_shadow(
    world_position: vec3<f32>,
    n: vec3<f32>,
    light_direction: vec3<f32>,
    light_index: u32,
    source_slope_normal_offset: bool,
    source_filter_width: f32,
) -> f32 {
    if shadow_globals.shadow_meta.w < 0.5
        || abs(f32(light_index) - shadow_globals.shadow_params.w) > 0.25
    {
        return 1.0;
    }

    // Source RenderChunk shadow fade over the final 10% (up to 8m)
    // of a configured shadow range. Retail far uniform is unavailable;
    // the native authored shadow distance is a compatibility substitute.
    // For the perspective camera clip W equals positive view-space depth.
    var source_shadow_fade = 0.0;
    if source_slope_normal_offset {
        let depth_row = vec4<f32>(
            frame.view_proj[0].w, frame.view_proj[1].w,
            frame.view_proj[2].w, frame.view_proj[3].w,
        );
        let camera_depth = max(dot(depth_row, vec4<f32>(world_position, 1.0)), 0.0);
        let source_shadow_far = shadow_globals.shadow_meta.w;
        let source_shadow_start = max(
            0.0, source_shadow_far - min(source_shadow_far * 0.1, 8.0),
        );
        source_shadow_fade = smoothstep(
            source_shadow_start, source_shadow_far, camera_depth,
        );
        if source_shadow_fade >= 1.0 {
            // Skip source PCF at distances guaranteed fully unshadowed.
            return 1.0;
        }
    }

    let camera_cascades = shadow_globals.shadow_meta.y < 0.0;
    let tile_count = max(u32(shadow_globals.shadow_meta.z), 1u);
    var tile_index = 0u;
    var tile_x = 0u;
    var tile_z = 0u;
    var tiles_x = 1u;
    if camera_cascades {
        // The common frustum planner writes ordered camera-depth split
        // endpoints into shadow_grid. First containing slice wins.
        let view_depth_row = vec4<f32>(
            frame.view_proj[0].w, frame.view_proj[1].w,
            frame.view_proj[2].w, frame.view_proj[3].w,
        );
        let receiver_depth = dot(view_depth_row, vec4<f32>(world_position, 1.0));
        if receiver_depth <= 0.0 || receiver_depth > shadow_globals.shadow_meta.w {
            return 1.0;
        }
        for (var cascade = 0u; cascade < tile_count; cascade += 1u) {
            tile_index = cascade;
            if receiver_depth <= shadow_globals.shadow_grid[cascade] {
                break;
            }
        }
    } else {
        tiles_x = max(u32(shadow_globals.shadow_meta.x), 1u);
        let tiles_z = max(u32(shadow_globals.shadow_meta.y), 1u);
        let step = max(shadow_globals.shadow_grid.zw, vec2<f32>(0.0001));
        let relative = (world_position.xz - shadow_globals.shadow_grid.xy) / step;
        tile_x = u32(clamp(floor(relative.x), 0.0, f32(tiles_x - 1u)));
        tile_z = u32(clamp(floor(relative.y), 0.0, f32(tiles_z - 1u)));
        tile_index = min(tile_z * tiles_x + tile_x, tile_count - 1u);
    }

    // RenderDragon's recovered directional shadow uses a normal offset
    // proportional to clamp(1 - max(N dot L, 0), 0, 1). Its runtime
    // NormalOffsetStrength is not recovered; reuse the authored generic
    // shadow-map bias magnitude. Other importers keep their fixed bias.
    let normal_slope = clamp(1.0 - max(dot(n, normalize(light_direction)), 0.0), 0.0, 1.0);
    let normal_offset_scale = select(1.0, normal_slope, source_slope_normal_offset);
    let biased_world = world_position
        + n * (shadow_globals.shadow_params.z * normal_offset_scale);
    var clip = shadow_globals.light_view_proj[tile_index]
        * vec4<f32>(biased_world, 1.0);
    // The recovered source uses only projections containing the receiver.
    // Camera cascades try subsequent coarser slices near boundaries;
    // world tiles retain the earlier immediate-neighbor overlap fallback.
    if source_slope_normal_offset && !shadow_projected_volume_contains(clip) {
        for (var candidate = 0u; candidate < tile_count; candidate += 1u) {
            if candidate == tile_index {
                continue;
            }
            if camera_cascades {
                if candidate < tile_index {
                    continue;
                }
            } else {
                let candidate_x = candidate % tiles_x;
                let candidate_z = candidate / tiles_x;
                if abs(i32(candidate_x) - i32(tile_x)) > 1
                    || abs(i32(candidate_z) - i32(tile_z)) > 1 {
                    continue;
                }
            }
            let candidate_clip = shadow_globals.light_view_proj[candidate]
                * vec4<f32>(biased_world, 1.0);
            if shadow_projected_volume_contains(candidate_clip) {
                tile_index = candidate;
                clip = candidate_clip;
                break;
            }
        }
    }
    if !shadow_projected_volume_contains(clip) {
        return 1.0;
    }
    let ndc = clip.xyz / clip.w;
    let uv = vec2<f32>(ndc.x * 0.5 + 0.5, 0.5 - ndc.y * 0.5);

    let reference_depth = clamp(ndc.z - shadow_globals.shadow_params.y, 0.0, 1.0);
    let texel = shadow_globals.shadow_params.x;
    if source_slope_normal_offset {
        // RenderChunkForwardPBR source: square PCF kernel width 1..9,
        // centering (sample - width/2 + 0.5) and division by width^2.
        // Each LINEAR hardware comparison sample already interpolates
        // its four depth comparisons, matching source textureGather's
        // bilinear compare combination. The shared shadow allocation
        // is still world-tiled; the original cascade matrices and
        // filter-width runtime uniform have not been recovered.
        let kernel_width = clamp(i32(round(source_filter_width)), 1, 9);
        let kernel_center = kernel_width / 2;
        var kernel_visibility = 0.0;
        for (var y = 0; y < kernel_width; y += 1) {
            for (var x = 0; x < kernel_width; x += 1) {
                let filter_offset = vec2<f32>(
                    f32(x - kernel_center) + 0.5,
                    f32(y - kernel_center) + 0.5,
                ) * texel;
                kernel_visibility += textureSampleCompare(
                    environment_shadow,
                    environment_shadow_sampler,
                    uv + filter_offset,
                    i32(tile_index),
                    reference_depth,
                );
            }
        }
        let kernel_shadow = kernel_visibility / f32(kernel_width * kernel_width);
        return mix(kernel_shadow, 1.0, source_shadow_fade);
    }

    // Unrelated importers keep the original four-tap fast path.
    let o = texel * 0.75;
    var visibility = 0.0;
    visibility += textureSampleCompare(
        environment_shadow,
        environment_shadow_sampler,
        uv + vec2<f32>(-o, -o),
        i32(tile_index),
        reference_depth,
    );
    visibility += textureSampleCompare(
        environment_shadow,
        environment_shadow_sampler,
        uv + vec2<f32>(o, -o),
        i32(tile_index),
        reference_depth,
    );
    visibility += textureSampleCompare(
        environment_shadow,
        environment_shadow_sampler,
        uv + vec2<f32>(-o, o),
        i32(tile_index),
        reference_depth,
    );
    visibility += textureSampleCompare(
        environment_shadow,
        environment_shadow_sampler,
        uv + vec2<f32>(o, o),
        i32(tile_index),
        reference_depth,
    );
    return visibility * 0.25;
}


// Forward+: the light range of the view cluster containing a fragment.
// scene_light_clusters = [(width, height), (near bits, slices per doubling
// bits), (global count, local count), (local offset, total count) per cluster];
// the grid matches
// surface_program_wgsl::LIGHT_CLUSTER_GRID and native_light_clusters.wgsl.
fn scene_light_cluster_range(fragment: vec4<f32>, world_position: vec3<f32>) -> vec2<u32> {
    // When every light is global/directional, all clusters contain precisely
    // the same immutable source indices. Skip per-fragment screen coordinate
    // division, view-depth dot product, log2 and cluster-range fetch. This
    // covers T6 maps with one sun and zero local sources (e.g. mp_dockside).
    // Keep the identical range count and the shared-global index order.
    if scene_light_clusters[2].y == 0u {
        let global_count = scene_light_clusters[2].x;
        return vec2<u32>(global_count, global_count);
    }
    let target_size = vec2<f32>(scene_light_clusters[0]);
    let slicing = scene_light_clusters[1];
    let tile_x = min(u32(fragment.x * 16.0 / max(target_size.x, 1.0)), 15u);
    let tile_y = min(u32(fragment.y * 9.0 / max(target_size.y, 1.0)), 8u);
    let depth_row = vec4<f32>(frame.view_proj[0].w, frame.view_proj[1].w, frame.view_proj[2].w, frame.view_proj[3].w);
    let depth = dot(depth_row, vec4<f32>(world_position, 1.0));
    let near = bitcast<f32>(slicing.x);
    var slice = 0u;
    if near > 0.0 && depth > near {
        slice = min(u32(floor(log2(depth / near) * bitcast<f32>(slicing.y))), 23u);
    }
    return scene_light_clusters[3u + tile_x + 16u * (tile_y + 9u * slice)];
}

// Global source IDs are stored once in the common prefix, followed by
// camera-dependent local indices in each cluster's compact segment.
// The original order is preserved within both classes.
fn scene_cluster_light_index(cluster: vec2<u32>, ordinal: u32) -> u32 {
    let global_count = scene_light_clusters[2].x;
    if ordinal < global_count {
        return scene_light_indices[ordinal];
    }
    return scene_light_indices[cluster.x + (ordinal - global_count)];
}

fn evaluate_scene_lights(
    fragment: vec4<f32>,
    world_position: vec3<f32>,
    n: vec3<f32>,
    v: vec3<f32>,
    diffuse_color: vec3<f32>,
    f0: vec3<f32>,
    roughness: f32,
    instance_index: u32,
    baked_visibility: f32,
    subsurface: f32,
) -> vec3<f32> {
    // Unlit imported scenes must not execute the cluster-depth logarithm,
    // material BRDF setup or source-light storage accesses per fragment.
    // This is exactly the original empty-light sum (vec3 zero).
    if scene_lights.counts.x == 0u {
        return vec3<f32>(0.0);
    }
    let cluster = scene_light_cluster_range(fragment, world_position);
    let count = cluster.y;
    if count == 0u {
        return vec3<f32>(0.0);
    }
    var result = vec3<f32>(0.0);

    let instance = instances[instance_index];
    // Source-neutral GGX BRDF admission. Per-instance values come from
    // recovered material/shader uniforms: zero preserves the legacy Smith
    // Schlick k=(r+1)^2/8. An authored positive coefficient switches to
    // k=r^2*coefficient with the source minimum roughness, without
    // introducing game-name checks or shader pipeline permutations.
    let authored_response = (instance.flags & INSTANCE_FLAG_DYNAMIC_SKY_VERTEX_LIGHT) != 0u
        && instance.motion.y > 0.5;
    let authored_ggx = select(0.0, max(instance.motion.z, 0.0), authored_response);
    let source_roughness_floor = select(0.0, clamp(instance.motion.w, 0.0, 1.0), authored_response);
    // Only an explicitly reconstructed nonzero GGX geometry coefficient
    // together with the source's >=0.05 roughness floor admits the exact
    // source NDF, where tiny denominators are physically meaningful.
    // A malformed/absent floor never disables the generic safety guard.
    let source_direct_ggx = authored_ggx > 0.0 && source_roughness_floor >= 0.05;
    let microfacet_roughness = max(roughness, source_roughness_floor);
    let roughness_squared = microfacet_roughness * microfacet_roughness;
    let roughness_a2 = roughness_squared * roughness_squared;
    let geometry_r = microfacet_roughness + 1.0;
    let legacy_geometry_k = (geometry_r * geometry_r) / 8.0;
    let geometry_k = select(legacy_geometry_k, roughness_squared * authored_ggx, authored_ggx > 0.0);
    let n_dot_v = max(dot(n, v), 0.0);
    let geometry_v_base = n_dot_v * (1.0 - geometry_k) + geometry_k;
    let geometry_v_denominator = select(
        max(geometry_v_base, 0.000001),
        geometry_v_base + 0.0001,
        source_direct_ggx,
    );
    let geometry_v = n_dot_v / geometry_v_denominator;

    var cursor = 0u;
    loop {
        if cursor >= count {
            break;
        }
        let light_index = scene_cluster_light_index(cluster, cursor);
        cursor += 1u;
        if light_index >= scene_lights.counts.x {
            continue;
        }

        let light = scene_lights.lights[light_index];
        let kind = light.params.y;
        var l = vec3<f32>(0.0, 1.0, 0.0);
        var attenuation = 1.0;

        if kind > 1.5 {
            // A source-neutral runtime sky cycle is not just a skybox
            // gradient: its primary directional sun MUST extinguish at
            // night as well. Otherwise an imported midday sun continues
            // lighting terrain beneath a midnight sky. Other maps with
            // no sky cycle keep their unchanged authored light intensity.
            // Authored source illuminance is updated by the shared mapped
            // light buffer each frame; never multiply it by the generic
            // daylight approximation a second time.
            if ibl_globals.sky_cycle.w > 0.5 && light.params.w < 0.5 {
                let cycle = ibl_globals.sky_cycle;
                let angle = (cycle.x + frame.camera_position.w * cycle.y)
                    / max(cycle.z, 1.0) * 6.28318530718;
                let daylight = clamp((sin(angle) + 0.06) / 0.22, 0.0, 1.0);
                if daylight <= 0.000001 {
                    continue;
                }
                attenuation *= daylight;
            }
            l = -light.direction_inner.xyz;
            if dot(n, l) <= 0.000001 && subsurface <= 0.000001 {
                continue;
            }
            // A source-baked visibility of zero means this directional
            // light contributes exactly zero, regardless of the moving-
            // shadow map. Skip its cascaded lookup and four PCF taps.
            // This is mathematically identical to min(shadow, 0.0) == 0
            // and does not change any partially visible/shadowed surfaces.
            if baked_visibility <= 0.0 {
                continue;
            }
            // Static surfaces carry baked visibility; the shadow map adds
            // occlusion from anything that moves.
            attenuation *= min(
                sample_directional_shadow(
                    world_position, n, l, light_index,
                    authored_response, instance.motion.y,
                ),
                baked_visibility,
            );
        } else {
            let delta = light.position_radius.xyz - world_position;
            if dot(n, delta) <= 0.000001 && subsurface <= 0.000001 {
                continue;
            }

            let distance_squared = dot(delta, delta);
            let radius = max(light.position_radius.w, 0.001);
            let radius_squared = radius * radius;
            if distance_squared >= radius_squared {
                continue;
            }

            if distance_squared > 0.00000001 {
                let inverse_distance = inverseSqrt(distance_squared);
                l = delta * inverse_distance;
                let distance = distance_squared * inverse_distance;
                let radial = clamp(1.0 - distance / radius, 0.0, 1.0);
                attenuation = radial * radial;
            }

            if kind > 0.5 {
                let travel = light.direction_inner.xyz;
                let from_light_to_surface = -l;
                let cone_cos = dot(travel, from_light_to_surface);
                let outer_cos = light.params.x;
                let inner_cos = light.direction_inner.w;
                attenuation *= smoothstep(outer_cos, inner_cos, cone_cos);
            }
        }

        if attenuation > 0.000001 {
            let radiance = light.color_intensity.rgb * light.color_intensity.w * attenuation;
            result += direct_pbr_precomputed(
                n,
                v,
                l,
                radiance,
                diffuse_color,
                f0,
                roughness_a2,
                geometry_k,
                geometry_v,
                subsurface,
                source_direct_ggx,
                light.params.z,
            );
        }
    }
    return result;
}

fn evaluate_diffuse_sh(n: vec3<f32>) -> vec3<f32> {
    let x = n.x;
    let y = n.y;
    let z = n.z;
    var irradiance = ibl_globals.sh0.rgb * 0.2820948;
    irradiance += ibl_globals.sh1.rgb * (0.48860252 * y);
    irradiance += ibl_globals.sh2.rgb * (0.48860252 * z);
    irradiance += ibl_globals.sh3.rgb * (0.48860252 * x);
    irradiance += ibl_globals.sh4.rgb * (1.0925485 * x * y);
    irradiance += ibl_globals.sh5.rgb * (1.0925485 * y * z);
    irradiance += ibl_globals.sh6.rgb * (0.31539157 * (3.0 * z * z - 1.0));
    irradiance += ibl_globals.sh7.rgb * (1.0925485 * x * z);
    irradiance += ibl_globals.sh8.rgb * (0.54627424 * (x * x - y * y));
    return max(irradiance, vec3<f32>(0.0));
}

// RenderChunkForwardPBR source samples s_BrdfLUT with
// uv = (clamp(dot(N,V),0,1), 1-roughness) and combines two coefficients
// as F0*lut.r + lut.g. The current data is a numerically integrated
// GGX compatibility LUT, *not* recovered original retail texels.
fn source_integrated_brdf(
    f0: vec3<f32>,
    roughness: f32,
    n_dot_v: f32,
) -> vec3<f32> {
    let uv = vec2<f32>(clamp(n_dot_v, 0.0, 1.0),
                       1.0 - clamp(roughness, 0.0, 1.0));
    let coefficients = textureSampleLevel(
        environment_brdf_lut, environment_brdf_sampler, uv, 0.0
    ).rg;
    return max(f0 * coefficients.x + vec3<f32>(coefficients.y),
               vec3<f32>(0.0));
}

fn environment_brdf_approximation(
    f0: vec3<f32>,
    roughness: f32,
    n_dot_v: f32,
) -> vec3<f32> {
    let c0 = vec4<f32>(-1.0, -0.0275, -0.572, 0.022);
    let c1 = vec4<f32>(1.0, 0.0425, 1.04, -0.04);
    let r = vec4<f32>(roughness) * c0 + c1;
    let a004 = min(r.x * r.x, exp2(-9.28 * n_dot_v)) * r.x + r.y;
    let ab = vec2<f32>(-1.04, 1.04) * a004 + r.zw;
    return max(f0 * ab.x + vec3<f32>(ab.y), vec3<f32>(0.0));
}

// Source RenderChunkForwardPBR's two specular cubemap convolution branches:
//   ConvolutionType.x == 1: 1 - (1-roughness)^2
//   other source mode:      1 - (1-roughness)^8
// These are *mip selection curves*. They do not substitute the missing
// source s_BrdfLUT pixels, rotating 3-record IBL buffers or original
// exposure uniforms. Zero preserves the generic linear roughness LOD.
fn specular_ibl_lod(roughness: f32, max_mip: f32, mode: f32) -> f32 {
    let r = clamp(roughness, 0.0, 1.0);
    var fraction = r;
    if mode >= 1.0 && mode < 2.0 {
        let smoothness = 1.0 - r;
        fraction = 1.0 - smoothness * smoothness;
    } else if mode >= 2.0 {
        let smoothness = 1.0 - r;
        let smooth_squared = smoothness * smoothness;
        let smooth_fourth = smooth_squared * smooth_squared;
        fraction = 1.0 - smooth_fourth * smooth_fourth;
    }
    return fraction * max(max_mip, 0.0);
}

// Recovered RenderChunkForwardPBR IBL sky fade (source lines 1442,
// 1923): sky_fade = clamp((16*sky_uv - low)/max(high-low,1),0,1)^3.
// The source terrain contract transports normalized sky-light nibble UVs,
// interpolated before nonlinear fragment-stage transfer. The authored
// scale only controls feature admission; never sqrt interpolated radiance.
// Zero/invalid scale or identical fade bounds disables the adjustment.
// This attenuates only reflected sky, NOT local probes or diffuse SH.
// The recovered RenderChunkForwardPBR pixel path multiplies source sky
// accessibility by *RGB* SkyAmbientLightColorIntensity, not a scalar gray
// value. Original runtime SkyAmbientLightColorIntensity is not preserved by
// a saved world. The client atmosphere DOES supply time-varying authentic
// sky zenith/horizon colors, so derive a normalized diffuse sky hue from
// those authored curves. This is a source-informed fallback for hue, NOT a
// claim of retail irradiance or reconstructed radiometric integration.
// Normalizing luminance keeps existing sky-access intensity authoritative.
fn source_atmosphere_ambient_tint() -> vec3<f32> {
    let cycle = ibl_globals.sky_cycle;
    let source_phase = fract(
        (cycle.x + frame.camera_position.w * cycle.y)
            / max(cycle.z, 1.0)
            + ibl_globals.sky_color_meta.z
    );
    let zenith_count = u32(ibl_globals.sky_color_meta.x);
    let horizon_count = u32(ibl_globals.sky_color_meta.y);
    let zenith_rgb = srgb_to_linear(
        sky_source_curve(true, zenith_count, source_phase)
    );
    let horizon_rgb = srgb_to_linear(
        sky_source_curve(false, horizon_count, source_phase)
    );
    // Approximate the hemispheric sky integral using the same two source
    // colors as the visible atmosphere. Unlike a static material tint, this
    // responds to real time-keyed dawn/dusk and custom biome sky changes.
    let diffuse_sky_rgb = mix(horizon_rgb, zenith_rgb, vec3<f32>(0.6));
    let luminance = dot(diffuse_sky_rgb, vec3<f32>(0.2126, 0.7152, 0.0722));
    return clamp(
        diffuse_sky_rgb / max(luminance, 0.0001),
        vec3<f32>(0.25),
        vec3<f32>(1.9),
    );
}

fn source_sky_specular_visibility(
    sky_nibble_uv: f32,
    fade_low: f32,
    fade_high: f32,
    max_irradiance: f32,
) -> f32 {
    if max_irradiance <= 0.0 || fade_high <= fade_low {
        return 1.0;
    }
    let normalized_sky = clamp(sky_nibble_uv, 0.0, 1.0);
    let source_coordinate = normalized_sky * 16.0;
    let ramp = clamp(
        (source_coordinate - fade_low) / max(fade_high - fade_low, 1.0),
        0.0, 1.0,
    );
    return ramp * ramp * ramp;
}

// RenderChunkForwardPBR original func_d903a (fragment 1303-1311):
//   target = mix(ambient, block_rgb * block_indirect_multiplier,
//                saturate(luminance(block_rgb * multiplier))) * metallic;
//   selected = luminance(environment_radiance) >= luminance(target)
//                ? environment_radiance : target;
// The actual BlockLightIndirectSpecularIntensity.x and
// BlockBaseAmbientLightColorIntensity.w source uniforms are not available.
// The importer already authored scaled block RGB; source opt-in currently
// uses a clearly labeled unit compatibility multiplier, never a claimed
// retail intensity. This is a *replacement*, not an additive glow.
fn source_block_specular_replacement(
    env_radiance: vec3<f32>,
    block_rgb: vec3<f32>,
    ambient_reference: vec3<f32>,
    metallic: f32,
) -> vec3<f32> {
    let rgb_weights = vec3<f32>(0.2126, 0.7152, 0.0722);
    let authored_block = max(block_rgb, vec3<f32>(0.0));
    let mix_factor = clamp(dot(authored_block, rgb_weights), 0.0, 1.0);
    let fallback = mix(max(ambient_reference, vec3<f32>(0.0)), authored_block,
        vec3<f32>(mix_factor)) * clamp(metallic, 0.0, 1.0);
    if dot(env_radiance, rgb_weights) >= dot(fallback, rgb_weights) {
        return env_radiance;
    }
    return fallback;
}

// Read only the opt-in source RGB vertex-light contract. It contains
// the original block nibble *separately* from sky visibility. Converting
// the authored scalar back into its source RGB curve avoids accidentally
// treating midday sky as a glowing block in the specular fallback.
fn source_block_specular_rgb(instance: EnvironmentInstance, vertex: vec4<f32>) -> vec3<f32> {
    let block_scale = max(instance.motion_aux.y, 0.000001);
    // Interpolate original light nibble UV before squaring.
    let block_uv = clamp(vertex.x, 0.0, 1.0);
    let q = block_uv * block_uv;
    let block_flux = block_scale * q;
    let green = clamp(instance.motion_aux.z, 0.0, 1.0);
    let blue = clamp(instance.motion_aux.w, 0.0, 1.0);
    return vec3<f32>(
        block_flux,
        block_flux * (green + (1.0 - green) * q),
        block_flux * (blue + (1.0 - blue) * q * q),
    );
}

// RenderChunkForwardPBR original three-record IBL interpolation:
//   mix(record[(LastSpecularIBLIdx+2)%3], record[LastSpecularIBLIdx],
//       IBLParameters.w)
// Record selection is source-neutral; index and interpolation factor
// must come from an authored manifest, not inferred retail runtime state.
fn sample_specular_ibl_history(
    direction: vec3<f32>,
    lod: f32,
) -> vec3<f32> {
    let last = u32(clamp(ibl_globals.specular_record_controls.x, 0.0, 2.0));
    let older = (last + 2u) % 3u;
    let blend = clamp(ibl_globals.specular_record_controls.y, 0.0, 1.0);
    let previous = textureSampleLevel(
        environment_specular_records, environment_cube_sampler,
        direction, older, lod,
    ).rgb;
    let current = textureSampleLevel(
        environment_specular_records, environment_cube_sampler,
        direction, last, lod,
    ).rgb;
    let history_radiance = mix(previous, current, vec3<f32>(blend));
    // Original RenderChunkForwardPBR fragment lines 1915-1922:
    // only when PreExposureEnabled.x > 0, multiply the already-blended
    // record radiance by the recovered inverse pre-exposure constant.
    // The host sets this flag only from explicit authored evidence.
    // Maps with no records never call this helper and retain unchanged
    // single-cubemap behavior.
    let inverse_pre_exposure = select(
        1.0, 301.72412109375,
        ibl_globals.specular_record_controls.w > 0.5,
    );
    return history_radiance * inverse_pre_exposure;
}

// Read the SAME authored atmosphere in PBR reflections and in the visible
// sky. This is a live analytic fallback when source reflection history
// cubemaps are missing, NOT a claim of recovered three-record IBL parity.
// Sampling the generated midnight cubemap at noon was visibly inconsistent.
fn source_animated_sky_reflection(direction: vec3<f32>, roughness: f32) -> vec3<f32> {
    let cycle = ibl_globals.sky_cycle;
    let current_day = (cycle.x + frame.camera_position.w * cycle.y)
        / max(cycle.z, 1.0);
    let source_phase = fract(current_day + ibl_globals.sky_color_meta.z);
    let zenith_count = u32(ibl_globals.sky_color_meta.x);
    let horizon_count = u32(ibl_globals.sky_color_meta.y);
    let zenith_color = srgb_to_linear(
        sky_source_curve(true, zenith_count, source_phase)
    );
    let horizon_color = srgb_to_linear(
        sky_source_curve(false, horizon_count, source_phase)
    );
    // Reuse the recovered cubic horizon fade from CloudForwardPBR.
    // The optional source horizon curves also drive the visible sky.
    var horizon_weight = 1.0 - sqrt(clamp(direction.y, 0.0, 1.0));
    if ibl_globals.sky_blend_meta.x >= 2.0
        && ibl_globals.sky_blend_meta.y >= 2.0
        && ibl_globals.sky_blend_meta.z >= 2.0
    {
        let low_bound = sky_blend_curve(
            0u, u32(ibl_globals.sky_blend_meta.x), source_phase
        ) - sky_blend_curve(
            2u, u32(ibl_globals.sky_blend_meta.z), source_phase
        );
        let upper = sky_blend_curve(
            1u, u32(ibl_globals.sky_blend_meta.y), source_phase
        );
        let horizon = 1.0 - smoothstep(
            low_bound, max(upper, low_bound + 0.000001), direction.y
        );
        horizon_weight = horizon * horizon * horizon;
    }
    // A wide roughness lobe cannot use a point-direction sample as an
    // exact preconvolution. Flatten toward a bounded average of the
    // authored zenith and horizon instead of inventing sharp highlights.
    horizon_weight = mix(
        horizon_weight, 0.5, clamp(roughness * roughness, 0.0, 1.0) * 0.65
    );
    return mix(zenith_color, horizon_color, horizon_weight)
        * max(ibl_globals.params.z, 0.0);
}

fn environment_ibl(
    n: vec3<f32>,
    v: vec3<f32>,
    diffuse_color: vec3<f32>,
    f0: vec3<f32>,
    roughness: f32,
    occlusion: f32,
    diffuse_scale: f32,
    probe: vec4<f32>,
    local_light: f32,
    source_ibl_mode: f32,
    source_sky_visibility: f32,
    source_block_rgb: vec3<f32>,
    source_metallic: f32,
    source_block_specular_enabled: bool,
) -> vec3<f32> {
    let tint = max(frame.ibl_params.rgb, vec3<f32>(0.0));
    let n_dot_v = max(dot(n, v), 0.0);
    let fresnel = fresnel_schlick_roughness(n_dot_v, f0, roughness);

    // A local reflection probe captured in the map replaces the sky cubemap
    // for specular and is used at full strength (it already contains the
    // surroundings, so no extra occlusion).
    if probe.x >= 0.0 {
        let reflection = normalize(reflect(-v, n));
        var specular_env = sample_reflection_probe(
            probe, reflection, specular_ibl_lod(roughness, probe.y, source_ibl_mode)
        );
        // A probe was captured somewhere else: scale what it shows by how
        // bright this spot is compared with the probe's surroundings.
        if local_light >= 0.0 && probe.z > 0.0001 {
            specular_env *= clamp(local_light / max(probe.z, 0.1), 0.0, 2.0);
        }
        let specular = specular_env * environment_brdf_approximation(f0, roughness, n_dot_v);
        var diffuse = vec3<f32>(0.0);
        if ibl_globals.params.x > 0.5 {
            diffuse = (vec3<f32>(1.0) - fresnel) * diffuse_color * evaluate_diffuse_sh(n) * tint
                * frame.render_params.w * occlusion * diffuse_scale;
        }
        return diffuse + specular;
    }

    if ibl_globals.params.x > 0.5 {
        let max_mip = max(ibl_globals.params.y, 0.0);
        let reflection = normalize(reflect(-v, n));
        let specular_lod = specular_ibl_lod(roughness, max_mip, source_ibl_mode);
        let diffuse_irradiance = evaluate_diffuse_sh(n);
        var specular_env = textureSampleLevel(
            environment_cube,
            environment_cube_sampler,
            reflection,
            specular_lod,
        ).rgb;
        // Only source-authored surfaces with three real history cubes
        // use the source's rotating-record interpolation. Unrelated
        // importers and source maps without history keep the original
        // single-cubemap lookup and its exact previous color behavior.
        if source_block_specular_enabled && ibl_globals.specular_record_controls.z > 0.5 {
            // Authentic source specular history always wins if available.
            specular_env = sample_specular_ibl_history(reflection, specular_lod);
        } else if source_block_specular_enabled
            && ibl_globals.sky_cycle.w > 0.5
            && ibl_globals.sky_color_meta.x >= 2.0
            && ibl_globals.sky_color_meta.y >= 2.0
        {
            // The fallback environment cubemap is fixed at midnight while
            // the source scene has live authored sky colours. Do not reflect
            // stars through bright daytime metals and wet materials.
            specular_env = source_animated_sky_reflection(reflection, roughness);
        }
        let k_d = vec3<f32>(1.0) - fresnel;
        let diffuse = k_d
            * diffuse_color
            * diffuse_irradiance
            * tint
            * frame.render_params.w
            * occlusion
            * diffuse_scale;
        var specular_brdf = environment_brdf_approximation(f0, roughness, n_dot_v);
        if source_block_specular_enabled {
            // No extra lookup for uncontracted game materials: retain
            // the previous fast generic fit in every other importer.
            specular_brdf = source_integrated_brdf(f0, roughness, n_dot_v);
        }
        var source_reflection_radiance = specular_env
            * source_sky_visibility * tint * frame.ibl_params.w;
        if source_block_specular_enabled && source_metallic > 0.0 {
            source_reflection_radiance = source_block_specular_replacement(
                source_reflection_radiance, source_block_rgb,
                scene_lights.ambient.rgb, source_metallic,
            );
        }
        let specular = source_reflection_radiance
            * specular_brdf
            * mix(0.55, 1.0, occlusion);
        return diffuse + specular;
    }

    let hemisphere = mix(0.35, 1.0, clamp(n.y * 0.5 + 0.5, 0.0, 1.0));
    let diffuse = diffuse_color
        * tint
        * frame.render_params.w
        * hemisphere
        * occlusion
        * diffuse_scale;
    let roughness_visibility = 1.0 - roughness * 0.72;
    let specular = fresnel
        * tint
        * frame.ibl_params.w
        * roughness_visibility
        * hemisphere
        * mix(0.55, 1.0, occlusion);
    return diffuse + specular;
}

fn evaluate_baked_sh(sh: array<vec4<f32>, 9>, n: vec3<f32>) -> vec3<f32> {
    var irradiance = sh[0].rgb * 0.2820948;
    irradiance += sh[1].rgb * (0.48860252 * n.y);
    irradiance += sh[2].rgb * (0.48860252 * n.z);
    irradiance += sh[3].rgb * (0.48860252 * n.x);
    irradiance += sh[4].rgb * (1.0925485 * n.x * n.y);
    irradiance += sh[5].rgb * (1.0925485 * n.y * n.z);
    irradiance += sh[6].rgb * (0.31539157 * (3.0 * n.z * n.z - 1.0));
    irradiance += sh[7].rgb * (1.0925485 * n.x * n.z);
    irradiance += sh[8].rgb * (0.54627424 * (n.x * n.x - n.y * n.y));
    return max(irradiance, vec3<f32>(0.0));
}

// Baked diffuse irradiance for an instance, or a negative value when it has none.
// Baked visibility of directional lights (lightmap direction alpha); 1 for
// surfaces without a lightmap.
struct BakedLightingEvaluation {
    irradiance: vec4<f32>,
    geometric_rgb: vec3<f32>,
    directional_visibility: f32,
};

// The two irradiance queries and the directional shadow-visibility query
// previously sampled the same three lightmap layers independently: 7 texture
// lookups per fragment (1 + 3 + 3). Evaluate those exact inputs once, then
// reuse their decoded RGBM and source direction for the shading and geometric
// normals. This leaves the baked-light equations and source texture filtering
// unchanged, and also shares probe SH calculations between both queries.
fn evaluate_baked_lighting(
    instance_index: u32,
    lightmap_uv: vec2<f32>,
    vertex_light: vec4<f32>,
    geometric_normal: vec3<f32>,
    n: vec3<f32>,
) -> BakedLightingEvaluation {
    let baked = baked_instances[instance_index];
    if baked.mode.x < 0.5 {
        return BakedLightingEvaluation(
            vec4<f32>(0.0, 0.0, 0.0, -1.0), vec3<f32>(0.0), 1.0
        );
    }
    // Explicit source-neutral diagnostic preview for an original compressed
    // native HDR atlas. This changes the actual fragment lighting and samples
    // real original BC6H/BC4 GPU image arrays (scene bindings 24 and 26).
    // It does NOT claim Source2 SH2 directionality, material VCS execution,
    // gamma/exposure parity, or the compiler's lightmap decode equation.
    // Source importers must certify the source UV stream before selecting mode 5.
    if baked.mode.x > 4.5 && baked.mode.x < 5.5 {
        let uv = clamp(lightmap_uv, vec2<f32>(0.0), vec2<f32>(1.0));
        let hdr = textureSampleLevel(
            source_baked_irradiance_hdr, lightmap_sampler, uv, 0, 0.0
        ).rgb;
        let visibility = textureSampleLevel(
            source_baked_direct_light_shadows, lightmap_sampler, uv, 0, 0.0
        ).r;
        let irradiance = max(hdr, vec3<f32>(0.0));
        return BakedLightingEvaluation(
            vec4<f32>(irradiance, 1.0), irradiance,
            clamp(visibility, 0.0, 1.0)
        );
    }
    // Per-vertex baked light, preserving the identical SH-relative variation
    // for both original invocations (shading and geometric normals).
    if baked.mode.x > 2.5 {
        let base = max(vertex_light.rgb, vec3<f32>(0.0));
        // A vertex-irradiance mesh with all-zero SH coefficients has no
        // additional normal-dependent variation. Evaluating SH9 twice
        // produces exactly zero; the old ratio branch therefore leaves
        // both surface and geometric irradiance equal to base. Preserve
        // the original vertex visibility while bypassing the wasted GPU
        // matrix/SH work in this source-neutral mode.
        if baked.mode.x > 3.5 {
            return BakedLightingEvaluation(
                vec4<f32>(base, 1.0), base, clamp(vertex_light.a, 0.0, 1.0)
            );
        }
        let at_geometry = evaluate_baked_sh(baked.sh, geometric_normal);
        let at_n = evaluate_baked_sh(baked.sh, n);
        var surface = base;
        var geometric = base;
        if dot(at_geometry, at_geometry) > 0.0 {
            let denom = max(at_geometry, vec3<f32>(0.02));
            surface *= clamp(at_n / denom, vec3<f32>(0.0), vec3<f32>(4.0));
            geometric *= clamp(at_geometry / denom, vec3<f32>(0.0), vec3<f32>(4.0));
        }
        return BakedLightingEvaluation(
            vec4<f32>(surface, 1.0), geometric,
            clamp(vertex_light.a, 0.0, 1.0)
        );
    }
    if baked.mode.x < 1.5 {
        let uv = lightmap_uv * baked.mode.zw;
        let layer = i32(baked.mode.y + 0.5);
        let ambient = textureSampleLevel(lightmap_textures, lightmap_sampler, uv, layer, 0.0);
        let directional = textureSampleLevel(lightmap_textures, lightmap_sampler, uv, layer + 1, 0.0);
        let direction = textureSampleLevel(lightmap_textures, lightmap_sampler, uv, layer + 2, 0.0);
        let ambient_rgb = ambient.rgb * ambient.a * LIGHTMAP_RGBM_RANGE;
        let directional_rgb = directional.rgb * directional.a * LIGHTMAP_RGBM_RANGE;
        let raw_direction = direction.xyz * 2.0 - vec3<f32>(1.0);
        var surface_weight = 0.0;
        var geometric_weight = 0.0;
        if dot(raw_direction, raw_direction) > 0.0001 {
            let axis = normalize(raw_direction);
            surface_weight = max(dot(n, axis), 0.0);
            geometric_weight = max(dot(geometric_normal, axis), 0.0);
        }
        return BakedLightingEvaluation(
            vec4<f32>(ambient_rgb + directional_rgb * surface_weight, 1.0),
            ambient_rgb + directional_rgb * geometric_weight,
            direction.a
        );
    }

    // Probe SH. The original visibility function uses the probe's scalar
    // except for the exact 1.5 boundary (or nonfinite mode) where it reads
    // the directional lightmap alpha, even though irradiance uses SH.
    let surface = evaluate_baked_sh(baked.sh, n);
    let geometric = evaluate_baked_sh(baked.sh, geometric_normal);
    var visibility = clamp(baked.mode.z, 0.0, 1.0);
    if !(baked.mode.x > 1.5) {
        let uv = lightmap_uv * baked.mode.zw;
        let layer = i32(baked.mode.y + 0.5);
        visibility = textureSampleLevel(
            lightmap_textures, lightmap_sampler, uv, layer + 2, 0.0
        ).a;
    }
    return BakedLightingEvaluation(vec4<f32>(surface, 1.0), geometric, visibility);
}

// Optical depth of the exponential height fog along a unit ray from the
// camera: density * exp(-(h - base) * falloff) integrated exactly. A negative
// distance means an infinite ray (the sky).
fn height_fog_depth(direction: vec3<f32>, distance: f32) -> f32 {
    let density = max(frame.render_fog.w, 0.0);
    let base_height = frame.render_params.x;
    let falloff = max(frame.render_params.y, 0.0);
    let at_camera = density * exp(clamp(-(frame.camera_position.y - base_height) * falloff, -30.0, 30.0));
    let a = falloff * direction.y;
    if distance < 0.0 {
        if a <= 0.000001 {
            return 1.0e9;
        }
        return at_camera / a;
    }
    if abs(a * distance) < 0.0001 {
        return at_camera * distance;
    }
    return at_camera * (1.0 - exp(-a * distance)) / a;
}

// Fog along a view ray: colour mixes toward the directional (sun) fog colour
// near its direction, and the amount scales by the matching maximum opacity.
fn apply_fog_along(color: vec3<f32>, direction: vec3<f32>, distance: f32) -> vec3<f32> {
    if frame.render_fog.w <= 0.0000001
        && ibl_globals.fog_shape.w <= 0.5
    {
        return color;
    }
    var fog_color = max(frame.render_fog.rgb, vec3<f32>(0.0));
    var opacity = ibl_globals.fog_shape.z;
    // Source-defined distance air-fog is a finite ramp, not an
    // exponential height extinction. Its fog_start and fog_end have
    // already been converted from original render-distance fractions
    // into world meters at import. Do not color the authored visible sky
    // with a static daytime fog color; only scene geometry is distance-fogged.
    if ibl_globals.fog_shape.w > 0.5 {
        if distance < 0.0 {
            return color;
        }
        let start = ibl_globals.fog_shape.x;
        let end = max(ibl_globals.fog_shape.y, start + 0.000001);
        let linear_fraction = clamp((distance - start) / (end - start), 0.0, 1.0);
        return mix(color, fog_color, vec3<f32>(
            linear_fraction * clamp(opacity, 0.0, 1.0)
        ));
    }
    if ibl_globals.sun_fog_direction.w > 0.5 {
        let range = max(ibl_globals.fog_shape.y - ibl_globals.fog_shape.x, 0.0001);
        let t = clamp((dot(direction, ibl_globals.sun_fog_direction.xyz) - ibl_globals.fog_shape.x) / range, 0.0, 1.0);
        fog_color = mix(fog_color, max(ibl_globals.sun_fog_color.rgb, vec3<f32>(0.0)), t);
        opacity = mix(opacity, ibl_globals.sun_fog_color.w, t);
    }
    let amount = clamp(1.0 - exp(-height_fog_depth(direction, distance)), 0.0, 1.0) * clamp(opacity, 0.0, 1.0);
    return mix(color, fog_color, vec3<f32>(amount));
}

fn apply_height_fog(color: vec3<f32>, world_position: vec3<f32>) -> vec3<f32> {
    // apply_fog_along already returns color unchanged with this condition.
    // Avoid world-ray normalization and a per-fragment square root entirely
    // in scenes whose imported atmosphere has no active fog.
    if frame.render_fog.w <= 0.0000001
        && ibl_globals.fog_shape.w <= 0.5
    {
        return color;
    }
    let ray = world_position - frame.camera_position.xyz;
    let distance = length(ray);
    if distance <= 0.0001 {
        return color;
    }
    return apply_fog_along(color, ray / distance, distance);
}

// Scene radiance (already exposed) -> value for the sRGB attachment.
fn display_transform(color: vec3<f32>) -> vec3<f32> {
    let c = max(color, vec3<f32>(0.0));
    // Linear-HDR scene: keep exposed radiance; the composite presents it.
    if ibl_globals.grade.x > 1.5 {
        return c;
    }
    if ibl_globals.grade.x < 0.5 {
        return aces_fitted(c);
    }
    var e = pow(c, vec3<f32>(ibl_globals.grade.y));
    let knee = ibl_globals.grade.z;
    // Exponential shoulder with unit slope at the knee, approaching 1.
    let slope = 1.0 / ((1.0 - knee) * 0.6931472);
    let shoulder = vec3<f32>(knee) + (1.0 - knee) * (vec3<f32>(1.0) - exp2(-(e - vec3<f32>(knee)) * slope));
    e = select(e, shoulder, e > vec3<f32>(knee));
    e = clamp(e, vec3<f32>(0.0), vec3<f32>(1.0));
    if ibl_globals.grade.w > 0.5 {
        let size = 32.0;
        let uv = e.rg * ((size - 1.0) / size) + vec2<f32>(0.5 / size);
        let slice = e.b * (size - 1.0);
        let lower = min(floor(slice), size - 2.0);
        let a = textureSampleLevel(display_lut, lightmap_sampler, uv, i32(lower), 0.0).rgb;
        let b = textureSampleLevel(display_lut, lightmap_sampler, uv, i32(lower) + 1, 0.0).rgb;
        e = mix(a, b, vec3<f32>(slice - lower));
    }
    // `e` is the display value; the attachment applies the sRGB encode.
    return srgb_to_linear(e);
}

fn aces_fitted(color: vec3<f32>) -> vec3<f32> {
    let a = 2.51;
    let b = 0.03;
    let c = 2.43;
    let d = 0.59;
    let e = 0.14;
    return clamp(
        (color * (a * color + vec3<f32>(b)))
            / (color * (c * color + vec3<f32>(d)) + vec3<f32>(e)),
        vec3<f32>(0.0),
        vec3<f32>(1.0),
    );
}

@fragment
fn fs_main(
    input: VertexOutput,
    @builtin(front_facing) front_facing: bool,
) -> @location(0) vec4<f32> {
    let material = materials[input.material_index];
    let point_sampled = (u32(material.params.w + 0.5) & 128u) != 0u;
    // Five-source landscape paint packs extra source albedos into otherwise
    // unused normal/metal-roughness/emissive texture semantic slots.
    let five_source_paint = (u32(material.params.w + 0.5) & 256u) != 0u;

    let texture_extent = textureDimensions(material_textures, 0);
    let base_layer = material_layer(material, 0u);
    let normal_layer = material_layer(material, 1u);
    let mr_layer = material_layer(material, 2u);
    let ao_layer = material_layer(material, 3u);
    let emissive_layer = material_layer(material, 4u);
    var base_sample = vec4<f32>(1.0);
    var normal_sample = vec4<f32>(0.5, 0.5, 1.0, 1.0);
    var has_normal_texture = normal_layer >= 0;
    var mr_sample = vec4<f32>(1.0);
    var ao_sample = vec4<f32>(1.0);
    var emissive_sample = vec4<f32>(1.0);

    let is_single_texel = texture_extent.x == 1u && texture_extent.y == 1u;
    // Parallax scale lives in unused, exactly representable GPU flag bits
    // 11..18. All existing materials have zero here and retain their exact
    // previous UVs and fragment cost.
    let parallax_code = (u32(material.params.w + 0.5) >> 11u) & 255u;
    // All dpdx/dpdy work MUST precede a per-pixel discard. The explicit
    // gradients captured here remain valid for the source-exact four-tap
    // textureSampleGrad calls after the alpha-cutout test.
    var sampling: MaterialSampling;
    var layer_gradients_0: MaterialGradients;
    var layer_gradients_1: MaterialGradients;
    var surface_uv = input.uv;
    if is_single_texel {
        if base_layer >= 0 {
            base_sample = textureLoad(material_textures, vec2<i32>(0, 0), base_layer, 0);
        }
    } else {
        sampling = build_material_sampling(input.uv, point_sampled);
        // WGSL derivative uniformity: capture both layer UV differentials
        // before discard, but defer the costlier footprint math until a
        // surviving fragment actually has that authored blend layer.
        layer_gradients_0 = capture_material_gradients(input.layer_uvs.xy);
        layer_gradients_1 = capture_material_gradients(input.layer_uvs.zw);
        if parallax_code > 0u && normal_layer >= 0 && !five_source_paint {
            surface_uv = parallax_height_uv(
                input.uv, input, normal_layer, sampling,
                f32(parallax_code) / 2040.0
            );
        }
        if base_layer >= 0 {
            base_sample = sample_material_layer(surface_uv, base_layer, sampling, point_sampled);
        }
    }

    // All blend-layer modes preserve base_sample.a verbatim. The cutoff can
    // therefore run immediately after base sampling, BEFORE normal, MR, AO,
    // emissive and blended texture lookups. Rejected vegetation/fence pixels
    // never perform those expensive samples or lighting calculations.
    var coverage = base_sample.a;
    if (u32(material.params.w + 0.5) & 64u) != 0u {
        coverage = 1.0;
    }
    let base_alpha = material.base_color.a * input.color.a * coverage;
    let alpha_cutoff = clamp(material.metallic_roughness_normal_alpha.w, 0.0, 1.0);
    if alpha_cutoff > 0.0 && base_alpha < alpha_cutoff {
        discard;
    }

    if is_single_texel {
        let texel = vec2<i32>(0, 0);
        if normal_layer >= 0 { normal_sample = textureLoad(material_textures, texel, normal_layer, 0); }
        if mr_layer >= 0 { mr_sample = textureLoad(material_textures, texel, mr_layer, 0); }
        if ao_layer >= 0 { ao_sample = textureLoad(material_textures, texel, ao_layer, 0); }
        if emissive_layer >= 0 { emissive_sample = textureLoad(material_textures, texel, emissive_layer, 0); }
    } else {
        if !five_source_paint {
            if normal_layer >= 0 { normal_sample = sample_material_layer(surface_uv, normal_layer, sampling, point_sampled); }
            if mr_layer >= 0 { mr_sample = sample_material_layer(surface_uv, mr_layer, sampling, point_sampled); }
        }
        if ao_layer >= 0 { ao_sample = sample_material_layer(surface_uv, ao_layer, sampling, point_sampled); }
        if !five_source_paint && emissive_layer >= 0 {
            emissive_sample = sample_material_layer(surface_uv, emissive_layer, sampling, point_sampled);
        }
        // Blend layers, each with its own UV set and combine mode (params.w
        // bits 2-3 for layer 1, 4-5 for layer 2): 0 blend by colour alpha x
        // vertex weight, 1 multiply by mix(1, colour, weight), 2 add colour x
        // alpha x weight. Weights are vertex R (layer 1) and G (layer 2).
        // Gradients were evaluated above the alpha test to satisfy WGSL's
        // derivative uniformity rule. Never recompute dpdx/dpdy after discard.
        let layer_flags = u32(material.params.w + 0.5);
        if five_source_paint {
            // Five independent original LandscapeLayerInfo weight channels.
            // The source diffuse image alpha does NOT determine paint coverage.
            let w = array<f32, 5>(
                clamp(input.color.r, 0.0, 1.0),
                clamp(input.color.g, 0.0, 1.0),
                clamp(input.vertex_data.x, 0.0, 1.0),
                clamp(input.vertex_data.y, 0.0, 1.0),
                clamp(input.vertex_data.z, 0.0, 1.0)
            );
            let total = w[0] + w[1] + w[2] + w[3] + w[4];
            let remainder = max(1.0 - total, 0.0);
            let denominator = max(total + remainder, 0.000001);
            var combined = base_sample.rgb * remainder;
            let paint_sampling = build_material_sampling_from_gradients(layer_gradients_0);
            for (var paint = 0u; paint < 5u; paint += 1u) {
                if w[paint] <= 0.0 { continue; }
                var semantic = 5u; // Forest
                if paint == 1u { semantic = 7u; } // Mud
                if paint == 2u { semantic = 2u; } // Gravel
                if paint == 3u { semantic = 4u; } // Road
                if paint == 4u { semantic = 1u; } // Arid
                let paint_layer = material_layer(material, semantic);
                if paint_layer >= 0 {
                    let color = sample_material_layer(
                        input.layer_uvs.xy, paint_layer, paint_sampling, point_sampled
                    );
                    combined += color.rgb * w[paint];
                } else {
                    combined += base_sample.rgb * w[paint];
                }
            }
            base_sample = vec4<f32>(combined / denominator, base_sample.a);
        } else {
        for (var layer = 0u; layer < 2u; layer += 1u) {
            let color_layer = material_layer(material, 5u + layer * 2u);
            if color_layer < 0 {
                continue;
            }
            var layer_uv = input.layer_uvs.xy;
            if layer == 1u {
                layer_uv = input.layer_uvs.zw;
            }
            var layer_sampling: MaterialSampling;
            if layer == 0u {
                layer_sampling = build_material_sampling_from_gradients(layer_gradients_0);
            } else {
                layer_sampling = build_material_sampling_from_gradients(layer_gradients_1);
            }
            let layer_color = sample_material_layer(layer_uv, color_layer, layer_sampling, point_sampled);
            var vertex_weight = input.color.r;
            if layer == 1u {
                vertex_weight = input.color.g;
            }
            let mode = (layer_flags >> (2u + layer * 2u)) & 3u;
            var weight = clamp(layer_color.a * vertex_weight, 0.0, 1.0);
            // Authored landscape weightmaps encode coverage independently
            // of a diffuse image alpha channel. Do not accidentally erase
            // painted ground where the source albedo has transparent texels.
            if mode == 3u {
                weight = clamp(vertex_weight, 0.0, 1.0);
            }
            if mode == 1u {
                weight = clamp(vertex_weight, 0.0, 1.0);
                base_sample = vec4<f32>(base_sample.rgb * mix(vec3<f32>(1.0), layer_color.rgb, weight), base_sample.a);
            } else if mode == 2u {
                base_sample = vec4<f32>(base_sample.rgb + layer_color.rgb * weight, base_sample.a);
            } else {
                base_sample = vec4<f32>(mix(base_sample.rgb, layer_color.rgb, weight), base_sample.a);
            }
            let normal_layer_slot = material_layer(material, 6u + layer * 2u);
            if normal_layer_slot >= 0 {
                has_normal_texture = true;
                let layer_normal = sample_material_layer(layer_uv, normal_layer_slot, layer_sampling, point_sampled);
                normal_sample = vec4<f32>(mix(normal_sample.xyz, layer_normal.xyz, weight), normal_sample.w);
            }
        }
        }
    }

    let base_texture_linear = srgb_to_linear(clamp(base_sample.rgb, vec3<f32>(0.0), vec3<f32>(1.0)));
    // Multiply blending: the surface's colour scales what is already drawn
    // (pipeline blend = dst * src), faded toward white by its alpha.
    if material.params.x > 1.5 {
        let tint = material.base_color.rgb * input.color.rgb * base_texture_linear;
        return vec4<f32>(mix(vec3<f32>(1.0), tint, clamp(base_alpha, 0.0, 1.0)), 1.0);
    }
    // Materials with blend layers keep their weights in vertex RG, not a tint.
    let material_flags = u32(material.params.w + 0.5);
    var vertex_tint = input.color.rgb;
    if (material_flags & 1u) != 0u {
        vertex_tint = vec3<f32>(1.0);
    }
    let base_color = clamp(
        material.base_color.rgb * vertex_tint * base_texture_linear,
        vec3<f32>(0.0),
        vec3<f32>(1.0),
    );
    if five_source_paint {
        // Present authenticated albedo through shared fog/exposure, without
        // misinterpreting the packed extra paint channels as PBR normals/MR.
        let geometric_n = normalize(input.world_normal);
        let radiance = lit_radiance(
            input, geometric_n, geometric_n,
            vec3<f32>(0.0), vec3<f32>(0.0), 1.0, 1.0, base_color, 0.0, 0.0
        );
        return present(radiance, base_alpha, material.params.x);
    }
    let metallic = clamp(material.metallic_roughness_normal_alpha.x * mr_sample.b, 0.0, 1.0);
    var roughness = clamp(material.metallic_roughness_normal_alpha.y * mr_sample.g, 0.045, 1.0);
    var diffuse_color = base_color * (1.0 - metallic);
    var f0 = mix(vec3<f32>(0.04), base_color, vec3<f32>(metallic));
    // Specular-glossiness materials: that layer holds specular colour (sRGB)
    // and gloss in alpha instead of metallic-roughness.
    if (material_flags & 2u) != 0u && mr_layer >= 0 {
        f0 = srgb_to_linear(clamp(mr_sample.rgb, vec3<f32>(0.0), vec3<f32>(1.0)));
        roughness = clamp(material.metallic_roughness_normal_alpha.y * (1.0 - mr_sample.a), 0.045, 1.0);
        diffuse_color = base_color * (1.0 - max(f0.r, max(f0.g, f0.b)));
    }
    // Gloss kept in base-colour alpha (opaque materials without a
    // specular map).
    if (material_flags & 64u) != 0u && (material_flags & 2u) == 0u {
        roughness = clamp(1.0 - base_sample.a, 0.045, 1.0);
    }
    let occlusion = clamp(material.emissive_occlusion.w * ao_sample.r, 0.0, 1.0);

    var geometry_normal = normalize(input.world_normal);
    if !front_facing {
        geometry_normal = -geometry_normal;
    }
    // The flat PBR path already has a unit-length geometric normal.
    // Reuse it rather than normalizing the same value twice.
    var n = geometry_normal;
    if has_normal_texture {
        let tangent = normalize(input.world_tangent.xyz);
        let bitangent = normalize(cross(geometry_normal, tangent)) * input.world_tangent.w;
        var tangent_normal = normal_sample.xyz * 2.0 - vec3<f32>(1.0);
        tangent_normal.x *= material.metallic_roughness_normal_alpha.z;
        tangent_normal.y *= material.metallic_roughness_normal_alpha.z;
        tangent_normal = normalize(tangent_normal);
        n = normalize(
            tangent * tangent_normal.x
                + bitangent * tangent_normal.y
                + geometry_normal * tangent_normal.z,
        );
    }

    let emissive_texture_linear = srgb_to_linear(clamp(emissive_sample.rgb, vec3<f32>(0.0), vec3<f32>(1.0)));
    var emissive = material.emissive_occlusion.rgb * emissive_texture_linear;
    // Generic opt-in for emissive-only source surfaces whose color comes
    // from their mesh vertices. The neutral bridge sets this only for
    // unlit materials, not for authored HDR emission on lit PBR surfaces.
    if (material_flags & 512u) != 0u {
        emissive *= vertex_tint;
    }
    // MR alpha is normally undefined/unused in glTF. Only a material
    // with the explicit generic thin-surface flag may interpret it as
    // a per-pixel scattering weight. No other importer changes behavior.
    let subsurface = select(
        0.0, clamp(mr_sample.a, 0.0, 1.0),
        (material_flags & 1024u) != 0u && mr_layer >= 0,
    );
    let color = lit_radiance(
        input, geometry_normal, n, diffuse_color, f0, roughness,
        occlusion, emissive, subsurface, metallic,
    );
    return present(color, base_alpha, material.params.x);
}

// Radiance leaving a surface toward the camera (scene lights, baked or
// ambient light, environment light, emission), fogged, before exposure.
// Source-neutral playable micro-occlusion proxy. This is deliberately not
// claimed as retail D1 SSAO. Where a material supplies a perturbed shading
// normal, strong deviation from the geometric surface receives bounded
// darkening; unperturbed/flat surfaces remain unchanged.
// Both callers of lit_radiance normalize geometry_normal and n before they
// reach this function. Re-normalizing both vectors here performs two costly
// reciprocal square roots per lit fragment with no geometric benefit.
fn micro_cavity(geometry_normal: vec3<f32>, shading_normal: vec3<f32>) -> f32 {
    let alignment = clamp(dot(geometry_normal, shading_normal), 0.0, 1.0);
    return mix(0.78, 1.0, smoothstep(0.15, 0.92, alignment));
}

// Bounded source-neutral studio response used only when an importer explicitly
// opts in through the generic render hint. This is the same visual-parity shape
// response used by the validated D1 Tower inspection path; it is not presented
// as retail source lighting.
fn studio_shaping(n: vec3<f32>) -> f32 {
    let strength = clamp(ibl_globals.params.w, 0.0, 1.0);
    if strength <= 0.0001 {
        return 1.0;
    }
    let key = normalize(vec3<f32>(0.34, 0.79, 0.51));
    let fill = normalize(vec3<f32>(-0.65, 0.30, -0.70));
    let shaped = clamp(0.82 + 0.18 * dot(n, key) + 0.07 * dot(n, fill), 0.58, 1.05);
    return mix(1.0, shaped, strength);
}

// Vertex coefficients preserve block-emitted radiance independently from
// saved skylight accessibility. Only instances explicitly opting into this
// source-neutral contract change during the sky cycle. Interior block light
// remains unchanged when the sun sets; static scenes take the previous path.
fn sampled_vertex_sky_irradiance(instance_index: u32, light: vec4<f32>) -> vec4<f32> {
    let instance = instances[instance_index];
    if (instance.flags & INSTANCE_FLAG_DYNAMIC_SKY_VERTEX_LIGHT) == 0u
        || ibl_globals.sky_cycle.w <= 0.5 {
        return light;
    }
    let cycle = ibl_globals.sky_cycle;
    let progress = (cycle.x + frame.camera_position.w * cycle.y)
        / max(cycle.z, 1.0) * 6.28318530718;
    let sun_height = sin(progress);
    let generic_daylight = clamp((sun_height + 0.06) / 0.22, 0.0, 1.0);
    // Source-authored solar illuminance is already sampled each frame in
    // the mapped scene-light header. Use it for the SAME terrain skylight,
    // instead of letting the sky nibble follow a contradictory sine ramp.
    // counts.z is opt-in: ordinary worlds retain their original sky clock.
    // Block-emitted RGB below does not depend on either daylight path.
    let daylight = select(
        generic_daylight,
        clamp(scene_lights.ambient.w, 0.0, 1.0),
        scene_lights.counts.z != 0u,
    );
    let night_floor = clamp(instance.motion.x, 0.0, 1.0);
    let sky_strength = mix(night_floor, 1.0, daylight);
    if instance.motion.y <= 0.5 {
        // Existing neutral grayscale transfer remains unchanged for all
        // source maps that did not provide a recovered RGB lightmap curve.
        let irradiance = max(light.x + light.y * sky_strength, 0.0);
        return vec4<f32>(vec3<f32>(irradiance), light.a);
    }
    // Recovered source lightmap transfer expressed entirely in authored,
    // per-instance curve parameters. This is not game-name dispatch.
    // q is the original normalized squared packed source-light nibble.
    // Sky irradiance is independent and stays neutral through the clock.
    // The source ambient expression combines block and sky first, then
    // maxes that energy against AmbientLightParams rather than adding
    // the minimum floor on top of every illuminated voxel.
    // Source ambient has authored RGB, not necessarily neutral gray.
    // counts.w opts into original scene ambient only when the importer
    // supplied both source color and illuminance. Legacy neutral scenes
    // keep the per-instance scalar ambient compatibility floor.
    let floor_rgb = select(
        vec3<f32>(max(instance.motion_aux.x, 0.0)),
        max(scene_lights.ambient.rgb, vec3<f32>(0.0)),
        scene_lights.counts.w != 0u,
    );
    let flux_scale = max(instance.motion_aux.y, 0.000001);
    // The source vertex program emits linearly interpolated normalized
    // nibble UVs; the fragment program squares the interpolated values.
    let block_uv = clamp(light.x, 0.0, 1.0);
    let sky_uv = clamp(light.y, 0.0, 1.0);
    let q = block_uv * block_uv;
    let block_flux = flux_scale * q;
    let green_base = clamp(instance.motion_aux.z, 0.0, 1.0);
    let blue_base = clamp(instance.motion_aux.w, 0.0, 1.0);
    let block_rgb = vec3<f32>(
        block_flux,
        block_flux * (green_base + (1.0 - green_base) * q),
        block_flux * (blue_base + (1.0 - blue_base) * q * q),
    );
    // The source-neutral authored unit-sky irradiance scale lives in
    // motion_extra.w (0.58 on the current Bedrock compatibility path).
    let sky_coefficient = max(instance.motion_extra.w, 0.0);
    // Recovered RenderChunkForwardPBR fragment (ForwardPBROpaque, near
    // source line 1983) evaluates BOTH authored sky-light nibble branches:
    //   mix(sky_uv^5, sky_uv^3, CameraLightIntensity.y).
    // The per-frame CameraLightIntensity.y uniform is not present in a
    // saved Bedrock world. Until recovered, 0.5 is an explicitly provisional
    // midpoint between the two source operations; this is NOT retail parity.
    // Crucially, do not square the source nibble before interpolating it:
    // the original shader applies the nonlinear response per fragment.
    let sky_cubic = sky_uv * sky_uv * sky_uv;
    let sky_quintic = sky_cubic * sky_uv * sky_uv;
    let sky_visibility = mix(sky_quintic, sky_cubic, 0.5);
    let sky_rgb = sky_coefficient * sky_visibility * sky_strength;
    var sky_irradiance = vec3<f32>(sky_rgb);
    // Original source RenderChunkForwardPBR combines colored block-light
    // with colored sky ambient. Older neutral lightmap providers continue
    // using the same gray scalar as before. Source atmosphere data must
    // have both original keyframe curves to enable the replacement.
    if ibl_globals.sky_color_meta.x >= 2.0
        && ibl_globals.sky_color_meta.y >= 2.0
    {
        sky_irradiance *= source_atmosphere_ambient_tint();
    }
    return vec4<f32>(
        max(floor_rgb, sky_irradiance + block_rgb),
        light.a,
    );
}

fn lit_radiance(
    input: VertexOutput,
    geometry_normal: vec3<f32>,
    n: vec3<f32>,
    diffuse_color: vec3<f32>,
    f0: vec3<f32>,
    roughness: f32,
    occlusion: f32,
    emissive: vec3<f32>,
    subsurface: f32,
    metallic: f32,
) -> vec3<f32> {
    let v = normalize(frame.camera_position.xyz - input.world_position);
    let cavity = micro_cavity(geometry_normal, n);
    let surface_occlusion = clamp(occlusion * cavity, 0.0, 1.0);
    let sky_light = sampled_vertex_sky_irradiance(
        input.instance_index, input.vertex_light,
    );
    let baked = evaluate_baked_lighting(
        input.instance_index, input.lightmap_uv, sky_light, geometry_normal, n
    );
    let direct = evaluate_scene_lights(
        input.position,
        input.world_position,
        n,
        v,
        diffuse_color,
        f0,
        roughness,
        input.instance_index,
        baked.directional_visibility,
        subsurface,
    );
    var ambient = diffuse_color * scene_lights.ambient.rgb * surface_occlusion;
    var diffuse_environment = 1.0;
    if baked.irradiance.w > 0.0 {
        ambient = diffuse_color * baked.irradiance.rgb * surface_occlusion;
        diffuse_environment = 0.0;
    }
    // Baked light also occludes sky reflections: dark interiors shouldn't
    // mirror the bright sky cubemap.
    var specular_occlusion = surface_occlusion;
    if baked.irradiance.w > 0.0 {
        let baked_luminance = dot(baked.irradiance.rgb, vec3<f32>(0.2126, 0.7152, 0.0722));
        specular_occlusion = surface_occlusion * clamp(baked_luminance * 2.0, 0.05, 1.0);
    }
    let probe = baked_instances[input.instance_index].probe;
    // Baked light arriving along the geometric normal, for probe scaling.
    var local_light = -1.0;
    if baked.irradiance.w > 0.0 {
        let geometric_light = baked.geometric_rgb;
        local_light = dot(geometric_light, vec3<f32>(0.2126, 0.7152, 0.0722));
    }
    let instance = instances[input.instance_index];
    let source_ibl_mode = select(
        0.0, instance.motion_extra.x,
        (instance.flags & INSTANCE_FLAG_DYNAMIC_SKY_VERTEX_LIGHT) != 0u
            && instance.motion.y > 0.5,
    );
    // The source sky-light coordinate is reconstructed from the ORIGINAL
    // vertex sky-accessibility coefficient, before the independent
    // day/night irradiance modulation in sampled_vertex_sky_irradiance.
    // Instance motion_extra Y/Z/W carries authored source thresholds
    // and the source's unit-sky irradiance normalization.
    let source_sky_visibility = select(
        1.0,
        source_sky_specular_visibility(
            input.vertex_light.y, instance.motion_extra.y,
            instance.motion_extra.z, instance.motion_extra.w,
        ),
        (instance.flags & INSTANCE_FLAG_DYNAMIC_SKY_VERTEX_LIGHT) != 0u
            && instance.motion.y > 0.5,
    );
    let source_block_enabled =
        (instance.flags & INSTANCE_FLAG_DYNAMIC_SKY_VERTEX_LIGHT) != 0u
        && instance.motion.y > 0.5;
    let source_block_rgb = select(
        vec3<f32>(0.0), source_block_specular_rgb(instance, input.vertex_light),
        source_block_enabled,
    );
    let ibl = environment_ibl(
        n, v, diffuse_color, f0, roughness, specular_occlusion,
        diffuse_environment, probe, local_light, source_ibl_mode,
        source_sky_visibility, source_block_rgb, metallic, source_block_enabled,
    );
    let lit = (ambient + direct + ibl) * studio_shaping(n);

    // Fog colour is scene radiance like everything else, so it is mixed in
    // before exposure. Emissive radiance is not studio-shaped.
    return apply_height_fog(lit + emissive, input.world_position);
}

// Scene radiance -> attachment value. `blend`: 0 normal (alpha in w),
// 1 additive (premultiplied by alpha).
fn present(radiance: vec3<f32>, alpha: f32, blend: f32) -> vec4<f32> {
    var color = radiance * max(frame.render_params.z, 0.000001);
    // The swapchain deliberately prefers *_SRGB with SRGB_NONLINEAR. Keep the
    // tone-mapped value linear here and let the attachment perform the one
    // display transfer. The former pow(1/2.2) caused a second encoding step and
    // visibly washed out the generic environment path.
    color = display_transform(color);
    // Additive blending (pipeline blend = src + dst): premultiply by alpha.
    if blend > 0.5 {
        return vec4<f32>(color * clamp(alpha, 0.0, 1.0), 1.0);
    }
    return vec4<f32>(color, alpha);
}

// Shading for a surface program's outputs (see `surface_program_wgsl`).
// `blend`: 0 lit surface, 1 additive radiance.
fn shade_program(
    input: VertexOutput,
    front_facing: bool,
    base_color: vec3<f32>,
    alpha: f32,
    has_normal: bool,
    normal: vec3<f32>,
    gloss: f32,
    metallic: f32,
    occlusion: f32,
    emissive: vec3<f32>,
    subsurface: f32,
    blend: f32,
) -> vec4<f32> {
    if blend > 0.5 {
        return present(max(emissive, vec3<f32>(0.0)), alpha, 1.0);
    }
    var geometry_normal = normalize(input.world_normal);
    if !front_facing {
        geometry_normal = -geometry_normal;
    }
    var n = geometry_normal;
    if has_normal && dot(normal, normal) > 0.0000001 {
        n = normalize(normal);
    }
    let albedo = clamp(base_color, vec3<f32>(0.0), vec3<f32>(1.0));
    let m = clamp(metallic, 0.0, 1.0);
    let diffuse_color = albedo * (1.0 - m);
    let f0 = mix(vec3<f32>(0.04), albedo, vec3<f32>(m));
    let roughness = clamp(1.0 - gloss, 0.045, 1.0);
    // Generic surface programs may explicitly provide a per-pixel
    // transmission factor. All programs omitting that optional output
    // supply zero and retain the original PBR lighting behavior.
    let color = lit_radiance(input, geometry_normal, n, diffuse_color, f0, roughness,
        clamp(occlusion, 0.0, 1.0), max(emissive, vec3<f32>(0.0)),
        clamp(subsurface, 0.0, 1.0), m);
    return present(color, alpha, 0.0);
}

// Sky background: a full-screen triangle on the far plane, drawn after
// opaque geometry where nothing else wrote depth. It shows the environment
// cubemap, so maps that author one get a matching sky and reflections.
//
// A camera-centred cube with depth forced to the far plane has vertices
// behind the camera; clipping those at w = 0 sends the clipped edges to
// infinity and some rasterizers then draw whole cube panels in the wrong
// place when the view looks along a cube edge. The full-screen triangle
// never crosses w = 0: each corner's world direction comes from the
// rotation part of view_proj instead.
struct SkyOutput {
    @builtin(position) position: vec4<f32>,
    @location(0) direction: vec3<f32>,
};

@vertex
fn vs_sky(@builtin(vertex_index) vertex_index: u32) -> SkyOutput {
    // Corners (-1,-1), (3,-1), (-1,3) cover the screen; extra vertices of
    // an older 36-vertex draw collapse onto the first corner.
    let corner = min(vertex_index, 3u);
    var ndc = vec2<f32>(-1.0, -1.0);
    if corner == 1u { ndc = vec2<f32>(3.0, -1.0); }
    if corner == 2u { ndc = vec2<f32>(-1.0, 3.0); }
    // clip.xyw = R * d for a direction d from the camera, where R holds the
    // x, y and w rows of view_proj restricted to xyz. Solve R d = (x, y, 1)
    // with the cofactor inverse; the scale of d does not matter.
    let m = frame.view_proj;
    let rx = vec3<f32>(m[0].x, m[1].x, m[2].x);
    let ry = vec3<f32>(m[0].y, m[1].y, m[2].y);
    let rw = vec3<f32>(m[0].w, m[1].w, m[2].w);
    var direction = ndc.x * cross(ry, rw) + ndc.y * cross(rw, rx) + cross(rx, ry);
    // In front of the camera: positive clip w.
    if dot(rw, direction) < 0.0 {
        direction = -direction;
    }
    var out: SkyOutput;
    // Reversed-Z scene depth: the sky lies on the far plane (depth 0).
    out.position = vec4<f32>(ndc, 0.0, 1.0);
    out.direction = direction;
    return out;
}

// Sample normalized source-day keyframes with periodic linear interpolation.
// Five binary-search steps cover all 16 stop slots. The original stop times
// and source RGB values are preserved; only HDR/sRGB presentation differs
// from the unrecovered RenderDragon atmospheric scattering equations.
fn sky_source_stop(zenith: bool, index: u32) -> vec4<f32> {
    if zenith {
        return ibl_globals.sky_zenith_stops[index];
    }
    return ibl_globals.sky_horizon_stops[index];
}

fn sky_source_curve(zenith: bool, count: u32, normalized_phase: f32) -> vec3<f32> {
    let n = clamp(count, 1u, 16u);
    let phase = fract(normalized_phase);
    var lo = 0u;
    var hi = n;
    for (var i = 0u; i < 5u; i += 1u) {
        if lo >= hi { break; }
        let mid = (lo + hi) / 2u;
        if sky_source_stop(zenith, mid).x <= phase {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    var before = sky_source_stop(zenith, (lo + n - 1u) % n);
    var after = sky_source_stop(zenith, lo % n);
    if lo == 0u { before.x -= 1.0; }
    if lo == n { after.x += 1.0; }
    let blend = clamp((phase - before.x) / max(after.x - before.x, 0.000001), 0.0, 1.0);
    return mix(before.yzw, after.yzw, blend);
}

// Keyframed scalar equivalent of the source color curve sampling. The
// RenderDragon atmosphere shader consumes horizon stops as three continuous
// boundaries; keep all original key times and interpolate cyclically.
fn sky_blend_stop(which: u32, index: u32) -> vec4<f32> {
    switch which {
        case 0u: { return ibl_globals.sky_blend_min[index]; }
        case 1u: { return ibl_globals.sky_blend_start[index]; }
        case 2u: { return ibl_globals.sky_blend_max[index]; }
        default: { return ibl_globals.sky_blend_mie_start[index]; }
    }
}

fn sky_blend_curve(which: u32, count: u32, normalized_phase: f32) -> f32 {
    let n = clamp(count, 1u, 16u);
    let phase = fract(normalized_phase);
    var lo = 0u;
    var hi = n;
    for (var i = 0u; i < 5u; i += 1u) {
        if lo >= hi { break; }
        let mid = (lo + hi) / 2u;
        if sky_blend_stop(which, mid).x <= phase { lo = mid + 1u; }
        else { hi = mid; }
    }
    var before = sky_blend_stop(which, (lo + n - 1u) % n);
    var after = sky_blend_stop(which, lo % n);
    if lo == 0u { before.x -= 1.0; }
    if lo == n { after.x += 1.0; }
    let weight = clamp((phase - before.x) / max(after.x - before.x, 0.000001), 0.0, 1.0);
    return mix(before.y, after.y, weight);
}

@fragment
fn fs_sky(input: SkyOutput) -> @location(0) vec4<f32> {
    let direction = normalize(input.direction);
    var sky = textureSampleLevel(environment_cube, environment_cube_sampler, direction, 0.0).rgb
        * max(ibl_globals.params.z, 0.0);
    if ibl_globals.sky_cycle.w > 0.5 {
        // The imported cubemap holds a generated compatibility midnight
        // star field, not recovered retail star positions. Daylight
        // and sunrise/sunset gradients evolve analytically at fragment time,
        // without reuploading six sky faces every frame.
        let cycle = ibl_globals.sky_cycle;
        let current_day = (cycle.x + frame.camera_position.w * cycle.y)
            / max(cycle.z, 1.0);
        let phase = fract(current_day) * 6.28318530718;
        let sun_height = sin(phase);
        let daylight = clamp((sun_height + 0.06) / 0.22, 0.0, 1.0);
        let zenith = sqrt(clamp(direction.y, 0.0, 1.0));
        let zenith_count = u32(max(ibl_globals.sky_color_meta.x, 0.0));
        let horizon_count = u32(max(ibl_globals.sky_color_meta.y, 0.0));
        if zenith_count >= 2u && zenith_count <= 16u
            && horizon_count >= 2u && horizon_count <= 16u
        {
            // Authored Bedrock atmosphere phase 0 is solar noon, unlike
            // Minecraft's tick 0 dawn. The phase origin is source metadata.
            let source_phase = fract(current_day + ibl_globals.sky_color_meta.z);
            let authored_zenith = srgb_to_linear(sky_source_curve(true, zenith_count, source_phase));
            let authored_horizon = srgb_to_linear(sky_source_curve(false, horizon_count, source_phase));
            var authored_rgb = mix(authored_horizon, authored_zenith, zenith);
            if ibl_globals.sky_blend_meta.x >= 2.0
                && ibl_globals.sky_blend_meta.y >= 2.0
                && ibl_globals.sky_blend_meta.z >= 2.0
            {
                // Decompiled Bedrock CloudForwardPBR:
                // 1 - smoothstep(FogSkyBlend.min - FogSkyBlend.max,
                //                 FogSkyBlend.start, direction.y)
                // followed by a CUBIC horizon contribution. Previously we
                // used a sqrt(height) gradient which spread the purple dusk
                // horizon across far too much of the upper sky.
                let bmin = sky_blend_curve(0u, u32(ibl_globals.sky_blend_meta.x), source_phase);
                let bstart = sky_blend_curve(1u, u32(ibl_globals.sky_blend_meta.y), source_phase);
                let bmax = sky_blend_curve(2u, u32(ibl_globals.sky_blend_meta.z), source_phase);
                let low = bmin - bmax;
                let horizon = 1.0 - smoothstep(low, max(bstart, low + 0.000001), direction.y);
                let weight = horizon * horizon * horizon;
                authored_rgb = mix(authored_zenith, authored_horizon, weight);
            }
            let authored = authored_rgb * max(ibl_globals.params.z, 0.0);
            // The generated midnight sky cube contains small raster stars.
            // Keep its star highlights, while using the actual client
            // source RGB curves for atmospheric colour at every source time.
            sky = max(authored, sky * (1.0 - daylight));
        } else {
            // No source atmosphere supplied: preserve existing neutral sky
            // presentation rather than inventing a Bedrock source palette.
            let day_horizon = vec3<f32>(0.68, 0.82, 0.96);
            let day_zenith = vec3<f32>(0.24, 0.50, 0.88);
            let day = mix(day_horizon, day_zenith, zenith);
            sky = mix(sky, day * max(ibl_globals.params.z, 0.0), daylight);
            let sun_dir = vec3<f32>(-cos(phase), sin(phase), 0.0);
            let glow = pow(max(dot(sun_dir, direction), 0.0), 64.0)
                * clamp((sun_height + 0.2) * 3.0, 0.0, 1.0) * 0.12;
            sky += vec3<f32>(1.0, 0.55, 0.18) * glow;
        }
        // These are generic *fallback* discs, not RenderDragon's source
        // celestial texture quads. The neutral sky contract carries bit
        // 0 when the source sun is missing and bit 1 for a missing moon.
        // This keeps a partially supplied source pack from drawing two
        // suns or two moons. Geometry uses the same 24k-tick epoch and
        // direction as source celestial sprites and moving sunlight.
        let fallback_mask = u32(clamp(ibl_globals.sky_color_meta.w, 0.0, 3.0) + 0.5);
        let sun_direction = vec3<f32>(-cos(phase), sin(phase), 0.0);
        if (fallback_mask & 1u) != 0u && sun_height > -0.04 {
            // Angular square rather than a blurred fake spherical sun.
            // No additional textures, samplers or screen-space passes.
            let tangent = vec3<f32>(sun_direction.y, -sun_direction.x, 0.0);
            let across = abs(dot(direction, tangent));
            let upward = abs(direction.z);
            let facing_sun = dot(direction, sun_direction);
            let half_angle = max(across, upward);
            let square_disc = (1.0 - smoothstep(0.032, 0.037, half_angle))
                * select(0.0, 1.0, facing_sun > 0.0);
            let solar_halo = pow(max(facing_sun, 0.0), 180.0)
                * daylight * 0.13;
            sky += vec3<f32>(1.0, 0.66, 0.34) * solar_halo;
            sky = mix(sky, vec3<f32>(1.0, 0.96, 0.82),
                square_disc * daylight);
        }
        if (fallback_mask & 2u) != 0u && sun_height < 0.04 {
            let moon_direction = -sun_direction;
            let toward_moon = max(dot(direction, moon_direction), 0.0);
            let night = clamp(1.0 - daylight, 0.0, 1.0);
            let moon_disc = smoothstep(0.9989, 0.99935, toward_moon);
            let moon_halo = pow(toward_moon, 260.0) * night * 0.11;
            sky += vec3<f32>(0.24, 0.32, 0.53) * moon_halo;
            sky = mix(sky, vec3<f32>(0.63, 0.70, 0.81), moon_disc * night);
        }
    }
    if ibl_globals.grade.x > 0.5 {
        let fogged = apply_fog_along(sky, normalize(input.direction), -1.0);
        return vec4<f32>(display_transform(fogged * max(frame.render_params.z, 0.000001)), 1.0);
    }
    return vec4<f32>(sky, 1.0);
}
