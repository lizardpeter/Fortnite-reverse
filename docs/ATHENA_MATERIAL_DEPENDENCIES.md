# Fortnite 5.41 — Original Athena terrain material dependency closure

**Source-verified 2026-10-10.** The goal is not to approximate how Fortnite's map looked. All source packages must be the original retail 5.41 bytes; all shader inputs must be grounded in original authored UObject references.

## Implemented source semantics

- [Rust-test PR #182](https://github.com/lizardpeter/Rust-test/pull/182): all **94** landscape components now decode their original `WeightmapLayerAllocations` as tagged UE4.21 `FWeightmapLayerAllocationInfo` objects. The exact per-record payload is 105 bytes. Source `LayerInfo` references, source weightmap texture indices and logical R/G/B/A channels are resolved and checked; source RGBA channels are recovered from the original BGRA8 top-mip bytes. All 208 weightmap texture references and 669 source layer allocations now resolve to 17 original named LandscapeLayerInfo objects.
- All original weightmap pixels are retained as separate **authored scalar paint-control weights** aligned with the exact 128×128 source vertices of each of the 94 terrain patches. This is not yet executable original material shading; no invented albedo, PBR, or replacement shader is used.
- [Public original-PAK CI #38090558756](https://github.com/lizardpeter/destiny-1/actions/runs/38090558756) confirms **28 importer tests passed**, complete original paint sample census and unchanged original terrain geometry/collision.

The original 17 source layer names are `Arid_Grass_Light`, `Arid`, `Arid_RockDetail`, `CraterOvergrowth`, `Farm_Grass`, `Flowers`, `Forest`, `Golf_Fairway`, `Golf_Green`, `Grass_Only`, `Grass_Topology`, `Gravel`, `Mountain_Grass`, `Mud`, `NoFoliage`, `NoTopo`, and `Road`. Some are semantic control masks and **must not be mistaken for visible albedo layers**.

## Original master material dependencies

The original `/Game/Athena/Environments/Landscape/Material/M_Athena_Terrain_Master` has 271 typed MaterialExpression objects. Its currently decoded *direct* reference set includes **36 external UObject references**: 26 Fortnite game-content packages and 10 original Unreal Engine material functions.

All 26 game-content package names were matched against the authenticated original `pakchunk0-WindowsClient.pak` v7 main index. **24 of 26** have complete `.uasset` + `.uexp` pairs, are uncompressed/unencrypted, and their total original indexed payload is **130,495 bytes**. **Two referenced texture package pairs** are absent from that **one** main archive; do not assume they are missing from the full build:

- `/Game/ContentCreationTools/TextureCreation/Textures/T_BPCreated_MacroNormal_01`
- `/Game/Environments/AutumnDecay/Terrain/Textures/T_Grass_AD_D`

The 24 archive-ready direct dependencies comprise:

- **Material parameter collection:** `MPC_Landscape`
- **Original landscape material functions:** `MF_Athena_Arid_Rock`, `MF_Athena_Arid_Rock_02`, `MF_Athena_Arid_Sand`, `MF_Athena_Material_BaseMultiply`, `MF_Athena_ReplaceBaseColor`, `MF_Athena_SedimentGradient`, `MF_Athena_WorldHeightGrad`, `MF_Athena_ZSandColor`, `MF_FarmGrass_Colors`, `MF_Landscape_GrassDistanceBlend`, `MF_LawnGrassColoration`, `MF_MountainGrass_Colors`, `MF_TerrainDistanceFade`, `MF_TerrainTopoAdjustment`
- **Original standard layer functions:** `MF_Athena_Crater_01`, `MF_Athena_Forest_01`, `MF_Athena_Grass_01`, `MF_Athena_Gravel_01`, `MF_Athena_Mud_01`, `MF_Athena_Road_01`, `MF_Athena_Rock_01`
- **Original source texture packages:** `T_Athena_Terrain_CombinedColors_01`, `T_Athena_Terrain_Topo_Mask`

Ten further references resolve to `/Engine/Functions/...` original UE material functions such as `HeightLerp`, `FlattenNormal` and `MatLayerBlend_Standard`. These need source decoding too; they are not optional approximations.

Verification: [public original-source dependency census](https://github.com/lizardpeter/destiny-1/actions/runs/38090717555).

## Extraction tools

`crates/fortnite_541/src/bin/athena_material_dependencies.rs` prints source-identical direct material object dependencies and checks them against the **authenticated** main PAK index, without extracting content.

`crates/fortnite_541/src/bin/athena_extract_materials.rs` and the isolated `material_extract` module provide a separately invoked, bounded, original-SHA-1-authenticated recursive extraction path for original material/function/texture packages. Output stays in an ignored local working directory; unavailable packages remain explicitly unresolved, not fabricated. The extractor uses the original source master to follow dependencies rather than a game-specific rendering shortcut. The recursive full-archive extraction and source texture shader parity must be verified separately; presence in the PAK index is not sufficient.

## Next original-material work

1. Execute and census recursive source extraction from all available original 5.41 PAK archives, including the two assets absent from main.
2. Parse nested function graphs, source texture object bindings, cooked material parameter overrides and static switches. Recover original actual base-color/normal/roughness source textures (and compressed texture formats).
3. Lower **complete executable source material semantics**, including weightmap layer blends, into the shared engine `SurfaceProgram` IR. Support more than two paint layers per surface without a hard-coded Fortnite Vulkan path.
4. Verify source fidelity in the Windows native Vulkan game and capture before/after. This work does **not** claim original sky, buildings, foliage, water or lighting are ready.

No invented colors, lighting, material approximations, or undocumented input-latency changes are part of this work.


## 2026-10-10 — Original texture and shader graph closure

**[Rust-test PR #185](https://github.com/lizardpeter/Rust-test/pull/185)** restored authenticated highest-resolution BC material texture payloads through the generic NeutralTexture bridge, with no Fortnite-specific Vulkan path:

- `T_Athena_Terrain_CombinedColors_01`: original 2048×2048 BC1/DXT1, 2,097,152 exact compressed bytes
- `T_Athena_Terrain_Topo_Mask`: original 2048×2048 BC3/DXT5, 4,194,304 exact compressed bytes
- Both original top mips have a source-authenticated external `.ubulk` offset of 0; both converted successfully into the shared `NeutralTexture` representation in [real-source CI](https://github.com/lizardpeter/destiny-1/actions/runs/38092177045)
- The original sources are NOT yet bound to terrain because their source-authored sampler UV/function mapping remains incomplete; no shader rendering parity is claimed

The staged original material extractor also recovered **28 source packages, 58 authenticated files, 8,972,533 bytes, and 459 original expression nodes**, retaining explicitly deferred transitive dependencies instead of fabricating them.

**[Rust-test PR #186](https://github.com/lizardpeter/Rust-test/pull/186)** decoded all **4 original MaterialExpressionLandscapeLayerBlend nodes and 20 nested layer records**. Each is an authenticated 379-byte tagged UE4.21 `LandscapeLayerBlendInput`, following the source 49-byte array tag. The source AST preserves LayerName, ELandscapeLayerBlendType, 40-byte FExpressionInput links, constant color, constant height, and preview weights. **19** source operators are `LB_WeightBlend` and **1** is `LB_HeightBlend`, with five author-layer names repeated across four operators: Grass_Only, Grass_Topology, Arid, Farm_Grass, Mountain_Grass. [Public CI #38092482055](https://github.com/lizardpeter/destiny-1/actions/runs/38092482055) passed 30 unit tests and the real retail source graph check. Typed AST data is NOT yet an executable original SurfaceProgram.

## 2026-10-10 — Original sky and time-of-day identity

The original Athena_Terrain.umap FortWorldSettings.WorldTimeOfDayManager source `SoftObjectPath` resolves to `/Game/TimeOfDay/TODM/BR/TODM_BR.TODM_BR_C`. The original Athena_Background.umap places `TRV_Skybox_Mountain_04` static mesh actors with source position, rotation and scale; the original main Athena map also has 429 FortHLODSMActor and 459 StaticMeshComponent exports.

The TODM_BR and TRV_Skybox_Mountain_04 source package pairs are **not in the single main pakchunk0-WindowsClient.pak**, so their original sun/sky data cannot be reconstructed from that archive alone. The new local `athena_locate_retail_sources` tool searches the other original operator-owned PAK indexes, and also targets the two missing master material textures. No source-unproven sunlight/skybox workaround was added.

Remaining: full transitive material function closure, native shader program lowering, original sky/time-of-day asset decoding, authentic structures and vegetation/water/lighting. Full Windows GPU visual parity remains unverified.

## 2026-10-10 — All missing direct source files recovered remotely

The previous statement that TODM_BR, the mountain skybox mesh, and two missing terrain textures could not be accessed without a local Windows command is obsolete. A public GitHub runner independently examined **89 candidate names**, found **7 actual public R2 retail Fortnite 5.41 WindowsClient PAKs**, and validated each encrypted UE4 v7 archive index against its original source SHA-1 checksum:

| Authenticated original archive | Original content index SHA-1 |
| --- | --- |
| `pakchunk0-WindowsClient.pak` | `fd1f4623c812f5fff47298f99cc3d0d8f2d0f11b` |
| `pakchunk0_s1-WindowsClient.pak` | `a37147494190b90c420b852d69740402f93f6103` |
| `pakchunk0_s2-WindowsClient.pak` | `42a45eee280ab70abbb5192b33a5945c119bd82c` |
| `pakchunk0_s3-WindowsClient.pak` | `27376dab8f8a3488d0d2b5332a2a2da7d28fd73e` |
| `pakchunk0_s4-WindowsClient.pak` | `96a67f9eae257051576e368fdb61a6fb78b2f56a` |
| `pakchunk1-WindowsClient.pak` | `b6b32c94f36c35a528d186bcb4a6b5f9bd89255f` |
| `pakchunk1_s1-WindowsClient.pak` | `f0aab02bece3410400e32f29bd92e13577a4109d` |

The original PAK **mount points are different**: split PAK index records can begin with `TimeOfDay/...`, `Environments/...` or `ContentCreationTools/...` rather than `FortniteGame/Content/...`. A previous scanner incorrectly required the fully qualified path and returned false missing results. The new public-R2 tools normalize mount-relative target paths before matching, then verify PAK-entry header, indexed source SHA-1 and payload SHA-1 before extracting anything. It does not download whole multi-gigabyte archives.

| Original source package | Exact original archive |
| --- | --- |
| `TimeOfDay/TODM/BR/TODM_BR` | `pakchunk0_s4-WindowsClient.pak` |
| `Environments/World/Backgrounds/Transylvania/Meshes/TRV_Skybox_Mountain_04` | `pakchunk0_s3-WindowsClient.pak` |
| `ContentCreationTools/TextureCreation/Textures/T_BPCreated_MacroNormal_01` | `pakchunk0_s2-WindowsClient.pak` |
| `Environments/AutumnDecay/Terrain/Textures/T_Grass_AD_D` | `pakchunk0_s2-WindowsClient.pak` |

Remote extraction **passed** in the public GitHub runner: **10 SHA-1-verified original files totaling 6,128,155 bytes** (`.uasset`, `.uexp`, and `.ubulk` where source files exist). [Public test run](https://github.com/lizardpeter/destiny-1/actions/runs/38093882777). The original data stays in temporary runner files, not Git; the public `fetch_remote_541_dependencies.py` utility reproduces the authenticated extraction without user-local steps.

The source `TODM_BR` package contains 23 original exports, including the `TODM_BR_C` default object, a `DirectionalLightComponent`, a `SkyLightComponent` referencing `/Game/Packages/Fortress_Sky/TexturesHDR/T_AthenaSkylight`, an `ExponentialHeightFogComponent`, four `LightAndFogPhaseSettings` source `DayPhaseInfo` fields, and morning/day/evening/night post-process components. Original `T_BPCreated_MacroNormal_01` is **PF_BC5** and original `T_Grass_AD_D` is **PF_DXT5 / BC3**, 2048×2048 top mip, 4,194,304 compressed bytes. These source facts were verified by `athena_remote_source_probe` in [passing remote-runner test](https://github.com/lizardpeter/destiny-1/actions/runs/38093882777).

**Important boundary:** source asset extraction and property parsing do not themselves mean original lighting or material shaders are executing in the game. The next steps are decoding TODM `DayPhaseInfo` nested structures, the skylight cubemap, skybox static mesh payload, and the original material-function dependency graph into the shared `NeutralScene`/`SurfaceProgram` renderer. There is no reason to ask the user to do the discovery, index scan, or decoding locally.

## Expanded source closure — authored sky materials and daylight environment

Continuing entirely in public GitHub runners, the authenticated seven-PAK R2 scanner recovered **22** original files (**6,688,933** source bytes). Added to the previously verified TODM, mountain skybox mesh and missing grass/macro-normal textures:

- `T_AthenaSkylight` (`TextureCube`, `PF_DXT5`) from `pakchunk0_s4-WindowsClient.pak`. Unlike the terrain Texture2D top mip this is a **cube** with its own cooked layout; its faces and mip chain must be decoded before assigning as an environment probe.
- The original **morning, daytime, evening and nighttime** `SkyDomeBasic01` material instances from `pakchunk0_s4-WindowsClient.pak`. The daytime instance inherits from the morning instance and carries **11 scalar** and **7 vector** parameter records that must be decoded and applied to the shared shader path.
- The source cloud-light-function material instance `LF_AthenaClouds_Inst` from the original main PAK.

The `TODM_BR_C` original blueprint default object contains four tagged `DayPhaseInfo` records. Authenticated nested-property decoding recovered these authored values:

| Phase | Source phase begins (hours) | Source directional brightness | Source skylight color (linear RGBA) | Source fog density |
| --- | ---: | ---: | --- | ---: |
| Morning | 3 | 3.5 | (1.000000, 0.634080, 0.663958, 0.70) | 0.004 |
| Day | 7 | 3.0 | (0.611440, 0.780079, 1.100000, 0.80) | 0.004 |
| Evening | inherited/unspecified in this record | 3.5 | (1.000000, 0.560073, 0.530209, 0.80) | 0.003 |
| Night | inherited/unspecified in this record | 8.0 | (0.580000, 0.699150, 1.000000, 0.75) | 0.009 |

Night has its own directional-light parameters; do not interpret its brightness as daytime sunlight. The original phase structs additionally include ExponentialHeightFogValues, directional inscattering colors, sky materials, post-process components and transition durations. Fields absent from source instances must be resolved against Unreal class defaults / base asset, not assumed zero. The dynamic sun position is not yet reconstructed, and the engine has not yet admitted these settings as actual scene lighting.

Verification: [public remote source scan and original-authored phase property tests](https://github.com/lizardpeter/destiny-1/actions/runs/38094052567) and [sky material / original cube scan](https://github.com/lizardpeter/destiny-1/actions/runs/38094235839). No Windows-local archive discovery commands are required.

## Original BR time-of-day typed integration — Rust-test PR #187

The previous source-only `TODM_BR` examination has been promoted to the isolated Rust importer `timeofday.rs`. It validates the four exact cooked UE4.21 `DayPhaseInfo` property streams from the **original SHA-1-authenticated s4 PAK**, including source-local `LightColor` `FColor` BGRA, directional brightness, `SkyLightColor` authored linear RGBA, `FogInscatteringColor`, fog density/falloff, and explicitly stored phase begin/length. Unknown layouts, invalid object classes and nonfinite coefficients fail closed.

All four phases passed independent real-asset testing: [original-time-of-day and game-adapter CI](https://github.com/lizardpeter/destiny-1/actions/runs/38094927342). The original daytime source record is phase 1, begins at 07:00 and runs for 12 hours, with SkyLightColor `(0.61144,0.780079,1.1,0.8)`, directional brightness `3`, sky fog RGB `(0.2,0.526164,1)` and fog density `.004`.

[Merged Rust-test PR #187](https://github.com/lizardpeter/Rust-test/pull/187) adds **automatic, native, cryptographically source-verified `pakchunk0_s4-WindowsClient.pak` extraction next to the auto-discovered main PAK**. The map source adapter uses the typed original daylight skylight RGB as a generic environment ambient input, with a **neutral unit intensity** as an explicitly identified rendering approximation—not an assertion about retail Unreal skylight alpha/intensity. It logs exact source directional light and fog settings without manufacturing an unknown dynamic sun direction, sky shader, or fog actor base-height transform. No user-local setup commands, performance-critical frame-loop changes, or fabricated Fortnite materials are involved.

**Render-parity limitation:** Athena geometry still uses height-diagnostic grayscale terrain; original material source graph and sky dome shader compilation, cubemap orientation, dynamical sun motion, authored geometry and exact fog semantics remain unfinished. The runtime scene is not yet a visually accurate Fortnite island.
