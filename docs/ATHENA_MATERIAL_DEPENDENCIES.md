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
