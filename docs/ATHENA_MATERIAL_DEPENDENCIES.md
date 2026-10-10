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
