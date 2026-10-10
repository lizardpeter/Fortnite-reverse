# Fortnite 5.41 — reproducible research status

**As of 2026-10-10.** Evidence-backed status only. Numbers are from the source-authenticated retail 5.41 archive and passing public CI, not inferred from a preview screenshot.

## Original-source identity

- Platform/source package: Windows FortniteGame version **5.41**, Unreal Engine cooked package format roughly UE4.21, main PAK v7.
- R2 original-archive locator: `https://r2.houseofkublai.com/Fortnite/5.41/FortniteGame/Content/Paks/pakchunk0-WindowsClient.pak`.
- PAK original length: **4,813,653,874 bytes**.
- Encrypted PAK index start: **4,805,651,429**, length **8,002,384**; source footer SHA-1 after index decryption: `fd1f4623c812f5fff47298f99cc3d0d8f2d0f11b`.
- Decoded main PAK index contains **54,299 entries**, including **281 .umap** and **2,564 .ubulk** entries. This is the main PAK only, not a complete all-Pak census.
- Python helper and native Rust loader check SHA-1 of every extracted original payload. Source code, logs and findings can be shared; retail game files stay outside Git.

## Exact source-backed Athena terrain

| Verified source fact | Result |
| --- | --- |
| Athena landscape streaming sublevels | LS_00 through LS_05 |
| Verified `LandscapeComponent` count | 94 (section counts 6, 12, 10, 31, 14, 21) |
| Authenticated top mip texture format | 128x128 BGRA8 PF_B8G8R8A8 |
| Heights per sample | `height16 = (red << 8) + green` |
| UE4 source Z unscaled height | `(height16 - 32768)/128` |
| Source-local grid quad extents | X 0..1524, Y 0..1524 |
| Decoded source-local vertices | 1,540,096 |
| Decoded triangles | 3,032,252 |
| Shared-edge exact height matches | 20,413 |
| Shared-edge mismatches | 0 |
| Original proxy/component placement validations | 94/94 |
| Current source terrain material dependency | `/Game/Athena/Environments/Landscape/Material/M_Athena_Terrain_01` |

The in-game test lowers these vertices into engine Y-up coordinates, 94 generic meshes and placements, 94 explicit grayscale *height diagnostic* textures, and a separate **3,032,252-triangle terrain-surface collision dataset**. The material presented to the GPU in that preview is **not Fortnite's original material**. Original heightfield collision component metadata beyond the surface mesh is not yet reconstructed.

## Original material graph: dependency discovery only

The original `M_Athena_Terrain_Master` package contains **271 `MaterialExpression` exports**, including 90 material function calls, 53 landscape layer samples, 45 scalar parameters and 20 collection parameters; also 12 layer-coordinate operators, 11 layer switches, 10 feature switches, 8 quality switches, 7 static-switch parameters, 4 landscape layer blends, 4 vector parameters, 3 texture samples, 2 texture objects, 1 landscape grass output and 1 texture sample parameter.

Source-level parsing currently identifies **117 direct `FExpressionInput` links**, **387 UObject references**, **36 unique external imports** and **0 unresolved direct node references** under the implemented parser. These are *not* whole-graph or executable shader coverage numbers: nested input structs and external function bodies still need decoding. Landscape weightmap layer allocations, original texture-channel semantics, base-color/normal/roughness and shaders are still open.

## Real validation

- [Public test run: game adapter from real Fortnite source and native local PAK auto extraction](https://github.com/lizardpeter/destiny-1/actions/runs/38084086581): 25 tests passed, standalone decoder and copied application adapter compiled against the source-neutral scene contract, 24/24 authenticated original source files (71,248,937 bytes) extracted from an original-byte sparse PAK, and complete 94-patch neutral scene produced.
- [Original real terrain and seam audit](https://github.com/lizardpeter/destiny-1/actions/runs/38081299261).
- [Rust-test #175 — in-game map admission](https://github.com/lizardpeter/Rust-test/pull/175).
- [Rust-test #176 — native local PAK extraction](https://github.com/lizardpeter/Rust-test/pull/176).

**Caveat:** These tests validate the isolated importer, the game-side source adapter, the scene types and source geometry. They do **not** prove a successful complete Windows `fps_game.exe` build, Vulkan upload, GPU frame, working map menu in a shipped binary, original material visuals, or Fortnite gameplay parity. The Rust-test private Actions infrastructure has previously failed before any steps ran.

## Ranked remaining closure work

1. Recover original landscape weightmap layer assignments, material instance scalar/vector/texture parameter overrides, function graphs, cooked static parameter switches and true source shaders. Map their executable semantics through generic `SurfaceProgram`; **do not** add game-specific Vulkan or guessed textures.
2. Decode referenced original `UStaticMesh` vertex/index buffers and ULevel StaticMeshComponent placements, level/background/streaming instances; verify world transforms and instancing.
3. Recover original sun, sky/atmosphere, ambient/skylight, reflection probes, baked/indirect irradiance, fog and exposure.
4. Restore original authored collision components and player spawn metadata, not invented gameplay surfaces.
5. Optimize memory usage and scene streaming/LOD on the generic engine path only after fidelity is proven; never degrade the existing low-latency input and frame scheduling features.

All new factual claims should include their exact asset path + hash, source parser code, commit and test run, or remain explicitly *unverified*.
