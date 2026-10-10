# Fortnite 5.41 — source-faithful reverse engineering

This public repository is the working home for **Fortnite 5.41** reverse-engineering source code, verifiable discoveries, importer experiments, and test contracts.

The original retail assets stay **outside Git** (local user installation or the pre-existing external asset bucket). Do not commit copyrighted retail game packages, large extracted textures, player data, credentials, secrets, or authenticated session material.

## Current concrete results (2026-10-10)

The native UE4.21 source decoder reads the original encrypted UE4 PAK v7 index with independently checked SHA-1; source UMAP/UAsset/UEXP export tables and Texture2D top-mip bulk samples are decoded. The authenticated original Athena landscape source contains:

| Finding | Direct evidence |
| --- | --- |
| Six landscape streaming sublevels | `Athena_Terrain_LS_00..05` from original retail map packages |
| 94 original `LandscapeComponent` objects | Parsed local source packages |
| 1,540,096 reconstructed source-local vertices | Original 128×128 heightmap samples |
| 3,032,252 heightfield triangles | Original source heightfield topology |
| 20,413 matching shared-edge height samples | Seam audit, no mismatches |
| 271 nodes in `M_Athena_Terrain_Master` graph | Cooked material expression audit; **not** executed shaders |
| 117 recognized direct expression links | Partial material graph; nested links not yet closed |
| 24 original Athena package files | Native local PAK extraction and file SHA-1 checks |

[Passing real-source parser and game-adapter validation](https://github.com/lizardpeter/destiny-1/actions/runs/38084086581) used only newly authored Rust code in its CI repository and temporary original R2 bytes; **25 unit tests passed**, and actual game-adapter lowering constructed all 94 generic scene meshes, 94 deliberately diagnostic grayscale textures, and 3,032,252 collision triangles.

The terrain diagnostic was integrated into [Rust-test PR #175](https://github.com/lizardpeter/Rust-test/pull/175) and local archive auto-extraction in [PR #176](https://github.com/lizardpeter/Rust-test/pull/176). **The full Rust-test Windows executable and GPU scene are not yet independently tested.**

## Code layout

- `crates/fortnite_541/` — independently testable original UE4 PAK, UObject, landscape, texture, geometry, material dependency, and local source-extraction decoder.
- `crates/fortnite_541/tools/fetch_athena_541.py` — reproducible SHA-1-verified download of selected source packages from an existing original R2 archive; development convenience only.
- `docs/RESEARCH_STATUS.md` — observed facts, remaining work, and explicit verification levels.
- `docs/INTEGRATION.md` — source-neutral contract for the Rust-test game importer.
- `.github/workflows/parser-check.yml` — unit tests and static type checking without copyrighted assets.

## Import architecture

```text
Original Fortnite 5.41 PAKs and cooked packages
   -> version-specific UE4 decoder (this repository)
   -> verified original geometry, textures, materials, actors, collision
   -> source-neutral NeutralScene + executable SurfaceProgram IR
   -> shared Rust-test renderer / gameplay / physics (never Fortnite-specific Vulkan)
```

**Important:** the current grayscale in-game landscape mode is an explicitly labeled **terrain-height diagnostic**, not Fortnite's retail colors, materials, sky, structures, or lighting. The remaining work is source-exact material function decoding, original weightmaps and texture dependencies, actor/static-mesh placements, sunlight/sky, and gameplay collision semantics.

## Build and test the independent parser

```bash
cargo test --manifest-path crates/fortnite_541/Cargo.toml --all-targets
cargo check --manifest-path crates/fortnite_541/Cargo.toml --all-targets
```

To reproduce the 24 original Athena landscape files (without uploading them to Git):

```bash
python3 crates/fortnite_541/tools/fetch_athena_541.py --all-landscape --destination crates/fortnite_541/work/athena/source
cargo run --manifest-path crates/fortnite_541/Cargo.toml --bin landscape_catalog -- crates/fortnite_541/work/athena/source
```

The helper requires Python 3, `curl`, and OpenSSL. The **Rust-test game** alternatively detects `%USERPROFILE%\Downloads\5.41\5.41` and can natively extract its Athena terrain files from `FortniteGame\Content\Paks\pakchunk0-WindowsClient.pak`; no environment setting is necessary at that standard location.

See [research status](docs/RESEARCH_STATUS.md), [Athena material dependency closure](docs/ATHENA_MATERIAL_DEPENDENCIES.md), and [integration contract](docs/INTEGRATION.md).