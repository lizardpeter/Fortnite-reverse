# Fortnite source importer ↔ Rust-test game integration

## Repositories

- **This public repository** (`lizardpeter/Fortnite-reverse`) is the working home for Fortnite format research, standalone importer code, experiments, verified findings and test artifacts. The independent crate is in `crates/fortnite_541/`.
- **Rust-test** (`lizardpeter/Rust-test`) owns the multiplayer game loop, map picker, the source-neutral scene bridge, shared renderer, generic collision and in-game wiring. Current copy of this importer: `asset_import/importers/fortnite_541/`; game adapter: `src/source_importers/fortnite_541.rs`.
- Keep any fixes synchronized deliberately across the independent public crate and Rust-test importer; avoid silently diverging duplicate parsers. No copyrighted retail assets in either Git repository.
- FalkorDB `uregraph` can index the original format, verified source evidence and recovered semantics using its **existing** `KGNode` / project / evidence ontology. Do not mix in or rewrite the separate medical graphs.

## Windows auto-discovery: no command required

On a Windows account where the retail install resides under `%USERPROFILE%\Downloads\5.41\5.41`, Rust-test already looks for `Engine/` and `FortniteGame/` and then the source archive at:

```text
%USERPROFILE%\Downloads\5.41\5.41\FortniteGame\Content\Paks\pakchunk0-WindowsClient.pak
```

Selecting **Fortnite 5.41 → Athena — source heightfield preview** causes one-time local extraction of the 24 source files if none are cached. The importer validates PAK footer, AES decrypted index hash, each original FPakEntry and extracted bytes. No network call, Python, OpenSSL, and no environment variable are required when this file is present.

An alternate custom location can be supplied *optionally* (PowerShell):

```powershell
$env:RUST_TEST_FORTNITE_541_PAK = "D:\Games\Fortnite541\FortniteGame\Content\Paks\pakchunk0-WindowsClient.pak"
```

Use `RUST_TEST_FORTNITE_541_ATHENA_SOURCE_ROOT` only if the 24 original packages have already been extracted to a nonstandard folder. The local preparer extracts only the necessary verified records into the ignored repo work directory. The original archive is never copied into Git.

## Runtime path and guarantees

```text
Original 5.41 PAK / SHA-1 verified source UObjects
  -> fortnite-541-importer::athena::load_verified_athena()
  -> source coordinates and heightfield topology
  -> src/source_importers/fortnite_541.rs
  -> neutral_scene::NeutralScene (Y-up)
  -> src/source_importers/neutral_bridge.rs
  -> existing EnvironmentRenderData, generic collision, generic renderer
```

One-time original terrain decoding happens at map load, not per frame. Temporary decoded source buffers are released after lowering to the generic scene. The current height preview is unlit grayscale generated *from* exact source height samples; all materials are named `DIAGNOSTIC_ONLY_` to prevent mistaken attribution as original retail shader output.

**Not yet implemented:** original Fortnite surface material execution, original textures, full sky and world lighting, static-mesh actors, authoritative gameplay collision, terrain streaming LOD and visual fidelity.

## Developer workflow

Test parser:
```bash
cargo test --manifest-path crates/fortnite_541/Cargo.toml --all-targets
```

Download authenticated original Athena source bytes for separate testing (only to an ignored work folder):
```bash
python3 crates/fortnite_541/tools/fetch_athena_541.py --all-landscape --with-terrain-materials --destination crates/fortnite_541/work/athena/source
```

Use the `landscape_catalog`, `material_catalog` and `athena_probe` diagnostics to ground each parser addition. Preserve per-source variant encodings and source-provenance evidence. Fail loudly on unsupported records instead of manufacturing plausible world data.
