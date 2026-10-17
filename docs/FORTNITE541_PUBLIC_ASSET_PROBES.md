# Public GitHub-hosted asset probe lab — Fortnite 5.41

Fortnite-reverse is the **public** source-asset analysis repository. Rust-test
is the **private** game/rendering repository. Public Actions jobs do not
checkout, build, or disclose private Rust-test source.

## Available workflows

See .github/workflows/fortnite541-public-asset-probes.yml.

- The parser smoke job runs original public Rust decoder tests and source
  manifest report tests, without downloading retail assets.
- The terrain job uses the existing fetch_athena_541.py to authenticate
  original source index and entry SHA-1, then executes athena_surface_probe,
  athena_material_graph_probe and athena_material_dependencies.
- The sky/time-of-day job uses fetch_remote_541_dependencies.py to verify
  split PAK indexes and retrieve selected original source dependencies,
  including the real M_SkyDome master material and all five authenticated
  TextureSample input packages. athena_remote_source_probe audits cooked
  expression nodes, retained dependencies and missing authored graph edges.
  This is an admission frontier report, not an executable cloud shader.
- A separate foliage job fetches the exact source UStaticMesh and material
  packages behind 230,583 invisible Athena grass instances observed in the
  runtime report. It inventories source parent materials, tagged BlendMode,
  OpacityMask and related links, and shader graph dependencies. Decoding a
  masked source contract does not mean a Vulkan alpha shader is executable.
  Following the first successful retail probe, it also stages the exact
  `M_Athena_Grass_Master` parent and five source-identified Texture2D inputs
  of `M_FieldGrassMatching`; parent and function dependencies are logged for
  subsequent universal shader closure without guessing transparency.
- The raw original retail packages are downloaded only into runner temporary
  storage and removed after the probes. No original .uasset, .uexp, .ubulk,
  .umap, full PAK or retail EXE is committed or uploaded as a workflow artifact.
- Only logs and metadata-only source inventories (file names, byte lengths,
  SHA-256) are retained as GitHub Actions artifacts.

## Run

In Fortnite-reverse, choose Actions > Fortnite 5.41 public retail asset
probe lab > Run workflow. Select scope terrain, sky, foliage or all.

Merging updates to this workflow starts both real asset families. PRs only
run public-parser smoke tests, so source downloads do not recur for every
change.

Continue to use the separate restored-Ghidra workflows for native executable
analysis. Transfer verified format discoveries and derived test cases to the
private Rust-test importer without transferring the private application's
source into public CI.

GitHub-hosted runners are not literally unlimited: jobs, concurrency,
artifacts, usage policy and retention are bounded.
