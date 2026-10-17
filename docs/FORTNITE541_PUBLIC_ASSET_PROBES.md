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
  split PAK indexes and retrieve selected original source dependencies, then
  executes athena_remote_source_probe.
- The raw original retail packages are downloaded only into runner temporary
  storage and removed after the probes. No original .uasset, .uexp, .ubulk,
  .umap, full PAK or retail EXE is committed or uploaded as a workflow artifact.
- Only logs and metadata-only source inventories (file names, byte lengths,
  SHA-256) are retained as GitHub Actions artifacts.

## Run

In Fortnite-reverse, choose Actions > Fortnite 5.41 public retail asset
probe lab > Run workflow. Select scope terrain, sky or all.

Merging updates to this workflow starts both real asset families. PRs only
run public-parser smoke tests, so source downloads do not recur for every
change.

Continue to use the separate restored-Ghidra workflows for native executable
analysis. Transfer verified format discoveries and derived test cases to the
private Rust-test importer without transferring the private application's
source into public CI.

GitHub-hosted runners are not literally unlimited: jobs, concurrency,
artifacts, usage policy and retention are bounded.
