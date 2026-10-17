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
  The real-source foliage job also scans BC1/BC3 and BGRA top-mip alpha
  values from the exact retained retail texture payloads, counting zero,
  partial and full coverage without copying pixels to its reports. Unsupported
  original mip layouts are explicitly unresolved, not treated as opaque.
  The authenticated external BC parser tracks both UE4 platform maximum
  dimensions and the actually resident first mip (which can be smaller for
  valid cooked grass textures). It never stretches a source mip to full size.
  These alpha counts are deliberately not interpreted as material OpacityMask:
  source shader graph and the selected runtime sampler must still prove that.

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

The grass master and field material source audit now follows six game-owned
MaterialFunction dependencies recovered from the original cooked expression
records. It also inventories actual FExpressionInput FName identities and
selectors from material/function exports, including links whose editor-only
nodes were stripped. Named graph edges are not executable OpacityMask, WPO,
wind, or biome math. Engine-owned functions are still separate dependencies.

The authenticated second-hop foliage contract also includes the real biome
mask and terrain color input textures, the internal wind texture sampling
function and the wind system's authored VectorOffset_RT2 render target. The
public probe enumerates original MaterialParameterCollection parameter names
and tagged render-target constructor fields. Runtime wind simulation and WPO
are separate GPU/runtime responsibilities; no static texture image is
substituted for a live render target.

## Incomplete original Athena POI worlds

The private universal renderer's last measured source report admitted 37/40
original POI regions. Three original source worlds still retained authentic
low-polygon HLOD proxies because their structural actor references were not
fully resolved: REC 13/16, Warehouses 17/20, Pueblo 58/65. These numbers
are **historical runtime inputs**, not new measured post-change results.

The separate public `poi-detail-original` runner now obtains the exact
`Athena_POI_REC_001`, `Athena_POI_Warehouses_003`, and
`Athena_POI_Pueblo_001` UMap/UExp pairs through the same SHA1-verifying
source PAK index workflow. A read-only parser reports authored actor class
FNames, source root StaticMesh FPackageIndex references, missing inherited
static-mesh paths, genuine Blueprint SceneComponent roots, and baked
`LODActor` proxy identities. The only persistent artifact is a textual
report. Original UMap/UExp files stay temporary and are deleted; no
private Rust-test checkout is performed. Reports are evidence for
source-true Blueprint CDO/SCS and nested world dependency closure, not a
substitute mesh or a relaxation of high-detail admission criteria.

