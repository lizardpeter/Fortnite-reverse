# Fortnite 5.41 restored analysis PE artifact

The Windows recovery workflow saves a reconstructed, analysis-only copy of
the original Fortnite 5.41 shipping executable in repository **Actions artifacts**.

## Download

1. Open the repository **Actions** tab.
2. Select **Fortnite 5.41 isolated Windows mapped-image comparison**.
3. Open a successful run and find the **Artifacts** section.
4. Download **fortnite541-restored-analysis-pe-<run-id>**.
5. Unzip the artifact to get:
   - FortniteClient-Win64-Shipping-5.41-restored-analysis.exe
   - manifest.json

## Verify

The manifest contains the SHA-256 and length of the recovered executable,
the pinned SHA-256 of the original input, and the GitHub commit/run ID.

Verify with PowerShell in the extracted directory:

    Get-FileHash .\FortniteClient-Win64-Shipping-5.41-restored-analysis.exe -Algorithm SHA256

Compare the result with manifest.json. The recovered PE is intended for
Ghidra/IDA analysis, not certified as an independently runnable game.

GitHub Actions artifacts are retained for **90 days** from upload. They
belong to this repository but are not stored in normal Git history. A fresh
run can generate a new artifact; move the image to durable storage before
retention expires.

## How recovery is validated

The workflow downloads the exact original 97,284,496-byte executable from
the R2 source, verifies SHA-256, stages original runtime DLLs and blocks
network access. After startup, it copies the runtime-restored bytes of each
executable PE section into its original raw-file position.

The reconstructed output must satisfy PE header, recovered byte coverage,
original function-entrypoint plausibility, full output SHA-256 and size
checks before the artifact can be uploaded. The archive contains the
analysis PE and its manifest, not a raw whole-process memory dump.

The recovery implementation is at:

    crates/fortnite_541/tools/probe_windows_runtime_image.py

Workflow configuration:

    .github/workflows/fortnite541-windows-runtime-proof.yml

The original executable's pinned SHA-256 is:

    7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108

This is proprietary executable code. Distribution and further use remain
subject to applicable rights.
