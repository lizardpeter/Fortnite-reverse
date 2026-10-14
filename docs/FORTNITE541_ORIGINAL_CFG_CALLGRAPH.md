# Fortnite 5.41 original CFG CALL provenance

This implementation extends the existing 16-runner Capstone recursive CFG census. It does not redo the 291,757 Ghidra function decompilations and does not claim C++ reconstruction.

## Prior verified source findings

- 291,757 authenticated original .pdata entries scanned.
- 1,450,067 entrypoint-reachable x64 instructions (partial CFG).
- 7,129 possible direct branch CALLs.
- 3,258 validated original five-byte E8 rel32 CALL instructions.
- 88 E8 targets landing inside original .pdata extents.
- 76 E8 targets pointing to executable non-pdata bytes.
- 3,094 E8 targets outside mapped executable function ranges.

An interior .pdata CALL destination cannot be described as an original function entrypoint. Existing linear disassembly has not provided a trustworthy full native callgraph.

## New machine-code evidence

On a successful full main-branch job, all source-authenticated 16 parallel shards are saved on the existing re/fortnite541-ghidra-full branch:

- decompilation/fortnite541/discovery/recursive_calls/records/verified_e8_calls_*.jsonl.gz
- decompilation/fortnite541/discovery/recursive_calls/original_cfg_source_verified_calls.jsonl.gz
- decompilation/fortnite541/discovery/recursive_calls/original_cfg_callgraph_status.json

Each entry includes original caller .pdata index and start RVA, machine CALL instruction RVA and five source bytes, exact destination RVA, containing .pdata owner (when any), exact-entry status, source binary SHA256 and evidence category.

The independent auditor verifies every rel32 displacement from the actual saved original instruction, enforces non-overlapping ordinal shards, rejects duplicate callsites, and cross-checks caller and target identities against the existing exact original .pdata index. Original interval overlap is handled using prefix-maximum ownership. An incomplete source range cannot be claimed complete.

Evidence is source-authenticated entrypoint-reachable original x64 E8 instruction decoding, not recovered UE4 class/function identification, original C++, verified linker behavior, or a complete machine CFG. Conservative CFG excludes unknown indirect branches, jump tables, exception flow, and virtual calls.

## Next steps

Use audited exact-entry and interior-target neighborhoods to cross-link source Ghidra C with machine CALL witnesses by original RVA. Review anomalies before labeling any new Unreal functions. Then recover material/shader function field layouts and relevant D3D11 behavior using retail code AND original cooked asset semantics, not pseudocode keywords alone.
