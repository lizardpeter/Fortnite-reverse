#!/usr/bin/env python3
"""Extract auditable function-reference edges from already committed Ghidra C.

This does NOT rerun Ghidra, recover original C++ symbol names, or prove
machine-code control flow. Every edge means a named FUN_... reference in an
authenticated Ghidra C body, not necessarily a verified original CALL opcode.
"""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import re
from pathlib import Path

from index_ghidra_pseudocode import TOTAL, gz_rows, load_recovered

IMAGE_BASE = 0x140000000
ORIGINAL_SHA256 = "7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"
CALL = re.compile(r"(?<![A-Za-z0-9_])(?:thunk_)?FUN_([0-9a-fA-F]{8,16})\s*\(")


def source_calls(source: str):
    """Count target Ghidra FUN addresses in C body, not its declaration."""
    body = source.partition("{")[2]
    out = collections.Counter()
    for match in CALL.finditer(body):
        va = int(match.group(1), 16)
        if IMAGE_BASE <= va < IMAGE_BASE + 0x80000000:
            out[va - IMAGE_BASE] += 1
    return out


def find_string_candidates(root: Path):
    candidate_file = root / "index" / "original_xrefs" / "candidate_function_evidence.jsonl.gz"
    if not candidate_file.is_file():
        return set()
    return {int(row["function_rva"], 16) for row in gz_rows(candidate_file)}


def extract(root: Path, out: Path):
    stat = json.loads((root / "status.json").read_text())
    audit = json.loads((root / "recovery_status.json").read_text())
    if stat.get("original_pdata_functions") != TOTAL or stat.get("covered_records") != TOTAL:
        raise ValueError("Incomplete original source inventory")
    if audit.get("original_pdata_functions") != TOTAL:
        raise ValueError("Original recovery ledger mismatch")
    recovered, modes = load_recovered(root, TOTAL)
    seeds = find_string_candidates(root)
    out.mkdir(parents=True, exist_ok=True)

    ordinals = {}
    lookup = root / "index" / "original_function_lookup.jsonl.gz"
    for entry in gz_rows(lookup):
        ix = entry["index"]
        rva = int(entry["rva"], 16)
        if ix in ordinals:
            raise ValueError(f"duplicate original index {ix}")
        ordinals[ix] = rva
    if len(ordinals) != TOTAL:
        raise ValueError(f"Unexpected original source lookup size {len(ordinals)}")
    source_functions = set(ordinals.values())
    inbound = collections.Counter()
    outbound = collections.Counter()
    named_edges = outside_edges = total_calls = nreal = 0
    seed_inbound, seed_outbound = collections.defaultdict(list), collections.defaultdict(list)
    seen_ordinals = 0
    gzf = out / "original_ghidra_c_function_calls.jsonl.gz"
    with gzip.open(gzf, "wt", encoding="utf-8", compresslevel=9) as stream:
        shards = sorted((root / "functions").glob("pdata_*.jsonl.gz"))
        if len(shards) != stat["shard_count"]:
            raise ValueError("Missing original verified Ghidra function shards")
        for shard in shards:
            for first in gz_rows(shard):
                index = first["index"]
                if index != seen_ordinals:
                    raise ValueError(f"Unexpected original ordinal {index}, expected {seen_ordinals}")
                seen_ordinals += 1
                start = int(first["rva"], 16)
                if ordinals[index] != start:
                    raise ValueError(f"Original source address mismatch at {index}")
                effective = first
                mode = "first_pass"
                source_file = f"functions/{shard.name}"
                if index in recovered:
                    if first.get("status") == "decompiled":
                        raise ValueError("Recovery replaced valid first-pass decompilation")
                    item = recovered[index]
                    effective = item["row"]
                    mode = item["mode"]
                    source_file = f"recovery/{mode}/records/{item['path']}"
                    if effective["rva"] != first["rva"]:
                        raise ValueError(f"Recovered RVA mismatch at original ordinal {index}")
                c = effective.get("c") or ""
                is_real = effective.get("status") == "decompiled" and bool(c.strip())
                if effective.get("status") == "decompiled" and not is_real:
                    raise ValueError(f"Empty C falsely marked decompiled at {index}")
                if is_real:
                    nreal += 1
                calls = source_calls(c) if is_real else collections.Counter()
                outbound[start] = len(calls)
                for target, occurrences in calls.items():
                    inbound[target] += 1
                    total_calls += occurrences
                    if target in source_functions:
                        named_edges += 1
                    else:
                        outside_edges += 1
                    if target in seeds:
                        seed_inbound[target].append({"caller_rva": f"0x{start:08x}", "occurrences": occurrences})
                    if start in seeds:
                        seed_outbound[start].append({"callee_rva": f"0x{target:08x}", "occurrences": occurrences})
                row = {
                    "original_ordinal": index, "caller_rva": f"0x{start:08x}",
                    "name": effective.get("name"), "status": effective.get("status"),
                    "source_shard": source_file, "recovery_mode": mode,
                    "c_sha256": hashlib.sha256(c.encode()).hexdigest() if is_real else None,
                    "ghidra_named_function_targets": [
                        {"callee_rva": f"0x{target:08x}", "mentions": occurrences,
                         "target_in_original_pdata": target in source_functions}
                        for target, occurrences in sorted(calls.items())
                    ],
                    "evidence_level": "ghidra_c_named_call_reference_not_verified_original_opcode",
                }
                stream.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
    if seen_ordinals != TOTAL or nreal != audit["effectively_decompiled"]:
        raise ValueError(f"Recovered original Ghidra C coverage mismatch {seen_ordinals}/{nreal}")

    summary = {
        "schema_version": 1,
        "original_pe_sha256": ORIGINAL_SHA256,
        "original_pdata_functions": TOTAL,
        "real_ghidra_c_functions": nreal,
        "remaining_without_c": TOTAL - nreal,
        "unique_named_edges_to_original_pdata": named_edges,
        "unique_named_edges_to_nonpdata_or_unindexed": outside_edges,
        "total_named_call_mentions": total_calls,
        "candidate_original_xref_functions": len(seeds),
        "recovery_modes_selected": modes,
        "edge_is_machine_call_verified": False,
        "edge_is_original_type_identification": False,
        "description": "C pseudocode named FUN_ addresses, preserving source original function ordinal and shard; not verified branch-reachable machine CALL edges",
    }
    (out / "callgraph_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    hotspot = {
        "source_pe_sha256": ORIGINAL_SHA256,
        "inbound_top": [
            {"rva": f"0x{rva:08x}", "unique_ghidra_c_callers": count,
             "original_pdata_start": rva in source_functions}
            for rva, count in inbound.most_common(80)
        ],
        "outbound_top": [
            {"rva": f"0x{rva:08x}", "unique_named_targets": count}
            for rva, count in outbound.most_common(80)
        ],
        "retail_string_candidate_neighborhoods": [
            {"rva": f"0x{seed:08x}", "incoming_ghidra_c": seed_inbound[seed][:300],
             "outgoing_ghidra_c": seed_outbound[seed][:300]}
            for seed in sorted(seeds)
        ],
        "verification": "discovery graph only, C symbol mentions not confirmed retail CALL instructions",
    }
    (out / "callgraph_hotspots.json").write_text(json.dumps(hotspot, indent=2) + "\n")
    print("FORTNITE541_ORIGINAL_GHIDRA_CALLGRAPH_COMPLETE", json.dumps(summary, sort_keys=True))
    return summary


def self_test():
    sample = ("void FUN_140001234(void)\n{\n"
              "FUN_140002222(); FUN_140002222(); thunk_FUN_140003333();\n"
              "(*((code *)(local_8)))();\n}\n")
    calls = source_calls(sample)
    assert calls == {0x2222: 2, 0x3333: 1}, calls
    assert not source_calls("void FUN_140001234(void) { return; }")
    assert not source_calls("int f(void) { FUN_7fff0000(); }")
    print("FORTNITE541_GHIDRA_C_CALLGRAPH_SELF_TEST_OK")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        if not args.root or not args.out:
            parser.error("--root and --out are required")
        extract(args.root, args.out)
