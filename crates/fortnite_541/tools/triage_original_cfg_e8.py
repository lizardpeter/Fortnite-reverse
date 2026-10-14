#!/usr/bin/env python3
"""Diagnose original source E8 call-target anomalies without relabeling C++.

Works only on SHA256-authenticated source CALL records and .pdata manifest
committed by independent decompilation workflows. No original binary copied.
"""
from __future__ import annotations
from collections import Counter, defaultdict
import argparse
import gzip
import json
from pathlib import Path
import struct

SOURCE_SHA256 = "7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"


def read_rows(path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def relative_bucket(n):
    distance = abs(n)
    if distance <= 128:
        return "up_to_128_bytes"
    if distance <= 4096:
        return "129_to_4096_bytes"
    if distance <= 1048576:
        return "4KiB_to_1MiB"
    if distance <= 16777216:
        return "1MiB_to_16MiB"
    if distance <= 268435456:
        return "16MiB_to_256MiB"
    return "over_256MiB"


def location_bucket(target, first, last):
    if target < first:
        return "below_first_original_pdata_entry"
    if target >= last:
        return "after_last_original_pdata_extent"
    return "inside_original_pdata_address_envelope"


def displacement_quantiles(values):
    if not values:
        return None
    xs = sorted(values)
    return {
        "min": xs[0],
        "p25": xs[(len(xs)-1)//4],
        "median": xs[(len(xs)-1)//2],
        "p75": xs[3*(len(xs)-1)//4],
        "max": xs[-1],
    }


def build(root, output):
    cfg = root / "discovery/recursive_calls"
    status = json.loads((cfg / "original_cfg_callgraph_status.json").read_text())
    if (status.get("original_source_sha256") != SOURCE_SHA256 or
        not status.get("complete_original_pdata_scan") or
        not status.get("independent_pdata_manifest_checked")):
        raise ValueError("Missing authenticated full original CFG evidence")
    count = 0
    first = last = None
    for entry in read_rows(root / "pdata_index.jsonl.gz"):
        if entry["index"] != count:
            raise ValueError("Duplicate/missing original unwind index")
        begin, end = int(entry["rva"], 16), int(entry["end_rva"], 16)
        if first is None:
            first = begin
        last = end if last is None else max(last, end)
        count += 1
    if count != status["original_pdata_functions"] or count != 291757:
        raise ValueError("Incomplete authenticated original .pdata manifest")

    source_edges = cfg / "original_cfg_source_verified_calls.jsonl.gz"
    totals = Counter()
    locations = defaultdict(Counter)
    displacement_bins = defaultdict(Counter)
    signed = defaultdict(Counter)
    distances = defaultdict(list)
    target_counts = defaultdict(Counter)
    examples = defaultdict(list)
    seen = set()

    for row in read_rows(source_edges):
        if row.get("source_original_pe_sha256") != SOURCE_SHA256:
            raise ValueError("Source CALL binary identity mismatch")
        ordinal, callsite = row["original_caller_index"], int(row["callsite_rva"], 16)
        target = int(row["target_rva"], 16)
        instruction = bytes.fromhex(row["instruction_hex"])
        if (len(instruction) != 5 or instruction[0] != 0xe8 or
            target != callsite+5+struct.unpack_from("<i", instruction, 1)[0]):
            raise ValueError("Forged original 5-byte E8 call witness")
        if (ordinal, callsite) in seen:
            raise ValueError("Repeated reachable original CALL site")
        seen.add((ordinal, callsite))
        kind = row["target_class"]
        delta = struct.unpack_from("<i", instruction, 1)[0]
        totals[kind] += 1
        locations[kind][location_bucket(target, first, last)] += 1
        displacement_bins[kind][relative_bucket(delta)] += 1
        signed[kind]["negative" if delta < 0 else "nonnegative"] += 1
        distances[kind].append(delta)
        target_counts[kind][target] += 1
        if len(examples[kind]) < 16:
            examples[kind].append({
                "original_caller_index": ordinal,
                "caller_rva": row["original_caller_rva"],
                "callsite_rva": row["callsite_rva"],
                "instruction_hex": row["instruction_hex"],
                "signed_rel32": delta,
                "original_target_rva": row["target_rva"],
                "original_pdata_target_index": row["target_original_index"],
            })
    total = sum(totals.values())
    if total != status["validated_original_e8_callgraph_rows"]:
        raise ValueError("Source evidence count disagrees with independent original CFG audit")
    expected = {
        "exact_original_pdata_entry": status["exact_original_pdata_entry_calls"],
        "interior_original_pdata_extent": status["interior_original_pdata_extent_calls"],
        "executable_nonpdata_target": status["executable_nonpdata_calls"],
        "nonexecutable_section_target": status["nonexecutable_section_calls"],
        "unmapped_target": status["unmapped_calls"],
    }
    if dict(totals) != {k: v for k, v in expected.items() if v}:
        raise ValueError("Original source target-class breakdown mismatch")
    result = {
        "schema_version": 1,
        "original_source_sha256": SOURCE_SHA256,
        "original_pdata_entries": count,
        "original_pdata_address_envelope": {"first_rva": hex(first), "last_end_rva": hex(last)},
        "source_verified_e8_edges": total,
        "class_totals": expected,
        "target_location_by_class": {k: dict(v) for k, v in locations.items()},
        "relative_distance_bins_by_class": {k: dict(v) for k, v in displacement_bins.items()},
        "rel32_direction_by_class": {k: dict(v) for k, v in signed.items()},
        "signed_rel32_quantiles_by_class": {k: displacement_quantiles(v) for k, v in distances.items()},
        "most_frequent_target_rvas_by_class": {
            k: [{"target_rva": hex(addr), "count": n} for addr, n in freq.most_common(12)]
            for k, freq in target_counts.items()
        },
        "example_source_reachable_calls_by_class": dict(examples),
        "notes": [
            "Source-authenticated conservative CFG E8 instructions; not all control flow or all native calls.",
            "The original .pdata address envelope is not the PE executable mapping and cannot alone prove valid code.",
            "A target in a non-executable section or unmapped RVA is not a confirmed original function.",
            "No original C++ source/linkage, symbol identities or shader semantics are inferred.",
        ],
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "original_e8_displacement_triage.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n"
    )
    print("ORIGINAL_FORTNITE_SOURCE_CFG_E8_TRIAGE", json.dumps({
        "validated_edges": total, "class_totals": expected,
        "unmapped_locations": result["target_location_by_class"].get("unmapped_target", {}),
    }, sort_keys=True))
    return result


def self_test():
    assert relative_bucket(-128) == "up_to_128_bytes"
    assert relative_bucket(4097) == "4KiB_to_1MiB"
    assert location_bucket(9, 10, 30) == "below_first_original_pdata_entry"
    assert location_bucket(30, 10, 30) == "after_last_original_pdata_extent"
    assert location_bucket(20, 10, 30) == "inside_original_pdata_address_envelope"
    assert displacement_quantiles([1, 2, 3, 4, 5])["median"] == 3
    print("FORTNITE541_REAL_E8_TARGET_DIAGNOSTIC_TESTS_PASSED")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        self_test()
    else:
        if a.root is None or a.out is None:
            ap.error("--root and --out required")
        build(a.root, a.out)
