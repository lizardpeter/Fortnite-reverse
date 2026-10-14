#!/usr/bin/env python3
"""Cross-link authenticated CFG-reachable original E8 calls to genuine Ghidra C.

This is an evidence JOIN only: generated Ghidra names are not original UE4
symbols, and E8 call relationships are not compiled/link-verified C++.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import gzip
import json
from pathlib import Path

ORIGINAL_TOTAL = 291757
SOURCE_SHA256 = "7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"
CLASSES = {
    "exact_original_pdata_entry",
    "interior_original_pdata_extent",
    "executable_nonpdata_target",
    "nonexecutable_section_target",
    "unmapped_target",
}


def read_rows(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def validate_edge_against_index(edge: dict, lookups: dict[int, dict]) -> dict:
    caller_index = edge["original_caller_index"]
    source = lookups.get(caller_index)
    if source is None or source["rva"] != edge["original_caller_rva"]:
        raise ValueError("Original CFG CALL caller ordinal/RVA not in authentic C lookup")
    if edge["source_original_pe_sha256"] != SOURCE_SHA256:
        raise ValueError("Unverified original retail source identity")
    target_index = edge["target_original_index"]
    category = edge["target_class"]
    if category not in CLASSES:
        raise ValueError("Unknown original CFG target class")
    target = int(edge["target_rva"], 16)
    linked = lookups.get(target_index) if target_index is not None else None
    if category in {"exact_original_pdata_entry", "interior_original_pdata_extent"}:
        if linked is None:
            raise ValueError("Source CFG pointed to missing .pdata target ordinal")
        begin, end = int(linked["rva"], 16), int(linked["end_rva"], 16)
        if edge["target_original_begin_rva"] != linked["rva"] or not begin <= target < end:
            raise ValueError("Source CFG destination does not fit the actual .pdata extent")
        exact = target == begin
        if exact != (category == "exact_original_pdata_entry") or exact != edge["exact_original_entry"]:
            raise ValueError("False claimed original function entrypoint")
    else:
        if linked is not None or edge["exact_original_entry"]:
            raise ValueError("Target beyond .pdata must not be assigned an original function")
    return {
        "original_caller_index": caller_index,
        "original_caller_rva": source["rva"],
        "original_caller_ghidra_name": source["name"],
        "original_caller_c_status": source["status"],
        "original_caller_c_sha256": source["c_sha256"],
        "original_caller_c_source_shard": source["source_shard"],
        "callsite_rva": edge["callsite_rva"],
        "original_e8_machine_bytes": edge["instruction_hex"],
        "target_rva": edge["target_rva"],
        "target_class": category,
        "target_original_index": target_index,
        "target_original_start_rva": linked["rva"] if linked else None,
        "target_original_ghidra_name": linked["name"] if linked else None,
        "target_original_c_status": linked["status"] if linked else None,
        "target_original_c_sha256": linked["c_sha256"] if linked else None,
        "target_original_c_source_shard": linked["source_shard"] if linked else None,
        "target_has_ghidra_c": bool(linked and linked["status"] == "decompiled" and linked["c_sha256"]),
        "evidence": "original_sha256_cfg_reachable_e8_plus_audited_ghidra_c_index",
        "function_names_are_original": False,
        "retail_call_is_cpp_linkage_verified": False,
    }


def build(root: Path, output: Path) -> dict:
    report_file = root / "discovery/recursive_calls/original_cfg_callgraph_status.json"
    report = json.loads(report_file.read_text())
    callgraph = root / "discovery/recursive_calls/original_cfg_source_verified_calls.jsonl.gz"
    source_index = root / "index/original_function_lookup.jsonl.gz"
    source_report = json.loads((root / "index/material_shader_candidates.json").read_text())
    if (report.get("original_source_sha256") != SOURCE_SHA256 or
        source_report.get("original_pe_sha256") != SOURCE_SHA256 or
        report.get("original_pdata_functions") != ORIGINAL_TOTAL or
        source_report.get("original_pdata_functions") != ORIGINAL_TOTAL or
        not report.get("complete_original_pdata_scan") or
        not report.get("independent_pdata_manifest_checked")):
        raise ValueError("Missing complete original source-verified CFG and C index")
    rows = list(read_rows(callgraph))
    if len(rows) != report.get("validated_original_e8_callgraph_rows"):
        raise ValueError("CFG callgraph source ledger count does not match audited status")
    needed = {
        idx for row in rows for idx in
        [row["original_caller_index"], row["target_original_index"]]
        if idx is not None
    }
    lookups = {}
    count, decompiled = 0, 0
    for item in read_rows(source_index):
        if item["index"] != count:
            raise ValueError("Original Ghidra function lookup has wrong ordinal order")
        count += 1
        if item["status"] == "decompiled" and item["c_sha256"]:
            decompiled += 1
        if item["index"] in needed:
            lookups[item["index"]] = item
    if (count != ORIGINAL_TOTAL or
        decompiled != source_report["real_decompiled_c"] or
        len(lookups) != len(needed)):
        raise ValueError("Missing original source C references / mismatched coverage")
    output.mkdir(parents=True, exist_ok=True)
    counts = Counter()
    targets = defaultdict(lambda: {"calls": 0, "callers": set(), "target_class": None})
    prior = (-1, -1)
    with gzip.open(output / "original_e8_cfg_c_crosslinks.jsonl.gz",
                   "wt", encoding="utf-8", compresslevel=9) as sink:
        for edge in rows:
            witness = (edge["original_caller_index"], int(edge["callsite_rva"], 16))
            if witness <= prior:
                raise ValueError("Unsorted or duplicate original source CFG CALL witnesses")
            prior = witness
            merged = validate_edge_against_index(edge, lookups)
            counts[edge["target_class"]] += 1
            counts["all"] += 1
            counts["caller_with_c"] += int(bool(merged["original_caller_c_sha256"]))
            counts["target_with_c"] += int(merged["target_has_ghidra_c"])
            if edge["target_original_index"] is not None:
                target_key = edge["target_original_index"]
                target = targets[target_key]
                target["calls"] += 1
                target["callers"].add(edge["original_caller_index"])
                target["target_class"] = edge["target_class"]
            sink.write(json.dumps(merged, separators=(",", ":"), sort_keys=True) + "\n")
    for label, field in (
        ("exact_original_pdata_entry", "exact_original_pdata_entry_calls"),
        ("interior_original_pdata_extent", "interior_original_pdata_extent_calls"),
        ("executable_nonpdata_target", "executable_nonpdata_calls"),
        ("nonexecutable_section_target", "nonexecutable_section_calls"),
        ("unmapped_target", "unmapped_calls"),
    ):
        if counts[label] != report[field]:
            raise ValueError("Original CFG source class count disagrees with independent auditor")
    hotspots = sorted(targets.items(), key=lambda row: (-row[1]["calls"], row[0]))
    (output / "original_cfg_c_target_neighborhoods.json").write_text(json.dumps({
        "source_original_pe_sha256": SOURCE_SHA256,
        "rankings_are_not_original_unreal_symbol_identifications": True,
        "pdata_targets": [
            {
                "original_target_index": ix,
                "original_target_rva": lookups[ix]["rva"],
                "target_ghidra_c_sha256": lookups[ix]["c_sha256"],
                "target_ghidra_c_shard": lookups[ix]["source_shard"],
                "target_ghidra_name": lookups[ix]["name"],
                "target_class": info["target_class"],
                "validated_original_e8_calls": info["calls"],
                "distinct_original_callers": len(info["callers"]),
            } for ix, info in hotspots
        ],
    }, sort_keys=True, indent=2) + "\n")
    summary = {
        "source_original_pe_sha256": SOURCE_SHA256,
        "original_pdata_functions": ORIGINAL_TOTAL,
        "verified_ghidra_c_bodies": decompiled,
        "source_verified_cfg_e8_calls": counts["all"],
        "callers_with_ghidra_c": counts["caller_with_c"],
        "targets_with_ghidra_c": counts["target_with_c"],
        "target_classes": {k: counts[k] for k in sorted(CLASSES)},
        "unique_indexed_target_owners": len(targets),
        "evidence": "original_cfg_reachable_e8_and_original_C_pseudocode_crossref",
        "native_cpp_linkage_verified": False,
        "unreal_function_identification_verified": False,
    }
    (output / "original_cfg_c_crosslink_summary.json").write_text(json.dumps(
        summary, sort_keys=True, indent=2
    ) + "\n")
    print("FORTNITE541_SOURCE_CFG_GHIDRA_C_CROSSLINK_OK", json.dumps(summary, sort_keys=True))
    return summary


def self_test():
    one = {
        "index": 5, "rva": "0x00001000", "end_rva": "0x00001020",
        "name": "FUN_140001000", "status": "decompiled",
        "c_sha256": "123456", "source_shard": "functions/test.jsonl.gz",
    }
    other = dict(one, index=6, rva="0x00001020", end_rva="0x00001040")
    source = {
        "source_original_pe_sha256": SOURCE_SHA256,
        "original_caller_index": 5, "original_caller_rva": "0x00001000",
        "callsite_rva": "0x00001004", "instruction_hex": "e817000000",
        "target_rva": "0x00001020", "target_class": "exact_original_pdata_entry",
        "target_original_index": 6,
        "target_original_begin_rva": "0x00001020", "exact_original_entry": True,
    }
    checked = validate_edge_against_index(source, {5: one, 6: other})
    assert checked["target_has_ghidra_c"] and checked["target_original_index"] == 6
    invalid = dict(source, target_class="interior_original_pdata_extent")
    try:
        validate_edge_against_index(invalid, {5: one, 6: other})
    except ValueError:
        pass
    else:
        raise AssertionError("False interior function relationship was accepted")
    outside = dict(source, target_original_index=None, target_original_begin_rva=None,
                   target_class="executable_nonpdata_target", exact_original_entry=False)
    checked = validate_edge_against_index(outside, {5: one})
    assert checked["target_original_index"] is None and not checked["target_has_ghidra_c"]
    print("FORTNITE541_CROSSLINK_STRICT_ORIGINAL_RVA_TESTS_PASSED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        if args.root is None or args.output is None:
            parser.error("--root and --output required")
        build(args.root, args.output)
