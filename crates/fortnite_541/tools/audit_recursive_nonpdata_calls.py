#!/usr/bin/env python3
"""Independent integrity and coverage audit of original reachable E8 CALLs.

Input shards were recovered from the SHA256-authenticated retail executable.
This auditor verifies original witnesses directly from E8 rel32 machine bytes,
source index boundaries, no duplicate shards, source identity, and reporting.
It does not treat any target as a confirmed compiled original C++ function.
"""
from __future__ import annotations
from collections import Counter
from bisect import bisect_right
import argparse
import gzip
import json
from pathlib import Path
import struct

ORIGINAL_COUNT = 291757
SOURCE_SHA256 = "7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"


def records(path: Path) -> list[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return [json.loads(x) for x in stream if x.strip()]


def parse_source_pdata_manifest(path: Path) -> tuple[list[dict], list[int], list[int], list[int]]:
    pdata = records(path)
    if len(pdata) != ORIGINAL_COUNT:
        raise ValueError("Original .pdata manifest count mismatch")
    starts, maxima, owners = [], [], []
    high, owner = 0, -1
    for index, item in enumerate(pdata):
        if item["index"] != index:
            raise ValueError("Original .pdata manifest ordinal mismatch")
        begin, end = int(item["rva"], 16), int(item["end_rva"], 16)
        if begin >= end or (starts and begin <= starts[-1]):
            raise ValueError("Original .pdata manifest not ordered or invalid")
        if end > high:
            high, owner = end, index
        starts.append(begin)
        maxima.append(high)
        owners.append(owner)
    return pdata, starts, maxima, owners


def audit(root: Path, known_source: Path | None = None,
          complete: bool = False, save: bool = True,
          pdata_manifest: Path | None = None) -> dict:
    report_dir = root / "reports"
    reports = sorted(report_dir.glob("recursive_calls_*.json"))
    if not reports:
        raise ValueError("No source-authenticated Ghidra/Capstone CALL reports")
    if complete and pdata_manifest is None:
        raise ValueError("A complete callgraph audit requires the original .pdata manifest")
    pdata = starts = maxima = owners = None
    if pdata_manifest is not None:
        pdata, starts, maxima, owners = parse_source_pdata_manifest(pdata_manifest)
    all_ranges = []
    total = Counter()
    found: dict[str, dict] = {}
    all_source_calls: list[dict] = []
    unique_callsites: set[tuple[int, int]] = set()
    for p in reports:
        report = json.loads(p.read_text(encoding="utf-8"))
        start = report["start_original_index"]
        end = report["end_original_index_exclusive"]
        if (not isinstance(start, int) or not isinstance(end, int)
            or not 0 <= start < end <= ORIGINAL_COUNT
            or report["source_sha256"] != SOURCE_SHA256
            or report["original_pdata_function_count"] != ORIGINAL_COUNT):
            raise ValueError(f"Source report identity or ordinal invalid: {p}")
        if (end - start != report["visited_original_functions"] +
            report.get("nonexecutable_origins", 0)):
            raise ValueError(f"Skipped original entries in source report: {p}")
        filename = p.name[:-len(".json")] + ".jsonl.gz"
        if report["record_file"] != filename:
            raise ValueError(f"Source report/record name mismatch: {p}")
        datafile = root / "records" / filename
        if not datafile.is_file():
            raise ValueError(f"Missing actual original source evidence: {datafile}")
        # Preserve ALL validated source-reachable E8 calls, not just
        # the special-case call destinations outside original .pdata.
        calls_name = p.name.replace("recursive_calls_", "verified_e8_calls_").replace(".json", ".jsonl.gz")
        if report.get("validated_e8_callgraph_file") != calls_name:
            raise ValueError("Callgraph report/file name mismatch")
        source_calls_path = root / "records" / calls_name
        if not source_calls_path.is_file():
            raise ValueError(f"Missing original CFG callgraph shard: {source_calls_path}")
        call_rows = records(source_calls_path)
        if (len(call_rows) != report.get("validated_e8_callgraph_rows") or
            len(call_rows) != report.get("verified_e8_rel32_edges", 0)):
            raise ValueError("Original CFG validated E8 rows disagree with source report")
        classifications = Counter()
        for edge in call_rows:
            if (edge.get("evidence_level") != "source_authenticated_cfg_reachable_e8_rel32"
                or edge.get("source_original_pe_sha256") != SOURCE_SHA256):
                raise ValueError("Unsupported callgraph evidence class or original PE identity")
            idx = edge.get("original_caller_index")
            if not isinstance(idx, int) or not start <= idx < end:
                raise ValueError("Original callgraph caller ordinal outside claimed shard")
            caller = int(edge["original_caller_rva"], 16)
            callsite = int(edge["callsite_rva"], 16)
            target = int(edge["target_rva"], 16)
            raw = bytes.fromhex(edge["instruction_hex"])
            if (len(raw) != 5 or raw[0] != 0xe8 or
                callsite + 5 + struct.unpack_from("<i", raw, 1)[0] != target):
                raise ValueError("Original CFG callgraph contains forged E8 rel32 bytes")
            key = (idx, callsite)
            if key in unique_callsites:
                raise ValueError("Repeated original E8 CALL instruction witness")
            unique_callsites.add(key)
            classification = edge["target_class"]
            if classification not in {
                    "exact_original_pdata_entry", "interior_original_pdata_extent",
                    "executable_nonpdata_target", "nonexecutable_section_target",
                    "unmapped_target",
                }:
                raise ValueError("Unknown original call target classification")
            if pdata is not None:
                if caller != int(pdata[idx]["rva"], 16):
                    raise ValueError("Original caller RVA mismatches source .pdata manifest")
                j = bisect_right(starts, target) - 1
                covered = j >= 0 and maxima[j] > target
                exact = covered and starts[j] == target
                if covered:
                    expected_class = ("exact_original_pdata_entry" if exact
                                      else "interior_original_pdata_extent")
                    owner = j if exact else owners[j]
                    if (edge["target_original_index"] != owner or
                        int(edge["target_original_begin_rva"], 16) != starts[owner] or
                        edge["exact_original_entry"] != exact):
                        raise ValueError("False original function-entry or interior classification")
                else:
                    expected_class = None
                    if edge["target_original_index"] is not None or edge["exact_original_entry"]:
                        raise ValueError("Unindexed original call was misclassified as indexed")
                if expected_class is not None and classification != expected_class:
                    raise ValueError("Original callgraph .pdata boundary contradiction")
                if expected_class is None and classification in {
                        "exact_original_pdata_entry", "interior_original_pdata_extent"}:
                    raise ValueError("Unindexed target falsely classified as .pdata")
            classifications[classification] += 1
        if (classifications["exact_original_pdata_entry"] +
            classifications["interior_original_pdata_extent"] !=
            report.get("call_edges_to_indexed_functions", 0)):
            raise ValueError("Original .pdata direct-call count contradicts CFG source")
        if classifications["executable_nonpdata_target"] != report.get(
                "unindexed_executable_call_edges", 0):
            raise ValueError("Original executable non-pdata source calls disagree")
        if (classifications["nonexecutable_section_target"] +
            classifications["unmapped_target"] != report.get(
                "call_edges_to_nonexecutable", 0)):
            raise ValueError("Original nonexecutable CALL classifications disagree")
        for kind, n in classifications.items():
            total["target_" + kind] += n
        total["validated_original_e8_callgraph_rows"] += len(call_rows)
        all_source_calls.extend(call_rows)
        entries = records(datafile)
        if len(entries) != report["unique_nonpdata_call_targets_in_shard"]:
            raise ValueError("Wrong source target count")
        if len({x["target_rva"] for x in entries}) != len(entries):
            raise ValueError("Duplicate original targets within shard")
        if sum(x["direct_call_edges"] for x in entries) != report.get("unindexed_executable_call_edges", 0):
            raise ValueError("Source CALL edge count inconsistent with actual records")
        for item in entries:
            target = item["target_rva"]
            if item["source_original_pe_sha256"] != SOURCE_SHA256:
                raise ValueError("Original executable identity mismatch")
            if not target.startswith("0x") or not item["direct_call_edges"] > 0:
                raise ValueError("Missing source target identity")
            target_int = int(target, 16)
            witnesses = item["callsite_witnesses"]
            if not witnesses or len(witnesses) > 16:
                raise ValueError("Original CALL candidate has no source instruction witnesses")
            for w in witnesses:
                index = w["original_caller_index"]
                callsite = int(w["callsite_rva"], 16)
                raw = bytes.fromhex(w["instruction_hex"])
                if not start <= index < end:
                    raise ValueError("CALL witness caller outside assigned original .pdata shard")
                if (len(raw) != 5 or raw[0] != 0xe8 or
                    callsite + 5 + struct.unpack_from("<i", raw, 1)[0] != target_int or
                    w["target_rva"] != target):
                    raise ValueError("Forged or invalid original source E8 rel32 witness")
            original = found.get(target)
            if original is None:
                found[target] = {
                    "target_rva": target,
                    "direct_call_edges": item["direct_call_edges"],
                    "sample_witnesses": witnesses[:16],
                    "source_original_pe_sha256": SOURCE_SHA256,
                }
            else:
                original["direct_call_edges"] += item["direct_call_edges"]
                slots = 16 - len(original["sample_witnesses"])
                if slots:
                    original["sample_witnesses"].extend(witnesses[:slots])
        total["original_function_entries_scanned"] += end - start
        total["source_verified_call_edges"] += report.get("unindexed_executable_call_edges", 0)
        total["reachable_instructions"] += report.get("reachable_instructions", 0)
        total["reachable_machine_bytes"] += report.get("reachable_machine_bytes", 0)
        all_ranges.append((start, end))
    all_ranges.sort()
    for i in range(1, len(all_ranges)):
        if all_ranges[i - 1][1] > all_ranges[i][0]:
            raise ValueError("Overlapping original .pdata ordinal shards")
    if complete and (all_ranges[0][0] != 0 or all_ranges[-1][1] != ORIGINAL_COUNT or
                     any(a[1] != b[0] for a, b in zip(all_ranges, all_ranges[1:]))):
        raise ValueError("Incomplete original 291757-function scan claimed complete")
    known = set()
    if known_source is not None:
        known = {r["target_rva"] for r in records(known_source)}
    new = sorted(set(found) - known)
    result = {
        "schema_version": 1,
        "original_source_sha256": SOURCE_SHA256,
        "original_pdata_functions": ORIGINAL_COUNT,
        "source_shard_count": len(reports),
        "scanned_original_pdata_entries": total["original_function_entries_scanned"],
        "complete_original_pdata_scan": bool(
            all_ranges[0][0] == 0 and all_ranges[-1][1] == ORIGINAL_COUNT and
            all(a[1] == b[0] for a, b in zip(all_ranges, all_ranges[1:]))
        ),
        "reachable_instructions": total["reachable_instructions"],
        "reachable_machine_bytes": total["reachable_machine_bytes"],
        "source_verified_unindexed_call_edges": total["source_verified_call_edges"],
        "unique_source_verified_unindexed_targets": len(found),
        "previously_known_ghidra_direct_call_targets": len(known),
        "previously_unseen_targets": len(new),
        "new_targets_are_candidates_not_original_C": True,
        "validated_original_e8_callgraph_rows": total["validated_original_e8_callgraph_rows"],
        "exact_original_pdata_entry_calls": total["target_exact_original_pdata_entry"],
        "interior_original_pdata_extent_calls": total["target_interior_original_pdata_extent"],
        "executable_nonpdata_calls": total["target_executable_nonpdata_target"],
        "nonexecutable_section_calls": total["target_nonexecutable_section_target"],
        "unmapped_calls": total["target_unmapped_target"],
        "independent_pdata_manifest_checked": pdata_manifest is not None,
        "source_x64_e8_is_control_flow_reachable": True,
        "original_cpp_linkage_verified": False,
    }
    if save:
        (root / "recursive_call_status.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (root / "original_cfg_callgraph_status.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with gzip.open(root / "original_cfg_source_verified_calls.jsonl.gz",
                       "wt", encoding="utf-8", compresslevel=9) as graph:
            for entry in sorted(all_source_calls,
                                key=lambda x: (x["original_caller_index"],
                                               int(x["callsite_rva"], 16))):
                graph.write(json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n")
        with gzip.open(root / "recursive_call_targets.jsonl.gz", "wt", encoding="utf-8") as out:
            for target in sorted(found):
                item = found[target]
                item["known_ghidra_candidate"] = target in known
                out.write(json.dumps(item, separators=(",", ":")) + "\n")
    return result


def self_test() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "reports").mkdir()
        (root / "records").mkdir()
        entry = {
            "target_rva": "0x00000110",
            "direct_call_edges": 1,
            "source_original_pe_sha256": SOURCE_SHA256,
            "callsite_witnesses": [{
                "original_caller_index": 1, "callsite_rva": "0x00000100",
                "target_rva": "0x00000110", "instruction_hex": "e80b000000"
            }],
        }
        name = "recursive_calls_000001_000002"
        report = {
            "source_sha256": SOURCE_SHA256, "original_pdata_function_count": ORIGINAL_COUNT,
            "start_original_index": 1, "end_original_index_exclusive": 2,
            "visited_original_functions": 1, "record_file": name + ".jsonl.gz",
            "unindexed_executable_call_edges": 1,
            "unique_nonpdata_call_targets_in_shard": 1,
            "validated_e8_callgraph_file": "verified_e8_calls_000001_000002.jsonl.gz",
            "validated_e8_callgraph_rows": 1,
            "verified_e8_rel32_edges": 1,
            "call_edges_to_indexed_functions": 0,
            "call_edges_to_nonexecutable": 0,
        }
        (root / "reports" / (name + ".json")).write_text(json.dumps(report))
        filename = root / "records" / (name + ".jsonl.gz")
        with gzip.open(filename, "wt") as out:
            out.write(json.dumps(entry) + "\n")
        with gzip.open(root / "records" / "verified_e8_calls_000001_000002.jsonl.gz", "wt") as out:
            out.write(json.dumps({
                "source_original_pe_sha256": SOURCE_SHA256,
                "original_caller_index": 1,
                "original_caller_rva": "0x00000100",
                "callsite_rva": "0x00000100",
                "instruction_hex": "e80b000000",
                "target_rva": "0x00000110",
                "target_class": "executable_nonpdata_target",
                "target_original_index": None,
                "target_original_begin_rva": None,
                "exact_original_entry": False,
                "target_section": ".text",
                "evidence_level": "source_authenticated_cfg_reachable_e8_rel32",
            }) + "\n")
        result = audit(root)
        assert result["unique_source_verified_unindexed_targets"] == 1, result
        assert result["validated_original_e8_callgraph_rows"] == 1, result
        assert not result["complete_original_pdata_scan"]
        entry["callsite_witnesses"][0]["instruction_hex"] = "e80c000000"
        with gzip.open(filename, "wt") as out:
            out.write(json.dumps(entry) + "\n")
        try:
            audit(root, save=False)
        except ValueError as exc:
            assert "E8 rel32" in str(exc)
        else:
            raise AssertionError("Forged source E8 instruction was admitted")
    print("FORTNITE541_REACHABLE_E8_CALL_AUDIT_TESTS_PASSED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("decompilation/fortnite541/discovery/recursive_calls"))
    parser.add_argument("--known", type=Path)
    parser.add_argument("--complete", action="store_true")
    parser.add_argument("--pdata-manifest", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        print(json.dumps(audit(args.root, args.known, args.complete,
                               pdata_manifest=args.pdata_manifest), sort_keys=True))
