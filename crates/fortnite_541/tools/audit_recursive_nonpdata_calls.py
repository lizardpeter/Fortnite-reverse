#!/usr/bin/env python3
"""Independent integrity and coverage audit of original reachable E8 CALLs.

Input shards were recovered from the SHA256-authenticated retail executable.
This auditor verifies original witnesses directly from E8 rel32 machine bytes,
source index boundaries, no duplicate shards, source identity, and reporting.
It does not treat any target as a confirmed compiled original C++ function.
"""
from __future__ import annotations
from collections import Counter
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


def audit(root: Path, known_source: Path | None = None,
          complete: bool = False, save: bool = True) -> dict:
    report_dir = root / "reports"
    reports = sorted(report_dir.glob("recursive_calls_*.json"))
    if not reports:
        raise ValueError("No source-authenticated Ghidra/Capstone CALL reports")
    all_ranges = []
    total = Counter()
    found: dict[str, dict] = {}
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
    }
    if save:
        (root / "recursive_call_status.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
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
            "unique_nonpdata_call_targets_in_shard": 1
        }
        (root / "reports" / (name + ".json")).write_text(json.dumps(report))
        filename = root / "records" / (name + ".jsonl.gz")
        with gzip.open(filename, "wt") as out:
            out.write(json.dumps(entry) + "\n")
        result = audit(root)
        assert result["unique_source_verified_unindexed_targets"] == 1, result
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
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        print(json.dumps(audit(args.root, args.known, args.complete), sort_keys=True))
