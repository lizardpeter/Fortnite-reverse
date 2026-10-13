#!/usr/bin/env python3
"""Verify real non-.pdata direct-call function C against original source witnesses."""
from __future__ import annotations
import argparse
from collections import Counter
import gzip
import json
from pathlib import Path


def rows_gz(path: Path) -> list[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def audit(root: Path, save: bool = True) -> dict:
    source = rows_gz(root / "discovery" / "nonpdata_direct_calls.jsonl.gz")
    if len(source) != 58:
        raise ValueError("Original source direct CALL evidence inventory is not 58")
    source_by_i = {i: row for i, row in enumerate(source)}
    recovered: dict[int, dict] = {}
    seen: set[int] = set()
    counts: Counter = Counter()
    base = root / "discovery" / "nonpdata_recovery"
    files = sorted((base / "records").glob("direct_calls_*.jsonl.gz"))
    if not files:
        raise ValueError("No source-verified real nonpdata native function results")
    for path in files:
        report_file = base / "reports" / (path.name[:-len(".jsonl.gz")] + ".json")
        report = json.loads(report_file.read_text(encoding="utf-8"))
        records = rows_gz(path)
        if not records:
            raise ValueError("Empty nonpdata original function decompiler shard")
        if report["source_direct_call_targets"] != 58:
            raise ValueError("Original call evidence inventory changed")
        if report["batch_start"] != records[0]["index"]:
            raise ValueError("Wrong initial original CALL target ordinal")
        if report["batch_end_exclusive"] != records[-1]["index"] + 1:
            raise ValueError("Wrong final original CALL target ordinal")
        if report["attempted"] != len(records):
            raise ValueError("Original Ghidra decompiler shard wrong count")
        subset = Counter()
        for row in records:
            index = row["index"]
            if index not in source_by_i or index in seen:
                raise ValueError(f"Invalid or duplicate source CALL target index {index}")
            seen.add(index)
            source_row = source_by_i[index]
            if (row["rva"] != source_row["target_rva"] or
                row["callsite_rva"] != source_row["first_callsite_rva"] or
                row["original_direct_calls"] != source_row["direct_calls"]):
                raise ValueError("Original executable source CALL witness mismatch")
            status = row["status"]
            if status not in ("decompiled", "decompiler_failed",
                              "missing_function", "invalid_witness"):
                raise ValueError(f"Unknown source decompilation outcome {status}")
            if status == "decompiled":
                if not row["witness_valid"] or not isinstance(row.get("c"), str) or not row["c"].strip():
                    raise ValueError("False claim of source-authenticated decompiled C")
                recovered[index] = row
            elif status == "invalid_witness" and row["witness_valid"]:
                raise ValueError("Invalid original CALL witness is marked valid")
            elif status != "invalid_witness" and not row["witness_valid"]:
                raise ValueError("Missing original CALL witness in Ghidra function record")
            subset[status] += 1
            counts[status] += 1
        for field in ("decompiled", "decompiler_failed", "missing_function", "invalid_witness"):
            if report[field] != subset[field]:
                raise ValueError(f"Original source report does not match actual {field} rows")
    result = {
        "schema_version": 1,
        "source_original_call_targets": len(source),
        "original_call_edges": sum(r["direct_calls"] for r in source),
        "attempted": len(seen),
        "genuine_c_pseudocode_functions": len(recovered),
        "not_yet_processed": len(source) - len(seen),
        "decompiler_failed": counts["decompiler_failed"],
        "missing_function": counts["missing_function"],
        "invalid_original_call_witness": counts["invalid_witness"],
        "separate_from_original_pdata_coverage": True,
    }
    if save:
        (base / "nonpdata_recovery_status.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        with gzip.open(base / "nonpdata_recovery_remaining.jsonl.gz", "wt") as out:
            for index, row in enumerate(source):
                if index not in recovered:
                    out.write(json.dumps({"index": index, **row}, separators=(",", ":")) + "\n")
    return result


def self_test() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        discovery = root / "discovery"
        (discovery / "nonpdata_recovery" / "records").mkdir(parents=True)
        (discovery / "nonpdata_recovery" / "reports").mkdir()
        source = [{"target_rva": f"0x{i*8:08x}",
                   "first_callsite_rva": f"0x{i*8+1:08x}",
                   "direct_calls": 1} for i in range(58)]
        with gzip.open(discovery / "nonpdata_direct_calls.jsonl.gz", "wt") as out:
            for row in source:
                out.write(json.dumps(row) + "\n")
        good = {"index": 0, "rva": source[0]["target_rva"],
                "callsite_rva": source[0]["first_callsite_rva"],
                "original_direct_calls": 1, "witness_valid": True,
                "status": "decompiled", "c": "void f(void) {}"}
        result_file = discovery / "nonpdata_recovery" / "records" / "direct_calls_000_000.jsonl.gz"
        with gzip.open(result_file, "wt") as out:
            out.write(json.dumps(good) + "\n")
        report_file = result_file.parent.parent / "reports" / "direct_calls_000_000.json"
        report_file.write_text(json.dumps({
            "source_direct_call_targets": 58, "batch_start": 0, "batch_end_exclusive": 1,
            "attempted": 1, "decompiled": 1, "decompiler_failed": 0,
            "missing_function": 0, "invalid_witness": 0,
        }))
        result = audit(root)
        assert result["genuine_c_pseudocode_functions"] == 1
        assert result["not_yet_processed"] == 57
        good["rva"] = "0xdeadbeef"
        with gzip.open(result_file, "wt") as out:
            out.write(json.dumps(good) + "\n")
        try:
            audit(root, save=False)
        except ValueError as e:
            assert "mismatch" in str(e)
        else:
            raise AssertionError("Forged original call target was admitted")
    print("NONPDATA_ORIGINAL_GHIDRA_RECOVERY_AUDIT_TESTS_PASSED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("decompilation/fortnite541"))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    print(json.dumps((self_test() if args.self_test else audit(args.root)), sort_keys=True))
