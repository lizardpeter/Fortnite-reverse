#!/usr/bin/env python3
"""Independent source/RVA audit of Ghidra C for newly discovered retail calls."""
from __future__ import annotations
import argparse
import gzip
import json
from pathlib import Path


def read_gz(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def audit(root: Path, save: bool = True) -> dict:
    source = read_gz(root / "recursive_call_targets.jsonl.gz")
    unseen = [r for r in source if not r["known_ghidra_candidate"]]
    if len(unseen) != 3:
        raise ValueError("Wrong source-verified new original CALL inventory")
    recovered_dir = root / "new_original_C"
    records_path = recovered_dir / "records" / "recursive_calls_000_002.jsonl.gz"
    report_path = recovered_dir / "reports" / "recursive_calls_000_002.json"
    records = read_gz(records_path)
    report = json.loads(report_path.read_text())
    if len(records) != 3 or report["attempted"] != 3 or report["source_direct_call_targets"] != 3:
        raise ValueError("Incorrect actual original C reconstruction count")
    counts = {k: 0 for k in ("decompiled", "decompiler_failed", "missing_function", "invalid_witness")}
    seen = set()
    for row in records:
        index = row["index"]
        if not isinstance(index, int) or index in seen or not 0 <= index < 3:
            raise ValueError("Duplicate/invalid candidate original-source ordinal")
        seen.add(index)
        original = unseen[index]
        if (row["rva"] != original["target_rva"] or
            row["callsite_rva"] != original["sample_witnesses"][0]["callsite_rva"] or
            row["original_direct_calls"] != original["direct_call_edges"]):
            raise ValueError("Original CALL target/caller RVA forged or mismatched")
        status = row["status"]
        if status not in counts:
            raise ValueError("Unrecognized Ghidra result status")
        if status == "decompiled":
            if not row["witness_valid"] or not isinstance(row["c"], str) or not row["c"].strip():
                raise ValueError("Nonempty original C pseudocode/witness required")
        elif status == "invalid_witness":
            if row["witness_valid"]:
                raise ValueError("Invalid call witness marked valid")
        elif not row["witness_valid"]:
            raise ValueError("Missing original CALL witness cannot be a Ghidra function")
        counts[status] += 1
    for field, value in counts.items():
        if report[field] != value:
            raise ValueError(f"Independent actual Ghidra {field} report mismatch")
    result = {
        "schema_version": 1,
        "source_new_original_direct_call_targets": 3,
        "actually_attempted": len(records),
        "genuine_additional_C_pseudocode": counts["decompiled"],
        "missing_function": counts["missing_function"],
        "decompiler_failed": counts["decompiler_failed"],
        "invalid_source_call_witness": counts["invalid_witness"],
        "separate_from_original_pdata_decompilation": True,
        "separate_from_previous_57_extra_C_bodies": True,
    }
    if save:
        (recovered_dir / "new_original_C_status.json").write_text(
            json.dumps(result, sort_keys=True, indent=2) + "\n"
        )
    return result


def self_test() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        data = root / "new_original_C"
        (data / "records").mkdir(parents=True)
        (data / "reports").mkdir()
        targets = []
        attempted = []
        for i in range(3):
            targets.append({
                "target_rva": f"0x{i+100:08x}",
                "known_ghidra_candidate": False,
                "sample_witnesses": [{"callsite_rva": f"0x{i+20:08x}"}],
                "direct_call_edges": 1,
            })
            attempted.append({
                "index": i, "rva": targets[-1]["target_rva"],
                "callsite_rva": targets[-1]["sample_witnesses"][0]["callsite_rva"],
                "original_direct_calls": 1, "witness_valid": True,
                "status": "decompiled", "c": "void f() {}",
            })
        with gzip.open(root / "recursive_call_targets.jsonl.gz", "wt") as f:
            for row in targets:
                f.write(json.dumps(row) + "\n")
        file = data / "records" / "recursive_calls_000_002.jsonl.gz"
        with gzip.open(file, "wt") as f:
            for row in attempted:
                f.write(json.dumps(row) + "\n")
        (data / "reports" / "recursive_calls_000_002.json").write_text(json.dumps({
            "attempted": 3, "source_direct_call_targets": 3,
            "decompiled": 3, "missing_function": 0,
            "decompiler_failed": 0, "invalid_witness": 0,
        }))
        assert audit(root)["genuine_additional_C_pseudocode"] == 3
        attempted[1]["rva"] = "0xdeadbeef"
        with gzip.open(file, "wt") as f:
            for row in attempted:
                f.write(json.dumps(row) + "\n")
        try:
            audit(root, save=False)
        except ValueError as exc:
            assert "mismatched" in str(exc)
        else:
            raise AssertionError("Forged original source target admitted")
    print("FORTNITE541_NEW_DIRECTCALL_C_AUDIT_TESTS_PASSED")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=Path("decompilation/fortnite541/discovery/recursive_calls"))
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    if args.self_test:
        self_test()
    else:
        print(json.dumps(audit(args.root), sort_keys=True))
