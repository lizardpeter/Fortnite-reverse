#!/usr/bin/env python3
"""Audit source-verified second-pass Ghidra recoveries without overwriting first-pass data."""
from __future__ import annotations
import argparse
import gzip
import json
from pathlib import Path


def audit(root: Path, save: bool = True) -> dict:
    base = json.loads((root / "status.json").read_text(encoding="utf-8"))
    total = base["original_pdata_functions"]
    unresolved_path = root / "unresolved.jsonl.gz"
    with gzip.open(unresolved_path, "rt", encoding="utf-8") as source:
        original = [json.loads(line) for line in source if line.strip()]
    indexes = {r["index"]: r for r in original}
    if len(indexes) != len(original) or len(original) != base["unresolved_total"]:
        raise ValueError("First-pass unresolved ledger not consistent with original status")
    successfully_recovered = {}
    mode_stats = {}
    for mode in ("fast_v1", "split_v1", "full_v1", "bounded_v1"):
        attempted = set()
        counts = dict(attempted=0, decompiled=0, decompiler_failed=0, missing_function=0)
        folder = root / "recovery" / mode
        for filename in sorted((folder / "records").glob("retry_*.jsonl.gz")):
            expected_report = folder / "reports" / (filename.name[:-len(".jsonl.gz")] + ".json")
            if not expected_report.is_file():
                raise ValueError(f"Missing source Ghidra report: {filename}")
            report = json.loads(expected_report.read_text(encoding="utf-8"))
            records = []
            with gzip.open(filename, "rt", encoding="utf-8") as file:
                for line in file:
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    idx = row.get("index")
                    if not isinstance(idx, int) or idx in attempted:
                        raise ValueError(f"Duplicate/invalid recovery original ordinal: {idx}")
                    if idx not in indexes:
                        raise ValueError(f"Recovery claimed an original successfully decompiled function: {idx}")
                    canonical = indexes[idx]
                    if row.get("rva") != canonical.get("rva") or row.get("end_rva") != canonical.get("end_rva"):
                        raise ValueError(f"Recovery original executable address mismatch: {idx}")
                    status = row.get("status")
                    if status not in ("decompiled", "missing_function", "decompiler_failed"):
                        raise ValueError(f"Invalid recovery outcome for {idx}")
                    if status == "decompiled":
                        if not isinstance(row.get("c"), str) or not row["c"].strip():
                            raise ValueError(f"Recovered function {idx} has no actual C pseudocode")
                        successfully_recovered[idx] = {"mode": mode, "record": filename.name}
                    counts[status] += 1
                    attempted.add(idx)
                    records.append(row)
            if not records:
                raise ValueError(f"Empty recovery shard: {filename}")
            if report.get("original_pdata_functions") != total:
                raise ValueError(f"Wrong source executable inventory in {filename}")
            if report.get("retry_count") != len(records):
                raise ValueError(f"Incorrect source recovery count in {filename}")
            if report.get("first_original_index") != records[0]["index"]:
                raise ValueError(f"Wrong first original recovery ordinal: {filename}")
            if report.get("last_original_index") != records[-1]["index"]:
                raise ValueError(f"Wrong last original recovery ordinal: {filename}")
            for field, status in (("recovered", "decompiled"),
                                  ("missing", "missing_function"),
                                  ("decompiler_failed", "decompiler_failed")):
                if report.get(field) != sum(r["status"] == status for r in records):
                    raise ValueError(f"Ghidra recovery report mismatch: {filename} {field}")
            counts["attempted"] += len(records)
        mode_stats[mode] = counts
    remaining = [r for r in original if r["index"] not in successfully_recovered]
    effective = base["actually_decompiled"] + len(successfully_recovered)
    if effective > total:
        raise ValueError("Recovery count exceeds original .pdata inventory")
    result = {
        "schema_version": 1,
        "original_pdata_functions": total,
        "first_pass_decompiled": base["actually_decompiled"],
        "first_pass_unresolved": len(original),
        "newly_recovered_unique_functions": len(successfully_recovered),
        "effectively_decompiled": effective,
        "effective_percent": round(100 * effective / total, 6),
        "unresolved_remaining": len(remaining),
        "recovery_modes": mode_stats,
    }
    if save:
        (root / "recovery_status.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        with gzip.open(root / "recovery_remaining.jsonl.gz", "wt", encoding="utf-8") as output:
            for row in remaining:
                output.write(json.dumps(row, separators=(",", ":")) + "\n")
    return result


def self_test() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "recovery" / "fast_v1" / "records").mkdir(parents=True)
        (root / "recovery" / "fast_v1" / "reports").mkdir()
        (root / "status.json").write_text(json.dumps({
            "original_pdata_functions": 5, "actually_decompiled": 3,
            "unresolved_total": 2,
        }))
        originals = [
            {"index": 1, "rva": "0x10", "end_rva": "0x20", "status": "missing_function"},
            {"index": 3, "rva": "0x30", "end_rva": "0x40", "status": "decompiler_failed"},
        ]
        with gzip.open(root / "unresolved.jsonl.gz", "wt") as f:
            for r in originals:
                f.write(json.dumps(r) + "\n")
        rows = [
            {"index": 1, "rva": "0x10", "end_rva": "0x20", "status": "decompiled", "c": "void f() {}"},
            {"index": 3, "rva": "0x30", "end_rva": "0x40", "status": "missing_function", "c": None},
        ]
        filename = root / "recovery" / "fast_v1" / "records" / "retry_000001_000003.jsonl.gz"
        with gzip.open(filename, "wt") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        report = filename.parent.parent / "reports" / "retry_000001_000003.json"
        report.write_text(json.dumps({
            "original_pdata_functions": 5, "retry_count": 2, "recovered": 1,
            "decompiler_failed": 0, "missing": 1,
            "first_original_index": 1, "last_original_index": 3,
        }))
        result = audit(root)
        assert result["effectively_decompiled"] == 4, result
        assert result["unresolved_remaining"] == 1, result
        assert result["recovery_modes"]["fast_v1"]["attempted"] == 2
        rows[0]["rva"] = "0x99"
        with gzip.open(filename, "wt") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        try:
            audit(root, save=False)
        except ValueError as exc:
            assert "address mismatch" in str(exc)
        else:
            raise AssertionError("Wrong original RVA accepted")
    print("GHIDRA_RECOVERY_AUDIT_TESTS_PASSED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("decompilation/fortnite541"))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        print(json.dumps(audit(args.root), sort_keys=True))
