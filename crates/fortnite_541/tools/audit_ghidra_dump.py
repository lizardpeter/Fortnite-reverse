#!/usr/bin/env python3
"""Validate every Fortnite 5.41 Ghidra shard and publish actual C pseudocode coverage.

A .pdata entry with 'missing_function' or 'decompiler_failed' is NOT considered
decompiled. This validator runs before a wave is permanently committed.
"""
from __future__ import annotations
import argparse
import gzip
import json
import re
from pathlib import Path

TOTAL = 291757
NAME = re.compile(r"pdata_(\d{6})_(\d{6})\.jsonl\.gz$")
STATUSES = ("decompiled", "decompiler_failed", "missing_function")


def scan(root: Path, total: int = TOTAL, save: bool = True) -> dict:
    files = sorted((root / "functions").glob("pdata_*.jsonl.gz"))
    if not files:
        raise ValueError("No original function shards found")
    seen = bytearray(total)
    counts = {s: 0 for s in STATUSES}
    unresolved = []
    for file in files:
        match = NAME.fullmatch(file.name)
        if match is None:
            raise ValueError(f"Invalid shard name {file}")
        lo, hi = map(int, match.groups())
        if not (0 <= lo <= hi < total):
            raise ValueError(f"Shard outside original inventory: {file}")
        expected = lo
        local = {s: 0 for s in STATUSES}
        with gzip.open(file, "rt", encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                row = json.loads(line)
                idx = row.get("index")
                if idx != expected:
                    raise ValueError(f"{file}: ordinal {idx!r}, expected {expected}")
                if seen[idx]:
                    raise ValueError(f"{file}: duplicate original ordinal {idx}")
                seen[idx] = 1
                state = row.get("status")
                if state not in STATUSES:
                    raise ValueError(f"{file}: unsupported status {state!r} at {idx}")
                if state == "decompiled" and not (
                    isinstance(row.get("c"), str) and row["c"].strip()
                ):
                    raise ValueError(f"{file}: function {idx} has no C pseudocode")
                if not isinstance(row.get("rva"), str) or not isinstance(row.get("end_rva"), str):
                    raise ValueError(f"{file}: malformed address at {idx}")
                counts[state] += 1
                local[state] += 1
                if state != "decompiled":
                    unresolved.append({
                        "index": idx, "rva": row["rva"], "end_rva": row["end_rva"],
                        "status": state, "error": row.get("error"),
                    })
                expected += 1
        if expected != hi + 1:
            raise ValueError(f"{file}: missing expected ordinals up to {hi}")
        label = f"pdata_{lo:06d}_{hi:06d}"
        report = root / "reports" / (label + ".json")
        if not report.exists() and lo == 0:
            report = root / "last_batch.json"
        if not report.is_file():
            raise ValueError(f"Missing original source report for {label}")
        metadata = json.loads(report.read_text(encoding="utf-8"))
        if metadata.get("original_pdata_functions") != total:
            raise ValueError(f"{report}: original executable inventory mismatch")
        if metadata.get("batch_start") != lo or metadata.get("batch_end_exclusive") != hi + 1:
            raise ValueError(f"{report}: reported range does not match source records")
        for k, state in (("decompiled", "decompiled"),
                         ("decompiler_failed", "decompiler_failed"),
                         ("missing", "missing_function")):
            if metadata.get(k) != local[state]:
                raise ValueError(f"{report}: reported {k} does not match source records")
    covered = sum(seen)
    begin = None
    pending = []
    for index, present in enumerate(seen):
        if not present and begin is None:
            begin = index
        elif present and begin is not None:
            pending.append([begin, index])
            begin = None
    if begin is not None:
        pending.append([begin, total])
    result = {
        "schema_version": 1,
        "original_pdata_functions": total,
        "covered_records": covered,
        "coverage_percent": round(covered * 100 / total, 6),
        "actually_decompiled": counts["decompiled"],
        "decompiled_percent_of_inventory": round(counts["decompiled"] * 100 / total, 6),
        "decompiler_failed": counts["decompiler_failed"],
        "missing_function": counts["missing_function"],
        "unprocessed": total - covered,
        "unresolved_total": len(unresolved),
        "shard_count": len(files),
        "pending_ranges": pending,
    }
    if save:
        (root / "status.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        with gzip.open(root / "unresolved.jsonl.gz", "wt", encoding="utf-8") as output:
            for row in unresolved:
                output.write(json.dumps(row, separators=(",", ":")) + "\n")
    return result


def self_test() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "functions").mkdir()
        (root / "reports").mkdir()
        rows = [
            {"index": 0, "rva": "0x10", "end_rva": "0x20", "status": "decompiled", "c": "void f() {}"},
            {"index": 1, "rva": "0x20", "end_rva": "0x30", "status": "missing_function", "c": None},
            {"index": 2, "rva": "0x30", "end_rva": "0x40", "status": "decompiler_failed", "c": None},
        ]
        target = root / "functions" / "pdata_000000_000002.jsonl.gz"
        with gzip.open(target, "wt") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")
        (root / "last_batch.json").write_text(json.dumps({
            "original_pdata_functions": 5, "batch_start": 0,
            "batch_end_exclusive": 3, "decompiled": 1,
            "decompiler_failed": 1, "missing": 1,
        }))
        result = scan(root, 5)
        assert result["covered_records"] == 3
        assert result["actually_decompiled"] == 1
        assert result["unresolved_total"] == 2
        assert result["pending_ranges"] == [[3, 5]]
        with gzip.open(root / "unresolved.jsonl.gz", "rt") as handle:
            assert len(handle.readlines()) == 2
        rows[1]["index"] = 0
        with gzip.open(target, "wt") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")
        try:
            scan(root, 5, save=False)
        except ValueError as error:
            assert "ordinal" in str(error)
        else:
            raise AssertionError("Duplicate/wrong ordinal was accepted")
    print("GHIDRA_DUMP_STATUS_VALIDATOR_TESTS_PASSED")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path("decompilation/fortnite541"))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        self_test()
    else:
        print(json.dumps(scan(args.root), sort_keys=True))
