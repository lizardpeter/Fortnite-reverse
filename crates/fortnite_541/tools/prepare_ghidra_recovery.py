#!/usr/bin/env python3
"""Prepare a bounded, source-indexed Ghidra retry slice from the permanent ledger.

The input comes from the independently audited original-decompile branch. Each
row in the TSV retains the ORIGINAL .pdata ordinal, not its retry-queue ordinal.
No successfully decompiled function is reprocessed.
"""
from __future__ import annotations
import argparse
import gzip
import json
from pathlib import Path


def load_unresolved(path: Path) -> list[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as src:
        rows = [json.loads(line) for line in src if line.strip()]
    seen = set()
    for row in rows:
        idx = row["index"]
        if not isinstance(idx, int) or idx in seen or idx < 0 or idx >= 291757:
            raise ValueError("Invalid/duplicate original .pdata index")
        if row.get("status") not in ("missing_function", "decompiler_failed"):
            raise ValueError("Refusing to retry a successful or unknown function")
        for key in ("rva", "end_rva"):
            value = row.get(key)
            if not isinstance(value, str) or not value.startswith("0x"):
                raise ValueError(f"Invalid original address: {row}")
            int(value, 16)
        if int(row["rva"], 16) >= int(row["end_rva"], 16):
            raise ValueError("Invalid original function extent")
        seen.add(idx)
    return rows


def slice_targets(rows: list[dict], start: int, count: int) -> list[dict]:
    if start < 0 or count < 1 or start >= len(rows) or start + count > len(rows):
        raise ValueError("Invalid unresolved queue slice")
    return rows[start:start + count]


def save_tsv(rows: list[dict], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as out:
        for row in rows:
            out.write(f'{row["index"]}\t{row["rva"]}\t{row["end_rva"]}\n')


def self_test() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        path = root / "unresolved.jsonl.gz"
        rows = [
            {"index": 4, "rva": "0x00000100", "end_rva": "0x00000110", "status": "missing_function"},
            {"index": 10, "rva": "0x00000400", "end_rva": "0x00000500", "status": "decompiler_failed"},
        ]
        with gzip.open(path, "wt", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")
        parsed = load_unresolved(path)
        assert len(parsed) == 2
        save_tsv(slice_targets(parsed, 1, 1), root / "subset.tsv")
        assert (root / "subset.tsv").read_text() == "10\t0x00000400\t0x00000500\n"
        try:
            slice_targets(parsed, 1, 2)
        except ValueError:
            pass
        else:
            raise AssertionError("Out-of-range slice passed")
    print("ORIGINAL_GHIDRA_RECOVERY_PLANNER_TESTS_PASSED")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unresolved", type=Path)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--count", type=int, default=128)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.unresolved is None or args.out is None:
        parser.error("--unresolved and --out are required")
    rows = load_unresolved(args.unresolved)
    subset = slice_targets(rows, args.start, args.count)
    save_tsv(subset, args.out)
    print(json.dumps({"source_unresolved_total": len(rows),
                      "retry_queue_start": args.start,
                      "retry_count": len(subset),
                      "first_original_index": subset[0]["index"],
                      "last_original_index": subset[-1]["index"]}))


if __name__ == "__main__":
    main()
