#!/usr/bin/env python3
"""Prepare original-source decoded direct CALL targets outside Fortnite .pdata."""
from __future__ import annotations
import argparse
import gzip
import json
from pathlib import Path


def source_targets(path: Path) -> list[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    if len(rows) != 58:
        raise ValueError(f"Expected 58 original source-backed direct CALL targets, got {len(rows)}")
    seen = set()
    for row in rows:
        rva = row["target_rva"]
        caller = row["first_callsite_rva"]
        if rva in seen or not isinstance(rva, str) or not rva.startswith("0x"):
            raise ValueError(f"Duplicate or invalid target: {rva}")
        if not isinstance(caller, str) or not caller.startswith("0x"):
            raise ValueError(f"Invalid original executable CALL witness: {caller}")
        if not isinstance(row["direct_calls"], int) or row["direct_calls"] < 1:
            raise ValueError("Missing source executable CALL evidence")
        int(rva, 16)
        int(caller, 16)
        seen.add(rva)
    return rows


def export(rows: list[dict], start: int, count: int, path: Path) -> None:
    if start < 0 or count < 1 or start + count > len(rows):
        raise ValueError("Invalid source-backed original CALL shard")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as out:
        for index in range(start, start + count):
            row = rows[index]
            out.write(f'{index}\t{row["target_rva"]}\t{row["first_callsite_rva"]}\t{row["direct_calls"]}\n')


def test() -> None:
    from tempfile import TemporaryDirectory
    with TemporaryDirectory() as d:
        root = Path(d)
        fake = [{"target_rva": f"0x{i*8:08x}",
                 "first_callsite_rva": f"0x{i*8+2:08x}", "direct_calls": 1} for i in range(58)]
        src = root / "calls.jsonl.gz"
        with gzip.open(src, "wt") as f:
            for row in fake:
                f.write(json.dumps(row) + "\n")
        rows = source_targets(src)
        export(rows, 0, 8, root / "targets.tsv")
        assert len((root / "targets.tsv").read_text().splitlines()) == 8
        try:
            export(rows, 55, 8, root / "broken.tsv")
        except ValueError:
            pass
        else:
            raise AssertionError("Out-of-range shard incorrectly accepted")
    print("ORIGINAL_NONPDATA_DIRECTCALL_QUEUE_TESTS_PASSED")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", type=Path)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--count", type=int, default=8)
    ap.add_argument("--output", type=Path)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        test()
    else:
        if args.source is None or args.output is None:
            ap.error("--source and --output required")
        targets = source_targets(args.source)
        export(targets, args.start, args.count, args.output)
        print(json.dumps({"original_call_targets": len(targets),
                          "subset_start": args.start, "subset_count": args.count}))
