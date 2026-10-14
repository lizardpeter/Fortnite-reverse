#!/usr/bin/env python3
"""Stage source-authenticated previously unseen retail CALL targets for Ghidra."""
from __future__ import annotations
import argparse
import gzip
import json
from pathlib import Path
import struct

SOURCE_SHA256 = "7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"


def load_candidates(path: Path) -> list[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        all_rows = [json.loads(line) for line in stream if line.strip()]
    rows = [row for row in all_rows if not row["known_ghidra_candidate"]]
    if len(rows) != 3:
        raise ValueError(f"Expected exactly three new original CALL candidates, got {len(rows)}")
    used = set()
    for row in rows:
        rva = row["target_rva"]
        if row["source_original_pe_sha256"] != SOURCE_SHA256 or rva in used:
            raise ValueError("Original executable SHA256 or duplicate candidate failure")
        used.add(rva)
        if not row["sample_witnesses"] or row["direct_call_edges"] < 1:
            raise ValueError("Candidate missing actual original source CALL instruction")
        witness = row["sample_witnesses"][0]
        callsite = int(witness["callsite_rva"], 16)
        raw = bytes.fromhex(witness["instruction_hex"])
        if len(raw) != 5 or raw[0] != 0xe8 or callsite + 5 + struct.unpack_from("<i", raw, 1)[0] != int(rva, 16):
            raise ValueError("Original source CALL witness did not resolve to advertised target")
    return rows


def write_tsv(rows: list[dict], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as f:
        for index, row in enumerate(rows):
            witness = row["sample_witnesses"][0]
            f.write(
                f'{index}\t{row["target_rva"]}\t{witness["callsite_rva"]}\t{row["direct_call_edges"]}\n'
            )


def self_test() -> None:
    from tempfile import TemporaryDirectory
    with TemporaryDirectory() as d:
        path = Path(d) / "targets.jsonl.gz"
        example = []
        for i in range(3):
            callsite = 0x100 + 0x10 * i
            target = callsite + 5 + 0x0b
            example.append({
                "target_rva": f"0x{target:08x}",
                "source_original_pe_sha256": SOURCE_SHA256,
                "known_ghidra_candidate": False,
                "direct_call_edges": 1,
                "sample_witnesses": [{"callsite_rva": f"0x{callsite:08x}",
                                      "instruction_hex": "e80b000000"}],
            })
        with gzip.open(path, "wt") as f:
            for item in example:
                f.write(json.dumps(item) + "\n")
        rows = load_candidates(path)
        write_tsv(rows, Path(d) / "targets.tsv")
        assert len((Path(d) / "targets.tsv").read_text().splitlines()) == 3
        example[0]["sample_witnesses"][0]["instruction_hex"] = "e80c000000"
        with gzip.open(path, "wt") as f:
            for item in example:
                f.write(json.dumps(item) + "\n")
        try:
            load_candidates(path)
        except ValueError as error:
            assert "witness" in str(error)
        else:
            raise AssertionError("Forged original call instruction accepted")
    print("FORTNITE541_NEW_RECURSIVE_CALL_QUEUE_TESTS_PASSED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        if args.source is None or args.out is None:
            parser.error("--source and --out required")
        targets = load_candidates(args.source)
        write_tsv(targets, args.out)
        print(json.dumps({"new_original_source_call_candidates": len(targets),
                          "rvas": [r["target_rva"] for r in targets]}))
