#!/usr/bin/env python3
"""Produce actionable, source-linked failure cases for original Fortnite 5.41.

Only remaining unsuccessful original .pdata entries are included. The evidence
comes from the verified original RVA ledger plus actual Ghidra result records,
not guesses or fabricated pseudocode.
"""
from __future__ import annotations
import argparse
from collections import Counter
import gzip
import json
from pathlib import Path


def read_gzip_jsonl(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def analyze(root: Path, write: bool = True) -> dict:
    status = json.loads((root / "recovery_status.json").read_text(encoding="utf-8"))
    remaining = list(read_gzip_jsonl(root / "recovery_remaining.jsonl.gz"))
    if len(remaining) != status["unresolved_remaining"]:
        raise ValueError("Remaining ledger count does not match latest recovery audit")
    remaining_by_id = {row["index"]: row for row in remaining}
    if len(remaining_by_id) != len(remaining):
        raise ValueError("Duplicate original function ordinal in remaining ledger")
    history: dict[int, list[dict]] = {index: [] for index in remaining_by_id}
    for mode in ("fast_v1", "split_v1", "full_v1"):
        for path in sorted((root / "recovery" / mode / "records").glob("retry_*.jsonl.gz")):
            for row in read_gzip_jsonl(path):
                index = row["index"]
                if index not in remaining_by_id:
                    continue
                original = remaining_by_id[index]
                if original["rva"] != row["rva"] or original["end_rva"] != row["end_rva"]:
                    raise ValueError(f"Source original .pdata address mismatch: {index}")
                if row["status"] == "decompiled":
                    raise ValueError(f"Recovered function {index} erroneously remains unresolved")
                if row["status"] not in ("missing_function", "decompiler_failed"):
                    raise ValueError(f"Invalid unresolved function status: {row['status']}")
                history[index].append({
                    "mode": mode,
                    "status": row["status"],
                    "name": row.get("name"),
                    "signature": row.get("signature"),
                    "error": (row.get("error") or "")[:1024],
                    "diagnostics": (row.get("diagnostics") or "")[:1024],
                    "source_shard": path.name,
                })

    def classify(item: dict) -> str:
        last = item["attempts"][-1] if item["attempts"] else {}
        if last.get("status") == "missing_function":
            if "inside" in last.get("diagnostics", ""):
                return "overlapping_ghidra_function"
            return "undecodable_original_entry"
        text = (last.get("error", "") + " " + last.get("diagnostics", "")).lower()
        if any(x in text for x in ("timeout", "timed out", "time limit")):
            return "decompiler_timeout"
        if any(x in text for x in ("low-level", "bad instruction", "invalid", "pcode",
                                    "constructor", "disassembl", "flow")):
            return "decompiler_invalid_ir_or_instruction"
        if "stack" in text:
            return "decompiler_stack_issue"
        if "memory" in text:
            return "decompiler_memory_issue"
        return "decompiler_unclassified"

    items = []
    for index, row in sorted(remaining_by_id.items()):
        attempts = history[index]
        if not attempts:
            raise ValueError(f"No recovery attempt was found for original ordinal {index}")
        latest = attempts[-1]
        item = {
            "index": index,
            "rva": row["rva"],
            "end_rva": row["end_rva"],
            "original_bytes": int(row["end_rva"], 16) - int(row["rva"], 16),
            "latest_status": latest["status"],
            "latest_error": latest["error"],
            "latest_diagnostics": latest["diagnostics"],
            "attempts": attempts,
        }
        item["error_class"] = classify(item)
        items.append(item)
    category = Counter(x["error_class"] for x in items)
    count_by_status = Counter(x["latest_status"] for x in items)
    summary = {
        "original_pdata_functions": status["original_pdata_functions"],
        "successfully_decompiled": status["effectively_decompiled"],
        "still_unresolved": len(items),
        "latest_statuses": dict(sorted(count_by_status.items())),
        "error_classes": dict(sorted(category.items())),
        "attempts_with_full_analysis": sum(
            any(a["mode"] == "full_v1" for a in x["attempts"]) for x in items
        ),
        "largest_function_bytes": max((x["original_bytes"] for x in items), default=0),
    }
    if write:
        (root / "recovery_failure_triage.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (root / "recovery_failure_cases.jsonl").write_text(
            "".join(json.dumps(x, separators=(",", ":")) + "\n" for x in items),
            encoding="utf-8",
        )
    return summary


def self_test() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        folder = root / "recovery" / "full_v1" / "records"
        folder.mkdir(parents=True)
        (root / "recovery_status.json").write_text(json.dumps({
            "unresolved_remaining": 1, "original_pdata_functions": 9,
            "effectively_decompiled": 8,
        }))
        row = {"index": 2, "rva": "0x00000120", "end_rva": "0x00000140"}
        with gzip.open(root / "recovery_remaining.jsonl.gz", "wt") as out:
            out.write(json.dumps(row) + "\n")
        with gzip.open(folder / "retry_000002_000002.jsonl.gz", "wt") as out:
            out.write(json.dumps({**row, "status": "decompiler_failed",
                                  "error": "Could not resolve pcode constructor"}) + "\n")
        report = analyze(root)
        assert report["still_unresolved"] == 1
        assert report["error_classes"]["decompiler_invalid_ir_or_instruction"] == 1
        saved = json.loads((root / "recovery_failure_cases.jsonl").read_text().strip())
        assert saved["original_bytes"] == 32 and saved["index"] == 2
        wrong = {**row, "rva": "0x00000121", "status": "decompiler_failed"}
        with gzip.open(folder / "retry_000002_000002.jsonl.gz", "wt") as out:
            out.write(json.dumps(wrong) + "\n")
        try:
            analyze(root, write=False)
        except ValueError as error:
            assert "mismatch" in str(error)
        else:
            raise AssertionError("Did not detect forged original function RVA")
    print("FORTNITE541_REAL_FAILURE_TRIAGE_TESTS_PASSED")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path("decompilation/fortnite541"))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        self_test()
    else:
        print(json.dumps(analyze(args.root), sort_keys=True))
