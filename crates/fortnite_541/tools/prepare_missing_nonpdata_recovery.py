#!/usr/bin/env python3
"""Queue only failed authentic original non-pdata CALL function recovery.

Inputs are the immutable source-authenticated 58-target direct CALL inventory
and existing independently audited Ghidra C recovery records. Never rerun or
overwrite successful C bodies, or promote missing/failed attempts to success.
"""
from __future__ import annotations
import argparse
import gzip
import json
from pathlib import Path

SOURCE_SHA256 = "7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"

def rows(path):
    with gzip.open(path, "rt", encoding="utf-8") as src:
        for line in src:
            if line.strip():
                yield json.loads(line)

def prepare(root: Path, output: Path) -> dict:
    recovery = root / "discovery/nonpdata_recovery"
    stats = json.loads((recovery / "nonpdata_recovery_status.json").read_text())
    source = list(rows(root / "discovery/nonpdata_direct_calls.jsonl.gz"))
    if (len(source) != 58 or stats["source_original_call_targets"] != 58
        or stats["attempted"] != 58 or stats["genuine_c_pseudocode_functions"] != 57
        or stats["missing_function"] != 1):
        raise ValueError("Source-backed 58-function Ghidra recovery ledger changed; stop before retry")
    attempts = {}
    for file in sorted((recovery / "records").glob("direct_calls_*.jsonl.gz")):
        for row in rows(file):
            index = row["index"]
            if index in attempts:
                raise ValueError(f"Duplicate original nonpdata Ghidra recovery index {index}")
            attempts[index] = row
    if set(attempts) != set(range(58)):
        raise ValueError("Missing original source-Ghidra recovery record")
    successes = 0
    failures = []
    for index, target in enumerate(source):
        rec = attempts[index]
        if (rec["rva"] != target["target_rva"] or
            rec["callsite_rva"] != target["first_callsite_rva"] or
            rec["original_direct_calls"] != target["direct_calls"]):
            raise ValueError(f"Original retail CALL evidence mismatched at index {index}")
        if rec["status"] == "decompiled":
            if not rec["witness_valid"] or not isinstance(rec.get("c"), str) or not rec["c"].strip():
                raise ValueError("False successful original C pseudocode")
            successes += 1
        elif rec["status"] == "missing_function" and rec["witness_valid"]:
            failures.append((index, target))
        else:
            raise ValueError(f"Unexpected original nonpdata failure mode at {index}: {rec['status']}")
    if successes != 57 or len(failures) != 1:
        raise ValueError("Targeted source recovery queue is not exactly one original missing C function")
    index, target = failures[0]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        f'{index}\t{target["target_rva"]}\t{target["first_callsite_rva"]}\t{target["direct_calls"]}\n',
        encoding="utf-8",
    )
    result = {
        "original_pe_sha256": SOURCE_SHA256,
        "original_source_direct_call_targets": 58,
        "preserved_successful_original_c_bodies": successes,
        "retry_only_missing": 1,
        "retry_source_ordinal": index,
        "retry_original_rva": target["target_rva"],
        "retry_original_callsite": target["first_callsite_rva"],
        "queue_file": str(output),
    }
    (output.parent / "targeted_retry_source_status.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    return result

def test():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        d = root / "discovery"
        rec = d / "nonpdata_recovery"
        (rec / "records").mkdir(parents=True)
        calls = []
        reports = []
        for i in range(58):
            addr = 0x10000 + 16*i
            calls.append({"target_rva": f"0x{addr:08x}",
                          "first_callsite_rva": f"0x{addr-32:08x}",
                          "direct_calls": 1})
            reports.append({
                "index": i, "rva": f"0x{addr:08x}",
                "callsite_rva": f"0x{addr-32:08x}",
                "original_direct_calls": 1, "witness_valid": True,
                "status": "decompiled" if i != 57 else "missing_function",
                "c": "void f(void) {}" if i != 57 else None,
            })
        with gzip.open(d/"nonpdata_direct_calls.jsonl.gz", "wt") as out:
            for r in calls: out.write(json.dumps(r)+"\n")
        with gzip.open(rec/"records/direct_calls_000_057.jsonl.gz", "wt") as out:
            for r in reports: out.write(json.dumps(r)+"\n")
        (rec/"nonpdata_recovery_status.json").write_text(json.dumps({
            "source_original_call_targets":58,"attempted":58,
            "genuine_c_pseudocode_functions":57,"missing_function":1}))
        status = prepare(d.parent,root/"retry.tsv")
        assert status["retry_source_ordinal"] == 57
        assert len((root/"retry.tsv").read_text().splitlines()) == 1
        reports[0]["rva"] = "0xBAD0"
        with gzip.open(rec/"records/direct_calls_000_057.jsonl.gz", "wt") as out:
            for r in reports: out.write(json.dumps(r)+"\n")
        try: prepare(d.parent,root/"retry2.tsv")
        except ValueError as e: assert "mismatched" in str(e)
        else: raise AssertionError("Altered original source function RVA accepted")
    print("FORTNITE541_ORIGINAL_ONLY_MISSING_DIRECTCALL_QUEUE_TESTS_PASSED")

if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--self-test",action="store_true")
    a=p.parse_args()
    if a.self_test: test()
    else:
        if a.root is None or a.out is None: p.error("--root --out required")
        print(json.dumps(prepare(a.root,a.out),sort_keys=True))
