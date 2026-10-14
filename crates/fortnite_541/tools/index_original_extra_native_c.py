#!/usr/bin/env python3
"""Durable source-linked C function catalog for Fortnite 5.41 native leaf calls.

Strictly lists genuine existing Ghidra C, original source call provenance,
C hashes and possible Ghidra signatures. Does not generate C++, names, or
functions. Optional targeted retry replaces one missing record only on success.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import re
from pathlib import Path

PE_SHA = "7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"
NAMED = re.compile(r"(?<![\w])(?:thunk_)?FUN_([0-9a-fA-F]{8,16})\s*\(")


def rows(path):
    with gzip.open(path, "rt", encoding="utf-8") as src:
        for line in src:
            if line.strip():
                yield json.loads(line)


def make_record(record, target, group, source_shard):
    if record["rva"] != target["target_rva"]:
        raise ValueError("Original source CALL address mismatch")
    c = record.get("c")
    real = record["status"] == "decompiled"
    if real and (not record["witness_valid"] or not isinstance(c, str) or not c.strip()):
        raise ValueError("Invalid original source Ghidra C output counted as recovered")
    if not real and c:
        raise ValueError("Non-success original CALL produced pseudocode without verification")
    if not record.get("witness_valid"):
        raise ValueError("Original function cannot be linked without original CALL")
    sig = c.partition("{")[0].strip() if real else None
    if sig and len(sig) > 800:
        sig = sig[-800:]
    refs = sorted(set(NAMED.findall(c.partition("{")[2]))) if real else []
    return {
        "source_group": group,
        "original_rva": record["rva"],
        "original_original_callsite_rva": record["callsite_rva"],
        "source_witnessed_direct_calls": record["original_direct_calls"],
        "source_record_ordinal": record["index"],
        "actual_ghidra_status": record["status"],
        "ghidra_function_name": record.get("name"),
        "ghidra_pseudocode_signature": sig,
        "ghidra_c_sha256": hashlib.sha256(c.encode()).hexdigest() if real else None,
        "ghidra_c_characters": len(c) if real else 0,
        "ghidra_named_function_references": refs,
        "original_source_shard": source_shard,
        "recovered_native_function_not_original_pdata": True,
        "symbol_original_identity_verified": False,
        "compiled_cpp_linkage_verified": False,
    }


def build(root: Path, out: Path):
    discover = root / "discovery"
    source58 = list(rows(discover/"nonpdata_direct_calls.jsonl.gz"))
    prior_dir = discover / "nonpdata_recovery"
    prior_status = json.loads((prior_dir/"nonpdata_recovery_status.json").read_text())
    if (len(source58) != 58 or prior_status["attempted"] != 58 or
        prior_status["genuine_c_pseudocode_functions"] != 57):
        raise ValueError("Incomplete original 58-source CALL inventory")
    prior = {}
    for shard in sorted((prior_dir/"records").glob("direct_calls_*.jsonl.gz")):
        for rec in rows(shard):
            if rec["index"] in prior:
                raise ValueError("Duplicate original source recovery ordinal")
            prior[rec["index"]] = (rec, "discovery/nonpdata_recovery/records/"+shard.name)
    if set(prior) != set(range(58)):
        raise ValueError("Incomplete original direct-CALL Ghidra output")
    for i, target in enumerate(source58):
        rec, _ = prior[i]
        if (rec["callsite_rva"] != target["first_callsite_rva"] or
            rec["original_direct_calls"] != target["direct_calls"]):
            raise ValueError("Original x64 CALL witness contradicted Ghidra source")

    updated = False
    retry_dir = prior_dir / "targeted_retry"
    if (retry_dir/"targeted_retry_outcome.json").exists():
        outcome = json.loads((retry_dir/"targeted_retry_outcome.json").read_text())
        i = outcome["retry_source_ordinal"]
        if (outcome["original_source_sha256"] != PE_SHA or not 0 <= i < 58 or
            outcome["retry_original_rva"] != source58[i]["target_rva"]):
            raise ValueError("Original isolated native recovery source identity changed")
        shardfiles = list((retry_dir/"records").glob("direct_calls_*.jsonl.gz"))
        if len(shardfiles) != 1:
            raise ValueError("Missing single native targeted retry evidence shard")
        records = list(rows(shardfiles[0]))
        if len(records) != 1 or records[0]["index"] != i:
            raise ValueError("Targeted native retry record mismatch")
        if (records[0]["rva"] != source58[i]["target_rva"] or
            records[0]["callsite_rva"] != source58[i]["first_callsite_rva"] or
            records[0]["status"] != outcome["latest_genuine_ghidra_status"]):
            raise ValueError("Targeted original native C retry source mismatch")
        if records[0]["status"] == "decompiled":
            if prior[i][0]["status"] == "decompiled":
                raise ValueError("Targeted retry redundantly overwrote previously genuine C")
            prior[i] = (records[0], "discovery/nonpdata_recovery/targeted_retry/records/"+shardfiles[0].name)
            updated = True

    source3 = [
        row for row in rows(discover/"recursive_calls/recursive_call_targets.jsonl.gz")
        if not row["known_ghidra_candidate"]
    ]
    extra = list(rows(discover/"recursive_calls/new_original_C/records/recursive_calls_000_002.jsonl.gz"))
    status3 = json.loads((discover/"recursive_calls/new_original_C/new_original_C_status.json").read_text())
    if len(source3) != 3 or len(extra) != 3 or status3["genuine_additional_C_pseudocode"] != 3:
        raise ValueError("Authentic three new original native Ghidra C corpus incomplete")
    seen_rvas, catalog = set(), []
    for i in range(58):
        rec, path = prior[i]
        if rec["status"] not in ("decompiled","missing_function"):
            raise ValueError("Unexpected original 58-function recovery state")
        candidate = make_record(rec, source58[i], "initial_nonpdata_58", path)
        if candidate["original_rva"] in seen_rvas:
            raise ValueError("Duplicate original source native CALL destination")
        seen_rvas.add(candidate["original_rva"])
        catalog.append(candidate)
    by_ix = {r["index"]: r for r in extra}
    if set(by_ix) != set(range(3)):
        raise ValueError("Missing original 3 new source native function indices")
    for i, source in enumerate(source3):
        rec = by_ix[i]
        if (rec["callsite_rva"] != source["sample_witnesses"][0]["callsite_rva"] or
            rec["original_direct_calls"] != source["direct_call_edges"]):
            raise ValueError("New original 3 native C CALL witness mismatch")
        candidate = make_record(
            rec, source, "new_recursive_source_3",
            "discovery/recursive_calls/new_original_C/records/recursive_calls_000_002.jsonl.gz",
        )
        if candidate["original_rva"] in seen_rvas:
            raise ValueError("Duplicate native original RVA across recovered source groups")
        seen_rvas.add(candidate["original_rva"])
        catalog.append(candidate)

    catalog.sort(key=lambda r: int(r["original_rva"],16))
    good = sum(bool(r["ghidra_c_sha256"]) for r in catalog)
    if len(catalog) != 61 or good != 60 + int(updated):
        raise ValueError("Unexpected genuine original native C count")
    out.mkdir(parents=True,exist_ok=True)
    with gzip.open(out/"original_extra_native_c_catalog.jsonl.gz","wt",encoding="utf-8") as sink:
        for entry in catalog:
            sink.write(json.dumps(entry,sort_keys=True,separators=(",",":"))+"\n")
    summary = {
        "original_pe_sha256": PE_SHA,
        "native_original_call_target_entries": len(catalog),
        "genuine_native_ghidra_c_bodies": good,
        "no_ghidra_c": len(catalog)-good,
        "original_initial_nonpdata_C": 57,
        "original_recursive_extra_C": 3,
        "targeted_retry_additional_C": int(updated),
        "original_pdata_291701_c_bodies_counted_separately": True,
        "recompilable_cpp_verified": False,
        "all_ghidra_names_and_pseudocode_signatures_heuristic": True,
    }
    (out/"original_extra_native_c_catalog_status.json").write_text(
        json.dumps(summary,sort_keys=True,indent=2)+"\n")
    print("FORTNITE541_SOURCE_NATIVE_GHIDRA_C_CATALOG_COMPLETE",json.dumps(summary,sort_keys=True))
    return summary


def self_test():
    t={"target_rva":"0x00001234"}
    x={"index":1,"rva":"0x00001234","callsite_rva":"0x00001000",
       "original_direct_calls":2,"status":"decompiled","witness_valid":True,
       "name":"FUN_140001234","c":"int FUN_140001234(void) { FUN_140009999(); return 1; }"}
    result=make_record(x,t,"extra","file.jsonl.gz")
    assert result["ghidra_c_sha256"] and result["ghidra_named_function_references"]==["140009999"]
    x["c"]=""
    try: make_record(x,t,"extra","file.jsonl.gz")
    except ValueError: pass
    else: raise AssertionError("False C body accepted")
    print("FORTNITE541_NATIVE_C_CATALOG_SELFTEST_OK")


if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--self-test",action="store_true")
    a=p.parse_args()
    if a.self_test:self_test()
    else:
        if a.root is None or a.out is None:p.error("--root --out required")
        build(a.root,a.out)
