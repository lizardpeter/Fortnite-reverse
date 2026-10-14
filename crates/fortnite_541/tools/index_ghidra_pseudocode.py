#!/usr/bin/env python3
"""Build a real, source-addressed search index of Fortnite 5.41 Ghidra C.

Only the user's previously committed original Ghidra C pseudocode is indexed.
The script scans all audited original .pdata records and upgrades missing
first-pass entries with successful independently audited recovery bodies.

Keyword matches are DISCOVERY CANDIDATES, not proven original C++ identities.
No Ghidra C is synthesized, modified, or guessed. All matches retain source
shard and exact original executable RVA for deeper class/shader-map analysis.
"""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import re
from pathlib import Path

TOTAL = 291757
TERMS = {
    "material_shader_map": r"material[\w:]*shader[\w:]*map|shader[\w:]*map",
    "material": r"material",
    "shader": r"shader",
    "texture": r"texture",
    "sampler": r"sampler",
    "uniform_expression": r"uniform[\w:]*expression|uniform[\w:]*buffer",
    "d3d11": r"d3d11|createpixelshader|pssetshader|vssetshader",
    "compiled_shader": r"dxbc|shex|pcd3d_sm5|shader[\w:]*code",
    "pixel_shader": r"pixel[\w:]*shader|pixelshader|fragment[\w:]*shader",
}
PATTERNS = {name: re.compile(expr, re.IGNORECASE) for name, expr in TERMS.items()}
WEIGHTS = {
    "material_shader_map": 12, "uniform_expression": 9, "d3d11": 9,
    "compiled_shader": 8, "pixel_shader": 8, "material": 2,
    "shader": 2, "texture": 1, "sampler": 1,
}
RECOVERY_ORDER = ("fast_v1", "split_v1", "full_v1", "bounded_v1")


def gz_rows(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as src:
        for line in src:
            if line.strip():
                yield json.loads(line)


def matching_evidence(source: str, signature: str, name: str):
    complete = "\n".join((name or "", signature or "", source))
    hits = {}
    for label, pattern in PATTERNS.items():
        found = list(pattern.finditer(complete))
        if not found:
            continue
        snippets = []
        for match in found[:2]:
            beginning = max(0, match.start() - 84)
            end = min(len(complete), match.end() + 84)
            snippets.append(" ".join(complete[beginning:end].split())[:190])
        hits[label] = {"occurrences": len(found), "snippets": snippets}
    return hits


def load_recovered(root: Path, originals: int):
    """Only original ordinal + nonempty Ghidra C; later audited mode wins."""
    out = {}
    statistics = collections.Counter()
    for mode in RECOVERY_ORDER:
        folder = root / "recovery" / mode / "records"
        for path in sorted(folder.glob("retry_*.jsonl.gz")):
            for row in gz_rows(path):
                if row.get("status") != "decompiled":
                    continue
                index = row.get("index")
                if not isinstance(index, int) or not 0 <= index < originals:
                    raise ValueError(f"Invalid original recovered index from {path}: {index}")
                source = row.get("c")
                if not isinstance(source, str) or not source.strip():
                    raise ValueError(f"False recovered C result in {path} index={index}")
                out[index] = dict(row=row, mode=mode, path=path.name)
                statistics[mode] += 1
    return out, dict(statistics)


def build(root: Path, output: Path):
    status = json.loads((root / "status.json").read_text())
    recovery = json.loads((root / "recovery_status.json").read_text())
    if status.get("original_pdata_functions") != TOTAL or \
       status.get("covered_records") != TOTAL or \
       recovery.get("original_pdata_functions") != TOTAL:
        raise ValueError("Source decompilation inventory does not match original retail .pdata")
    recovered, modes = load_recovered(root, TOTAL)
    output.mkdir(parents=True, exist_ok=True)
    base = output / "original_function_lookup.jsonl.gz"
    candidates = output / "material_shader_candidates.jsonl.gz"
    stats = collections.Counter()
    by_kind = collections.Counter()
    ranked = []
    expected = 0
    with gzip.open(base, "wt", encoding="utf-8") as lookup, \
         gzip.open(candidates, "wt", encoding="utf-8") as material:
        files = sorted((root / "functions").glob("pdata_*.jsonl.gz"))
        if len(files) != status.get("shard_count"):
            raise ValueError("Missing source-authenticated first-pass Ghidra shards")
        for shard in files:
            for first in gz_rows(shard):
                index = first.get("index")
                if index != expected:
                    raise ValueError(f"Missing or repeated original function ordinal {index}; expected {expected}")
                expected += 1
                effective = first
                label = "first_pass"
                relative = f"functions/{shard.name}"
                if index in recovered:
                    upgraded = recovered[index]
                    if first.get("status") == "decompiled":
                        raise ValueError(f"Recovery overwrote a successful first-pass source index {index}")
                    if upgraded["row"].get("rva") != first.get("rva") or \
                       upgraded["row"].get("end_rva") != first.get("end_rva"):
                        raise ValueError(f"Recovered original PE RVA mismatch at {index}")
                    effective = upgraded["row"]
                    label = upgraded["mode"]
                    relative = f"recovery/{label}/records/{upgraded['path']}"
                code = effective.get("c") or ""
                is_real = effective.get("status") == "decompiled"
                if is_real and (not isinstance(code, str) or not code.strip()):
                    raise ValueError(f"Original Ghidra function {index} claims C without source")
                if not is_real:
                    code = ""
                stats["covered"] += 1
                stats["decompiled" if is_real else "unresolved"] += 1
                length = len(code)
                hits = matching_evidence(code, effective.get("signature") or "", effective.get("name") or "") if is_real else {}
                plain = {
                    "index": index,
                    "rva": first["rva"],
                    "end_rva": first["end_rva"],
                    "status": effective.get("status"),
                    "name": effective.get("name"),
                    "signature": effective.get("signature"),
                    "source_shard": relative,
                    "recovery_mode": label,
                    "c_characters": length,
                    "c_sha256": hashlib.sha256(code.encode()).hexdigest() if is_real else None,
                    "has_keyword_evidence": bool(hits),
                }
                lookup.write(json.dumps(plain, separators=(",", ":")) + "\n")
                if hits:
                    stats["keyword_candidate_functions"] += 1
                    by_kind.update(hits.keys())
                    score = sum(WEIGHTS.get(k, 1) * min(2, v["occurrences"]) for k, v in hits.items())
                    # Ranking from *actual* source C, not guessed original C++ function names.
                    candidate = {k: plain[k] for k in
                                 ("index", "rva", "end_rva", "name", "source_shard", "c_characters")}
                    candidate.update(keyword_evidence=hits, score=score,
                                     identification="pseudocode_keyword_only_unverified")
                    material.write(json.dumps(candidate, separators=(",", ":")) + "\n")
                    ranked.append(candidate)
    if expected != TOTAL or stats["covered"] != TOTAL:
        raise ValueError(f"Missing original C index coverage: {expected}/{TOTAL}")
    if stats["decompiled"] != recovery["effectively_decompiled"]:
        raise ValueError("Effective C code count disagrees with independently audited recovery ledger")
    if stats["unresolved"] != recovery["unresolved_remaining"]:
        raise ValueError("Unresolved code count differs from audited source original")
    ranked.sort(key=lambda r: (-r["score"], -r["c_characters"], r["index"]))
    summary = {
        "schema_version": 1,
        "original_pe_sha256": "7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108",
        "original_pdata_functions": TOTAL,
        "real_decompiled_c": stats["decompiled"],
        "unresolved": stats["unresolved"],
        "source_keyword_candidate_count": stats["keyword_candidate_functions"],
        "keyword_counts": dict(sorted(by_kind.items())),
        "recoveries_selected": modes,
        "ranking_is_not_function_identification": True,
        "best_candidates": ranked[:150],
    }
    (output / "material_shader_candidates.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("FORTNITE541_ORIGINAL_C_PSEUDOCODE_SEARCH_COMPLETE",
          json.dumps({k: v for k, v in summary.items() if k != "best_candidates"}))
    return summary


def self_test():
    assert not matching_evidence("int n = 0;", "", "")
    hits = matching_evidence("FMaterialShaderMap uses PSSetShader and TextureSampler", "", "")
    assert "material_shader_map" in hits
    assert "d3d11" in hits
    assert "texture" in hits and "sampler" in hits
    assert len(hits["d3d11"]["snippets"]) == 1
    print("FORTNITE541_C_SEARCH_INDEX_UNIT_TESTS_PASSED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("decompilation/fortnite541"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        summary = build(args.root, args.output or args.root / "index")
        if not summary["source_keyword_candidate_count"]:
            print("No named shader strings in Ghidra C; no false function attribution made.")
