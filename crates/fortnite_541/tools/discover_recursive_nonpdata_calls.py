#!/usr/bin/env python3
"""Recover true source-byte CALL rel32 witnesses from original .pdata CFGs.

Unlike a raw E8 signature scan, callers here are Capstone instructions
reachable from an authenticated original function entry via explicit
intra-function control flow. Targets outside every .pdata extent are still
CANDIDATES, not completed/verified C++ functions.
"""
from __future__ import annotations
import argparse
from bisect import bisect_right
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import pefile

from disassemble_original_remaining import (
    ORIGINAL_COUNT, MACHINE_AMD64, EXECUTABLE_FLAG,
    original_pdata, decode_reachable_cfg,
)


def inside_any_pdata(rva: int, begins: list[int], maximum_ends: list[int]) -> bool:
    i = bisect_right(begins, rva) - 1
    return i >= 0 and maximum_ends[i] > rva


def exact_e8_destination(instruction_bytes: bytes, original_rva: int) -> int | None:
    """Only 5-byte near direct E8 CALLs; no source-byte guesses."""
    if len(instruction_bytes) != 5 or instruction_bytes[0] != 0xE8:
        return None
    delta = struct.unpack_from("<i", instruction_bytes, 1)[0]
    return original_rva + 5 + delta


def classify_original_target(target: int, begins: list[int],
                             max_ends: list[int], owner_indices: list[int],
                             pe: pefile.PE) -> dict:
    """Map a validated E8 destination to ORIGINAL unwind provenance only.

    A containing interval is not an original function *entry*. Overlap-safe
    prefix-maximum indexing prevents attributing a target to a shorter,
    unrelated .pdata extent.
    """
    j = bisect_right(begins, target) - 1
    if j >= 0 and max_ends[j] > target:
        owner = owner_indices[j]
        exact = begins[j] == target
        return {
            "target_class": "exact_original_pdata_entry" if exact
                            else "interior_original_pdata_extent",
            "target_original_index": j if exact else owner,
            "target_original_begin_rva": f"0x{begins[j] if exact else begins[owner]:08x}",
            "exact_original_entry": exact,
        }
    section = pe.get_section_by_rva(target) if target >= 0 else None
    if section is None:
        label = "unmapped_target"
        name = None
    elif section.Characteristics & EXECUTABLE_FLAG:
        label = "executable_nonpdata_target"
        name = section.Name.rstrip(b"\x00").decode("ascii", "replace")
    else:
        label = "nonexecutable_section_target"
        name = section.Name.rstrip(b"\x00").decode("ascii", "replace")
    return {
        "target_class": label, "target_original_index": None,
        "target_original_begin_rva": None, "exact_original_entry": False,
        "target_section": name,
    }


def discover(exe_path: Path, start: int, count: int, out_dir: Path,
             expected_sha256: str) -> dict:
    source = exe_path.read_bytes()
    original_sha = hashlib.sha256(source).hexdigest()
    if original_sha != expected_sha256.lower():
        raise ValueError("Wrong original Fortnite 5.41 retail executable")
    pe = pefile.PE(data=source, fast_load=True)
    if pe.FILE_HEADER.Machine != MACHINE_AMD64 or pe.OPTIONAL_HEADER.Magic != 0x20B:
        raise ValueError("Source is not x64 PE32+ retail shipping client")
    pdata = original_pdata(pe)
    if start < 0 or count < 1 or start + count > ORIGINAL_COUNT:
        raise ValueError("Invalid bounded original .pdata ordinal work interval")
    beginnings = [entry[0] for entry in pdata]
    upper = []
    owners = []
    high, owner = 0, -1
    for i, (begin, end, _) in enumerate(pdata):
        if end > high:
            high, owner = end, i
        upper.append(high)
        owners.append(owner)
    target_rows = {}
    complete_call_rows = []
    stats = Counter()
    first = start
    last = start + count
    base = pe.OPTIONAL_HEADER.ImageBase

    for original_index in range(first, last):
        begin, end, _ = pdata[original_index]
        block = pe.get_section_by_rva(begin)
        if block is None or not (block.Characteristics & EXECUTABLE_FLAG):
            stats["nonexecutable_origins"] += 1
            continue
        body = pe.get_data(begin, end - begin)
        if len(body) != end - begin:
            raise ValueError(f"Truncated genuine original body {original_index}")
        graph = decode_reachable_cfg(body, base, begin)
        stats["visited_original_functions"] += 1
        stats["reachable_instructions"] += graph["instruction_count"]
        stats["reachable_machine_bytes"] += graph["instruction_bytes"]
        # Source-address keyed Ghidra and Capstone-independent E8 rel32 check.
        ins_by_rva = {ins["rva"]: ins for ins in graph["instructions"]}
        for edge in graph["branch_edges"]:
            if edge["kind"] != "call":
                continue
            stats["reachable_direct_call_edges"] += 1
            callsite = int(edge["from_rva"], 16)
            target = int(edge["to_rva"], 16)
            instruction = ins_by_rva[edge["from_rva"]]
            machine = bytes.fromhex(instruction["bytes"])
            actual_target = exact_e8_destination(machine, callsite)
            if actual_target != target:
                # No synthetic evidence from unsupported call encodings.
                stats["unsupported_direct_call_encoding"] += 1
                continue
            stats["verified_e8_rel32_edges"] += 1
            where = classify_original_target(target, beginnings, upper, owners, pe)
            classification = where["target_class"]
            stats["target_" + classification] += 1
            complete_call_rows.append({
                "source_original_pe_sha256": original_sha,
                "original_caller_index": original_index,
                "original_caller_rva": f"0x{begin:08x}",
                "callsite_rva": f"0x{callsite:08x}",
                "instruction_hex": machine.hex(),
                "target_rva": f"0x{target:08x}",
                **where,
                "evidence_level": "source_authenticated_cfg_reachable_e8_rel32",
            })
            if classification in ("exact_original_pdata_entry",
                                  "interior_original_pdata_extent"):
                stats["call_edges_to_indexed_functions"] += 1
                continue
            if classification != "executable_nonpdata_target":
                stats["call_edges_to_nonexecutable"] += 1
                continue
            if not pe.get_data(target, 1):
                stats["call_edges_to_unmapped"] += 1
                continue
            stats["unindexed_executable_call_edges"] += 1
            item = target_rows.get(target)
            if item is None:
                item = {
                    "target_rva": f"0x{target:08x}",
                    "source_original_pe_sha256": original_sha,
                    "direct_call_edges": 0,
                    "callsite_witnesses": [],
                }
                target_rows[target] = item
            item["direct_call_edges"] += 1
            # Evidence witnesses are exact original instructions from real
            # authenticated unwind-defined callers, not raw E8 matches.
            if len(item["callsite_witnesses"]) < 16:
                item["callsite_witnesses"].append({
                    "original_caller_index": original_index,
                    "callsite_rva": f"0x{callsite:08x}",
                    "instruction_hex": machine.hex(),
                    "target_rva": f"0x{target:08x}",
                })
    out_dir.mkdir(parents=True, exist_ok=True)
    suffix = f"{first:06d}_{last:06d}"
    records_file = f"recursive_calls_{suffix}.jsonl.gz"
    report_file = f"recursive_calls_{suffix}.json"
    records_path = out_dir / records_file
    call_file = f"verified_e8_calls_{suffix}.jsonl.gz"
    with gzip.open(out_dir / call_file, "wt", encoding="utf-8", compresslevel=9) as stream:
        for row in complete_call_rows:
            stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    with gzip.open(records_path, "wt", encoding="utf-8", compresslevel=9) as stream:
        for target in sorted(target_rows):
            stream.write(json.dumps(target_rows[target], separators=(",", ":")) + "\n")
    stats["unique_nonpdata_call_targets_in_shard"] = len(target_rows)
    result = {
        "schema_version": 1,
        "source_sha256": original_sha,
        "original_pdata_function_count": ORIGINAL_COUNT,
        "start_original_index": first,
        "end_original_index_exclusive": last,
        "record_file": records_file,
        "validated_e8_callgraph_file": call_file,
        "validated_e8_callgraph_rows": len(complete_call_rows),
        **dict(stats),
    }
    (out_dir / report_file).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def self_test() -> None:
    assert exact_e8_destination(bytes.fromhex("e80b000000"), 0x1000) == 0x1010
    assert exact_e8_destination(bytes.fromhex("e8fbffffff"), 0x1000) == 0x1000
    assert exact_e8_destination(bytes.fromhex("9090909090"), 0x1000) is None
    assert exact_e8_destination(bytes.fromhex("e8ff"), 0x1000) is None
    assert not inside_any_pdata(0x0, [0x10, 0x30], [0x20, 0x40])
    assert inside_any_pdata(0x15, [0x10, 0x30], [0x20, 0x40])
    assert not inside_any_pdata(0x20, [0x10, 0x30], [0x20, 0x40])
    assert inside_any_pdata(0x35, [0x10, 0x30], [0x20, 0x40])
    assert not inside_any_pdata(0x40, [0x10, 0x30], [0x20, 0x40])
    # Branch-reachable original E8 CALL, not just a matching sequence in data.
    body = bytes.fromhex("eb05e80b000000e803000000c3ccccccc3")
    graph = decode_reachable_cfg(body, 0x140000000, 0x1000)
    callsites = [x["rva"] for x in graph["instructions"] if x["mnemonic"] == "call"]
    assert callsites == ["0x00001007"], callsites
    class DummySection:
        Characteristics = EXECUTABLE_FLAG
        Name = b".text\x00\x00\x00"
    class FakePE:
        def get_section_by_rva(self, rva):
            return DummySection() if 0x1000 <= rva < 0x2000 else None
    pe = FakePE()
    begins = [0x1000, 0x1020]
    maximums = [0x1040, 0x1040]
    owners = [0, 0]  # first unwind entry spans across second begin
    assert classify_original_target(0x1000, begins, maximums, owners, pe)[
        "target_class"] == "exact_original_pdata_entry"
    assert classify_original_target(0x1020, begins, maximums, owners, pe)[
        "target_original_index"] == 1
    interior = classify_original_target(0x1030, begins, maximums, owners, pe)
    assert interior["target_class"] == "interior_original_pdata_extent"
    assert interior["target_original_index"] == 0
    assert classify_original_target(0x1100, begins, maximums, owners, pe)[
        "target_class"] == "executable_nonpdata_target"
    assert classify_original_target(0x3000, begins, maximums, owners, pe)[
        "target_class"] == "unmapped_target"
    print("FORTNITE541_SOURCE_REACHABLE_CALL_TESTS_PASSED")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--original-exe", type=Path)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--count", type=int, default=2000)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--sha256", type=str)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return
    if args.original_exe is None or args.out is None or args.sha256 is None:
        ap.error("--original-exe, --out and --sha256 are required")
    print(json.dumps(discover(
        args.original_exe, args.start, args.count, args.out, args.sha256
    ), sort_keys=True))


if __name__ == "__main__":
    main()
