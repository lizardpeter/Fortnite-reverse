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
    high = 0
    for begin, end, _ in pdata:
        high = max(end, high)
        upper.append(high)
    target_rows = {}
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
            if inside_any_pdata(target, beginnings, upper):
                stats["call_edges_to_indexed_functions"] += 1
                continue
            dst = pe.get_section_by_rva(target) if target >= 0 else None
            if dst is None or not (dst.Characteristics & EXECUTABLE_FLAG):
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
                    "unique_original_caller_functions": 0,
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
