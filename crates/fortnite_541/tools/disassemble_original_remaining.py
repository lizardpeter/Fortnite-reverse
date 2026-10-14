#!/usr/bin/env python3
"""Exact original retail x64 evidence for routines where Ghidra C fails.

This is a linear Capstone interpretation of byte-identical source PE .pdata
spans. The original bytes' SHA256, actual original ordinals and all failures
are retained. Linear instructions are NOT a verified control-flow graph, C++,
or a claim that all bytes in an unwind span are executable instructions.
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_INT
from capstone.x86 import X86_OP_IMM
import pefile

ORIGINAL_COUNT = 291757
MACHINE_AMD64 = 0x8664
EXECUTABLE_FLAG = 0x20000000


def read_rows(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def original_pdata(pe: pefile.PE) -> list[tuple[int, int, int]]:
    section = next((s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata"), None)
    if section is None:
        raise ValueError("Retail original PE has no .pdata section")
    image = pe.get_data(section.VirtualAddress, section.Misc_VirtualSize)
    seen: set[int] = set()
    values = []
    for at in range(0, len(image) - 11, 12):
        begin, end, unwind = struct.unpack_from("<III", image, at)
        if begin >= end or end - begin > 10_000_000:
            continue
        if pe.get_section_by_rva(begin) is None or pe.get_section_by_rva(end - 1) is None:
            continue
        if begin in seen:
            continue
        seen.add(begin)
        values.append((begin, end, unwind))
    values.sort(key=lambda x: x[0])
    if len(values) != ORIGINAL_COUNT:
        raise ValueError(
            f"Original PE .pdata count mismatch: got {len(values)}, "
            f"expected {ORIGINAL_COUNT}"
        )
    return values


def decode_original_x64(data: bytes, image_base: int, rva: int) -> dict:
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = False
    start = image_base + rva
    entries = []
    cursor = 0
    # A purely linear byte decoder can run into data islands. Stop at the
    # first undecodable position; never invent instructions for remaining bytes.
    for instruction in decoder.disasm(data, start):
        if instruction.address != start + cursor:
            break
        entries.append({
            "rva": f"0x{rva + cursor:08x}",
            "bytes": instruction.bytes.hex(),
            "mnemonic": instruction.mnemonic,
            "operands": instruction.op_str,
        })
        cursor += instruction.size
    return {
        "linear_instructions": entries,
        "linear_decoded_bytes": cursor,
        "undecoded_remaining_bytes": len(data) - cursor,
        "undecoded_tail_sha256": hashlib.sha256(data[cursor:]).hexdigest()
        if cursor < len(data) else None,
    }




def decode_reachable_cfg(data: bytes, image_base: int, rva: int) -> dict:
    """Conservative recursive descent from the real unwind entrypoint.

    Only instruction bytes reached via decoded fallthrough/relative branches
    within the original .pdata interval are marked. No heuristic jump-table,
    exception-edge or indirect-flow inference is silently accepted.
    """
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    base = image_base + rva
    count = len(data)
    queued: list[int] = [0]
    decoded: dict[int, dict] = {}
    byte_owner: dict[int, int] = {}
    undecodable: set[int] = set()
    conflicting: set[int] = set()
    branch_edges: list[dict] = []
    outside_edges = 0

    while queued:
        cursor = queued.pop()
        while 0 <= cursor < count:
            if cursor in decoded:
                break
            if cursor in byte_owner:
                conflicting.add(cursor)
                break
            instruction = next(decoder.disasm(data[cursor:], base + cursor, count=1), None)
            if instruction is None or instruction.size < 1 or cursor + instruction.size > count:
                undecodable.add(cursor)
                break
            if any(at in byte_owner for at in range(cursor, cursor + instruction.size)):
                conflicting.add(cursor)
                break
            for at in range(cursor, cursor + instruction.size):
                byte_owner[at] = cursor
            is_call = instruction.group(CS_GRP_CALL)
            is_jump = instruction.group(CS_GRP_JUMP)
            is_ret = instruction.group(CS_GRP_RET)
            is_interrupt = instruction.group(CS_GRP_INT)
            target_va = None
            if (is_call or is_jump) and instruction.operands and instruction.operands[0].type == X86_OP_IMM:
                target_va = int(instruction.operands[0].imm)
            item = {
                "rva": f"0x{rva + cursor:08x}",
                "bytes": instruction.bytes.hex(),
                "mnemonic": instruction.mnemonic,
                "operands": instruction.op_str,
                "length": instruction.size,
            }
            if target_va is not None:
                target_rva = target_va - image_base
                in_body = rva <= target_rva < rva + count
                kind = "call" if is_call else "jump"
                branch_edges.append({
                    "from_rva": item["rva"],
                    "to_rva": f"0x{target_rva:08x}" if 0 <= target_rva <= 0xffffffff else str(target_rva),
                    "kind": kind,
                    "inside_original_extent": in_body,
                })
                if in_body and is_jump:
                    queued.append(int(target_rva - rva))
                if not in_body:
                    outside_edges += 1
            decoded[cursor] = item
            # Explicit terminal x86 control transfers have no fallthrough.
            if is_ret or is_interrupt or instruction.mnemonic in ("ud2", "hlt", "jmp", "ljmp"):
                break
            cursor += instruction.size

    instructions = [decoded[k] for k in sorted(decoded)]
    covered = len(byte_owner)
    return {
        "method": "capstone_x86_64_reachable_cfg_conservative",
        "warning": "Only statically reachable original instruction bytes; indirect branches, exceptions and jump tables unresolved",
        "instructions": instructions,
        "instruction_count": len(instructions),
        "instruction_bytes": covered,
        "unreached_or_undecodable_bytes": count - covered,
        "explicit_undecodable_entries": [f"0x{rva + p:08x}" for p in sorted(undecodable)],
        "overlapping_entry_conflicts": [f"0x{rva + p:08x}" for p in sorted(conflicting)],
        "branch_edges": branch_edges,
        "edges_outside_original_extent": outside_edges,
        "instruction_byte_range_sha256": hashlib.sha256(
            b"".join(data[k:k + len(bytes.fromhex(decoded[k]["bytes"]))] for k in sorted(decoded))
        ).hexdigest(),
    }

def export(source: Path, unresolved: Path, output: Path,
           expected_sha256: str | None = None) -> dict:
    exe = source.read_bytes()
    digest = hashlib.sha256(exe).hexdigest()
    if expected_sha256 and digest.lower() != expected_sha256.lower():
        raise ValueError("Original Fortnite retail executable SHA256 mismatch")
    pe = pefile.PE(data=exe, fast_load=True)
    if pe.FILE_HEADER.Machine != MACHINE_AMD64 or pe.OPTIONAL_HEADER.Magic != 0x20B:
        raise ValueError("Input executable is not original PE32+ AMD64")
    spans = original_pdata(pe)
    remaining = list(read_rows(unresolved))
    if not remaining or len({x["index"] for x in remaining}) != len(remaining):
        raise ValueError("Missing or repeated original remaining-function indices")
    output.mkdir(parents=True, exist_ok=True)
    record_path = output / "original_unresolved_x64.jsonl.gz"
    counts = Counter()
    cfg_path = output / "original_unresolved_cfg.jsonl.gz"
    with (gzip.open(record_path, "wt", encoding="utf-8", compresslevel=9) as stream,
          gzip.open(cfg_path, "wt", encoding="utf-8", compresslevel=9) as cfg_stream):
        for row in remaining:
            index = row["index"]
            if not isinstance(index, int) or not 0 <= index < len(spans):
                raise ValueError(f"Invalid original .pdata ordinal: {index}")
            begin, end, unwind = spans[index]
            if row["rva"] != f"0x{begin:08x}" or row["end_rva"] != f"0x{end:08x}":
                raise ValueError(f"Original executable RVA does not match Ghidra ledger: {index}")
            section = pe.get_section_by_rva(begin)
            if section is None or not (section.Characteristics & EXECUTABLE_FLAG):
                raise ValueError(f"Original function {index} is not in an executable section")
            body = pe.get_data(begin, end - begin)
            if len(body) != end - begin:
                raise ValueError(f"Source original function bytes truncated: {index}")
            decoded = decode_original_x64(body, pe.OPTIONAL_HEADER.ImageBase, begin)
            graph = decode_reachable_cfg(body, pe.OPTIONAL_HEADER.ImageBase, begin)
            counts["cfg_instruction_count"] += graph["instruction_count"]
            counts["cfg_instruction_bytes"] += graph["instruction_bytes"]
            counts["cfg_unreached_or_undecodable_bytes"] += graph["unreached_or_undecodable_bytes"]
            counts["cfg_branch_edges"] += len(graph["branch_edges"])
            counts["cfg_edges_outside_original_extent"] += graph["edges_outside_original_extent"]
            counts["cfg_functions_with_unknown_bytes"] += int(graph["unreached_or_undecodable_bytes"] > 0)
            cfg_stream.write(json.dumps({
                "index": index,
                "rva": row["rva"],
                "end_rva": row["end_rva"],
                "original_source_sha256": hashlib.sha256(body).hexdigest(),
                **graph,
            }, separators=(",", ":")) + "\n")
            counts["original_functions"] += 1
            counts["original_bytes"] += len(body)
            counts["linear_decoded_bytes"] += decoded["linear_decoded_bytes"]
            counts["linear_instruction_count"] += len(decoded["linear_instructions"])
            if decoded["undecoded_remaining_bytes"]:
                counts["functions_with_undecoded_tail"] += 1
            record = {
                "index": index,
                "rva": row["rva"],
                "end_rva": row["end_rva"],
                "original_unwind_rva": f"0x{unwind:08x}",
                "section": section.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
                "source_body_bytes": len(body),
                "source_body_sha256": hashlib.sha256(body).hexdigest(),
                "decode_method": "capstone_x86_64_linear_heuristic",
                "warning": "Linear disassembly, not a verified function control flow graph or C++",
                **decoded,
            }
            stream.write(json.dumps(record, separators=(",", ":")) + "\n")
    report = {
        "source_original_pe_sha256": digest,
        "machine": "AMD64",
        "original_pdata_function_count": len(spans),
        **counts,
    }
    (output / "original_unresolved_x64_status.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def self_test() -> None:
    code = bytes.fromhex("554889e531c05dc3")
    decoded = decode_original_x64(code, 0x140000000, 0x1000)
    assert [x["mnemonic"] for x in decoded["linear_instructions"]] == [
        "push", "mov", "xor", "pop", "ret"
    ], decoded
    assert decoded["linear_decoded_bytes"] == 8
    assert decoded["undecoded_remaining_bytes"] == 0
    damaged = decode_original_x64(b"\x0f", 0x140000000, 0x1000)
    assert damaged["linear_instructions"] == []
    assert damaged["undecoded_remaining_bytes"] == 1
    # Jump over invalid/embedded data to a real reachable return.
    jump_over_data = bytes.fromhex("eb050f0f0f0f0f31c0c3")
    cfg = decode_reachable_cfg(jump_over_data, 0x140000000, 0x1000)
    assert [x["mnemonic"] for x in cfg["instructions"]] == ["jmp", "xor", "ret"], cfg
    assert cfg["instruction_bytes"] == 5 and cfg["unreached_or_undecodable_bytes"] == 5, cfg
    assert cfg["edges_outside_original_extent"] == 0
    # A conditional jump must record both outcomes, but never guess a data island.
    conditional = bytes.fromhex("750390c30f31c0c3")
    graph = decode_reachable_cfg(conditional, 0x140000000, 0x2000)
    assert graph["instruction_bytes"] == 7, graph
    assert graph["unreached_or_undecodable_bytes"] == 1, graph
    # An invalid instruction must remain explicitly undecodable, never become C.
    invalid = decode_reachable_cfg(b"\x0f", 0x140000000, 0x3000)
    assert invalid["instruction_count"] == 0 and len(invalid["explicit_undecodable_entries"]) == 1
    print("FORTNITE541_ORIGINAL_X64_FALLBACK_TESTS_PASSED")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--original-exe", type=Path)
    ap.add_argument("--remaining", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--expected-sha256")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return
    if args.original_exe is None or args.remaining is None or args.out is None:
        ap.error("--original-exe, --remaining and --out required")
    print(json.dumps(export(
        args.original_exe, args.remaining, args.out, args.expected_sha256
    ), sort_keys=True))


if __name__ == "__main__":
    main()
