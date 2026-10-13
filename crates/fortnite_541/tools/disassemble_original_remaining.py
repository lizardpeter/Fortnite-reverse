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

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
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
    with gzip.open(record_path, "wt", encoding="utf-8", compresslevel=9) as stream:
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
