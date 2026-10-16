#!/usr/bin/env python3
"""Verify real Fortnite 5.41 lighting-related native xrefs in restored AMD64 code.

Not a filename/string-only catalog: each evidence item is an authenticated
RIP-relative LEA inside one original .pdata function whose displacement points
to an actual on-disk compiler-emitted ASCII/UTF16 string. Every target in the
reviewed TSV must match a unique original function extent AND at least one
such native code instruction. No function is claimed decompiled here.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import re
import struct
from pathlib import Path

ORIGINAL_SHA256 = "7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"
RESTORED_SHA256 = "b2792fd5d7639a7277cd131ca50bdd898ff2b8721c66bc4ae0e8ebcd61652379"
TEXTS = (
    "FortTimeOfDayManager", "TimeOfDay", "SunriseDirectionalLightRotation",
    "SunsetDirectionalLightRotation", "SunAndMoonModelWorldPosition",
    "SkyDome", "SkyLight", "MaterialShaderMap", "ExponentialHeightFog",
    "DirectionalLight", "GBuffer", "ReflectionCapture", "WorldPositionOffset",
)
# AMD64 LEA with RIP-relative ModRM, REX prefix, signed displacement.
RIP_LEA = re.compile(b"[\x48-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")


def read_original_pdata(data: bytes, section: dict) -> dict[int, tuple[int, int]]:
    raw = data[section["raw"]:section["raw"] + section["file_bytes"]]
    output = {}
    for at in range(0, len(raw) - 11, 12):
        first, end, unwind = struct.unpack_from("<III", raw, at)
        if first < end and 0 < end - first < 10_000_000:
            output.setdefault(first, (end, unwind))
    if len(output) != 291757:
        raise ValueError(f"wrong original .pdata function count {len(output)}")
    return output


def pe_sections(data: bytes) -> list[dict]:
    if data[:2] != b"MZ":
        raise ValueError("missing MZ")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    if data[pe:pe+4] != b"PE\0\0":
        raise ValueError("missing PE32+ header")
    count = struct.unpack_from("<H", data, pe+6)[0]
    length = struct.unpack_from("<H", data, pe+20)[0]
    if struct.unpack_from("<H", data, pe+24)[0] != 0x20b:
        raise ValueError("not PE32+")
    sections = []
    for i in range(count):
        at = pe+24+length+40*i
        name = data[at:at+8].split(b"\0")[0].decode("ascii")
        virt_len, rva, file_bytes, raw = struct.unpack_from("<IIII", data, at+8)
        if raw+file_bytes > len(data):
            raise ValueError(f"{name} raw section outside original file")
        sections.append({
            "name": name, "rva": rva, "virtual_bytes": virt_len,
            "file_bytes": file_bytes, "raw": raw,
        })
    return sections


def find_source_strings(data: bytes, sections: list[dict]) -> dict[int, list[str]]:
    result: dict[int, list[str]] = {}
    for section in sections:
        if section["name"] not in (".rdata", ".data", "_RDATA", ".text"):
            continue
        chunk = data[section["raw"]:section["raw"] + section["file_bytes"]]
        for word in TEXTS:
            for codec in ("ascii", "utf-16-le"):
                value = word.encode(codec)
                cursor = 0
                while (at := chunk.find(value, cursor)) >= 0:
                    result.setdefault(section["rva"] + at, []).append(f"{word}:{codec}")
                    cursor = at + 1
    return result


def scan_references(data: bytes, sections: list[dict], strings: dict[int, list[str]],
                    pdata: dict[int, tuple[int, int]]) -> dict[int, list[dict]]:
    sorted_starts = sorted(pdata)
    evidence: dict[int, list[dict]] = {}
    for section in sections:
        if section["name"] != ".text":
            continue
        chunk = data[section["raw"]:section["raw"] + section["file_bytes"]]
        for match in RIP_LEA.finditer(chunk):
            at = match.start()
            if at+7 > len(chunk):
                continue
            disp = struct.unpack_from("<i", chunk, at+3)[0]
            target = section["rva"] + at + 7 + disp
            names = strings.get(target)
            if not names:
                continue
            instruction = section["rva"] + at
            index = bisect.bisect_right(sorted_starts, instruction) - 1
            if index < 0:
                continue
            owner = sorted_starts[index]
            if instruction >= pdata[owner][0]:
                continue
            evidence.setdefault(owner, []).append({
                "instruction_rva": f"0x{instruction:08x}",
                "string_rva": f"0x{target:08x}",
                "source_strings": names,
            })
    return evidence


def main() -> None:
    args = argparse.ArgumentParser()
    args.add_argument("--exe", type=Path, required=True)
    args.add_argument("--targets", type=Path, required=True)
    args.add_argument("--out", type=Path, required=True)
    options = args.parse_args()
    data = options.exe.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != RESTORED_SHA256:
        raise ValueError(f"expected verified restored PE, not protected EXE: {digest}")
    sections = pe_sections(data)
    pdata = read_original_pdata(data, next(s for s in sections if s["name"] == ".pdata"))
    starts = sorted(pdata)
    evidence = scan_references(data, sections, find_source_strings(data, sections), pdata)
    rows = []
    seen = set()
    for line in options.targets.read_text().splitlines():
        if not line.strip():
            continue
        i, s, e = line.split("\t")
        ordinal, start, end = int(i), int(s, 16), int(e, 16)
        if ordinal in seen or ordinal < 0 or ordinal >= len(starts):
            raise ValueError(f"duplicate/outside ordinal {ordinal}")
        seen.add(ordinal)
        if starts[ordinal] != start or pdata[start][0] != end:
            raise ValueError(f"original pdata mismatch {ordinal} {s}")
        refs = evidence.get(start, [])
        if not refs:
            raise ValueError(f"no native RIP-relative source-lighting xref in {s}")
        rows.append({
            "original_function_ordinal": ordinal,
            "function_rva": s, "end_rva": e,
            "verified_original_code_references": refs[:50],
            "matching_instruction_count": len(refs),
        })
    if len(rows) != 14:
        raise ValueError(f"wrong selected original native function count {len(rows)}")
    payload = {
        "original_sha256": ORIGINAL_SHA256,
        "reconstructed_sha256": RESTORED_SHA256,
        "total_original_pdata_functions": len(starts),
        "selected_native_functions": len(rows),
        "contract": "real restored LEA RIP displacement into source string, exact .pdata owner",
        "functions": rows,
    }
    options.out.parent.mkdir(parents=True, exist_ok=True)
    options.out.write_text(json.dumps(payload, indent=2)+"\n")
    print("FORTNITE541_ORIGINAL_LIGHTING_NATIVE_XREFS_VERIFIED",
          len(rows), sum(r["matching_instruction_count"] for r in rows))


if __name__ == "__main__":
    main()
