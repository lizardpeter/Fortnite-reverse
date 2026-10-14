#!/usr/bin/env python3
"""Index original Fortnite 5.41 string references to retail x64 .pdata functions.

Evidence from a bounded linear disassembly is NOT verified reachable CFG, restored
C++, or a verified UE4 symbol. No executable bytes or retail assets are exported.
"""
import argparse
import bisect
import gzip
import hashlib
import json
import re
import struct
from collections import defaultdict
from pathlib import Path

SOURCE_SHA256 = "7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"
EXPECTED_PDATA = 291757
TERMS = {
    "materialshadermap": 20, "materialuniform": 15, "uniformexpression": 15,
    "shaderpipeline": 12, "shaderresource": 12, "shadercode": 12,
    "shadercache": 10, "materialinstance": 10, "material": 5,
    "shader": 5, "landscape": 4, "d3d11": 5, "texture": 2, "rhi": 2,
}
ASCII = re.compile(rb"[\x20-\x7e]{8,}")
UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){8,}")


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def hx(x):
    return f"0x{x:08x}"


def parse_pe(b):
    if b[:2] != b"MZ":
        raise ValueError("not a PE DOS header")
    nt = u32(b, 0x3c)
    if b[nt:nt + 4] != b"PE\0\0":
        raise ValueError("bad PE header")
    coff = nt + 4
    if u16(b, coff) != 0x8664:
        raise ValueError("expected AMD64 PE")
    count = u16(b, coff + 2)
    opt = coff + 20
    if u16(b, opt) != 0x20b:
        raise ValueError("expected PE32+")
    imagebase = u64(b, opt + 24)
    sections = []
    st = opt + u16(b, coff + 16)
    for i in range(count):
        o = st + i * 40
        name = b[o:o + 8].split(b"\x00", 1)[0].decode("ascii", "replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", b, o + 8)
        if rawptr + rawsize > len(b):
            raise ValueError(f"truncated section {name}")
        sections.append({
            "name": name, "va": va, "vsize": vsize,
            "rawsize": rawsize, "rawptr": rawptr, "flags": u32(b, o + 36),
        })
    return imagebase, sections


def contents(b, s):
    return memoryview(b)[s["rawptr"]:s["rawptr"] + s["rawsize"]]


def original_pdata(b, sections):
    pdata = next((s for s in sections if s["name"] == ".pdata"), None)
    if pdata is None:
        raise ValueError("missing original .pdata")
    rows, seen = [], set()
    raw = contents(b, pdata)
    for off in range(0, len(raw) - 11, 12):
        start, end, _unwind = struct.unpack_from("<III", raw, off)
        if start >= end or end - start > 10_000_000 or start in seen:
            continue
        seen.add(start)
        rows.append((start, end))
    return sorted(rows)


def scan_anchors(b, sections):
    anchors = {}
    for sec in sections:
        if sec["flags"] & 0x20000000 or not (sec["flags"] & 0x40000000):
            continue  # readable and non-executable sections only
        raw = contents(b, sec)
        for enc, pat in (("ascii", ASCII), ("utf16le", UTF16)):
            for match in pat.finditer(raw):
                value = match.group().decode(
                    "ascii" if enc == "ascii" else "utf-16le", "replace"
                )
                if len(value) > 512:
                    continue
                lower = value.lower()
                matched = {word: score for word, score in TERMS.items() if word in lower}
                if not matched:
                    continue
                rva = sec["va"] + match.start()
                anchors[rva] = {
                    "rva": hx(rva), "section": sec["name"], "encoding": enc,
                    "byte_length": len(match.group()), "literal": value,
                    "keywords": sorted(matched), "score": max(matched.values()),
                }
    return anchors


def original_string_pointer_slots(b, imagebase, sections, anchors):
    """Find source PE 64-bit VA pointer slots referencing exact string ranges.

    An indirect code reference to a verified original data pointer is stronger
    evidence than a coincidental keyword, but does not identify a UE4 class.
    """
    keys = sorted(anchors)
    slots = {}
    for sec in sections:
        if sec["flags"] & 0x20000000 or not (sec["flags"] & 0x40000000):
            continue
        raw = contents(b, sec)
        for off in range(0, len(raw) - 7, 8):
            target = struct.unpack_from("<Q", raw, off)[0] - imagebase
            j = bisect.bisect_right(keys, target) - 1
            if j < 0:
                continue
            original = keys[j]
            if target < original + anchors[original]["byte_length"]:
                slots[sec["va"] + off] = original
    return slots


def function_code(b, sections, start, end):
    for sec in sections:
        if not (sec["flags"] & 0x20000000):
            continue
        if sec["va"] <= start < end <= sec["va"] + sec["rawsize"]:
            pos = sec["rawptr"] + start - sec["va"]
            return bytes(memoryview(b)[pos:pos + end - start])
    return None


def direct_calls(code, rva, imagebase, decoder):
    from capstone.x86_const import X86_OP_IMM
    for ins in decoder.disasm(code, imagebase + rva):
        if ins.mnemonic == "call" and ins.operands and ins.operands[0].type == X86_OP_IMM:
            yield ins.address - imagebase, ins.operands[0].imm - imagebase


def discover(b, imagebase, sections, pdata, anchors, pointers=None):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86_const import X86_OP_MEM, X86_REG_RIP
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    keys = sorted(anchors)
    pointers = pointers or {}
    source_refs = defaultdict(list)
    fn_hits = defaultdict(list)
    visited = skipped = 0

    # Limit each linear decode to its source-authenticated unwind extent.
    for start, end in pdata:
        code = function_code(b, sections, start, end)
        if code is None:
            skipped += 1
            continue
        visited += 1
        for ins in decoder.disasm(code, imagebase + start):
            for op in ins.operands:
                if op.type != X86_OP_MEM or op.mem.base != X86_REG_RIP:
                    continue
                target = ins.address + ins.size + op.mem.disp - imagebase
                j = bisect.bisect_right(keys, target) - 1
                key = keys[j] if j >= 0 else None
                direct = key is not None and target < key + anchors[key]["byte_length"]
                if not direct:
                    key = pointers.get(target)
                    if key is None:
                        continue
                evidence = {
                    "function_rva": hx(start), "instruction_rva": hx(ins.address - imagebase),
                    "target_rva": hx(target), "mnemonic": ins.mnemonic,
                    "reference_kind": ("direct_string_range" if direct
                                       else "indirect_original_va_pointer_slot"),
                }
                source_refs[key].append(evidence)
                fn_hits[start].append((key, evidence))

    candidates = set(fn_hits)
    incoming, outgoing = defaultdict(list), defaultdict(list)
    begins = [f[0] for f in pdata]
    for start, end in pdata:
        code = function_code(b, sections, start, end)
        if code is None:
            continue
        for site, target in direct_calls(code, start, imagebase, decoder):
            j = bisect.bisect_right(begins, target) - 1
            if j < 0 or target >= pdata[j][1]:
                continue
            callee = pdata[j][0]
            if callee in candidates:
                incoming[callee].append({
                    "caller_rva": hx(start), "callsite_rva": hx(site),
                    "target_rva": hx(target), "exact_entry": target == callee,
                })
            if start in candidates:
                outgoing[start].append({
                    "callee_rva": hx(callee), "callsite_rva": hx(site),
                    "target_rva": hx(target), "exact_entry": target == callee,
                })
    return source_refs, fn_hits, incoming, outgoing, visited, skipped


def write_gzip(path, rows):
    with gzip.open(path, "wt", encoding="utf-8", compresslevel=9) as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exe", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    b = args.exe.read_bytes()
    digest = hashlib.sha256(b).hexdigest()
    if digest != SOURCE_SHA256:
        raise SystemExit(f"wrong original PE SHA256: {digest}")
    imagebase, sections = parse_pe(b)
    pdata = original_pdata(b, sections)
    if len(pdata) != EXPECTED_PDATA:
        raise SystemExit(f"wrong original .pdata count: {len(pdata)}")
    anchors = scan_anchors(b, sections)
    pointers = original_string_pointer_slots(b, imagebase, sections, anchors)
    refs, hits, incoming, outgoing, visited, skipped = discover(
        b, imagebase, sections, pdata, anchors, pointers
    )
    args.out.mkdir(parents=True, exist_ok=True)
    write_gzip(
        args.out / "string_reference_evidence.jsonl.gz",
        ({**anchors[k], "references": refs.get(k, [])} for k in sorted(anchors)),
    )
    write_gzip(
        args.out / "candidate_function_evidence.jsonl.gz",
        ({
            "function_rva": hx(f),
            "anchor_count": len({k for k, _ in hits[f]}),
            "reference_count": len(hits[f]),
            "score": sum(anchors[k]["score"] for k in {x for x, _ in hits[f]}),
            "anchors": [
                {"rva": hx(k), "source_instruction_rva": e["instruction_rva"]}
                for k, e in hits[f]
            ],
            "incoming_direct_calls": incoming[f],
            "outgoing_direct_calls": outgoing[f],
            "evidence_level": "linear_disassembly_rip_string_xref_unverified_function_identity",
        } for f in sorted(hits)),
    )
    report = {
        "schema_version": 1, "source_sha256": digest,
        "original_pdata_count": len(pdata), "scanned_pdata_functions": visited,
        "unmapped_pdata_functions": skipped, "anchor_strings": len(anchors),
        "retail_va_string_pointer_slots": len(pointers),
        "string_or_pointer_references": sum(map(len, refs.values())),
        "direct_string_references": sum(
            sum(e["reference_kind"] == "direct_string_range" for e in items)
            for items in refs.values()
        ),
        "indirect_string_pointer_references": sum(
            sum(e["reference_kind"] == "indirect_original_va_pointer_slot" for e in items)
            for items in refs.values()
        ),
        "candidate_functions": len(hits),
        "candidate_incoming_calls": sum(map(len, incoming.values())),
        "candidate_outgoing_calls": sum(map(len, outgoing.values())),
        "control_flow_verified": False, "function_identity_verified": False,
        "notes": "Original x64 RIP-relative string addresses or original retail absolute-VA string pointer slots in function-bounded linear disassembly; candidates are not confirmed UE4 symbols or proven live branches.",
    }
    (args.out / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
