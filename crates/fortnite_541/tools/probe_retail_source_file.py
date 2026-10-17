#!/usr/bin/env python3
"""Bounded, read-only Fortnite 5.41 retail-file evidence probe.

Works with the user's existing public R2 read endpoint. Reports only file
metadata, SHA-256, conservative signatures, PE section stats and DXBC magic
counts. Never executes source binaries or publishes proprietary file bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import pathlib
import struct
from collections import Counter

WINDOW = 65536
MAX_SOURCE_BYTES = 512 * 1024 * 1024
KNOWN_ORIGINAL_EXE_SHA256 = (
    "7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"
)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return round(-sum((v / n) * math.log2(v / n) for v in counts.values()), 4)


def fetch_at(f, offset: int, size: int) -> bytes:
    f.seek(offset)
    return f.read(size)


def pe_sections(f, total: int) -> dict | None:
    if total < 512 or fetch_at(f, 0, 2) != b"MZ":
        return None
    pe = struct.unpack("<I", fetch_at(f, 0x3c, 4))[0]
    if pe > min(total - 24, 4 * 1024 * 1024):
        return None
    header = fetch_at(f, pe, 24)
    if len(header) != 24 or header[:4] != b"PE\0\0":
        return None
    number = struct.unpack_from("<H", header, 6)[0]
    optional_size = struct.unpack_from("<H", header, 20)[0]
    if number > 96 or optional_size > 4096:
        return None
    optional = fetch_at(f, pe + 24, optional_size)
    if len(optional) < 2:
        return None
    magic = struct.unpack_from("<H", optional)[0]
    if magic not in (0x10b, 0x20b):
        return None
    sections = []
    table = pe + 24 + optional_size
    for i in range(number):
        raw = fetch_at(f, table + 40 * i, 40)
        if len(raw) != 40:
            return None
        name = raw[:8].split(b"\0")[0].decode("ascii", "replace")
        virtual_bytes, rva, disk_bytes, offset = struct.unpack_from("<IIII", raw, 8)
        if offset + disk_bytes > total:
            return None
        windows = []
        if disk_bytes:
            stride = max(WINDOW, disk_bytes // 16)
            for j in range(0, disk_bytes, stride):
                data = fetch_at(f, offset + j, min(WINDOW, disk_bytes - j))
                if data:
                    windows.append(entropy(data))
        stats = {
            "name": name, "rva": rva, "virtual_bytes": virtual_bytes,
            "raw_offset": offset, "raw_bytes": disk_bytes,
            "entropy_min": min(windows) if windows else None,
            "entropy_max": max(windows) if windows else None,
            "entropy_mean": round(sum(windows) / len(windows), 4) if windows else None,
            "entropy_windows": len(windows),
        }
        if name == ".pdata" and disk_bytes:
            valid = 0
            candidates = disk_bytes // 12
            for j in range(candidates):
                entry = fetch_at(f, offset + 12*j, 12)
                start, end, _ = struct.unpack("<III", entry)
                if 0 < start < end and end-start < 10000000:
                    valid += 1
            stats["x64_runtime_function_candidates"] = candidates
            stats["x64_runtime_function_plausible"] = valid
        sections.append(stats)
    return {"type": "PE32+" if magic == 0x20b else "PE32", "sections": sections}


def signature(head: bytes, tail: bytes) -> dict:
    kind = "unknown"
    if head.startswith(b"MZ"):
        kind = "PE executable or DLL"
    elif head.startswith(b"DXBC"):
        kind = "D3D DXBC container"
    elif head.startswith(b"\x89PNG\r\n\x1a\n"):
        kind = "PNG"
    elif head.startswith(b"RIFF"):
        kind = "RIFF"
    elif head.startswith(b"PK\x03\x04"):
        kind = "ZIP"
    elif head.startswith(b"\x28\xb5\x2f\xfd"):
        kind = "Zstandard frame"
    elif head.startswith(b"\x1f\x8b"):
        kind = "gzip"
    # UE4 FPakInfo magic at the end is not guaranteed to be in the final
    # four bytes. Report its position, not a fabricated PAK version.
    ue4_magic = struct.pack("<I", 0x5A6F12E1)
    return {
        "kind": kind, "head_magic_hex": head[:16].hex(),
        "tail_ue4_pak_magic_offsets_from_end": [
            len(tail)-i for i in range(len(tail))
            if tail.startswith(ue4_magic, i)
        ][:20]
    }


def inspect(source: pathlib.Path, original_path: str, expected_sha: str = "") -> dict:
    total = source.stat().st_size
    if total <= 0 or total > MAX_SOURCE_BYTES:
        raise ValueError(f"source length outside (0, {MAX_SOURCE_BYTES}]: {total}")
    hash_code = hashlib.sha256()
    magic_counts = {"DXBC": 0, "DXIL": 0}
    last = b""
    with source.open("rb") as f:
        while block := f.read(1024*1024):
            hash_code.update(block)
            buff = last + block
            for key in magic_counts:
                magic_counts[key] += buff.count(key.encode("ascii"))
            last = block[-3:]
        sha = hash_code.hexdigest()
        if expected_sha and sha.lower() != expected_sha.lower():
            raise ValueError(f"file SHA-256 mismatch: got {sha}, expected {expected_sha}")
        head = fetch_at(f, 0, min(4096, total))
        tail = fetch_at(f, max(0, total-4096), min(4096, total))
        data = {
            "source": original_path,
            "size_bytes": total,
            "sha256": sha,
            "sha256_authenticated": bool(expected_sha),
            "known_fortnite541_exe_match": sha == KNOWN_ORIGINAL_EXE_SHA256,
            "signature": signature(head, tail),
            "container_signatures_seen": magic_counts,
            "sample_window_bytes": WINDOW,
            "sample_entropies": [],
        }
        for off in sorted({0, total//4, total//2, (3*total)//4, max(0,total-WINDOW)}):
            data["sample_entropies"].append({
                "offset": off, "bits_per_byte": entropy(fetch_at(f, off, min(WINDOW,total-off)))
            })
        data["pe"] = pe_sections(f, total)
    return data


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=pathlib.Path, required=True)
    p.add_argument("--relative-path", required=True)
    p.add_argument("--expected-sha256", default="")
    p.add_argument("--output", type=pathlib.Path, required=True)
    args = p.parse_args()
    report = inspect(args.input, args.relative_path, args.expected_sha256)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("FORTNITE541_RETAIL_PROBE_OK",
          f"size={report['size_bytes']}",
          f"sha256={report['sha256']}",
          f"kind={report['signature']['kind']}",
          f"dxbc_signatures={report['container_signatures_seen']['DXBC']}")
    if report["pe"]:
        print("PE_SECTIONS", ", ".join(
            f"{s['name']}:{s['raw_bytes']}B/E={s['entropy_mean']}"
            for s in report["pe"]["sections"]
        ))


if __name__ == "__main__":
    main()
