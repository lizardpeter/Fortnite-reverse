#!/usr/bin/env python3
"""Fetch original Fortnite 5.41 Athena map packages using verified R2 byte ranges.

This is an OFFLINE development importer helper, never the game/runtime render
path. Only file indexes and selected source assets are downloaded. Every
plaintext entry and index is SHA-1 checked against the original game records.
Required programs: Python 3, curl, and OpenSSL (available on GitHub runners).
"""
import argparse
import hashlib
import json
import pathlib
import struct
import subprocess
import tempfile

ARCHIVE = "https://r2.houseofkublai.com/Fortnite/5.41/FortniteGame/Content/Paks/pakchunk0-WindowsClient.pak"
HISTORICAL_KEY = "81C42E03B21760A5C457C8DB7D52BA066F0633D0891FD9E37CF118F27687924A"
MAGIC = 0x5A6F12E1

def ranged(start, size, url=ARCHIVE):
    if start < 0 or size <= 0 or size > 128 * 1024 * 1024:
        raise ValueError("refusing unbounded remote range")
    with tempfile.TemporaryDirectory(prefix="fn541-range-") as d:
        dest = pathlib.Path(d) / "data"
        subprocess.run([
            "curl", "--fail", "--silent", "--show-error", "--location", "--retry", "4",
            "--range", f"{start}-{start+size-1}", "--output", str(dest), url
        ], check=True)
        data = dest.read_bytes()
    if len(data) != size:
        raise ValueError(f"requested {size} source bytes, got {len(data)}")
    return data

def fstring(data, offset):
    count = struct.unpack_from("<i", data, offset)[0]
    offset += 4
    if count == 0:
        return "", offset
    if abs(count) > 131072:
        raise ValueError("implausible source string")
    size = count if count > 0 else -count * 2
    value = data[offset:offset+size]
    if len(value) != size:
        raise ValueError("truncated source string")
    offset += size
    if count > 0:
        if not value.endswith(b"\0"):
            raise ValueError("unterminated source string")
        return value[:-1].decode("utf-8"), offset
    if not value.endswith(b"\0\0"):
        raise ValueError("unterminated source UTF16 string")
    return value[:-2].decode("utf-16-le"), offset

def index_entries(data):
    _, pos = fstring(data, 0)
    count = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    if count > 1000000:
        raise ValueError("implausible source entry count")
    entries = {}
    for _ in range(count):
        path, pos = fstring(data, pos)
        offset, stored, unpacked, method = struct.unpack_from("<QQQI", data, pos)
        pos += 28
        digest = data[pos:pos+20]
        pos += 20
        if method:
            blocks = struct.unpack_from("<I", data, pos)[0]
            if blocks > 1000000:
                raise ValueError("too many compression blocks")
            pos += 4 + 16 * blocks
        encrypted = data[pos] & 1
        pos += 5
        if pos > len(data):
            raise ValueError("entry exceeds verified index")
        if path.startswith("/") or ".." in path.replace("\\", "/").split("/"):
            raise ValueError("unsafe source path in index")
        entries[path] = (offset, stored, unpacked, method, digest, encrypted)
    if len(data) - pos >= 16:
        raise ValueError("unexplained index suffix")
    return entries

def derive_footer():
    # This exact Fortnite 5.41 archive has been measured on the source R2,
    # keeping the expensive request to only its 61-byte version-7 footer.
    size = 4813653874
    tail = ranged(size-61, 61)
    if struct.unpack_from("<I", tail, 17)[0] != MAGIC or struct.unpack_from("<I", tail, 21)[0] != 7:
        raise ValueError("original retail archive footer did not match expected UE4 pak v7")
    offset, length = struct.unpack_from("<QQ", tail, 25)
    digest = tail[41:61]
    if tail[16] != 1 or offset + length > size - 61:
        raise ValueError("invalid encrypted original PakInfo bounds")
    return offset, length, digest

def run(destination, include_landscape, include_materials, key):
    idxoff, idxlen, expected = derive_footer()
    if idxlen > 64*1024*1024 or idxlen % 16:
        raise ValueError("unexpected index size or AES block alignment")
    encrypted = ranged(idxoff, idxlen)
    with tempfile.TemporaryDirectory(prefix="fn541-decrypt-") as d:
        encrypted_path = pathlib.Path(d) / "index.encrypted"
        encrypted_path.write_bytes(encrypted)
        decoded_path = pathlib.Path(d) / "index.plain"
        subprocess.run([
            "openssl", "enc", "-aes-256-ecb", "-d", "-nopad",
            "-K", key, "-in", str(encrypted_path), "-out", str(decoded_path)
        ], check=True)
        decoded = decoded_path.read_bytes()
    if hashlib.sha1(decoded).digest() != expected:
        raise ValueError("historical AES key or decrypted index SHA-1 is incorrect")
    entries = index_entries(decoded)
    print(f"UE4 v7 index verified: {len(entries)} indexed entries")
    suffixes = [
        "/Maps/Athena_Terrain.umap", "/Maps/Athena_Terrain.uexp",
        "/Maps/Streaming/Sublevel_X0Y0.umap", "/Maps/Streaming/Sublevel_X0Y0.uexp",
        "/Maps/Background/Athena_Background.umap", "/Maps/Background/Athena_Background.uexp",
    ]
    landscape_indices = range(6) if include_landscape else range(1)
    for i in landscape_indices:
        suffixes.extend([
            f"/Maps/Landscape/Athena_Terrain_LS_{i:02}.umap",
            f"/Maps/Landscape/Athena_Terrain_LS_{i:02}.uexp",
            f"/Maps/Landscape/Athena_Terrain_LS_{i:02}.ubulk",
        ])
    if include_materials:
        for material in ["M_Athena_Terrain_01", "M_Athena_Terrain_Master",
                         "M_Athena_Terrain_01_NoAridRock", "M_Athena_Terrain_01_Masked"]:
            for extension in [".uasset", ".uexp"]:
                suffixes.append(f"/Environments/Landscape/Material/{material}{extension}")
    found = []
    for suffix in suffixes:
        matches = [(name, record) for name, record in entries.items() if name.endswith(suffix)]
        if len(matches) != 1:
            raise ValueError(f"expected exactly one source file for {suffix}, found {len(matches)}")
        name, (offset, stored, unpacked, method, digest, encrypted_entry) = matches[0]
        if stored != unpacked or stored > 64*1024*1024 or method or encrypted_entry:
            raise ValueError(f"unsupported compression/encryption for source package {name}")
        # Unreal v7 on-disk FPakEntry is 53 bytes for method=0 records.
        raw = ranged(offset, stored + 53)
        header, payload = raw[:53], raw[53:]
        if struct.unpack_from("<QQQI", header, 0)[1:] != (stored, unpacked, 0):
            raise ValueError(f"source FPakEntry header mismatch for {name}")
        if header[28:48] != digest or hashlib.sha1(payload).digest() != digest:
            raise ValueError(f"source SHA-1 mismatch for {name}")
        if name.endswith(".umap") and not payload.startswith(bytes.fromhex("c1832a9e")):
            raise ValueError(f"source UE4 package signature mismatch for {name}")
        dest = destination / pathlib.PurePosixPath(name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(payload)
        found.append({"path": name, "bytes": len(payload), "sha1": digest.hex(), "archive_offset": offset})
        print(f"VERIFIED {name} ({len(payload)} bytes)")
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "fortnite541-source-manifest.json").write_text(json.dumps({
        "source": ARCHIVE, "pak_version": 7, "index_sha1": expected.hex(),
        "files": found
    }, indent=2), encoding="utf8")
    print(f"Saved {len(found)} SHA-1-verified source packages under {destination}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=pathlib.Path,
                        default=pathlib.Path("asset_import/work/fortnite_541/athena/source"))
    parser.add_argument("--all-landscape", action="store_true",
                        help="fetch all six landscape sections, not just LS_00")
    parser.add_argument("--with-terrain-materials", action="store_true",
                        help="also download original Athena material and master asset source packages")
    parser.add_argument("--aes-key", default=HISTORICAL_KEY,
                        help="AES key for an original 5.41 build; historical public key is default")
    args = parser.parse_args()
    run(args.destination, args.all_landscape, args.with_terrain_materials, args.aes_key.removeprefix("0x"))
