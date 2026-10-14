#!/usr/bin/env python3
"""Extract exactly source-indexed original compiled Dust2 resources from VPK shards.

Input is the two-pass Source 2 VMAT/VTEX manifest, never guessed file names.
Only compiled .vmat_c and .vtex_c bytes are emitted, in their original paths.
All slices are bounded and CRC32-tested against the official VPK directory.
"""
import argparse, hashlib, os, pathlib, re, sys, zlib

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--manifest',required=True)
    ap.add_argument('--archive-dir',required=True)
    ap.add_argument('--output',required=True)
    ap.add_argument('--indices',required=True)
    args=ap.parse_args()
    indices={int(v) for v in args.indices.split(",") if v}
    source_dir=pathlib.Path(args.archive_dir)
    output=pathlib.Path(args.output)/"cs2-base-resources"
    count=0
    total=0
    seen={}
    digest_lines=[]
    for line in pathlib.Path(args.manifest).read_text().splitlines():
        parts=line.split("|",7)
        if len(parts)!=8 or parts[0]!="ASSET_PLAN_RESOURCE":
            continue
        _,stage,idx,path,crc,offset,length,preload_hex=parts
        if int(idx) not in indices:
            continue
        if (not path.endswith((".vmat_c",".vtex_c"))
            or path.startswith("/")
            or "\\" in path or ":" in path
            or any(x in {"","..","."} for x in path.split("/"))):
            raise ValueError(f"unsafe original resource path: {path}")
        if path in seen:
            if seen[path]!=(idx,crc,offset,length,preload_hex):
                raise ValueError(f"conflicting material and texture manifest for {path}")
            continue
        seen[path]=(idx,crc,offset,length,preload_hex)
        length_i=int(length); offset_i=int(offset)
        if length_i<0 or length_i>512*1024*1024 or offset_i<0:
            raise ValueError(f"invalid source VPK byte extent for {path}")
        original=source_dir/f"pak01_{idx}.vpk"
        if not original.is_file():
            raise FileNotFoundError(f"required original archive absent: {original}")
        if original.stat().st_size<offset_i+length_i:
            raise ValueError(f"truncated original archive {original} for {path}")
        with original.open("rb") as file:
            file.seek(offset_i)
            body=file.read(length_i)
        compiled=bytes.fromhex(preload_hex)+body
        actual=zlib.crc32(compiled)&0xffffffff
        if actual!=int(crc):
            raise ValueError(f"original Valve CRC mismatch {path}: {actual} != {crc}")
        dest=output/pathlib.PurePosixPath(path)
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(compiled)
        sha=hashlib.sha256(compiled).hexdigest()
        digest_lines.append(f"{sha}  {path}")
        count+=1
        total+=len(compiled)
    if count==0:
        raise ValueError("no matching compiled Source 2 entries in this archive batch")
    (pathlib.Path(args.output)/"SOURCE_SHA256SUMS.txt").write_text(
        "\n".join(sorted(digest_lines))+"\n")
    print(f"COMPACT_SOURCE_PACKAGE entries={count} original_bytes={total} indices={args.indices}")
    print("COMPACT_SHA256_VERIFIED",count)
    return 0

if __name__=="__main__":
    sys.exit(main())
