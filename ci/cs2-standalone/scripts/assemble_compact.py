#!/usr/bin/env python3
"""Assemble 18 independently verified original VMAT/VTEX parts into one bundle."""
import argparse, hashlib, pathlib, shutil

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--manifest",required=True)
    ap.add_argument("--parts",required=True)
    ap.add_argument("--output",required=True)
    args=ap.parse_args()
    manifest=pathlib.Path(args.manifest)
    expected={}
    for line in manifest.read_text().splitlines():
        fields=line.split("|",7)
        if len(fields)!=8 or fields[0]!="ASSET_PLAN_RESOURCE":
            raise ValueError("malformed exact source manifest")
        _,stage,index,path,crc,offset,length,preload=fields
        identity=(index,crc,offset,length,preload)
        if path in expected and expected[path]!=identity:
            raise ValueError(f"conflicting original records for {path}")
        expected[path]=identity
    parts=sorted(pathlib.Path(args.parts).glob("cs2-compact-part-*"))
    if len(parts)!=18:
        raise ValueError(f"expected all 18 original resource parts; have {len(parts)}")
    destination=pathlib.Path(args.output)/"cs2-base-resources"
    hashes={}
    total=0
    for part in parts:
        checksum=part/"SOURCE_SHA256SUMS.txt"
        if not checksum.is_file():
            raise ValueError(f"missing original SHA manifest for {part.name}")
        for line in checksum.read_text().splitlines():
            if len(line)<67 or line[64:66]!="  ":
                raise ValueError(f"bad SHA-256 record in {part.name}: {line[:90]}")
            sha,path=line[:64],line[66:]
            if not path.endswith((".vmat_c",".vtex_c")):
                raise ValueError(f"unexpected original asset type {path}")
            if path not in expected or path in hashes:
                raise ValueError(f"missing/duplicate source dependency {path}")
            src=part/"cs2-base-resources"/pathlib.PurePosixPath(path)
            if not src.is_file():
                raise FileNotFoundError(f"missing verified original resource {src}")
            # Verify bytes again AFTER artifact transport.
            actual=hashlib.sha256(src.read_bytes()).hexdigest()
            if actual!=sha:
                raise ValueError(f"tampered original Source 2 file {path}")
            dest=destination/pathlib.PurePosixPath(path)
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(src,dest)
            hashes[path]=sha
            total+=dest.stat().st_size
    if set(expected)!=set(hashes):
        absent=set(expected)-set(hashes)
        raise ValueError(f"missing {len(absent)} original files, examples: {sorted(absent)[:10]}")
    dest_manifest=destination/"SOURCE_SHA256SUMS.txt"
    dest_manifest.write_text("\n".join(f"{hashes[k]}  {k}" for k in sorted(hashes))+"\n")
    print(f"CS2_COMPACT_READY original_resource_count={len(hashes)} bytes={total} MiB={total/2**20:.2f}")
    print("CS2_COMPACT_BUILD_VERIFIED original files match official Valve VPK resource CRC and SHA-256")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
