#!/usr/bin/env python3
"""Fetch source-authenticated original Fortnite 5.41 sky, time-of-day and
terrain texture assets from observed PUBLIC R2 split PAKs, never from the
user's machine. Writes only ignored temporary runner files, not repository.
"""
import argparse
import hashlib
import json
import pathlib
import struct
from probe_remote_541_paks import BASE, TARGETS, head, authenticated_index, ranged

# Seven observed and independently verified source SHA1 PAK indexes.
PAKS=[
 "pakchunk0-WindowsClient.pak",
 "pakchunk0_s1-WindowsClient.pak",
 "pakchunk0_s2-WindowsClient.pak",
 "pakchunk0_s3-WindowsClient.pak",
 "pakchunk0_s4-WindowsClient.pak",
 "pakchunk1-WindowsClient.pak",
 "pakchunk1_s1-WindowsClient.pak",
]
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--destination",type=pathlib.Path,required=True)
    p.add_argument("--sparse-retail-paks",type=pathlib.Path,
                   help="construct sparse exact source-byte PAKs for native Rust test only")
    args=p.parse_args()
    wanted={t.lstrip("/"):t for t in TARGETS}
    # Source-authored packages: optional original external texture bulk,
    # static-mesh bulk; no guessed color or material substitutions.
    for target in TARGETS:
        if target.endswith(".uasset"):
            bulk=target.removesuffix(".uasset")+".ubulk"
            wanted[bulk.lstrip("/")]=bulk
    authentic=[]
    for archive in PAKS:
        name,size,status=head(archive)
        if size is None:
            print(f"ORIGINAL_541_SPLIT_PAK_NOT_AVAILABLE {archive} reason={status}",flush=True)
            continue
        entries,verdict=authenticated_index(archive,size,
            "81C42E03B21760A5C457C8DB7D52BA066F0633D0891FD9E37CF118F27687924A")
        if entries is None:
            print(f"ORIGINAL_541_SPLIT_PAK_UNSUPPORTED {archive} reason={verdict}",flush=True)
            continue
        authentic.append((archive,entries))
    report=[]
    spans={}
    for requested in sorted(wanted):
        sources=[]
        for archive,entries in authentic:
            for internal,record in entries.items():
                if internal.replace("\\","/").lstrip("/").lower().endswith(requested.lower()):
                    sources.append((archive,internal,record))
        if not sources:
            print(f"ORIGINAL_541_ASSET_UNAVAILABLE {requested}",flush=True)
            continue
        if len(sources)!=1:
            raise RuntimeError(f"ambiguous archive ownership for {requested}: {[(s[0],s[1]) for s in sources]}")
        archive,internal,record=sources[0]
        offset,stored,unpacked,method,digest,encrypted=record
        if encrypted or method or stored!=unpacked or stored>64*1024*1024:
            print(f"ORIGINAL_541_ASSET_UNSUPPORTED {requested} archive={archive} method={method} encrypted={encrypted} sizes={stored}/{unpacked}",flush=True)
            continue
        header_and_payload=ranged(f"{BASE}/{archive}",offset,stored+53)
        h=header_and_payload[:53]
        payload=header_and_payload[53:]
        if len(h)!=53 or struct.unpack_from("<QQQI",h,0)[1:]!=(stored,unpacked,0):
            raise ValueError(f"source FPakEntry header mismatch {requested}")
        if h[28:48]!=digest or hashlib.sha1(payload).digest()!=digest:
            raise ValueError(f"source entry SHA1 mismatch {requested}")
        dest=args.destination/"FortniteGame"/"Content"/requested
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(payload)
        spans.setdefault(archive,[]).append((offset,stored+53))
        record_out={"path":str(dest),"original_pak":archive,"archived_name":internal,
                    "size":len(payload),"sha1":digest.hex()}
        report.append(record_out)
        print(f"ORIGINAL_541_ASSET_VERIFIED {archive} {requested} bytes={len(payload)} sha1={digest.hex()}",flush=True)
    args.destination.mkdir(parents=True,exist_ok=True)
    (args.destination/"verified-541-source-manifest.json").write_text(json.dumps(report,indent=2))
    print(f"ORIGINAL_541_REMOTE_SOURCE_CLOSURE authenticated_archives={len(authentic)} verified_files={len(report)} original_bytes={sum(i['size'] for i in report)}",flush=True)
    if args.sparse_retail_paks:
        # Reproduce the retail PAK logical size, original encrypted index,
        # footer and authenticated source entry spans. Every other offset
        # remains a hole in a sparse file; no full PAK is downloaded.
        args.sparse_retail_paks.mkdir(parents=True,exist_ok=True)
        for archive,offsets in spans.items():
            name,size,status=head(archive)
            if size is None:
                raise RuntimeError(f"original source archive {archive} missing: {status}")
            url=f"{BASE}/{archive}"
            footer=ranged(url,size-61,61)
            index_at,index_size=struct.unpack_from("<QQ",footer,25)
            encrypted_index=ranged(url,index_at,index_size)
            output=args.sparse_retail_paks/archive
            with output.open("w+b") as out:
                out.truncate(size)
                out.seek(index_at)
                out.write(encrypted_index)
                out.seek(size-61)
                out.write(footer)
                for source_offset,span_size in sorted(set(offsets)):
                    out.seek(source_offset)
                    out.write(ranged(url,source_offset,span_size))
            print(f"ORIGINAL_541_SPARSE_SOURCE_ARCHIVE_VERIFIED archive={archive} logical_bytes={size} exact_entry_spans={len(set(offsets))}",flush=True)
        print(f"ORIGINAL_541_SPARSE_RETAIL_PAK_CENSUS archived_files={len(spans)} validated_original_source_entries={sum(len(set(v)) for v in spans.values())}",flush=True)
    if not report:
        raise RuntimeError("no missing source assets retrieved")
if __name__=="__main__":
    main()
