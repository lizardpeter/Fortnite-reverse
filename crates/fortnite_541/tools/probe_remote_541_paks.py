#!/usr/bin/env python3
"""Discover original 5.41 public-R2 PAKs and authenticate their encrypted
UE4 index before reporting missing Fortnite landscape shader / sky assets.
Source-only offline analysis in a public runner, NEVER in game hot paths.
Does not fetch full PAKs or commit proprietary asset bytes.
"""
from __future__ import annotations
import concurrent.futures
import hashlib
import os
import pathlib
import re
import subprocess
import tempfile
from fetch_athena_541 import HISTORICAL_KEY, MAGIC, index_entries

BASE = "https://r2.houseofkublai.com/Fortnite/5.41/FortniteGame/Content/Paks"
TARGETS = [
    "/TimeOfDay/TODM/BR/TODM_BR.uasset",
    "/TimeOfDay/TODM/BR/TODM_BR.uexp",
    "/Environments/World/Backgrounds/Transylvania/Meshes/TRV_Skybox_Mountain_04.uasset",
    "/Environments/World/Backgrounds/Transylvania/Meshes/TRV_Skybox_Mountain_04.uexp",
    "/ContentCreationTools/TextureCreation/Textures/T_BPCreated_MacroNormal_01.uasset",
    "/ContentCreationTools/TextureCreation/Textures/T_BPCreated_MacroNormal_01.uexp",
    "/Environments/AutumnDecay/Terrain/Textures/T_Grass_AD_D.uasset",
    "/Environments/AutumnDecay/Terrain/Textures/T_Grass_AD_D.uexp",
]
def curl(args: list[str], *, timeout: int=30) -> bytes:
    p=subprocess.run(["curl","--silent","--show-error","--location",
                      "--retry","2","--retry-delay","1",
                      "--connect-timeout","6","--max-time",str(timeout),*args],
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    timeout=timeout+6)
    if p.returncode:
        raise RuntimeError(p.stderr.decode("utf8","replace")[-220:])
    return p.stdout
def head(filename: str):
    url=f"{BASE}/{filename}"
    try:
        raw=curl(["--head","--fail",url],timeout=14).decode("utf8","replace")
        chunks=re.split(r"\r?\n\r?\n",raw.strip())
        headers=chunks[-1]
        status=headers.splitlines()[0]
        match=re.search(r"(?im)^content-length:\s*([0-9]+)",headers)
        size=int(match.group(1)) if match else None
        if size is None or size<61:
            return (filename,None,f"response {status}; no valid content-length")
        return (filename,size,"ok")
    except Exception as e:
        return (filename,None,str(e)[:110])
def ranged(url: str, offset:int, length:int) -> bytes:
    if length<=0 or length>64*1024*1024 or offset<0:
        raise ValueError("invalid bounded original source PAK range")
    blob=curl(["--fail","--range",f"{offset}-{offset+length-1}",url],timeout=40)
    if len(blob)!=length:
        raise ValueError(f"server did not honor exact original PAK range, asked {length} got {len(blob)}")
    return blob
def authenticated_index(filename:str,size:int, key:str):
    url=f"{BASE}/{filename}"
    tail=ranged(url,size-61,61)
    import struct
    if struct.unpack_from("<I",tail,17)[0]!=MAGIC or struct.unpack_from("<I",tail,21)[0]!=7:
        return None,"non-UE4-v7-footer (not silently assuming source compatibility)"
    offset,length=struct.unpack_from("<QQ",tail,25)
    digest=tail[41:61]
    if tail[16]!=1 or length%16 or length>64*1024*1024 or offset+length>size-61:
        return None,"unrecognized encrypted original PAK index bounds"
    ciphertext=ranged(url,offset,length)
    with tempfile.TemporaryDirectory(prefix="fn541-auth-index-") as d:
        enc=pathlib.Path(d)/"enc"
        enc.write_bytes(ciphertext)
        p=subprocess.run(["openssl","enc","-aes-256-ecb","-d","-nopad",
                          "-K",key,"-in",str(enc)],stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
        if p.returncode:
            return None,"encrypted index could not be decrypted"
        plain=p.stdout
    if hashlib.sha1(plain).digest()!=digest:
        return None,"encrypted index SHA1 did not match source footer (wrong key or corrupt source)"
    entries=index_entries(plain)
    return entries,f"verified v7 footer & index SHA1 {digest.hex()}"
def main():
    # Known original main PAK first; common Epic PAK chunk variants probed
    # as DISCOVERY ONLY, never asserted to exist without authenticated HEAD.
    candidates={"pakchunk0-WindowsClient.pak"}
    candidates.update(f"pakchunk{n}-WindowsClient.pak" for n in range(1,41))
    candidates.update(f"pakchunk{n}_s{k}-WindowsClient.pak"
                      for n in range(0,12) for k in range(1,5))
    # Do not chase random URLs or list private objects.
    candidates=sorted(candidates)
    print(f"REMOTE_FORTNITE_DISCOVERY candidate_paths={len(candidates)} base={BASE}",flush=True)
    results=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        for out in pool.map(head,candidates):
            results.append(out)
    present=[(name,size) for name,size,state in results if size is not None]
    for name,size in present:
        print(f"REMOTE_FORTNITE_PAK_PRESENT {name} bytes={size}",flush=True)
    print(f"REMOTE_FORTNITE_PAK_CENSUS authenticated_candidate_paths={len(candidates)} present={len(present)}",flush=True)
    for name,size in present:
        try:
            entries,status=authenticated_index(name,size,os.environ.get("RUST_TEST_FORTNITE_541_AES_KEY",HISTORICAL_KEY))
            print(f"REMOTE_FORTNITE_PAK_INDEX {name} {status} entries={len(entries) if entries is not None else 'unknown'}",flush=True)
            if entries is None:
                continue
            # Different source archives can cook a soft-object reference
            # under an alias or different package naming convention. Search
            # by source-identifying fragments too, without claiming a match.
            print(f"REMOTE_FORTNITE_INDEX_SAMPLE archive={name} samples={list(entries)[:4]}",flush=True)
            fragments=("todm","timeofday","skybox","transylvania","macronormal","grass_ad_d","grasslands","terrain")
            for fragment in fragments:
                hits=[k for k in entries if fragment in k.lower()]
                print(f"REMOTE_FORTNITE_FUZZY archive={name} fragment={fragment} count={len(hits)} samples={hits[:12]}",flush=True)
            for target in TARGETS:
                matches=[(path,record) for path,record in entries.items()
                         if path.replace("\\","/").endswith(target)]
                for path,record in matches:
                    print(f"REMOTE_FORTNITE_ORIGINAL_DEPENDENCY archive={name} source_path={path} offset={record[0]} unpacked={record[2]} compression={record[3]} encrypted={record[5]}",flush=True)
            print(f"REMOTE_FORTNITE_TARGET_CENSUS archive={name} matched_entries={sum(1 for path in entries if any(path.replace(chr(92),'/').endswith(t) for t in TARGETS))}",flush=True)
        except Exception as e:
            print(f"REMOTE_FORTNITE_PAK_INDEX_UNSUPPORTED {name} reason={str(e)[:220]}",flush=True)
    if not present:
        raise RuntimeError("no public original R2 PAK endpoint could be verified; cannot infer other assets exist")
if __name__=="__main__":
    main()
