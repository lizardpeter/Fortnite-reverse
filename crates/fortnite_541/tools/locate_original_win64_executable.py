#!/usr/bin/env python3
"""Locate the user's original Fortnite 5.41 Windows PE in the same R2 tree
as the SHA1-authenticated retail PAKs. No binary is uploaded to Git.

Check the exact candidate object paths using bounded HEAD requests. If found,
read only the PE headers with one HTTP Range and report architecture, image
base, original COFF/section identity, and compilation/debug metadata. This
does not claim that code has been decompiled until a PE is retrieved.
"""
from __future__ import annotations
import concurrent.futures
import os
import struct
import sys
import urllib.error
import urllib.request

BASE = "https://r2.houseofkublai.com/Fortnite/5.41/"
NAMES = (
    "FortniteClient-Win64-Shipping.exe",
    "FortniteClient-Win64-Shipping_BE.exe",
    "FortniteClient-Win64-Shipping_EAC.exe",
    "FortniteClient-Win64-Shipping.pdb",
    "FortniteGame-Win64-Shipping.exe",
    "FortniteLauncher.exe",
)
FOLDERS = (
    "FortniteGame/Binaries/Win64/",
    "5.41/FortniteGame/Binaries/Win64/",
    "Binaries/Win64/",
    "",
)
HEAD_TIMEOUT = 12
CANDIDATES = tuple(BASE + directory + name for directory in FOLDERS for name in NAMES)

def head(url: str) -> tuple[str,int | None,str]:
    try:
        req=urllib.request.Request(url,method="HEAD",headers={
            "User-Agent":"Fortnite541-RetailPE-IdentityCheck/1.0"
        })
        with urllib.request.urlopen(req,timeout=HEAD_TIMEOUT) as response:
            length=response.headers.get("Content-Length")
            size=int(length) if length and length.isdigit() else None
            return url,size,f"HTTP {response.status}"
    except urllib.error.HTTPError as exc:
        return url,None,f"HTTP {exc.code}"
    except Exception as exc:
        return url,None,f"ERROR {type(exc).__name__}: {str(exc)[:95]}"

def ranged_header(url: str,bytes_requested: int=65536) -> bytes:
    req=urllib.request.Request(url,headers={
        "Range":f"bytes=0-{bytes_requested-1}",
        "User-Agent":"Fortnite541-RetailPE-IdentityCheck/1.0",
    })
    with urllib.request.urlopen(req,timeout=35) as response:
        if response.status!=206 or not response.headers.get("Content-Range","").startswith("bytes 0-"):
            raise ValueError(f"R2 did not honor bounded range (status={response.status})")
        data=response.read(bytes_requested+1)
    if len(data)>bytes_requested:raise ValueError("source R2 range exceeded maximum")
    return data

def pe_headers(data:bytes) -> dict:
    if len(data)<0x100 or data[:2]!=b"MZ":
        raise ValueError("original object does not start with an MS-DOS MZ header")
    pe=struct.unpack_from("<I",data,0x3c)[0]
    if pe+24>len(data) or data[pe:pe+4]!=b"PE\\0\\0".replace(b"\\0",b"\0"):
        raise ValueError("missing PE signature inside bounded original header")
    machine,sections,timestamp,_,_,opt_size,characteristics=struct.unpack_from("<HHIIIHH",data,pe+4)
    opt=pe+24
    if opt+opt_size>len(data):raise ValueError("partial optional header")
    magic=struct.unpack_from("<H",data,opt)[0]
    if magic!=0x20b:raise ValueError(f"not a 64-bit PE32+ executable: magic=0x{magic:x}")
    image_base=struct.unpack_from("<Q",data,opt+24)[0]
    image_size=struct.unpack_from("<I",data,opt+56)[0]
    hdr_size=struct.unpack_from("<I",data,opt+60)[0]
    subsystem=struct.unpack_from("<H",data,opt+68)[0]
    table=opt+opt_size
    records=[]
    for i in range(sections):
        pos=table+i*40
        if pos+40>len(data):raise ValueError("section table extends past first 64KiB")
        name=data[pos:pos+8].split(b"\0",1)[0].decode("ascii","replace")
        virtual_size,virtual_addr,raw_size,raw_ptr=struct.unpack_from("<IIII",data,pos+8)
        records.append({"name":name,"rva":hex(virtual_addr),"virtual_bytes":virtual_size,
            "file_offset":raw_ptr,"file_bytes":raw_size})
    return {"machine":hex(machine),"section_count":sections,"timestamp":timestamp,
        "image_base":hex(image_base),"image_size":image_size,
        "headers_size":hdr_size,"characteristics":hex(characteristics),
        "subsystem":subsystem,"sections":records}

def main()->int:
    print("RETAIL_541_PE_LOCATOR original_source_base="+BASE,flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        responses=list(pool.map(head,CANDIDATES))
    for url,size,state in responses:
        if size is not None:
            print(f"RETAIL_541_PE_FOUND url={url} content_length={size} {state}",flush=True)
        elif state!="HTTP 404":
            print(f"RETAIL_541_PE_UNCERTAIN url={url} {state}",flush=True)
    found=[(url,size) for url,size,_ in responses if size is not None]
    exe=[(url,size) for url,size in found if url.lower().endswith(".exe")]
    print(f"RETAIL_541_PE_SCAN candidates={len(CANDIDATES)} present={len(found)} original_executables={len(exe)}",flush=True)
    for url,size in exe:
        try:
            header=ranged_header(url)
            record=pe_headers(header)
            print("RETAIL_541_PE_VERIFIED",{"url":url,"source_object_bytes":size,**record},flush=True)
        except Exception as exc:
            print(f"RETAIL_541_PE_CANNOT_VALIDATE url={url} reason={exc}",flush=True)
    if not exe:
        print("RETAIL_541_PE_NOT_AT_TESTED_PATHS: No executable was found at the "
              "standard WindowsClient locations. This does NOT prove that the "
              "user's R2 bucket lacks the executable; a nonstandard key may be used.",flush=True)
    return 0

if __name__=="__main__":
    sys.exit(main())
