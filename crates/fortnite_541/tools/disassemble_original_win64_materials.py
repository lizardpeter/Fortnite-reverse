#!/usr/bin/env python3
"""Targeted static x64 disassembly of the user's original 5.41 shipping EXE.

Runs on a temporary GitHub runner. Downloads the authentic publicly available
R2 PE to /tmp and NEVER uploads or commits binary data. Reports original
section SHA256, source material/shader string RVAs, RIP-relative code references,
.pdata original function extents, and bounded disassembly around those refs.
This is actual retail machine-code evidence, NOT UE4 function name guessing.
"""
from __future__ import annotations
import bisect
import collections
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
import urllib.request

URL="https://r2.houseofkublai.com/Fortnite/5.41/FortniteGame/Binaries/Win64/FortniteClient-Win64-Shipping.exe"
MAX_EXE=112*1024*1024
KEYWORDS=(
    "materialshadermap","shader map","shadermap",
    "shaderresource","shadercode","shaderpipeline","shaderformat",
    "uniformexpression","uniform buffer","uniformbuffer",
    "materialexpression","materialinstance","materialrender",
    "materialshader","materialfunction","materialquality",
    "materialparameter","materialtexture","materialinterface",
    "serializeinlineshadermap","materialserialization",
    "pcd3d_sm5","d3d11","globalshader","shadermeta","shaderpermutation",
    "shadercompiler","shaderparameters","shadertype","shaderidentifier",
    "textureparameter","samplerstate","materialtemplate",
    "unable to find shader","failed to find shader",
)

def read_exe()->bytes:
    req=urllib.request.Request(URL,headers={"User-Agent":"Fortnite541-SourceDisassembly/1.0"})
    with urllib.request.urlopen(req,timeout=120) as resp:
        size=resp.headers.get("Content-Length")
        if size and int(size)>MAX_EXE:raise RuntimeError("Source binary exceeds bounded PE download")
        data=resp.read(MAX_EXE+1)
        if len(data)>MAX_EXE:raise RuntimeError("Original source binary over limit")
    return data

def u16(b,p):return struct.unpack_from("<H",b,p)[0]
def u32(b,p):return struct.unpack_from("<I",b,p)[0]

class PE:
    def __init__(self,b):
        self.b=b
        if b[:2]!=b"MZ":raise RuntimeError("not an MZ executable")
        pe=u32(b,0x3c)
        if b[pe:pe+4]!=b"PE\0\0":raise RuntimeError("original file is not PE")
        if u16(b,pe+4)!=0x8664:raise RuntimeError("not AMD64")
        n=u16(b,pe+6);size=u16(b,pe+20);opt=pe+24
        if u16(b,opt)!=0x20b:raise RuntimeError("not PE32+")
        self.image_base=struct.unpack_from("<Q",b,opt+24)[0]
        self.sections=[]
        p=opt+size
        for i in range(n):
            vsize,rva,rsize,off=struct.unpack_from("<IIII",b,p+8+i*40)
            name=b[p+i*40:p+i*40+8].split(b"\0")[0].decode("ascii","replace")
            self.sections.append(dict(name=name,rva=rva,vsize=vsize,off=off,rsize=rsize))
    def offset_to_rva(self,off):
        for s in self.sections:
            if s["off"]<=off<s["off"]+s["rsize"]:
                return s["rva"]+off-s["off"]
        return None
    def rva_to_offset(self,rva):
        for s in self.sections:
            if s["rva"]<=rva<s["rva"]+s["rsize"]:
                return s["off"]+rva-s["rva"]
        return None
    def section_bytes(self,section):
        return self.b[section["off"]:section["off"]+section["rsize"]]

def strings(pe):
    entries={}
    keyword_hits=collections.Counter()
    search_sections=[x for x in pe.sections if x["name"] in (".rdata",".data","_RDATA")]
    for section in search_sections:
        data=pe.section_bytes(section)
        for m in re.finditer(rb"[\x20-\x7e]{8,}",data):
            raw=m.group(0)
            text=raw.decode("ascii","replace")
            lowered=text.lower()
            relevant=tuple(w for w in KEYWORDS if w in lowered)
            if not relevant:continue
            rva=section["rva"]+m.start()
            entries[rva]=dict(rva=rva,text=text[:220],section=section["name"],keywords=relevant)
            keyword_hits.update(relevant)
        # UTF16LE retail logging strings, only plausible printable UTF16.
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){8,}",data):
            raw=m.group(0)
            text=raw.decode("utf-16le","replace")
            lowered=text.lower()
            relevant=tuple(w for w in KEYWORDS if w in lowered)
            if not relevant:continue
            rva=section["rva"]+m.start()
            entries[rva]=dict(rva=rva,text=text[:220],section=section["name"],keywords=relevant)
            keyword_hits.update(relevant)
    return entries,keyword_hits

def runtime_functions(pe):
    entries=[]
    for section in pe.sections:
        if section["name"]!=".pdata":continue
        data=pe.section_bytes(section)
        for i in range(0,len(data)-11,12):
            begin,end,unwind=struct.unpack_from("<III",data,i)
            if begin>=end or end>0x80000000:continue
            entries.append((begin,end,unwind))
    entries.sort()
    return entries,[v[0] for v in entries]

def find_lea_code_xrefs(pe,entries):
    refs=[]
    # 64-bit RIP-relative LEA/MOV, one signed 32-bit displacement.
    # Validate actual instruction in disassembler after filtering.
    for section in pe.sections:
        if section["name"]!=".text":continue
        data=pe.section_bytes(section)
        pattern=re.compile(rb"[\x48-\x4f][\x8b\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")
        for match in pattern.finditer(data):
            start=match.start()
            if start+7>len(data):continue
            displacement=struct.unpack_from("<i",data,start+3)[0]
            instruction_rva=section["rva"]+start
            target=instruction_rva+7+displacement
            item=entries.get(target)
            if item is not None:
                refs.append(dict(code_rva=instruction_rva,target_rva=target,
                    target=item["text"],section=section["name"],opcode=data[start:start+3].hex()))
    return refs

def best_targets(pe,functions,begins,refs,cap=35):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    by_function={}
    for ref in refs:
        pos=bisect.bisect_right(begins,ref["code_rva"])-1
        if pos<0 or not(functions[pos][0]<=ref["code_rva"]<functions[pos][1]):continue
        start,end,_=functions[pos]
        key=(start,end)
        by_function.setdefault(key,[]).append(ref)
    result=[]
    ordered=sorted(by_function.items(),key=lambda item:(
        -len(set(ref["target"] for ref in item[1])),
        -len(item[1]),item[0][0]))
    for (start,end),references in ordered[:cap]:
        size=end-start
        if size<=0 or size>200_000:continue
        code_off=pe.rva_to_offset(start)
        if code_off is None:continue
        # Restrict displayed disassembly to bounded instructions around each
        # confirmed string reference. This is the original x64 PE .text,
        # not inferred C++ or a fabricated original function.
        probes=[]
        for reference in references[:5]:
            centre=reference["code_rva"]
            begin=max(start,centre-56)
            stop=min(end,centre+120)
            off=pe.rva_to_offset(begin)
            if off is None:continue
            block=pe.b[off:off+(stop-begin)]
            instructions=[]
            for ins in decoder.disasm(block,pe.image_base+begin):
                if ins.address<pe.image_base+centre-25:continue
                instructions.append(f"{ins.address:016x}: {ins.mnemonic} {ins.op_str}".strip())
                if len(instructions)>=17:break
            probes.append(dict(reference_rva=hex(centre),
                original_string=reference["target"][:150],instructions=instructions))
        result.append(dict(start_rva=hex(start),end_rva=hex(end),
            function_bytes=size,string_references=len(references),
            unique_strings=sorted(set(x["target"][:160] for x in references))[:18],
            disassembly=probes))
    return result,len(by_function)

def main():
    print("ORIGINAL_541_X64_STATIC_DISASSEMBLY downloading original PE to temporary runner only",flush=True)
    exe=read_exe()
    sha=hashlib.sha256(exe).hexdigest()
    pe=PE(exe)
    names,kcount=strings(pe)
    funcs,begins=runtime_functions(pe)
    refs=find_lea_code_xrefs(pe,names)
    regions,referenced_functions=best_targets(pe,funcs,begins,refs)
    result=dict(
        origin=URL,
        pe_size_bytes=len(exe),sha256=sha,
        image_base=hex(pe.image_base),sections=pe.sections,
        runtime_function_boundaries=len(funcs),
        material_shader_string_count=len(names),
        keyword_counts=dict(kcount.most_common()),
        direct_rip_code_references=len(refs),
        original_functions_referring_to_strings=referenced_functions,
        original_string_examples=sorted(names.values(),
            key=lambda x:("shadermap" not in x["text"].lower(),
                "materialshader" not in x["text"].lower(),len(x["text"])))[:180],
        original_functions_disassembled=regions,
    )
    output=os.environ.get("FORTNITE_PE_RESULTS","/tmp/fortnite541-original-x64-analysis.json")
    with open(output,"w") as f:json.dump(result,f,indent=2)
    print("ORIGINAL_541_X64_RESULT sha256="+sha+" file_bytes="+str(len(exe))+
        " pdata_functions="+str(len(funcs))+
        " material_shader_strings="+str(len(names))+
        " x64_rip_references="+str(len(refs))+
        " referenced_functions="+str(referenced_functions),flush=True)
    print("ORIGINAL_541_X64_KEYWORDS "+str(kcount.most_common(20)),flush=True)
    for region in regions[:12]:
        print(f"ORIGINAL_541_X64_FUNCTION {region['start_rva']}-{region['end_rva']} references={region['string_references']} original_string_examples={region['unique_strings'][:4]}",flush=True)
        for block in region["disassembly"][:2]:
            print("  SOURCE_REF "+block["reference_rva"]+" "+block["original_string"][:90],flush=True)
            for asm in block["instructions"][:12]:
                print("    "+asm,flush=True)
    print("ORIGINAL_541_X64_REPORT "+output+" (metadata + disassembly only; no executable uploaded)",flush=True)
if __name__=="__main__":
    main()
