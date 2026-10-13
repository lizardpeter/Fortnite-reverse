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
            entries[rva]=dict(rva=rva,byte_len=len(raw),text=text[:220],section=section["name"],keywords=relevant)
            keyword_hits.update(relevant)
        # UTF16LE retail logging strings, only plausible printable UTF16.
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){8,}",data):
            raw=m.group(0)
            text=raw.decode("utf-16le","replace")
            lowered=text.lower()
            relevant=tuple(w for w in KEYWORDS if w in lowered)
            if not relevant:continue
            rva=section["rva"]+m.start()
            entries[rva]=dict(rva=rva,byte_len=len(raw),text=text[:220],section=section["name"],keywords=relevant)
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

def material_string_pointer_table(pe,entries):
    """Real PE relocatable pointers into original shader/material strings.

    Unreal uses global FName/RTTI structures, many of which reference
    UTF16/ANSI strings indirectly through RVA-addressed pointer tables.
    Only exact original address matches are promoted to evidence.
    """
    by_va={pe.image_base+rva:entry for rva,entry in entries.items()}
    pointers={}
    total=0
    for section in pe.sections:
        if section["name"] not in (".rdata",".data","_RDATA"):continue
        data=pe.section_bytes(section)
        for offset in range(0,len(data)-7,8):
            total+=1
            ptr=struct.unpack_from("<Q",data,offset)[0]
            source=by_va.get(ptr)
            if source is None:continue
            pointers[section["rva"]+offset]=source
    return pointers,total

def find_lea_code_xrefs(pe,entries,pointers):
    refs=[]
    matched_instructions=0
    indirect_hits=0
    near_hits=0
    strings=sorted(entries)
    source_total=len(entries)
    pointer_targets=collections.Counter()
    rdata_examples=[]
    # 64-bit RIP-relative LEA/MOV, one signed 32-bit displacement.
    # Validate actual instruction in disassembler after filtering.
    for section in pe.sections:
        if section["name"]!=".text":continue
        data=pe.section_bytes(section)
        pattern=re.compile(rb"[\x48-\x4f][\x8b\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")
        for match in pattern.finditer(data):
            matched_instructions+=1
            start=match.start()
            if start+7>len(data):continue
            displacement=struct.unpack_from("<i",data,start+3)[0]
            instruction_rva=section["rva"]+start
            target=instruction_rva+7+displacement
            for target_section in pe.sections:
                if target_section["rva"]<=target<target_section["rva"]+target_section["vsize"]:
                    pointer_targets[target_section["name"]]+=1
                    if target_section["name"]==".rdata" and len(rdata_examples)<15:
                        offset=pe.rva_to_offset(target)
                        sample=pe.b[offset:offset+45] if offset is not None else b""
                        rdata_examples.append(dict(
                            code_rva=hex(instruction_rva),target_rva=hex(target),
                            raw=repr(sample[:35])
                        ))
                    break
            item=entries.get(target)
            proof="direct-LEA"
            if item is None and target in pointers:
                item=pointers[target]
                indirect_hits+=1
                proof="original-VA-string-pointer"
            if item is None:
                index=bisect.bisect_right(strings,target)-1
                if index>=0:
                    start= strings[index]
                    candidate=entries[start]
                    if start<=target<start+candidate["byte_len"]:
                        item=candidate
                        near_hits+=1
                        proof="original-string-interior"
            if item is not None:
                refs.append(dict(code_rva=instruction_rva,target_rva=target,
                    target=item["text"],section=section["name"],
                    reference_type=proof,opcode=data[start:start+3].hex()))
    return refs,dict(
        inspected_original_material_strings=source_total,
        relocatable_string_pointers=len(pointers),
        indirect_pointer_code_references=indirect_hits,
        exact_string_interior_refs=near_hits,
        candidate_rip_relative_instructions=matched_instructions,
        target_section_counts=dict(pointer_targets),
        rdata_reference_samples=rdata_examples,
    )

def full_x64_ip_relative_xrefs(pe,entries,pointers):
    """Real decoded x64 RIP-relative memory references in original .text."""
    from iced_x86 import Decoder
    keys=sorted(entries)
    refs=[]
    counters=collections.Counter()
    for section in pe.sections:
        if section["name"]!=".text":continue
        decoder=Decoder(64,pe.section_bytes(section),ip=pe.image_base+section["rva"])
        for inst in decoder:
            counters["original_x64_instructions_decoded"]+=1
            if not inst.is_ip_rel_memory_operand:continue
            counters["original_x64_rip_operand_count"]+=1
            original_rva=inst.ip_rel_memory_address-pe.image_base
            item=entries.get(original_rva)
            proof="original-x64-direct"
            if item is None:
                item=pointers.get(original_rva)
                if item is not None:proof="original-PE-VA-pointer"
            if item is None:
                i=bisect.bisect_right(keys,original_rva)-1
                if i>=0:
                    key=keys[i]
                    match=entries[key]
                    if key<=original_rva<key+match["byte_len"]:
                        item=match
                        proof="original-x64-string-interior"
            if item is None:continue
            counters[proof]+=1
            refs.append(dict(code_rva=inst.ip-pe.image_base,
                target_rva=original_rva,target=item["text"],
                section=section["name"],opcode=hex(inst.code),
                reference_type=proof))
    return refs,dict(counters)

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
            # Disassemble from the verified .pdata *function entry*, never
            # an arbitrary centre-56 offset (which can begin halfway through
            # an x64 instruction and produce fabricated-looking mnemonics).
            begin=start
            stop=min(end,centre+160)
            off=pe.rva_to_offset(begin)
            if off is None:continue
            block=pe.b[off:off+(stop-begin)]
            decoded=list(decoder.disasm(block,pe.image_base+begin))
            index=next((i for i,ins in enumerate(decoded)
                if ins.address<=pe.image_base+centre<ins.address+ins.size),None)
            if index is None:continue
            nearby=decoded[max(0,index-9):index+12]
            instructions=[f"{ins.address:016x}: {ins.mnemonic} {ins.op_str}".strip()
                for ins in nearby]
            probes.append(dict(reference_rva=hex(centre),
                original_string=reference["target"][:150],
                reference_kind=reference.get("reference_type"),
                instructions=instructions))
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
    pointers,inspected_pointers=material_string_pointer_table(pe,names)
    manual_refs,scan_metrics=find_lea_code_xrefs(pe,names,pointers)
    refs,x64_metrics=full_x64_ip_relative_xrefs(pe,names,pointers)
    scan_metrics["source_pointer_slots_checked"]=inspected_pointers
    scan_metrics["narrow_RIP_candidate_refs"]=len(manual_refs)
    scan_metrics.update(x64_metrics)
    regions,referenced_functions=best_targets(pe,funcs,begins,refs)
    result=dict(
        origin=URL,
        pe_size_bytes=len(exe),sha256=sha,
        image_base=hex(pe.image_base),sections=pe.sections,
        runtime_function_boundaries=len(funcs),
        material_shader_string_count=len(names),
        keyword_counts=dict(kcount.most_common()),
        direct_rip_code_references=len(refs),rip_scan_diagnostics=scan_metrics,
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
    print("ORIGINAL_541_X64_RIP_DIAGNOSTICS "+str(scan_metrics),flush=True)
    for region in regions[:12]:
        print(f"ORIGINAL_541_X64_FUNCTION {region['start_rva']}-{region['end_rva']} references={region['string_references']} original_string_examples={region['unique_strings'][:4]}",flush=True)
        for block in region["disassembly"][:2]:
            print("  SOURCE_REF "+block["reference_rva"]+" "+block["original_string"][:90],flush=True)
            for asm in block["instructions"][:12]:
                print("    "+asm,flush=True)
    print("ORIGINAL_541_X64_REPORT "+output+" (metadata + disassembly only; no executable uploaded)",flush=True)
if __name__=="__main__":
    main()
