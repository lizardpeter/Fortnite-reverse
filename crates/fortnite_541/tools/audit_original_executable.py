#!/usr/bin/env python3
"""Read-only, SHA-verified PE study of the original Fortnite 5.41 client.
Never executes the executable or publishes its original binary bytes.
"""
import argparse
import collections
import hashlib
import json
import math
import pathlib
import statistics
import struct

SHA="7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"
SIZE=97284496

def entropy(buf):
    if not buf:return 0.
    counts=collections.Counter(buf); n=len(buf)
    return round(-sum((v/n)*math.log2(v/n) for v in counts.values()),4)

def sha256(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for part in iter(lambda:f.read(2**20),b""):h.update(part)
    return h.hexdigest()

def audit(p):
    import pefile
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    from capstone.x86_const import X86_INS_CALL,X86_OP_IMM
    actual_sha=sha256(p)
    if actual_sha!=SHA or p.stat().st_size!=SIZE:
        raise ValueError("Original source SHA-256 or size mismatch; refusing audit")
    pe=pefile.PE(str(p))
    if pe.FILE_HEADER.Machine!=0x8664 or pe.OPTIONAL_HEADER.Magic!=0x20b:
        raise ValueError("Original is not a PE32+ AMD64 executable")
    base=int(pe.OPTIONAL_HEADER.ImageBase)
    entry=int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    sections=[]
    for s in pe.sections:
        name=s.Name.rstrip(b"\0").decode("ascii","replace")
        sections.append(dict(name=name,rva=hex(int(s.VirtualAddress)),
            raw_size=int(s.SizeOfRawData),raw_offset=int(s.PointerToRawData),
            virtual_size=int(s.Misc_VirtualSize),entropy=entropy(s.get_data()),
            executable=bool(s.Characteristics&0x20000000),writable=bool(s.Characteristics&0x80000000),
            entrypoint=int(s.VirtualAddress)<=entry<int(s.VirtualAddress)+max(int(s.Misc_VirtualSize),int(s.SizeOfRawData))))
    exe_ranges=[(int(s.VirtualAddress),int(s.VirtualAddress)+max(int(s.Misc_VirtualSize),int(s.SizeOfRawData))) for s in pe.sections if s.Characteristics&0x20000000]
    exc=pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    pdata=pe.get_data(exc.VirtualAddress,exc.Size)
    records=[struct.unpack_from("<III",pdata,i) for i in range(0,len(pdata)-11,12)]
    valid=[(a,b,u) for a,b,u in records if 0<a<b]
    starts={a for a,b,u in valid}
    lengths=sorted(b-a for a,b,u in valid)
    selected=set(range(min(10,len(valid))))
    if valid:selected.update(int(i*(len(valid)-1)/255) for i in range(256))
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    counters=collections.Counter();examples=[]
    for idx in sorted(selected):
        start,end,_=valid[idx]
        raw=pe.get_data(start,min(end-start,2048))
        insns=list(md.disasm(raw,base+start))
        counters["sampled_ranges"]+=1
        counters["sampled_bytes"]+=len(raw)
        counters["decoded_bytes"]+=sum(i.size for i in insns)
        counters["empty_disassemblies"]+=not bool(insns)
        for i in insns:
            if i.id==X86_INS_CALL and i.operands and i.operands[0].type==X86_OP_IMM:
                counters["direct_calls"]+=1
                target=int(i.operands[0].imm)-base
                if target in starts:counters["exact_pdata_entry_calls"]+=1
                elif any(lo<=target<hi for lo,hi in exe_ranges):counters["other_executable_calls"]+=1
                else:counters["outside_executable_calls"]+=1
        if len(examples)<20:
            examples.append(dict(ordinal=idx,start_rva=hex(start),end_rva=hex(end),
                decoded_bytes=sum(i.size for i in insns),source_bytes=len(raw),
                instructions=[dict(rva=hex(i.address-base),mnemonic=i.mnemonic,operands=i.op_str,hex=i.bytes.hex()) for i in insns[:10]]))
    imports=[]
    for d in getattr(pe,"DIRECTORY_ENTRY_IMPORT",[]):
        imports.append(dict(dll=d.dll.decode("ascii","replace") if d.dll else "<unknown>",
            count=len(d.imports),samples=[x.name.decode("ascii","replace") if x.name else "#"+str(x.ordinal) for x in d.imports[:8]]))
    buf=p.read_bytes()
    patterns=[b"Unreal",b"UE4",b"Fortnite",b"FortniteGame",b"/Game/",b"/Engine/",b"FMaterial",b".pdb"]
    end_of_sections=max((int(s.PointerToRawData)+int(s.SizeOfRawData) for s in pe.sections),default=0)
    result=dict(
        kind="authenticated_read_only_static_pe_audit_not_runtime_analysis",
        source_sha256=actual_sha,file_size=buf.__len__(),
        headers=dict(machine=hex(pe.FILE_HEADER.Machine),image_base=hex(base),
            entry_rva=hex(entry),entry_section=next((x["name"] for x in sections if x["entrypoint"]),None),
            image_size=int(pe.OPTIONAL_HEADER.SizeOfImage),size_of_code=int(pe.OPTIONAL_HEADER.SizeOfCode),
            overlay_bytes=max(0,len(buf)-end_of_sections)),
        sections=sections,imports=imports,
        pdata=dict(directory_size=int(exc.Size),raw_records=len(records),valid_records=len(valid),
            distinct_starts=len(starts),starts_in_executable_sections=sum(any(lo<=a<hi for lo,hi in exe_ranges) for a in starts),
            min_range=lengths[0] if lengths else 0,median_range=statistics.median(lengths) if lengths else 0,
            p90_range=lengths[int((len(lengths)-1)*.9)] if lengths else 0,
            at_most_16_bytes=sum(n<=16 for n in lengths),at_most_64_bytes=sum(n<=64 for n in lengths)),
        code_sample=dict(counters,examples=examples),
        strings={p.decode():buf.count(p) for p in patterns},
        caveats=["Unwind entries are NOT automatically genuine decompiled function bodies.",
            "Linear x64 disassembly can decode junk data as instructions.",
            "High section entropy alone cannot prove executable encryption or packing.",
            "No runtime memory comparison was performed.","Only source SHA-256 authenticates the exact binary."])
    return result

def markdown(r):
    h=r["headers"];p=r["pdata"];c=r["code_sample"]
    lines=["# Fortnite 5.41 original PE audit","",
        "Downloaded and SHA-256-verified the original 97 MB executable on an ephemeral GitHub-hosted runner. Static inspection only; no execution and no upload of the binary.","",
        "## Source","SHA-256: "+r["source_sha256"],"Size: "+str(r["file_size"]),"",
        "## PE","Entrypoint: "+h["entry_rva"]+" ("+str(h["entry_section"])+")",
        "Raw SizeOfCode: "+str(h["size_of_code"]),"Overlay bytes: "+str(h["overlay_bytes"]),"",
        "| Section | Size | Entropy | Executable |","|---|---:|---:|---|"]
    for s in r["sections"]:
        lines.append("| "+s["name"]+" | "+str(s["raw_size"])+" | "+str(s["entropy"])+" | "+str(s["executable"])+" |")
    lines += ["","## Unwind index","Valid ranges: "+str(p["valid_records"]),
        "Unique start RVAs: "+str(p["distinct_starts"]),"In executable sections: "+str(p["starts_in_executable_sections"]),
        "Median range: "+str(p["median_range"])+" bytes",
        "At most 16 bytes: "+str(p["at_most_16_bytes"]),"At most 64 bytes: "+str(p["at_most_64_bytes"]),"",
        "## Machine-code sample",
        "Sampled ranges: "+str(c.get("sampled_ranges",0)),"Source bytes sampled: "+str(c.get("sampled_bytes",0)),
        "Linearly decoded bytes: "+str(c.get("decoded_bytes",0)),
        "Direct calls: "+str(c.get("direct_calls",0)),
        "Calls to exact .pdata starts: "+str(c.get("exact_pdata_entry_calls",0)),
        "Other executable call targets: "+str(c.get("other_executable_calls",0)),
        "Targets outside executable sections: "+str(c.get("outside_executable_calls",0)),"",
        "## Imported DLLs",", ".join(i["dll"] for i in r["imports"]),"",
        "## Raw ASCII markers",", ".join(k+": "+str(v) for k,v in r["strings"].items()),"",
        "## Caution","This audit cannot prove absence of runtime decryption. Match original machine instructions against Unreal Engine source before trusting Ghidra pseudocode.","",
        "Full machine-code excerpts, section data and imports are in the JSON report."]
    return "\n".join(lines)+"\n"

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--exe",type=pathlib.Path)
    ap.add_argument("--out",type=pathlib.Path)
    ap.add_argument("--self-test",action="store_true")
    args=ap.parse_args()
    if args.self_test:
        assert entropy(bytes(100))==0
        assert entropy(bytes(range(256)))==8
        print("FORTNITE541_PE_AUDIT_SELF_TEST_PASSED")
        return
    if not args.exe or not args.out:ap.error("Require --exe and --out")
    args.out.mkdir(parents=True,exist_ok=True)
    r=audit(args.exe)
    (args.out/"fortnite541_pe_audit.json").write_text(json.dumps(r,indent=2)+"\n")
    (args.out/"fortnite541_pe_audit.md").write_text(markdown(r))
    print("FORTNITE541_ORIGINAL_PE_AUDIT_COMPLETE",r["source_sha256"],r["pdata"]["valid_records"])

if __name__=="__main__":
    main()
