#!/usr/bin/env python3
"""Bounded, SHA-verified static CFG study of Fortnite 5.41 protection handoffs.

Does NOT execute, patch, emulate, decrypt, or republish the executable.
Only reachable-on-disk instruction candidates are collected; ambiguous paths
are explicitly labeled hypotheses rather than original recovered game code.
"""
from __future__ import annotations
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct

SHA256="7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"
SIZE=97_284_496
ROOTS={"entry_call_handoff":0x4419,
       "secondary_register_guard":0x5C83D4E,
       "secondary_shared_code":0x5BC8859,
       "original_entrypoint":0x351CA98,
       "handoff_branch_body":0xBCF126,
       "shared_code_branch_body":0x5C32A2A,
       "secondary_guard_alignment_branch":0xEB6B64,
       "secondary_guard_nonalign_branch":0x597BC9,
       "handoff_indirect_caller":0x3D0C9,
       "handoff_direct_callee":0x47794,
       "shared_direct_callee":0x5D986DE,
       "shared_global_state_update":0x5BD4B1B,
       "guard_shared_call_gate":0x1568966,
       "executable_write_followon":0x5C4CE84,
       "bytecode_byte_reader":0x5C61E26,
       "handoff_second_stage":0x41522}
MAX_INSTRUCTIONS=1150
MAX_SPAN=4096
MAX_OUTPUT_INSTRUCTIONS=220
BAD_MNEMONICS={"hlt","ud2","int1","iret","iretq","retf","retfq","in","out","insb","insd","outsb","outsd","cli","sti"}

def checked_pe(path):
    import pefile
    h=hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda:stream.read(1<<20),b""):h.update(chunk)
    if h.hexdigest()!=SHA256 or path.stat().st_size!=SIZE:
        raise ValueError("Fortnite original SHA256/size mismatch")
    pe=pefile.PE(str(path),fast_load=False)
    if pe.FILE_HEADER.Machine!=0x8664 or pe.OPTIONAL_HEADER.Magic!=0x20B:
        raise ValueError("Expected original AMD64 PE32+")
    return pe

def load_section(pe,rva):
    for s in pe.sections:
        lo=int(s.VirtualAddress)
        if lo<=rva<lo+int(s.SizeOfRawData):
            return s
    return None

def peek(pe,rva,size=15):
    sec=load_section(pe,rva)
    if sec is None:return b""
    lo=int(sec.VirtualAddress)
    n=min(size,lo+int(sec.SizeOfRawData)-rva)
    return pe.get_data(rva,n)

def import_table(pe):
    imports={}
    for directory in getattr(pe,"DIRECTORY_ENTRY_IMPORT",[]):
        dll=directory.dll.decode("ascii","replace") if directory.dll else "?"
        for item in directory.imports:
            name=item.name.decode("ascii","replace") if item.name else "#"+str(item.ordinal)
            imports[int(item.address)-int(pe.OPTIONAL_HEADER.ImageBase)]=dll+"!"+name
    return imports

def pdata_envelope(pe,root):
    dir=pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    raw=pe.get_data(dir.VirtualAddress,dir.Size)
    begins=[];records=[]
    for off in range(0,len(raw)-11,12):
        start,end,unwind=struct.unpack_from("<III",raw,off)
        if 0<start<end:
            begins.append(start)
            records.append((start,end))
    # Sorted unwind functions are the standard x64 exception table order.
    pairs=sorted(records)
    idx=bisect.bisect_right(pairs,(root,0xFFFFFFFF))-1
    if idx>=0:
        start,end=pairs[idx]
        if start<=root<end:return {"begin":start,"end":end}
    return None

def instructions_at(md,pe,image_base,rva,max_len=15):
    buf=peek(pe,rva,max_len)
    if not buf:return None
    result=list(md.disasm(buf,image_base+rva,count=1))
    if not result or result[0].address!=image_base+rva:return None
    return result[0]

def probe_outbound(md,pe,base,rva):
    s=load_section(pe,rva)
    if s is None:return {"rva":hex(rva),"kind":"not_initialized_image"}
    out=[]
    for i in md.disasm(peek(pe,rva,80),base+rva,count=7):
        out.append({"rva":hex(int(i.address-base)),"op":i.mnemonic,"args":i.op_str})
    return {"rva":hex(rva),"section":s.Name.rstrip(b"\0").decode("ascii","replace"),
            "section_executable":bool(s.Characteristics&0x20000000),"preview":out}

def inspect_root(md,pe,root,label,imports,base):
    from capstone import CS_AC_WRITE
    from capstone.x86_const import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP
    sec=load_section(pe,root)
    if sec is None:raise ValueError("Missing original root: "+label)
    sec_lo=int(sec.VirtualAddress)
    sec_hi=sec_lo+int(sec.SizeOfRawData)
    envelope=pdata_envelope(pe,root)
    # Restrict root to bounded source bytes: prevents incorrectly walking far
    # into packed opaque data after a plausible instruction prefix.
    low=root
    high=min(sec_hi,root+MAX_SPAN)
    if envelope is not None:
        low=max(low,envelope["begin"])
        high=min(high,envelope["end"])
    frontier=[root];visited={};edges=[];outbound=[];candidate_calls=[];writes=[];suspicious=[]
    decoded_bytes=0
    while frontier and len(visited)<MAX_INSTRUCTIONS:
        addr=frontier.pop()
        if addr in visited or not low<=addr<high:continue
        ins=instructions_at(md,pe,base,addr)
        if ins is None:
            suspicious.append({"rva":hex(addr),"reason":"undecodable_at_address"})
            continue
        decoded_bytes+=ins.size
        record={"rva":hex(addr),"op":ins.mnemonic,"args":ins.op_str,"bytes":ins.bytes.hex()}
        visited[addr]=record
        if ins.mnemonic in BAD_MNEMONICS:
            suspicious.append({"rva":hex(addr),"reason":"unlikely_normal_user_mode_instruction","op":ins.mnemonic})
            continue
        destination=None
        for operand in ins.operands:
            if operand.type==X86_OP_MEM:
                mem=operand.mem
                ea=None
                if mem.base==X86_REG_RIP:ea=int(ins.address+ins.size+mem.disp)-base
                iat_name=imports.get(ea)
                if iat_name and ins.mnemonic in ("call","jmp"):
                    candidate_calls.append({"source_rva":hex(addr),"type":"iat_indirect","import":iat_name})
                if operand.access & CS_AC_WRITE:
                    target_section=load_section(pe,ea) if ea is not None else None
                    writes.append({"source_rva":hex(addr),"op":ins.mnemonic,
                        "address_expr":ins.op_str,
                        "rip_resolved_target_rva":hex(ea) if ea is not None else None,
                        "rip_target_executable":bool(target_section and target_section.Characteristics&0x20000000),
                        "target_section":(target_section.Name.rstrip(b"\0").decode("ascii","replace") if target_section else None)})
        if ins.operands and ins.operands[0].type==X86_OP_IMM:
            if ins.mnemonic=="call" or ins.mnemonic.startswith("j") or ins.mnemonic.startswith("loop"):
                destination=int(ins.operands[0].imm)-base
        fallthrough=addr+ins.size
        if ins.mnemonic=="call":
            candidate_calls.append({"source_rva":hex(addr),"type":"direct" if destination is not None else "indirect",
                                    "target_rva":hex(destination) if destination is not None else None})
            frontier.append(fallthrough)
            if destination is not None:outbound.append(destination)
            edges.append({"from":hex(addr),"to":hex(fallthrough),"kind":"call_return_fallthrough"})
        elif ins.mnemonic=="jmp":
            if destination is not None:
                edges.append({"from":hex(addr),"to":hex(destination),"kind":"direct_jump"})
                if low<=destination<high:frontier.append(destination)
                else:outbound.append(destination)
            else:edges.append({"from":hex(addr),"kind":"unresolved_indirect_jump"})
        elif ins.mnemonic.startswith("j") or ins.mnemonic.startswith("loop"):
            if destination is not None:
                edges.append({"from":hex(addr),"to":hex(destination),"kind":"conditional_taken"})
                if low<=destination<high:frontier.append(destination)
                else:outbound.append(destination)
            edges.append({"from":hex(addr),"to":hex(fallthrough),"kind":"conditional_fallthrough"})
            if low<=fallthrough<high:frontier.append(fallthrough)
        elif ins.mnemonic.startswith("ret") or ins.mnemonic in ("int3","syscall","sysenter"):
            edges.append({"from":hex(addr),"kind":"terminal"})
        else:
            if low<=fallthrough<high:frontier.append(fallthrough)
    distinct_outbound=sorted(set(outbound))
    # Distinguish a statically decodable block from actual runtime execution:
    # no branch or call is guaranteed to execute, even when bytes are coherent.
    return {
        "label":label,"root_rva":hex(root),
        "section":sec.Name.rstrip(b"\0").decode("ascii","replace"),
        "source_region":{"begin_rva":hex(low),"end_rva":hex(high),"bytes":high-low},
        "pdata_envelope":({"begin_rva":hex(envelope["begin"]),"end_rva":hex(envelope["end"])} if envelope else None),
        "decoded_instruction_starts":len(visited),"decoded_instruction_bytes":decoded_bytes,
        "truncated_by_limit":len(visited)>=MAX_INSTRUCTIONS,
        "suspicious_stops":suspicious[:50],
        "calls":candidate_calls[:180],"call_count":len(candidate_calls),
        "writes":writes[:180],"write_instruction_count":len(writes),
        "source_writes_to_known_executable_image":sum(x["rip_target_executable"] for x in writes),
        "outbound_targets":[probe_outbound(md,pe,base,a) for a in distinct_outbound[:35]],
        "outbound_target_count":len(distinct_outbound),
        "edge_count":len(edges),"edges":edges[:280],
        "original_instruction_sample":[visited[k] for k in sorted(visited)[:MAX_OUTPUT_INSTRUCTIONS]],
        "caveat":"Paths are statically decoded from original disk bytes, not observed runtime execution."
    }

def run(pe):
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    base=int(pe.OPTIONAL_HEADER.ImageBase)
    imports=import_table(pe)
    studies={}
    for label,root in ROOTS.items():
        studies[label]=inspect_root(md,pe,root,label,imports,base)
    return {
        "source_sha256_verified":SHA256,
        "source_file_bytes":SIZE,
        "analysis":"read_only_static_pe_call_branch_and_memory_access_audit",
        "decode_boundaries":"pData function extent when applicable; otherwise <=4096 initialized executable bytes",
        "candidate_roots":{label:hex(v) for label,v in ROOTS.items()},
        "import_slots_resolved":len(imports),
        "studies":studies,
        "limits":[
            "No runtime memory was inspected, and no encrypted code was decrypted.",
            "A RIP-relative store to an executable section is a statically resolvable destination; dynamic writes are not provable statically.",
            "Static decoded branch targets are hypotheses about reachable code, not evidence they were executed.",
            "Opaque bytes can decode into plausible x86 instructions. Suspicious operations stop individual walks.",
            "The instruction sample is deliberately bounded and does not reproduce full proprietary routines."]
    }

def markdown(report):
    lines=["# Fortnite 5.41 authenticated guarded-execution CFG audit","",
        "Read-only static study of original SHA256-verified shipping EXE. Not an unpacker or a decryption claim.","",
        "| Root | Decoded instruction starts | CALL references | Memory-write operations | RIP writes into executable section | Outbound targets |",
        "|---|---:|---:|---:|---:|---:|"]
    for key,row in report["studies"].items():
        lines.append("| "+key+" ("+row["root_rva"]+") | "+str(row["decoded_instruction_starts"])+" | "+str(row["call_count"])+" | "+str(row["write_instruction_count"])+" | "+str(row["source_writes_to_known_executable_image"])+" | "+str(row["outbound_target_count"])+" |")
    for key,row in report["studies"].items():
        lines+=["","## "+key,"Root RVA: "+row["root_rva"],
            "Static interpretation region: "+row["source_region"]["begin_rva"]+"–"+row["source_region"]["end_rva"],
            "Calls: "+", ".join(x.get("import") or x.get("target_rva") or "unresolved" for x in row["calls"][:25]),
            "Resolved RIP-relative writes into executable section: "+str(row["source_writes_to_known_executable_image"]),
            "Outbound preview targets: "+", ".join(x["rva"] for x in row["outbound_targets"][:20])]
    lines+=["","## Limits",
       "An unknown-pointer memory store does not establish that program code is being decrypted. No runtime memory was inspected.",
       "See the JSON file for independently sourced original instruction previews and followable control-flow edges."]
    return "\n".join(lines)+"\n"

def self_test():
    assert SIZE==97_284_496 and len(SHA256)==64
    assert ROOTS["entry_call_handoff"]==0x4419
    print("FORTNITE541_GUARDED_CFG_SELFTEST_PASSED")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--exe",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--self-test",action="store_true")
    a=p.parse_args()
    if a.self_test:return self_test()
    if not a.exe or not a.out:p.error("Specify --exe and --out")
    a.out.mkdir(parents=True,exist_ok=True)
    report=run(checked_pe(a.exe))
    (a.out/"fortnite541_guard_cfg.json").write_text(json.dumps(report,indent=2)+"\n")
    (a.out/"fortnite541_guard_cfg.md").write_text(markdown(report))
    print("FORTNITE541_GUARDED_CFG_COMPLETE",SHA256)
    print(markdown(report))

if __name__=="__main__":main()
