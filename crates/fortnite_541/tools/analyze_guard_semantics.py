#!/usr/bin/env python3
"""SHA-verified bounded instruction/dataflow study of Fortnite 5.41's
actual protected native call chain. Read-only: never executes or patches PE.

This intentionally describes *static evidence*, not runtime decryption.
Relative call sites, RIP-resolved stores, register-indirect stores and
bitstream decoder patterns are kept distinct.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct

EXPECTED_SHA = "7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"
EXPECTED_SIZE = 97_284_496
ROOTS = {
    "guard_argument_setup":0x5C4CE84,
    "guard_call_target":0x5B0CF49,
    "guard_call_continuation":0x5CDA17B,
    "seven_bit_reader":0x5C61E26,
    "seven_bit_reader_caller":0x5D986DE,
    "known_text_store":0x5BD4B1B,
}
MAX_INSTRUCTIONS=512
MAX_BYTES=1536
MAX_CHILDREN=8

def sha256(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1<<20),b""):h.update(b)
    return h.hexdigest()

def authentic_pe(path):
    import pefile
    if path.stat().st_size!=EXPECTED_SIZE or sha256(path)!=EXPECTED_SHA:
        raise ValueError("Authentic Fortnite 5.41 executable SHA256/size check failed")
    pe=pefile.PE(str(path),fast_load=False)
    if pe.FILE_HEADER.Machine!=0x8664 or pe.OPTIONAL_HEADER.Magic!=0x20B:
        raise ValueError("Expected original x64 PE32+ executable")
    return pe

def read_pe(pe, rva, n):
    for s in pe.sections:
        lo=int(s.VirtualAddress)
        hi=lo+int(s.SizeOfRawData)
        if lo<=rva<hi:
            return pe.get_data(rva,min(n,hi-rva))
    return b""

def section(pe, rva):
    for s in pe.sections:
        lo=int(s.VirtualAddress)
        hi=lo+max(int(s.SizeOfRawData),int(s.Misc_VirtualSize))
        if lo<=rva<hi:
            return {"name":s.Name.rstrip(b"\0").decode("ascii","replace"),
                    "rva":hex(lo),
                    "executable":bool(s.Characteristics & 0x20000000),
                    "writable":bool(s.Characteristics & 0x80000000)}
    return None

def pdata_intervals(pe):
    d=pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    raw=pe.get_data(d.VirtualAddress,d.Size)
    result=[]
    for i in range(0,len(raw)-11,12):
        lo,hi,_=struct.unpack_from("<III",raw,i)
        if 0<lo<hi:result.append((lo,hi))
    return sorted(result)

def enclosing(rva,intervals):
    import bisect
    i=bisect.bisect_right(intervals,(rva,2**32))-1
    if i>=0 and intervals[i][0]<=rva<intervals[i][1]:
        return intervals[i]
    return None

def pe_imports(pe):
    by_rva={}
    base=int(pe.OPTIONAL_HEADER.ImageBase)
    for d in getattr(pe,"DIRECTORY_ENTRY_IMPORT",[]):
        lib=d.dll.decode("ascii","replace") if d.dll else "UNKNOWN"
        for v in d.imports:
            api=v.name.decode("ascii","replace") if v.name else "#"+str(v.ordinal)
            by_rva[int(v.address)-base]=lib+"!"+api
    return by_rva

def memory_kind(base_reg,index_reg,is_rip,target_sec):
    from capstone.x86_const import X86_REG_RSP, X86_REG_RBP, X86_REG_RIP
    if is_rip:
        if target_sec:
            return "rip_executable_section" if target_sec["executable"] else "rip_nonexecutable_section"
        return "rip_unmapped"
    if base_reg in (X86_REG_RSP,X86_REG_RBP) and not index_reg:
        return "stack_frame"
    return "register_indirect"

def decode(pe,md,base,root,intervals,imports):
    from capstone import CS_AC_READ,CS_AC_WRITE
    from capstone.x86_const import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP
    env=enclosing(root,intervals)
    bound_hi=min(root+MAX_BYTES,env[1] if env else root+MAX_BYTES)
    # A known function start can be an interior chunk in compiler-exception
    # metadata: cap the span instead of forcing a single linear decode.
    queue=[root];visited={};edges=[];calls=[];memory=[];bit_ops=[];stops=[];child_addresses=set()
    base_code=int(pe.OPTIONAL_HEADER.ImageBase)
    while queue and len(visited)<MAX_INSTRUCTIONS:
        rva=queue.pop()
        if rva in visited or not(root<=rva<bound_hi):continue
        code=read_pe(pe,rva,15)
        insns=list(md.disasm(code,base_code+rva,count=1))
        if not insns:
            stops.append({"rva":hex(rva),"kind":"undecodable"});continue
        i=insns[0]
        record={"rva":hex(rva),"mnemonic":i.mnemonic,"operands":i.op_str,"hex":i.bytes.hex()}
        visited[rva]=record
        if i.mnemonic in ("hlt","ud2","int1","iret","iretq","retf","retfq","in","out","cli","sti"):
            stops.append({"rva":hex(rva),"kind":"unusual_privileged_instruction","op":i.mnemonic})
            continue
        for j,operand in enumerate(i.operands):
            if operand.type==X86_OP_MEM:
                mem=operand.mem
                rip=mem.base==X86_REG_RIP
                target=int(i.address+i.size+mem.disp)-base_code if rip else None
                sec=section(pe,target) if target is not None else None
                obj={"rva":hex(rva),"instruction":i.mnemonic,"args":i.op_str,
                     "kind":memory_kind(mem.base,mem.index,rip,sec),
                     "access":"read_write" if operand.access & CS_AC_READ and operand.access & CS_AC_WRITE
                          else "write" if operand.access & CS_AC_WRITE else "read" if operand.access & CS_AC_READ else "unknown",
                     "width":operand.size,
                     "rip_target_rva":hex(target) if target is not None else None,
                     "target_section":sec["name"] if sec else None,
                     "target_writable_in_pe":sec["writable"] if sec else None,
                     "iat_name":imports.get(target)}
                memory.append(obj)
                if i.mnemonic in ("call","jmp") and imports.get(target):
                    calls.append({"rva":hex(rva),"kind":"import_via_rip","api":imports[target]})
            elif operand.type==X86_OP_IMM:
                if i.mnemonic in ("and","or","xor","shl","shr","sar","rol","ror","add","sub","imul","movzx","mov"):
                    imm=int(operand.imm)
                    if i.mnemonic not in ("mov","add","sub") or abs(imm) in (7,0x7f,0x80,0x7fff,0xff,0x3fff):
                        bit_ops.append({"rva":hex(rva),"mnemonic":i.mnemonic,"imm":hex(imm),"operands":i.op_str})
        fallthrough=rva+i.size
        dest=None
        if i.operands and i.operands[0].type==X86_OP_IMM and (i.mnemonic=="call" or i.mnemonic.startswith("j") or i.mnemonic.startswith("loop")):
            dest=int(i.operands[0].imm)-base_code
        if i.mnemonic=="call":
            info={"rva":hex(rva),"kind":"direct" if dest is not None else "indirect",
                  "target_rva":hex(dest) if dest is not None else None}
            calls.append(info)
            if dest is not None:
                child_addresses.add(dest)
            edges.append({"from":hex(rva),"to":hex(fallthrough),"kind":"call_fallthrough"})
            if fallthrough<bound_hi:queue.append(fallthrough)
        elif i.mnemonic=="jmp":
            edges.append({"from":hex(rva),"to":hex(dest) if dest is not None else None,"kind":"jump"})
            if dest is not None:
                if root<=dest<bound_hi:queue.append(dest)
                else:child_addresses.add(dest)
        elif i.mnemonic.startswith("j") or i.mnemonic.startswith("loop"):
            edges.append({"from":hex(rva),"to":hex(dest) if dest is not None else None,"kind":"conditional_branch"})
            if dest is not None:
                if root<=dest<bound_hi:queue.append(dest)
                else:child_addresses.add(dest)
            if fallthrough<bound_hi:queue.append(fallthrough)
        elif i.mnemonic.startswith("ret") or i.mnemonic in ("int3","syscall"):
            stops.append({"rva":hex(rva),"kind":"terminal","op":i.mnemonic})
        else:
            if fallthrough<bound_hi:queue.append(fallthrough)
    mem_writes=[x for x in memory if x["access"] in ("write","read_write")]
    rip_writes=[x for x in mem_writes if x["kind"]=="rip_executable_section"]
    dynamic_writes=[x for x in mem_writes if x["kind"]=="register_indirect"]
    return {
        "entry_rva":hex(root),
        "entry_section":section(pe,root),
        "pdata_range":({"begin":hex(env[0]),"end":hex(env[1])} if env else None),
        "bound_end":hex(bound_hi),
        "instruction_count":len(visited),
        "truncated":bool(queue),
        "call_count":len(calls),"calls":calls[:100],
        "memory_write_count":len(mem_writes),
        "register_indirect_write_count":len(dynamic_writes),
        "rip_executable_write_count":len(rip_writes),
        "memory_writes":mem_writes[:180],
        "memory_reads":[x for x in memory if x["access"]=="read"][:130],
        "bit_operations":bit_ops[:140],
        "bounded_control_edges":edges[:160],
        "candidate_outbound_rvas":[hex(x) for x in sorted(child_addresses)[:70]],
        "instruction_source":[visited[x] for x in sorted(visited)[:240]],
        "stop_reasons":stops[:40],
    }

def explain(report):
    rows=["# Fortnite 5.41 original guard callee / bitstream analysis","",
          "Source SHA-256 verified. Static analysis of original on-disk instructions; neither plaintext game code nor runtime execution is claimed.","",
          "| Native root | Instructions decoded | Calls | Register-addressed writes | Direct executable-section writes | Bitwise operations |",
          "|---|---:|---:|---:|---:|---:|"]
    for label,item in report["roots"].items():
        rows.append(f"| {label} ({item['entry_rva']}) | {item['instruction_count']} | {item['call_count']} | {item['register_indirect_write_count']} | {item['rip_executable_write_count']} | {len(item['bit_operations'])} |")
    for label,item in report["roots"].items():
        rows+=["","## "+label,"Original source RVA: "+item["entry_rva"],
              "Call targets: "+", ".join(c.get("target_rva") or c.get("api") or "unresolved" for c in item["calls"][:40]),
              "Writes through register-indirect pointers: "+str(item["register_indirect_write_count"]),
              "Bit operations: "+", ".join(x["mnemonic"]+" "+x["imm"] for x in item["bit_operations"][:25])]
    rows+=["","## Explicit limits",
          "Disassembly, branches, and memory operations are observed on disk, not proven runtime code execution.",
          "A memory write through RCX/RDX or another register may modify a code page or ordinary data; without runtime pointer values the destination cannot be determined.",
          "The 7-bit / 0x7F pattern suggests variable-length integer decoding but its exact algorithm is not established until more loop and caller context is recovered.",
          "No decrypted executable bytes have been produced."]
    return "\n".join(rows)+"\n"

def study(path):
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    pe=authentic_pe(path)
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    intervals=pdata_intervals(pe)
    imports=pe_imports(pe)
    roots={}
    for label,rva in ROOTS.items():
        roots[label]=decode(pe,md,int(pe.OPTIONAL_HEADER.ImageBase),rva,intervals,imports)
    child_roots=sorted({
        int(c["target_rva"],16) for item in roots.values() for c in item["calls"]
        if c.get("kind")=="direct" and c.get("target_rva")
    })
    # Analyze immediate original call targets once, capped to avoid cascading
    # into nonsense in still-opaque sections. No recursive export of code bytes.
    children={}
    for rva in child_roots[:MAX_CHILDREN]:
        s=section(pe,rva)
        if s and s["executable"] and rva not in ROOTS.values():
            children[hex(rva)]=decode(pe,md,int(pe.OPTIONAL_HEADER.ImageBase),rva,intervals,imports)
    return {"sha256_verified":EXPECTED_SHA,"source_size":EXPECTED_SIZE,
        "roots":roots,"direct_child_callees":children,
        "note":"Original on-disk structural analysis only; no runtime decrypted executable."}

def self_test():
    class _Sec:
        Characteristics=0x20000000
    assert EXPECTED_SIZE>90_000_000
    assert memory_kind(0,0,False,None)=="register_indirect"
    assert memory_kind(0,0,True,{"executable":True})=="rip_executable_section"
    assert len(EXPECTED_SHA)==64
    print("FORTNITE541_CALLEE_SEMANTICS_SELFTEST_PASSED")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--exe",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--self-test",action="store_true")
    args=p.parse_args()
    if args.self_test:return self_test()
    if not args.exe or not args.out:p.error("--exe and --out required")
    args.out.mkdir(parents=True,exist_ok=True)
    report=study(args.exe)
    (args.out/"fortnite541_guard_semantics.json").write_text(json.dumps(report,indent=2)+"\n")
    (args.out/"fortnite541_guard_semantics.md").write_text(explain(report))
    print("FORTNITE541_GUARD_SEMANTICS_ANALYSIS_PASSED")
    print(explain(report))

if __name__=="__main__":main()
