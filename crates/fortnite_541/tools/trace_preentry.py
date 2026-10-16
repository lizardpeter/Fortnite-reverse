#!/usr/bin/env python3
"""Source-authenticated static pre-entrypoint / entry-trampoline assessment.

The read-only scan does not execute the game, modify the retail EXE, or
claim that a chance E8 byte sequence is an actual reachable CALL instruction.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import struct

ORIGINAL_SHA256="7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"
ORIGINAL_LENGTH=97_284_496
MAX_CALLBACKS=32

def validate(path):
    sha=hashlib.sha256()
    with path.open("rb") as f:
        for data in iter(lambda:f.read(1<<20),b""):sha.update(data)
    if sha.hexdigest()!=ORIGINAL_SHA256 or path.stat().st_size!=ORIGINAL_LENGTH:
        raise ValueError("The source EXE does not match its verified retail SHA-256/size.")

def raw_at(pe, data, rva, length):
    """Only return data fully mapped into initialized raw PE section bytes."""
    for s in pe.sections:
        lo=int(s.VirtualAddress)
        hi=lo+int(s.SizeOfRawData)
        if lo<=rva and rva+length<=hi:
            o=int(s.PointerToRawData)+(rva-lo)
            return data[o:o+length] if o+length<=len(data) else b""
    return b""

def rel32_target(inst_rva, body):
    """Decode x86 E8 rel32 at a trusted instruction boundary only."""
    if len(body)<5 or body[0]!=0xE8:return None
    return inst_rva+5+struct.unpack_from("<i",body,1)[0]

def call_patterns(start, body, dest_lo, dest_hi):
    """Raw byte-pattern hypotheses; NOT verified instructions."""
    rows=[]
    for offset in range(min(24,max(0,len(body)-4))):
        target=rel32_target(start+offset,body[offset:offset+5])
        if target is not None and dest_lo<=target<dest_hi:
            rows.append((offset,target))
    return rows

def trace_direct_gate_chain(pe,data,base,md,start,max_hops=24):
    """Conservative chain of short original x64 unconditional near-JMP gates.

    No arbitrary fallthrough disassembly after jumps, and no speculation
    across indirect branches or branches into non-executable regions.
    """
    hops=[];seen=set();current=start
    for _ in range(max_hops):
        if current in seen:
            hops.append({"rva":hex(current),"stop":"cycle"})
            break
        seen.add(current)
        sec=next((s for s in pe.sections if s.Characteristics&0x20000000
                  and int(s.VirtualAddress)<=current<
                    int(s.VirtualAddress)+int(s.SizeOfRawData)),None)
        if sec is None:
            hops.append({"rva":hex(current),"stop":"outside_initialized_executable_sections"})
            break
        raw=raw_at(pe,data,current,80)
        ins=list(md.disasm(raw,base+current,count=12))
        cur={"rva":hex(current),"source_hex_prefix":raw[:32].hex(),"insns":[]}
        destination=None
        for x in ins:
            cur["insns"].append({"rva":hex(x.address-base),"hex":x.bytes.hex(),
                  "op":x.mnemonic,"args":x.op_str})
            if x.mnemonic=="jmp":
                if x.operands and x.operands[0].type==2:
                    destination=int(x.operands[0].imm)-base
                else:cur["stop"]="indirect_jump"
                break
            if x.mnemonic.startswith("j") or x.mnemonic.startswith("ret") or x.mnemonic in ("call","int3","ud2","int1","hlt","in","out","retf"):
                cur["stop"]="nonlinear_or_suspicious_instruction"
                break
        if destination is None and "stop" not in cur:
            cur["stop"]="no_bounded_direct_jump"
        if destination is not None:cur["direct_jump_target_rva"]=hex(destination)
        hops.append(cur)
        if destination is None:break
        current=destination
    return hops

def instruction_preview(md, base, pe, data, rva, count=16):
    src=raw_at(pe,data,rva,256)
    return [
        {"rva":hex(int(i.address-base)),"hex":i.bytes.hex(),"mnemonic":i.mnemonic,"operands":i.op_str}
        for i in md.disasm(src,base+rva,count=count)
    ]

def tls_callbacks(pe, data, base, md):
    directory=getattr(pe,"DIRECTORY_ENTRY_TLS",None)
    if directory is None:return {"present":False,"callbacks":[]}
    info=directory.struct
    va=int(info.AddressOfCallBacks)
    callback_list=[]
    for i in range(MAX_CALLBACKS):
        raw=raw_at(pe,data,va-base+i*8,8)
        if len(raw)!=8:break
        callback_va=struct.unpack("<Q",raw)[0]
        if callback_va==0:break
        if callback_va<base or callback_va>=base+pe.OPTIONAL_HEADER.SizeOfImage:
            callback_list.append({"pointer_va":hex(callback_va),"valid_image_rva":False})
            break
        rva=callback_va-base
        callback_list.append({
            "pointer_va":hex(callback_va),"callback_rva":hex(rva),
            "valid_image_rva":True,"first_instructions":instruction_preview(md,base,pe,data,rva,18)
        })
    return {
        "present":True,"callback_table_va":hex(va),"callback_table_rva":hex(va-base) if va>=base else None,
        "callback_list_raw":len(callback_list),"callbacks":callback_list,
        "start_raw_data_va":hex(int(info.StartAddressOfRawData)),
        "end_raw_data_va":hex(int(info.EndAddressOfRawData)),
        "zero_fill_bytes":int(info.SizeOfZeroFill),
        "callback_list_truncated":len(callback_list)==MAX_CALLBACKS
    }

def run(path):
    import pefile
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    validate(path)
    data=path.read_bytes()
    pe=pefile.PE(data=data,fast_load=False)
    assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Magic==0x20b
    base=int(pe.OPTIONAL_HEADER.ImageBase)
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True

    sec=[{"name":s.Name.rstrip(b"\x00").decode("ascii","replace"),
          "rva":int(s.VirtualAddress),"size":int(s.SizeOfRawData),
          "executable":bool(s.Characteristics&0x20000000)}
         for s in pe.sections]
    executable=[s for s in sec if s["executable"]]
    if len(executable)<2:raise ValueError("Expected original pair of executable sections not found")
    secondary=executable[-1]
    destination_min=secondary["rva"]
    destination_max=destination_min+secondary["size"]

    ep=int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    entry_bytes=raw_at(pe,data,ep,32)
    entry=instruction_preview(md,base,pe,data,ep,12)
    # Source-verified previous audit identified an E8 rel32 at EP + 4.
    assert entry_bytes[:4].hex()=="4883ec28", "Original entrypoint instructions changed"
    original_call=rel32_target(ep+4,entry_bytes[4:9])
    if original_call!=0x5AE6509:
        raise ValueError("Verified retail entrypoint trampoline destination changed")
    branch_targets=[0x88664,0x2DB999]
    direct_branch_targets=[]
    for rva in branch_targets:
        raw=raw_at(pe,data,rva,32)
        direct_branch_targets.append({"rva":hex(rva),
            "raw_first_32_bytes":raw.hex(),
            "first_instructions":instruction_preview(md,base,pe,data,rva,10)})

    exc=pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    raw=pe.get_data(exc.VirtualAddress,exc.Size)
    intervals=[]
    for i in range(0,len(raw)-11,12):
        start,end,unwind=struct.unpack_from("<III",raw,i)
        if 0<start<end:intervals.append((start,end))
    starts=sorted(set(start for start,end in intervals))
    counts=Counter()
    first_hit_counts=Counter()
    special_targets=Counter()
    sample_evidence=[]
    all_observed_E8=[]
    all_targets=Counter()
    signature=Counter()
    entrypoint_offsets=Counter()
    starts_per_exec=Counter()
    # Deterministic offset controls have same distance-to-page-edge shape
    # as the observed function starts but are not asserted instruction starts.
    controls=[]
    stride=max(1,len(starts)//10000)
    for idx,start in enumerate(starts):
        section=next((s for s in executable if s["rva"]<=start<s["rva"]+s["size"]),None)
        if section is None:
            counts["starts_outside_exec"]+=1
            continue
        starts_per_exec[hex(section["rva"])]+=1
        body=raw_at(pe,data,start,32)
        if len(body)<32:
            counts["incomplete_start_bytes"]+=1;continue
        counts["starts_examined"]+=1
        signature[body[:2].hex()]+=1
        for offset,target in call_patterns(start,body,destination_min,destination_max):
            counts["any_first_24_byte_E8_into_secondary"]+=1
            if offset==0:counts["E8_at_start_into_secondary"]+=1
            first_hit_counts[offset]+=1
            all_targets[target]+=1
            if len(all_observed_E8)<100:
                all_observed_E8.append({"start_rva":hex(start),"offset":offset,
                  "callsite_rva":hex(start+offset),"target_rva":hex(target),
                  "source_E8_bytes":body[offset:offset+5].hex(),
                  "function_prefix_24":body[:24].hex(),
                  "source_first_instructions":instruction_preview(md,base,pe,data,start,8)})
            if target==original_call:
                special_targets[offset]+=1
                if len(sample_evidence)<24:
                    sample_evidence.append({"start_rva":hex(start),"offset":offset,
                      "callsite_rva":hex(start+offset),"target_rva":hex(target),
                      "bytes":body[offset:offset+5].hex()})
        if idx%stride==0 and len(controls)<10000:
            control=start+0x31
            if control+32<section["rva"]+section["size"]:
                controls.append((control,raw_at(pe,data,control,32)))
    control_counts=Counter()
    for start,body in controls:
        if len(body)!=32:continue
        control_counts["samples"]+=1
        for offset,target in call_patterns(start,body,destination_min,destination_max):
            control_counts["raw_E8_into_secondary"]+=1
            if target==original_call:control_counts["target_original_trampoline"]+=1
        control_counts["first_byte_0xE8"]+=(body[:1]==b"\xe8")

    # Inspect exact first instruction at each of a bounded number of verified
    # targets. Reject results that cannot be decoded from actual executable bytes.
    frequent=[]
    for target,count in all_targets.most_common(15):
        frequent.append({"target_rva":hex(target),"raw_byte_pattern_hits":count,
                         "first_target_instructions":instruction_preview(md,base,pe,data,target,10)})
    return {"source_sha256_verified":ORIGINAL_SHA256,"scan_kind":"read_only_original_disk_image",
       "original_entrypoint_rva":hex(ep),"entrypoint_prologue":entry,
       "entrypoint_call_target_rva":hex(original_call),
       "tls":tls_callbacks(pe,data,base,md),"executable_sections":executable,
       "total_unwind_ranges":len(intervals),"unique_unwind_starts":len(starts),
       "starts_per_executable_section":dict(starts_per_exec),
       "function_start_pattern_census":dict(counts),
       "first_two_byte_patterns":signature.most_common(24),
       "E8_pattern_offset_histogram":dict(sorted(first_hit_counts.items())),
       "E8_into_known_trampoline_by_offset":dict(sorted(special_targets.items())),
       "call_pattern_examples":sample_evidence,
       "all_E8_pattern_evidence":all_observed_E8,
       "direct_jmp_gate_chains":{
         "entry_aligned_path":trace_direct_gate_chain(pe,data,base,md,0x88664),
         "entry_unaligned_path":trace_direct_gate_chain(pe,data,base,md,0x2DB999),
         "common_secondary_call_target":trace_direct_gate_chain(pe,data,base,md,0x5BC8859)},
       "top_call_pattern_target_counts":frequent,
       "non_entrypoint_controls":dict(control_counts),
       "branch_targets_in_protected_section":direct_branch_targets,
       "limits":[
         "An E8 sequence inside opaque/encrypted bytes may occur by chance; matches are hypotheses, not proven calls.",
         "No PE TLS callback does not exclude indirect early-initialization or custom external protection.",
         "The original executable has not been run, decrypted or modified.",
         "On-disk entropy and first-instruction decoding alone do not identify a packer.",
         "The normal Windows loader runs TLS callbacks before the PE entrypoint if they are present."]
    }

def markdown(d):
    tls=d["tls"];c=d["function_start_pattern_census"]
    lines=["# Fortnite 5.41 pre-entrypoint / trampoline census","",
      "SHA-256 verified retail executable; static inspection only. No game execution.",
      "","## Pre-entrypoint candidates",
      "TLS directory: **"+("present" if tls["present"] else "absent")+"**.",
      "Raw TLS callback pointers: **"+str(tls.get("callback_list_raw",0))+"**.",
      "","## Exact original entrypoint",
      "Original RVA: "+d["original_entrypoint_rva"],
      "Original E8 target: "+d["entrypoint_call_target_rva"],
      "","## Original unwind starts and trampoline patterns",
      "Unique unwind starts: "+str(d["unique_unwind_starts"]),
      "Starts examined: "+str(c.get("starts_examined",0)),
      "Raw E8 byte-pattern hits into second .text within first 24 bytes: "+str(c.get("any_first_24_byte_E8_into_secondary",0)),
      "Raw E8 hits at offset 0: "+str(c.get("E8_at_start_into_secondary",0)),
      "Raw E8 byte patterns into original trampoline by offset: "+str(d["E8_into_known_trampoline_by_offset"]),
      "Deterministic non-entrypoint controls: "+str(d["non_entrypoint_controls"]),
      "","## Most frequent E8 byte-pattern destinations",
      "| Destination RVA | Raw hits | First decoded mnemonic |",
      "|---|---:|---|"]
    for x in d["top_call_pattern_target_counts"][:12]:
        head=x["first_target_instructions"]
        lines.append("| "+x["target_rva"]+" | "+str(x["raw_byte_pattern_hits"])+" | "+(head[0]["mnemonic"] if head else "<invalid>")+" |")
    lines += ["","## Direct original x64 near-JMP gate chain"]
    for label,chain in d["direct_jmp_gate_chains"].items():
        lines.append("### "+label)
        for hop in chain[:18]:
            lines.append(hop["rva"]+" -> "+hop.get("direct_jump_target_rva",hop.get("stop","end")))
    lines += ["","## Interpretive limits",
      "A byte-pattern hit is not a verified instruction or executable call. The report compares original function starts against deterministic non-entrypoint controls and records the original source hashes. No plaintext reconstruction has been claimed.",
      "","See the JSON report for TLS callback snippets, protected branch targets, and frequency data."]
    return "\n".join(lines)+"\n"

def self_test():
    assert rel32_target(0x1000,b"\xe8\x00\x00\x00\x00")==0x1005
    assert rel32_target(0x1000,b"\xe8\xfb\xff\xff\xff")==0x1000
    assert rel32_target(0x1000,b"\x90"*5) is None
    assert call_patterns(0x1000,b"\x90\x90\xe8\x09\x00\x00\x00"+b"\x90"*26,0x1010,0x1020)==[(2,0x1010)]
    print("FORTNITE541_PREENTRY_SELF_TEST_PASSED")

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--exe",type=Path)
    a.add_argument("--out",type=Path)
    a.add_argument("--self-test",action="store_true")
    args=a.parse_args()
    if args.self_test:return self_test()
    if not args.exe or not args.out:a.error("--exe and --out required")
    args.out.mkdir(parents=True,exist_ok=True)
    d=run(args.exe)
    (args.out/"fortnite541_preentry.json").write_text(json.dumps(d,indent=2)+"\n")
    (args.out/"fortnite541_preentry.md").write_text(markdown(d))
    print("FORTNITE541_PREENTRY_COMPLETE",d["source_sha256_verified"])
    print(markdown(d))

if __name__=="__main__":main()
