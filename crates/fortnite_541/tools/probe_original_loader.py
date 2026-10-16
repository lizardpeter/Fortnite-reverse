#!/usr/bin/env python3
"""Read-only, SHA-authenticated Fortnite 5.41 PE entrypoint/loader probe.

Never starts the game, decrypts code, or exports the retail binary. Report
source-backed evidence only; static code interpretation may be incomplete.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import statistics
import struct

SHA="7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"
SIZE=97284496
WINDOW=65536
UNUSUAL={"in","out","insb","insd","outsb","outsd","cli","sti","hlt","iret","iretq","retf","retfq","ud2","int1"}

def entropy(data):
    if not data:return 0.
    freqs=Counter(data);n=len(data)
    return round(-sum((v/n)*math.log2(v/n) for v in freqs.values()),5)

def sha256(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1<<20),b""):h.update(chunk)
    return h.hexdigest()

def inspect(path):
    import pefile
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    from capstone.x86_const import X86_INS_CALL,X86_OP_IMM
    if path.stat().st_size!=SIZE or sha256(path)!=SHA:
        raise RuntimeError("Retail EXE SHA-256/length did not match canonical source")
    pe=pefile.PE(str(path))
    assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Magic==0x20b
    base=int(pe.OPTIONAL_HEADER.ImageBase);entry=int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    exc=pe.OPTIONAL_HEADER.DATA_DIRECTORY[3];data=pe.get_data(exc.VirtualAddress,exc.Size)
    pdata=[struct.unpack_from("<III",data,i) for i in range(0,len(data)-11,12)]
    pdata=[(a,b,u) for a,b,u in pdata if 0<a<b]
    starts={a for a,b,u in pdata}
    sections=[]
    for s in pe.sections:
        raw=s.get_data()
        win=[(i,entropy(raw[i:i+WINDOW])) for i in range(0,len(raw),WINDOW) if len(raw[i:i+WINDOW])>=WINDOW//2]
        vals=[e for _,e in win]
        executable=bool(s.Characteristics&0x20000000)
        info=dict(name=s.Name.rstrip(b"\0").decode("ascii","replace"),rva=hex(s.VirtualAddress),
            raw_bytes=len(raw),executable=executable,entropy=entropy(raw),
            window_count=len(vals),window_median=statistics.median(vals) if vals else None,
            window_min=min(vals) if vals else None,window_max=max(vals) if vals else None,
            windows_over_795=sum(x>7.95 for x in vals),windows_under_75=sum(x<7.5 for x in vals),
            lowest_entropy_windows=[{"offset":v,"entropy":e} for v,e in sorted(win,key=lambda x:x[1])[:12]])
        if executable and len(raw)>=256:
            grid=[]
            for k in range(32):
                o=min(len(raw)-128,int(len(raw)*(k+.5)/32))
                ins=list(md.disasm(raw[o:o+128],base+s.VirtualAddress+o))
                grid.append(dict(offset=o,decoded_bytes=sum(x.size for x in ins),
                    strange=sum(x.mnemonic in UNUSUAL for x in ins)))
            info["code_disassembly_grid"]=grid
        sections.append(info)
    actual_section=next((s for s in pe.sections if s.VirtualAddress<=entry<s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData)),None)
    entry_raw=pe.get_data(entry,512)
    instructions=list(md.disasm(entry_raw,base+entry,count=80))
    entry_instructions=[{"rva":hex(i.address-base),"hex":i.bytes.hex(),"mnemonic":i.mnemonic,"operands":i.op_str} for i in instructions]
    # The entrypoint's original near-CALL destination is a grounded loader anchor.
    entry_calls=[]
    targets=[]
    for i in instructions[:12]:
        if i.id==X86_INS_CALL and i.operands and i.operands[0].type==X86_OP_IMM:
            target=int(i.operands[0].imm)-base
            entry_calls.append(dict(source_rva=hex(i.address-base),target_rva=hex(target),
                                    in_second_text=(target>=0x5ae4000)))
            if target>=0:targets.append(target)
    initial_loaders=[]
    # Target-specific disassembly avoids treating encrypted bytes after the
    # initial CALL as normal sequential executable instructions.
    for target in targets[:4]:
        sec=next((s for s in pe.sections if s.VirtualAddress<=target<s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData) and s.Characteristics&0x20000000),None)
        if sec is None:continue
        lower=int(sec.VirtualAddress)
        upper=lower+int(sec.Misc_VirtualSize)
        first=list(md.disasm(pe.get_data(target,1024),base+target,count=65))
        # Conservative, bounded direct-edge exploration; never follow an
        # unresolved indirect branch, outside-section edge or unknown bytes.
        frontier=[target];seen=set();collected=[];out_calls=set()
        stops=Counter()
        while frontier and len(seen)<1200:
            rva=frontier.pop()
            if rva in seen or not lower<=rva<upper:continue
            ins=list(md.disasm(pe.get_data(rva,15),base+rva,count=1))
            if not ins or ins[0].address != base+rva:
                stops["decode_failed"]+=1;continue
            x=ins[0]
            seen.add(rva)
            if len(collected)<180:
                collected.append(dict(rva=hex(rva),hex=x.bytes.hex(),op=x.mnemonic,args=x.op_str))
            next_rva=rva+x.size
            target_rva=None
            if x.operands and x.operands[0].type==X86_OP_IMM and (x.id==X86_INS_CALL or x.mnemonic.startswith("j")):
                target_rva=int(x.operands[0].imm)-base
            if x.id==X86_INS_CALL:
                if target_rva is not None:
                    out_calls.add(target_rva)
                    if lower<=target_rva<upper:frontier.append(target_rva)
                else:stops["indirect_call"]+=1
                frontier.append(next_rva)
            elif x.mnemonic.startswith("ret") or x.mnemonic in ("int3","ud2","hlt"):
                stops["terminal"]+=1
            elif x.mnemonic=="jmp":
                if target_rva is not None and lower<=target_rva<upper:
                    frontier.append(target_rva)
                else:stops["unresolved_jump"]+=1
            elif x.mnemonic.startswith("j") or x.mnemonic.startswith("loop"):
                if target_rva is not None and lower<=target_rva<upper:
                    frontier.append(target_rva)
                frontier.append(next_rva)
            else:
                frontier.append(next_rva)
        initial_loaders.append(dict(entry_call_target_rva=hex(target),
            executable_section_start=hex(lower),section_bytes=upper-lower,
            first_target_instructions=[dict(rva=hex(x.address-base),hex=x.bytes.hex(),op=x.mnemonic,args=x.op_str) for x in first[:40]],
            first_target_linear_decoded_bytes=sum(x.size for x in first),
            cfg_unique_instructions=len(seen),cfg_stop_reasons=dict(stops),
            cfg_source_instruction_sample=collected[:80],
            cfg_direct_call_targets=[hex(x) for x in sorted(out_calls)[:60]],
            cfg_direct_calls=len(out_calls),cfg_truncated=bool(frontier)))
    samples=[]
    ordinals=set(range(min(16,len(pdata))))
    ordinals.update(min(len(pdata)-1,int((i+.5)*len(pdata)/384)) for i in range(384))
    closest=min(range(len(pdata)),key=lambda j:abs(pdata[j][0]-entry))
    ordinals.update(range(max(0,closest-3),min(len(pdata),closest+4)))
    for idx in sorted(ordinals):
        a,b,_=pdata[idx]
        width=min(b-a,128)
        raw=pe.get_data(a,width)
        ins=list(md.disasm(raw,base+a))
        decoded=sum(i.size for i in ins)
        directs=[i for i in ins if i.id==X86_INS_CALL and i.operands and i.operands[0].type==X86_OP_IMM]
        samples.append(dict(ordinal=idx,rva=hex(a),declared_length=b-a,sampled_bytes=len(raw),
            decoded_bytes=decoded,decode_fraction=round(decoded/len(raw),4) if raw else 0.,
            implausible=sum(i.mnemonic in UNUSUAL for i in ins),
            direct_calls=len(directs),
            calls_to_exact_pdata_entries=sum(int(i.operands[0].imm)-base in starts for i in directs),
            preview=[f"{i.mnemonic} {i.op_str}".strip() for i in ins[:5]]))
    imports=[]
    noteworthy={"VirtualAlloc","VirtualAllocEx","VirtualProtect","VirtualProtectEx",
        "VirtualQuery","VirtualQueryEx","GetProcAddress","LoadLibraryA","LoadLibraryW",
        "LoadLibraryExW","FlushInstructionCache","ReadProcessMemory",
        "WriteProcessMemory","BCryptDecrypt","CryptDecrypt","RtlDecompressBuffer"}
    for desc in getattr(pe,"DIRECTORY_ENTRY_IMPORT",[]):
        for obj in desc.imports:
            name=obj.name.decode("ascii","replace") if obj.name else ""
            if name in noteworthy:imports.append(desc.dll.decode("ascii","replace")+"!"+name)
    return dict(source_sha256=SHA,verified_size=SIZE,analysis="static_only_no_runtime_decryption",
        original_entry_rva=hex(entry),
        entry_section=(actual_section.Name.rstrip(b"\0").decode("ascii","replace") if actual_section else None),
        entry_first_32_bytes=entry_raw[:32].hex(),
        entry_disassembly=entry_instructions,
        entrypoint_direct_calls=entry_calls,entrypoint_call_target_probes=initial_loaders,
        sections=sections,original_pdata_records=len(pdata),
        unwind_sampled_count=len(samples),sampled_90pct_decoded=sum(s["decode_fraction"]>=.9 for s in samples),
        median_sampled_decode_fraction=statistics.median(s["decode_fraction"] for s in samples),
        entry_closest_unwind_ordinal=closest,unwind_samples=samples,
        loader_relevant_imports=imports,
        caveats=["High entropy alone does not prove encryption or identify protection technology.",
           "Capstone linear decoding can interpret random bytes as instructions.",
           "Static data cannot prove runtime decryption or recover decrypted memory.",
           "Unwind ranges and Ghidra pseudocode are not independently confirmed source implementations."])

def markdown(d):
    text=["# Fortnite 5.41 original loader/entrypoint probe","",
      "All results are static, from the original SHA-256-verified retail executable. No game execution or runtime injection.",
      "",f"Entrypoint: **{d['original_entry_rva']}**, section **{d['entry_section']}**.",
      f"Unwind entries: {d['original_pdata_records']:,}; broad stratified samples: {d['unwind_sampled_count']}; samples decoding >=90%: {d['sampled_90pct_decoded']}.",
      "","## Executable section entropy in 64 KiB blocks","",
      "| Section (RVA) | Raw bytes | Overall entropy | Window median | Windows >7.95 | Windows <7.5 |",
      "|---|---:|---:|---:|---:|---:|"]
    for s in d["sections"]:
        if s["executable"]:
            text.append(f"| {s['name']} ({s['rva']}) | {s['raw_bytes']:,} | {s['entropy']} | {s['window_median']} | {s['windows_over_795']}/{s['window_count']} | {s['windows_under_75']} |")
    text+=["","## Original entrypoint direct CALL targets"]
    for probe in d["entrypoint_call_target_probes"]:
        text.append(f"Entry target {probe['entry_call_target_rva']}: {probe['cfg_unique_instructions']} entrypoint-reachable static x64 instructions within section {probe['executable_section_start']}; unique direct call destinations {probe['cfg_direct_calls']}.")
        text.append("~~~asm")
        for i in probe["first_target_instructions"][:22]:
            text.append(f"{i['rva']} {i['hex']:<24} {i['op']} {i['args']}")
        text.append("~~~")
    text+=["","## Authenticated entrypoint first 30 decoded x64 instructions","", "~~~asm"]
    for i in d["entry_disassembly"][:30]:
        text.append(f"{i['rva']} {i['hex']:<24} {i['mnemonic']} {i['operands']}")
    text+=["~~~","","## Relevant imported Windows APIs",", ".join(d["loader_relevant_imports"]) or "(none found)",
      "","## Limits","This is structural evidence, not a proven offline decryptor. The correct next move depends on whether the entrypoint and second executable section form coherent loader code. The full JSON retains spatial samples and instruction previews."]
    return "\n".join(text)+"\n"

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--exe",type=Path)
    a.add_argument("--out",type=Path)
    a.add_argument("--self-test",action="store_true")
    x=a.parse_args()
    if x.self_test:
        assert entropy(bytes(256))==0 and entropy(bytes(range(256)))==8
        print("FORTNITE541_LOADER_PROBE_SELF_TEST_PASSED")
        return
    if not x.exe or not x.out:a.error("require --exe and --out")
    x.out.mkdir(parents=True,exist_ok=True)
    d=inspect(x.exe)
    (x.out/"fortnite541_loader_probe.json").write_text(json.dumps(d,indent=2)+"\n")
    (x.out/"fortnite541_loader_probe.md").write_text(markdown(d))
    print("FORTNITE541_LOADER_PROBE_COMPLETE",d["source_sha256"])
    print(markdown(d))

if __name__=="__main__":main()
