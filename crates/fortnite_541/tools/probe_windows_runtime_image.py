#!/usr/bin/env python3
"""Test the *hypothesis* that Fortnite 5.41 changes executable code on startup.

This is not an unpacker. It compares the SHA-256-authenticated on-disk image
against sampled pages of the game's OWN child process, and reports ONLY
aggregate byte counts/entropies. No process-memory contents or decrypted code
are written anywhere. Never connects to game services.

The runner MUST enforce outbound firewall isolation before invoking this
script. It launches the exact retail shipping EXE; no anti-cheat bypass,
tampering, injection, debugger attachment, or replacement DLLs are used.
"""
from __future__ import annotations
import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import struct
import sys
import time

CANONICAL_SHA256 = "7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"
CANONICAL_BYTES = 97_284_496
PAGE_BYTES = 4096
CREATE_SUSPENDED=0x00000004
CREATE_NO_WINDOW=0x08000000
PROCESS_TERMINATE=0x0001
STILL_ACTIVE=259
MAX_RUNTIME_SEC=10.0

if os.name=="nt":
    from ctypes import WinDLL
    kernel32=WinDLL("kernel32",use_last_error=True)
    psapi=WinDLL("psapi",use_last_error=True)
    ntdll=WinDLL("ntdll",use_last_error=True)
    SIZE_T=C.c_size_t
    HANDLE=W.HANDLE
    LPVOID=C.c_void_p
    DWORD=W.DWORD

    class STARTUPINFOW(C.Structure):
        _fields_=[("cb",DWORD),("lpReserved",W.LPWSTR),
           ("lpDesktop",W.LPWSTR),("lpTitle",W.LPWSTR),
           ("dwX",DWORD),("dwY",DWORD),("dwXSize",DWORD),
           ("dwYSize",DWORD),("dwXCountChars",DWORD),
           ("dwYCountChars",DWORD),("dwFillAttribute",DWORD),
           ("dwFlags",DWORD),("wShowWindow",W.WORD),
           ("cbReserved2",W.WORD),("lpReserved2",C.c_void_p),
           ("hStdInput",HANDLE),("hStdOutput",HANDLE),
           ("hStdError",HANDLE)]
    class PROCESS_INFORMATION(C.Structure):
        _fields_=[("hProcess",HANDLE),("hThread",HANDLE),
                  ("dwProcessId",DWORD),("dwThreadId",DWORD)]
    class PROCESS_BASIC_INFORMATION(C.Structure):
        _fields_=[("Reserved1",C.c_void_p),("PebBaseAddress",C.c_void_p),
                  ("Reserved2",C.c_void_p*2),("UniqueProcessId",SIZE_T),
                  ("Reserved3",C.c_void_p)]
    ntdll.NtQueryInformationProcess.argtypes=[HANDLE,DWORD,C.c_void_p,
                                              DWORD,C.POINTER(DWORD)]
    ntdll.NtQueryInformationProcess.restype=W.LONG
    kernel32.CreateProcessW.argtypes=[
        W.LPCWSTR,W.LPWSTR,C.c_void_p,C.c_void_p,W.BOOL,
        DWORD,C.c_void_p,W.LPCWSTR,C.POINTER(STARTUPINFOW),
        C.POINTER(PROCESS_INFORMATION)]
    kernel32.CreateProcessW.restype=W.BOOL
    kernel32.ReadProcessMemory.argtypes=[
        HANDLE,LPVOID,C.c_void_p,SIZE_T,C.POINTER(SIZE_T)]
    kernel32.ReadProcessMemory.restype=W.BOOL
    kernel32.ResumeThread.argtypes=[HANDLE]
    kernel32.ResumeThread.restype=DWORD
    kernel32.TerminateProcess.argtypes=[HANDLE,DWORD]
    kernel32.TerminateProcess.restype=W.BOOL
    kernel32.GetExitCodeProcess.argtypes=[HANDLE,C.POINTER(DWORD)]
    kernel32.GetExitCodeProcess.restype=W.BOOL
    kernel32.CloseHandle.argtypes=[HANDLE]
    kernel32.CloseHandle.restype=W.BOOL
    psapi.EnumProcessModulesEx.argtypes=[HANDLE,
        C.POINTER(HANDLE),DWORD,C.POINTER(DWORD),DWORD]
    psapi.EnumProcessModulesEx.restype=W.BOOL

def source_sha256(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1<<20),b""):
            h.update(chunk)
    return h.hexdigest()

def entropy(buf:bytes)->float:
    if not buf:
        return 0.0
    counts=[0]*256
    for byte in buf:
        counts[byte]+=1
    length=len(buf)
    return round(-sum((n/length)*math.log2(n/length) for n in counts if n),4)

def sample_rvas(pe,section):
    """Deterministic, stratified page sampling (no changed bytes exported)."""
    sec_rva=int(section.VirtualAddress)
    sec_bytes=min(int(section.SizeOfRawData),int(section.Misc_VirtualSize))
    if sec_bytes<PAGE_BYTES:
        return []
    max_offset=sec_bytes-PAGE_BYTES
    count=128 if sec_bytes>20_000_000 else 48 if sec_bytes>1_000_000 else 12
    offsets={int(max_offset*i/(count-1)) for i in range(count)}
    # High-entropy original code has many .pdata boundaries; sample some known
    # first instructions in a deterministic way as well.
    exception=pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    raw=pe.get_data(exception.VirtualAddress,exception.Size)
    entries=[]
    for i in range(0,len(raw)-11,12):
        start,end,unwind=struct.unpack_from("<III",raw,i)
        if sec_rva<=start<sec_rva+sec_bytes-PAGE_BYTES and 0<start<end:
            entries.append(start-sec_rva)
    if entries:
        for j in range(32):
            offsets.add(entries[int((len(entries)-1)*j/31)])
    return [sec_rva+x for x in sorted(offsets)]

def read_remote(handle,address,length=PAGE_BYTES):
    buf=(C.c_ubyte*length)()
    got=SIZE_T(0)
    ok=kernel32.ReadProcessMemory(handle,LPVOID(address),buf,length,C.byref(got))
    if not ok or got.value!=length:
        return None
    return bytes(buf)

def process_base(handle,expected_base):
    """Locate child image without assuming loader module lists exist yet."""
    # The loader's LDR module list is often not initialized while the first
    # thread remains suspended. The kernel creates the PEB before user code.
    pbi=PROCESS_BASIC_INFORMATION()
    returned=DWORD()
    status=ntdll.NtQueryInformationProcess(handle,0,C.byref(pbi),
                                          C.sizeof(pbi),C.byref(returned))
    if status==0 and pbi.PebBaseAddress:
        ptr=read_remote(handle,int(pbi.PebBaseAddress)+0x10,8)
        if ptr:
            value=struct.unpack("<Q",ptr)[0]
            if value and read_remote(handle,value,2)==b"MZ":
                return value,"PEB_ImageBaseAddress_verified_MZ"
    modules=(HANDLE*512)()
    needed=DWORD()
    if psapi.EnumProcessModulesEx(handle,modules,C.sizeof(modules),C.byref(needed),3):
        if needed.value>=C.sizeof(HANDLE) and modules[0]:
            value=int(modules[0])
            if read_remote(handle,value,2)==b"MZ":
                return value,"EnumProcessModulesEx_verified_MZ"
    if read_remote(handle,expected_base,2)==b"MZ":
        return expected_base,"expected_image_base_MZ_verified"
    return None,"PEB_and_module_list_not_accessible"

def probe_function_starts(pe,section,limit=96):
    """Sample only actual source unwind-index starts in the primary .text."""
    sec_rva=int(section.VirtualAddress)
    sec_end=sec_rva+int(section.SizeOfRawData)
    exc=pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    raw=pe.get_data(exc.VirtualAddress,exc.Size)
    starts=[]
    for off in range(0,len(raw)-11,12):
        start,end,unwind=struct.unpack_from("<III",raw,off)
        if sec_rva<=start<sec_end-256 and start<end:
            starts.append(start)
    if not starts:
        return []
    return [starts[int((len(starts)-1)*i/(limit-1))] for i in range(limit)]

def code_validation(pe,handle,base,section):
    """Aggregate original x64 disassembly quality; NEVER serialize instructions."""
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=False
    rvas=probe_function_starts(pe,section)
    original_fractions=[]
    mapped_fractions=[]
    original_unusual=[]
    mapped_unusual=[]
    original_prefixes=[]
    mapped_prefixes=[]
    changed=0
    unreadable=0
    unusual={"hlt","ud2","iret","iretd","iretq","retf","retfq",
             "in","out","insb","insd","outsb","outsd","cli","sti","int1"}
    plausible={"push","sub","mov","lea","xor","jmp","nop","endbr64","cmp"}
    def inspect(buf,rva):
        ins=list(md.disasm(buf,base+rva))
        return (
           round(sum(i.size for i in ins)/len(buf),4) if buf else 0,
           sum(i.mnemonic in unusual for i in ins),
           bool(ins and ins[0].mnemonic in plausible))
    for rva in rvas:
        disk=pe.get_data(rva,192)
        mem=read_remote(handle,base+rva,192)
        if mem is None or len(disk)!=192:
            unreadable+=1
            continue
        changed+=mem!=disk
        x=inspect(disk,rva)
        y=inspect(mem,rva)
        original_fractions.append(x[0])
        mapped_fractions.append(y[0])
        original_unusual.append(x[1])
        mapped_unusual.append(y[1])
        original_prefixes.append(x[2])
        mapped_prefixes.append(y[2])
    return {
        "source":".pdata_starts_only",
        "rvas_requested":len(rvas),
        "rvas_readable":len(mapped_fractions),
        "rvas_unreadable":unreadable,
        "rvas_differing_from_disk":changed,
        "median_disk_linear_disassembly_fraction":round(statistics.median(original_fractions),4) if original_fractions else None,
        "median_memory_linear_disassembly_fraction":round(statistics.median(mapped_fractions),4) if mapped_fractions else None,
        "disk_unusual_privileged_instruction_count":sum(original_unusual),
        "memory_unusual_privileged_instruction_count":sum(mapped_unusual),
        "disk_plausible_first_instruction_count":sum(original_prefixes),
        "memory_plausible_first_instruction_count":sum(mapped_prefixes),
        "caution":"Static disassembly validity is not sufficient alone to prove game logic or execution."
    }

def private_analysis_image(pe,handle,base,exe:Path,out:Path):
    """Rebuild executable section RAW bytes from memory, privately.

    Output is an analysis input for local Ghidra only. It is NOT claimed
    executable/runnable. IAT, relocations, section permissions, and
    protection runtime may still require extensive restoration.

    NEVER upload this output to a public Actions artifact.
    """
    import pefile
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    out=out.resolve()
    # Fail closed if an Actions workspace could accidentally track the image.
    workspace=os.environ.get("GITHUB_WORKSPACE")
    if workspace and out.is_relative_to(Path(workspace).resolve()):
        raise ValueError("Refusing to create a plaintext executable in GITHUB_WORKSPACE")
    if out.exists():
        raise FileExistsError("Private analysis image already exists; refusing overwrite")
    original=exe.read_bytes()
    image=bytearray(original)
    section_stats=[]
    total_changed=0
    total_read=0
    for section in pe.sections:
        if not section.Characteristics&0x20000000:
            continue
        n=min(int(section.SizeOfRawData),int(section.Misc_VirtualSize))
        if n<=0:continue
        offset=int(section.PointerToRawData)
        rva=int(section.VirtualAddress)
        count_pages=0
        unreadable=0
        changed=0
        read_bytes=0
        for relative in range(0,n,PAGE_BYTES):
            length=min(PAGE_BYTES,n-relative)
            memory=read_remote(handle,base+rva+relative,length)
            if memory is None:
                unreadable+=1
                continue
            start=offset+relative
            end=start+length
            if end>len(image):
                raise RuntimeError("Executable PE section extends beyond raw file")
            changed+=sum(x!=y for x,y in zip(original[start:end],memory))
            image[start:end]=memory
            count_pages+=1
            read_bytes+=length
        section_stats.append({
            "section_rva":hex(rva),
            "bytes_in_original_executable_section":n,
            "bytes_read_from_runtime":read_bytes,
            "pages_recovered":count_pages,
            "pages_unreadable":unreadable,
            "bytes_changed_relative_to_disk":changed})
        total_changed+=changed
        total_read+=read_bytes
    if total_read<1_000_000 or total_changed<100_000:
        raise RuntimeError("Insufficient recovered code to create an honest analysis PE")
    restored=pefile.PE(data=bytes(image),fast_load=True)
    if restored.FILE_HEADER.Machine!=0x8664:
        raise RuntimeError("Reconstructed PE header invalid")
    if restored.FILE_HEADER.NumberOfSections!=pe.FILE_HEADER.NumberOfSections:
        raise RuntimeError("PE section headers changed unexpectedly")
    starts=probe_function_starts(pe,pe.sections[0],96)
    # Section order is not guaranteed; select the largest executable section.
    executable=[s for s in pe.sections if s.Characteristics&0x20000000]
    if executable:
        starts=probe_function_starts(pe,max(executable,key=lambda s:int(s.SizeOfRawData)),96)
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    unusual={"hlt","ud2","iret","iretq","retf","in","out","cli","sti","int1"}
    plausible={"push","sub","mov","lea","xor","jmp","nop","endbr64","cmp"}
    scoring={"function_starts_sampled":len(starts),
             "original_plausible_starts":0,
             "restored_plausible_starts":0,
             "original_unusual_instructions":0,
             "restored_unusual_instructions":0}
    for rva in starts:
        before=pe.get_data(rva,192)
        after=restored.get_data(rva,192)
        ins_before=list(md.disasm(before,int(pe.OPTIONAL_HEADER.ImageBase)+rva))
        ins_after=list(md.disasm(after,int(pe.OPTIONAL_HEADER.ImageBase)+rva))
        scoring["original_plausible_starts"]+=bool(ins_before and ins_before[0].mnemonic in plausible)
        scoring["restored_plausible_starts"]+=bool(ins_after and ins_after[0].mnemonic in plausible)
        scoring["original_unusual_instructions"]+=sum(x.mnemonic in unusual for x in ins_before)
        scoring["restored_unusual_instructions"]+=sum(x.mnemonic in unusual for x in ins_after)
    if scoring["restored_plausible_starts"] <= scoring["original_plausible_starts"]:
        raise RuntimeError("Private reconstruction has no verified improvement at original function starts")
    out.parent.mkdir(parents=True,exist_ok=True)
    partial=out.with_suffix(".partial")
    try:
        partial.write_bytes(image)
        partial.replace(out)
    finally:
        partial.unlink(missing_ok=True)
    return {
        "created_privately":True,
        "input_kind":"runtime-mapped original machine-code bytes in original PE raw layout",
        "output_kind":"analysis-only PE; not runnable retail replacement",
        "size":len(image),
        "source_imagebase":hex(int(pe.OPTIONAL_HEADER.ImageBase)),
        "actual_process_imagebase":hex(base),
        "reconstructed_sha256":hashlib.sha256(image).hexdigest(),
        "total_executable_bytes_read":total_read,
        "total_executable_bytes_changed_from_disk":total_changed,
        "sections":section_stats,
        "function_boundary_evidence":scoring,
        "availability":"private temporary Windows runner only; not uploaded"
    }

def capture(pe,handle,base,rvas,snapshot):
    out={"stage":snapshot,"sections":[]}
    for section,rvases in rvas:
        name=section.Name.rstrip(b"\x00").decode("ascii","replace")
        values=[]
        errors=0
        diffs=[]
        disk_entropy=[]
        mem_entropy=[]
        for rva in rvases:
            on_disk=pe.get_data(rva,PAGE_BYTES)
            in_ram=read_remote(handle,base+rva)
            if in_ram is None or len(on_disk)!=PAGE_BYTES:
                errors+=1
                continue
            delta=sum(x!=y for x,y in zip(on_disk,in_ram))
            diffs.append(delta)
            disk_entropy.append(entropy(on_disk))
            mem_entropy.append(entropy(in_ram))
            values.append(delta>0)
        out["sections"].append({
            "name":name,
            "samples_requested":len(rvases),
            "samples_readable":len(values),
            "samples_unreadable":errors,
            "windows_changed":sum(values),
            "changed_bytes":sum(diffs),
            "sampled_bytes":len(diffs)*PAGE_BYTES,
            "disk_entropy_median":round(statistics.median(disk_entropy),4) if disk_entropy else None,
            "ram_entropy_median":round(statistics.median(mem_entropy),4) if mem_entropy else None,
            "max_bytes_changed_in_one_page":max(diffs) if diffs else None,
            "original_function_entry_instruction_quality":code_validation(pe,handle,base,section) if int(section.SizeOfRawData)>20_000_000 else None,
        })
    return out

def error_code():
    return C.get_last_error() if os.name=="nt" else -1

def runtime_probe(pe,exe:Path,snap_delays,private_image_out=None):
    if os.name!="nt":
        raise RuntimeError("Windows-only runtime proof; do not execute this elsewhere")
    startup=STARTUPINFOW()
    startup.cb=C.sizeof(startup)
    info=PROCESS_INFORMATION()
    cmd=C.create_unicode_buffer('"'+str(exe)+'"')
    ok=kernel32.CreateProcessW(
        str(exe),cmd,None,None,False,
        CREATE_SUSPENDED|CREATE_NO_WINDOW,None,str(exe.parent),
        C.byref(startup),C.byref(info))
    if not ok:
        return {"spawned":False,"win32_error":error_code(),"snapshots":[]}
    report={"spawned":True,"snapshots":[],"running_after_last_sample":False}
    try:
        base,source=process_base(info.hProcess,int(pe.OPTIONAL_HEADER.ImageBase))
        report["image_base_source"]=source
        sections=[]
        for s in pe.sections:
            if s.Characteristics&0x20000000:
                sections.append((s,sample_rvas(pe,s)))
        report["sampled_sections"]=len(sections)
        if base is not None:
            report["snapshots"].append(capture(pe,info.hProcess,base,sections,"created_suspended"))
        else:
            report["baseline_missing"]="Cannot identify the mapped image while suspended"
        start=time.monotonic()
        result=kernel32.ResumeThread(info.hThread)
        if result==0xffffffff:
            report["blocker"]="ResumeThread failed"
            report["win32_error"]=error_code()
            return report
        for seconds in snap_delays:
            wait=max(0.0,start+seconds-time.monotonic())
            if wait:
                time.sleep(wait)
            status=DWORD()
            kernel32.GetExitCodeProcess(info.hProcess,C.byref(status))
            if base is None:
                base,source=process_base(info.hProcess,int(pe.OPTIONAL_HEADER.ImageBase))
                report["image_base_source_after_resume"]=source
            if base is not None:
                report["snapshots"].append(capture(pe,info.hProcess,base,sections,f"after_{seconds}_seconds"))
            else:
                report["blocker"]="Image base unavailable in suspended and resumed process"
            report.setdefault("process_status",[]).append({
                "elapsed_requested_seconds":seconds,
                "process_exited":status.value!=STILL_ACTIVE,
                "exit_code":status.value if status.value!=STILL_ACTIVE else None
            })
            if status.value!=STILL_ACTIVE:
                break
        status=DWORD()
        kernel32.GetExitCodeProcess(info.hProcess,C.byref(status))
        report["running_after_last_sample"]=status.value==STILL_ACTIVE
        if private_image_out is not None:
            if status.value==STILL_ACTIVE and base is not None:
                report["private_reconstruction"]=private_analysis_image(
                    pe,info.hProcess,base,exe,private_image_out)
            else:
                report["private_reconstruction"]={
                    "created_privately":False,
                    "blocker":"Source process exited or original image unmapped"}
        report["execution_isolated"]="Windows firewall rule required before this script launched the process"
        return report
    finally:
        # Terminate even on exceptions/timeouts; do not leave game in runner.
        kernel32.TerminateProcess(info.hProcess,0)
        kernel32.CloseHandle(info.hThread)
        kernel32.CloseHandle(info.hProcess)

def format_markdown(d):
    lines=["# Fortnite 5.41 offline mapped-image comparison","",
        "The exact source binary was verified by SHA-256 before inspection.",
        "The original binary was launched in a bounded, network-blocked Windows runner.",
        "No executable bytes, decrypted pages, or memory dumps are published.","",
        "**Process created:** "+str(d.get("spawned")),
        "**Blocker:** "+str(d.get("blocker","none")),
        "**Process status:** "+str(d.get("process_status",[])),""]
    for snap in d.get("snapshots",[]):
        lines+=["## "+snap["stage"],"",
           "| PE section | Windows read | Pages changed from disk | Changed bytes | Median on-disk entropy | Median memory entropy |",
           "|---|---:|---:|---:|---:|---:|"]
        for s in snap["sections"]:
            lines.append(f"| {s['name']} | {s['samples_readable']}/{s['samples_requested']} | {s['windows_changed']} | {s['changed_bytes']} | {s['disk_entropy_median']} | {s['ram_entropy_median']} |")
        lines.append("")
    for snap in d.get("snapshots",[]):
        for s in snap["sections"]:
            q=s.get("original_function_entry_instruction_quality")
            if not q:continue
            lines+=["**"+snap["stage"]+" native function-entrypoint test:** "
                +str(q["rvas_readable"])+"/"+str(q["rvas_requested"])+" readable; "
                +str(q["rvas_differing_from_disk"])+" modified; "
                +"plausible first instruction disk/memory "
                +str(q["disk_plausible_first_instruction_count"])+"/"
                +str(q["memory_plausible_first_instruction_count"])+"; "
                +"unusual instructions disk/memory "
                +str(q["disk_unusual_privileged_instruction_count"])+"/"
                +str(q["memory_unusual_privileged_instruction_count"])+".",""]
    r=d.get("private_reconstruction")
    if r:
        lines+=["## Private analysis-only PE reconstruction",
            "Created: "+str(r.get("created_privately",False))]
        if r.get("created_privately"):
            lines+=["Recovered executable bytes: "+str(r["total_executable_bytes_read"]),
                "Bytes different from original disk image: "+str(r["total_executable_bytes_changed_from_disk"]),
                "Function-boundary evidence: "+str(r["function_boundary_evidence"]),
                "Reconstructed image SHA-256: "+r["reconstructed_sha256"],
                "Only aggregate proof was published; full image stayed temporary on Windows runner.",""]
        else:
            lines+=["Blocker: "+str(r.get("blocker","unknown")),""]
    lines+=["## Interpretation limits",
        "The Windows PE loader may apply relocations or write import pointers even without decryption.",
        "Sampled pages may miss code decrypted only on demand.",
        "A process that exits before samples cannot establish whether successful game startup would decrypt code.",
        "Failed ReadProcessMemory does not imply encryption, and readable changed pages do not necessarily imply decrypted executable code."]
    return "\n".join(lines)+"\n"

def self_test():
    assert entropy(bytes(2048))==0
    assert entropy(bytes(range(256)))==8
    assert len(CANONICAL_SHA256)==64
    assert CANONICAL_BYTES==97_284_496
    print("OFFLINE_MAPPED_IMAGE_PROBE_SELF_TEST_PASSED")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--exe",type=Path)
    ap.add_argument("--out",type=Path)
    ap.add_argument("--private-analysis-image",type=Path)
    ap.add_argument("--self-test",action="store_true")
    args=ap.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.exe or not args.out:
        ap.error("--exe and --out required")
    exe=args.exe.resolve()
    if exe.stat().st_size!=CANONICAL_BYTES or source_sha256(exe)!=CANONICAL_SHA256:
        raise RuntimeError("Authentic original SHA256/size validation failed")
    import pefile
    pe=pefile.PE(str(exe),fast_load=False)
    if pe.FILE_HEADER.Machine!=0x8664 or pe.OPTIONAL_HEADER.Magic!=0x20b:
        raise RuntimeError("Not original x64 PE32+ file")
    t0=time.monotonic()
    diag={"source_sha256_verified":CANONICAL_SHA256,
          "file_size_verified":CANONICAL_BYTES,
          "experiment":"bounded Windows CreateProcess suspended/resumed; no anti-cheat bypass",
          "max_wall_clock_seconds":MAX_RUNTIME_SEC}
    try:
        diag["runtime"]=runtime_probe(pe,exe,[0.5,2.0,6.0],args.private_analysis_image)
    except Exception as e:
        diag["runtime"]={"spawned":None,"blocker":type(e).__name__+": "+str(e),"snapshots":[]}
    diag["experiment_seconds"]=round(time.monotonic()-t0,3)
    args.out.mkdir(parents=True,exist_ok=True)
    (args.out/"fortnite541_runtime_image_diff.json").write_text(json.dumps(diag,indent=2)+"\n")
    (args.out/"fortnite541_runtime_image_diff.md").write_text(format_markdown(diag["runtime"]))
    print("RUNTIME_MEMORY_COMPARISON_COMPLETE")
    print(format_markdown(diag["runtime"]))

if __name__=="__main__":
    main()
