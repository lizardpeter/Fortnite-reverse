#!/usr/bin/env python3
"""Micro-emulate ONE authenticated original Fortnite 5.41 varuint loop.

Unicorn receives only source-verified on-disk second-.text section bytes and
synthetic input vectors; the retail game itself is never launched, injected,
unpacked, or run. Execution stops after the source accumulator update,
before the succeeding branch-based dispatcher.

This supports proving arithmetic equivalence to a Rust implementation; it
does not decrypt original executable code or defeat any runtime protection.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct

ORIGINAL_SHA="7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108"
ORIGINAL_SIZE=97_284_496
LOOP_RVA=0x5C61E26
LOOP_END_RVA=0x5BF2A18
POST_STORE_STOP_RVA=0x5BF2A34
SECTION_RVA=0x5AE4000
IMAGE_BASE=0x140000000
STACK_BASE=0x400000000
IO_BASE=0x500000000
VECTORS=[
    ("zero",bytes([0]),0,1),
    ("one",bytes([1]),1,1),
    ("single_max",bytes([127]),127,1),
    ("two_bytes",bytes([0x80,1]),128,2),
    ("three_bytes",bytes([0xe5,0x8e,0x26]),624485,3),
    ("u32_max",bytes([0xff,0xff,0xff,0xff,0x0f]),0xffffffff,5),
    ("read_until_stop",bytes([0x80,0x00,0x55]),0,2),
    ("original_x86_shift_wrap",bytes([0x80,0x80,0x80,0x80,0x80,1]),8,6),
]

def original_math(data):
    shift=0
    result=0
    for i,b in enumerate(data):
        result=(result+(((b&0x7f) << (shift&31)) & 0xffffffff))&0xffffffff
        shift=(shift+7)&0xffffffff
        if b<0x80:return result,i+1
    raise ValueError("unterminated test vector")

def hash_file(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1<<20),b""):h.update(chunk)
    return h.hexdigest()

def verified_code(path):
    import pefile
    if path.stat().st_size!=ORIGINAL_SIZE or hash_file(path)!=ORIGINAL_SHA:
        raise ValueError("retail PE file does not match canonical original bytes")
    pe=pefile.PE(str(path))
    sec=next((s for s in pe.sections if int(s.VirtualAddress)==SECTION_RVA
       and s.Name.rstrip(b"\x00")==b".text"),None)
    if sec is None or not (sec.Characteristics&0x20000000):
        raise ValueError("expected original protected native x64 section absent")
    if pe.get_data(0x5C61E30,3).hex()!="83e07f":
        raise ValueError("expected original payload mask instruction changed")
    if pe.get_data(0x5C61E46,4).hex()!="83450807":
        raise ValueError("expected original bit-offset increment changed")
    return sec.get_data(),int(sec.SizeOfRawData)

def micro_emulate(sec_data,section_size,source):
    from unicorn import (
        Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_PROT_READ,
        UC_PROT_WRITE,UC_PROT_EXEC
    )
    from unicorn.x86_const import UC_X86_REG_RBP,UC_X86_REG_RSP,UC_X86_REG_RIP
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    mapped_size=(section_size+0xfff)&~0xfff
    start=IMAGE_BASE+SECTION_RVA
    uc.mem_map(start,mapped_size,UC_PROT_READ|UC_PROT_WRITE|UC_PROT_EXEC)
    uc.mem_write(start,sec_data)
    uc.mem_protect(start,mapped_size,UC_PROT_READ|UC_PROT_EXEC)

    uc.mem_map(STACK_BASE,0x10000,UC_PROT_READ|UC_PROT_WRITE)
    uc.mem_map(IO_BASE,0x10000,UC_PROT_READ|UC_PROT_WRITE)
    rbp=STACK_BASE+0x8000
    buffer=IO_BASE+0x1000
    cursor_ptr=IO_BASE+0x2000
    output_ptr=IO_BASE+0x3000
    initial_current=10
    initial_bias=4
    uc.mem_write(buffer,source)
    uc.mem_write(cursor_ptr,struct.pack("<Q",buffer))
    uc.mem_write(rbp+0x30,struct.pack("<Q",cursor_ptr))
    uc.mem_write(rbp+0x38,struct.pack("<Q",output_ptr))
    uc.mem_write(output_ptr,struct.pack("<II",initial_current,initial_bias))
    uc.mem_write(rbp+0x08,struct.pack("<I",0))
    uc.mem_write(rbp+0x0C,struct.pack("<I",0))
    uc.reg_write(UC_X86_REG_RBP,rbp)
    uc.reg_write(UC_X86_REG_RSP,rbp-0x200)
    uc.reg_write(UC_X86_REG_RIP,IMAGE_BASE+LOOP_RVA)
    state={"reached_sentinel":False,"instructions":0}
    sentinel=IMAGE_BASE+POST_STORE_STOP_RVA
    def hook(uc,address,size,user_data):
        state["instructions"]+=1
        if address==sentinel:
            state["reached_sentinel"]=True
            uc.emu_stop()
        elif state["instructions"]>256:
            uc.emu_stop()
    uc.hook_add(UC_HOOK_CODE,hook)
    uc.emu_start(IMAGE_BASE+LOOP_RVA,0,count=256)
    if not state["reached_sentinel"]:
        raise RuntimeError("authenticated x64 loop did not reach its verified completion")
    value=struct.unpack("<I",bytes(uc.mem_read(rbp+0x0C,4)))[0]
    advanced=struct.unpack("<Q",bytes(uc.mem_read(cursor_ptr,8)))[0]-buffer
    stored_current=struct.unpack("<I",bytes(uc.mem_read(output_ptr,4)))[0]
    return {"result":value,"consumed":advanced,"instructions":state["instructions"]-1,
            "stored_current":stored_current,"original_current":initial_current,"bias":initial_bias}

def self_test():
    for label,data,value,n in VECTORS:
        got=original_math(data)
        assert got==(value,n),(label,got,value,n)
    print("FORTNITE_ORIGINAL_VARUINT_REFERENCE_SELFTEST_PASSED")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--exe",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--self-test",action="store_true")
    a=p.parse_args()
    if a.self_test:return self_test()
    if not a.exe or not a.out:p.error("--exe and --out are required")
    sec_data,size=verified_code(a.exe)
    records=[]
    for name,data,expected,consumed in VECTORS:
        vm=micro_emulate(sec_data,size,data)
        actual=(vm["result"],vm["consumed"])
        target=(expected,consumed)
        reference=original_math(data)
        expected_accum=(10+4+expected)&0xffffffff
        if vm["stored_current"]!=expected_accum:
            raise AssertionError(f"native x64 postdecode state mismatch: {name}")
        if actual!=target or actual!=reference:
            raise AssertionError(f"original x64 instruction mismatch for {name}: VM={actual}, reference={reference}, expected={target}")
        records.append({"test":name,"input_hex":data.hex(),"expected_u32":expected,
                        "source_x64_result":vm["result"],
                        "bytes_consumed":vm["consumed"],"x64_instructions":vm["instructions"],
                        "accumulated_u32":vm["stored_current"],
                        "postdecode_expected_u32":expected_accum,
                        "match":True})
    report={"source_sha256_verified":ORIGINAL_SHA,"original_loop_rva":hex(LOOP_RVA),
            "completion_rva":hex(LOOP_END_RVA),
            "postdecode_store_stop_rva":hex(POST_STORE_STOP_RVA),
            "execution_mode":"isolated original x64 loop and immediate accumulator update: stops before branch dispatch",
            "all_passed":True,"vectors":records,
            "limits":["No game binary execution, decrypted executable or runtime memory inspection",
               "Only standalone varuint loop behavior under synthetic inputs",
               "The source x64 loop performs masked SHL and wrapping 32-bit addition"]}
    a.out.mkdir(parents=True,exist_ok=True)
    (a.out/"fortnite541_varuint_microemu.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# Authenticated native ULEB128 micro-emulation","",
           "Original EXE SHA256 verified: "+ORIGINAL_SHA,"",
           "Only the original loop at RVA "+hex(LOOP_RVA)+" and accumulator update at "+hex(LOOP_END_RVA)+" execute in a no-syscall Unicorn sandbox. Execution stops before further dispatch at "+hex(POST_STORE_STOP_RVA)+".","",
           "| Synthetic input | Original decoded u32 | Accumulated u32 | Bytes consumed | Actual x64 instructions |",
           "|---|---:|---:|---:|---:|"]
    for x in records:
        lines.append(f"| {x['test']} | {x['source_x64_result']} | {x['accumulated_u32']} | {x['bytes_consumed']} | {x['x64_instructions']} |")
    lines+=["","Every case agrees with the Rust source-equivalent 32-bit wrapping arithmetic. This is not a claim that any Fortnite game logic has been decrypted."]
    (a.out/"fortnite541_varuint_microemu.md").write_text("\n".join(lines)+"\n")
    print("FORTNITE_ORIGINAL_VARUINT_X64_MICROEMULATION_ALL_PASSED",len(records))
    print("\n".join(lines))

if __name__=="__main__":main()
