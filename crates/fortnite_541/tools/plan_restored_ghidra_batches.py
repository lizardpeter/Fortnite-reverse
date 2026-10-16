#!/usr/bin/env python3
"""Deterministically schedule every original Fortnite 5.41 .pdata entry once.

The canonical list comes from the actual Ghidra run (291757 original function
addresses; the PE unwind table contained 291760 records before deduplication).
Existing committed public JSONL.GZ shards are the durable progress ledger.
Never infer success from a workflow dispatch or a runner starting.
"""
from __future__ import annotations
import argparse, json, os, re, subprocess
from pathlib import Path

TOTAL=291757
PREFIX="decompilation/fortnite541_restored/functions/"
SHARD_RE=re.compile(r"^"+re.escape(PREFIX)+r"pdata_(\d{6})_(\d{6})\.jsonl\.gz$")

def completed_ranges(files: list[str]) -> list[tuple[int,int]]:
    ranges=[]
    for path in files:
        match=SHARD_RE.fullmatch(path.strip())
        if not match: continue
        lo,hi=map(int,match.groups())
        if not(0<=lo<=hi<TOTAL):
            raise ValueError(f"invalid original function shard {path}")
        ranges.append((lo,hi+1))
    ranges.sort()
    merged=[]
    for lo,hi in ranges:
        if merged and lo<=merged[-1][1]:
            merged[-1]=(merged[-1][0],max(hi,merged[-1][1]))
        else:
            merged.append((lo,hi))
    return merged

def pending_shards(ranges:list[tuple[int,int]],count:int,workers:int):
    jobs=[]
    missing=TOTAL-sum(hi-lo for lo,hi in ranges)
    idx=0
    cursor=0
    while cursor<TOTAL and len(jobs)<workers:
        while idx<len(ranges) and ranges[idx][1]<=cursor:
            idx+=1
        if idx<len(ranges) and ranges[idx][0]<=cursor<ranges[idx][1]:
            cursor=ranges[idx][1]
            continue
        next_covered=ranges[idx][0] if idx<len(ranges) else TOTAL
        end=min(cursor+count,next_covered,TOTAL)
        if end<=cursor:
            raise ValueError("non-progressing source function range planner")
        jobs.append({"start":cursor,"count":end-cursor,
                     "end_exclusive":end,"label":f"{cursor:06d}_{end-1:06d}"})
        cursor=end
    planned=sum(x["count"] for x in jobs)
    return jobs,missing,missing-planned

def load_remote()->list[str]:
    result=subprocess.run(["git","ls-tree","-r","--name-only",
                           "origin/re/fortnite541-ghidra-restored","--",PREFIX],
                          capture_output=True,text=True,check=True)
    return result.stdout.splitlines()

def test()->None:
    rs=completed_ranges([
        PREFIX+"pdata_000000_000011.jsonl.gz",
        PREFIX+"pdata_000002_000005.jsonl.gz",
        PREFIX+"pdata_000015_000019.jsonl.gz",
    ])
    assert rs==[(0,12),(15,20)],rs
    jobs,missing,more=pending_shards(rs,10,2)
    assert jobs==[
        dict(start=12,count=3,end_exclusive=15,label="000012_000014"),
        dict(start=20,count=10,end_exclusive=30,label="000020_000029"),
    ]
    assert more==missing-13
    all_done=pending_shards([(0,TOTAL)],100,16)
    assert all_done==([],0,0)
    print("ORIGINAL_PDATA_SHARD_PLANNER_TESTS_PASSED")

def main()->None:
    parser=argparse.ArgumentParser()
    parser.add_argument("--batch",type=int,default=2000)
    parser.add_argument("--workers",type=int,default=16)
    parser.add_argument("--self-test",action="store_true")
    args=parser.parse_args()
    if args.self_test:
        test()
        return
    if not(1<=args.batch<=10000 and 1<=args.workers<=32):
        raise SystemExit("invalid original Ghidra shard planning bounds")
    ranges=completed_ranges(load_remote())
    jobs,missing,remaining=pending_shards(ranges,args.batch,args.workers)
    assert missing>=0 and remaining>=0
    payload={"include":jobs}
    print(json.dumps({
        "original_source_pdata_entries":TOTAL,
        "successfully_committed_entry_ranges":ranges,
        "already_covered":TOTAL-missing,
        "missing_before":missing,"selected_workers":len(jobs),
        "function_count_scheduled":missing-remaining,
        "missing_after_if_successful":remaining,
        "shards":jobs,
    },separators=(",",":")))
    if dest:=os.getenv("GITHUB_OUTPUT"):
        with open(dest,"a") as f:
            f.write("matrix="+json.dumps(payload,separators=(",",":"))+"\n")
            f.write("workers="+str(len(jobs))+"\n")
            f.write("more="+("true" if remaining>0 else "false")+"\n")
            f.write("missing_before="+str(missing)+"\n")
            f.write("missing_after="+str(remaining)+"\n")

if __name__=="__main__":
    main()
