// Targeted Ghidra second pass for original Fortnite 5.41 executable routines.
// Input TSV is extracted from the independently checked unresolved JSONL audit.
// No successfully decompiled .pdata entry is in this work queue.
//
// Usage: Fortnite541Recover.java OUTPUT_DIR ORIGINAL_ORDINAL_RVA_TSV TIMEOUT_SECONDS
// Output: genuine C pseudocode or explicit failure, retaining the original RVA.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.GZIPOutputStream;

public class Fortnite541Recover extends GhidraScript {
    private static class Extent {
        final long start,end;
        Extent(long s,long e){start=s;end=e;}
    }
    private static class Target {
        final int index;
        final long start,end;
        Target(int i,long s,long e){index=i;start=s;end=e;}
    }
    private static long u32(Memory m,Address a)throws Exception{
        return Integer.toUnsignedLong(m.getInt(a));
    }
    private static String hex(long x){return String.format("0x%08x",x);}
    private static String json(String s){
        if(s==null)return "null";
        StringBuilder b=new StringBuilder("\"");
        for(int i=0;i<s.length();i++){
            char c=s.charAt(i);
            switch(c){
                case '\\':b.append("\\\\");break;
                case '"':b.append("\\\"");break;
                case '\n':b.append("\\n");break;
                case '\r':b.append("\\r");break;
                case '\t':b.append("\\t");break;
                default: if(c<32)b.append(String.format("\\u%04x",(int)c));else b.append(c);
            }
        }
        return b.append('"').toString();
    }
    private List<Extent> originalPdata()throws Exception{
        Memory m=currentProgram.getMemory();
        MemoryBlock b=m.getBlock(".pdata");
        if(b==null)throw new IllegalStateException("Original PE .pdata absent");
        Address image=currentProgram.getImageBase();
        List<Extent> ranges=new ArrayList<>();
        Set<Long> seen=new HashSet<>();
        for(long i=0;i<b.getSize()/12;i++){
            Address a=b.getStart().add(i*12);
            long s=u32(m,a), e=u32(m,a.add(4));
            if(s>=e||e-s>10000000L)continue;
            if(!m.contains(image.add(s))||!m.contains(image.add(e-1)))continue;
            if(seen.add(s))ranges.add(new Extent(s,e));
        }
        Collections.sort(ranges,Comparator.comparingLong(x->x.start));
        if(ranges.size()!=291757)throw new IllegalStateException(
            "Wrong original .pdata inventory: "+ranges.size());
        return ranges;
    }
    private static long parseRva(String value){
        if(!value.startsWith("0x"))throw new IllegalArgumentException("Bad RVA");
        return Long.parseUnsignedLong(value.substring(2),16);
    }
    private List<Target> targets(Path input,List<Extent> pdata)throws Exception{
        List<Target> targets=new ArrayList<>();
        Set<Integer> seen=new HashSet<>();
        for(String line:Files.readAllLines(input,StandardCharsets.UTF_8)){
            if(line.isBlank())continue;
            String[] parts=line.split("\\t",-1);
            if(parts.length!=3)throw new IllegalArgumentException("Bad original target TSV");
            int index=Integer.parseInt(parts[0]);
            long start=parseRva(parts[1]),end=parseRva(parts[2]);
            if(index<0||index>=pdata.size()||!seen.add(index))
                throw new IllegalArgumentException("Duplicate/out-of-range original index");
            Extent genuine=pdata.get(index);
            if(genuine.start!=start||genuine.end!=end)
                throw new IllegalStateException("RVA mismatch with retail PE at ordinal "+index);
            targets.add(new Target(index,start,end));
        }
        if(targets.isEmpty()||targets.size()>10000)
            throw new IllegalArgumentException("Invalid recovery batch size");
        return targets;
    }
    @Override public void run()throws Exception{
        String[] args=getScriptArgs();
        if(args.length!=3 && args.length!=4)throw new IllegalArgumentException(
            "Expected OUTPUT_DIR ORIGINAL_ORDINAL_RVA_TSV TIMEOUT_SECONDS [fast|split|bounded]");
        String strategy=args.length==4?args[3]:"fast";
        if(!strategy.equals("fast")&&!strategy.equals("split")&&!strategy.equals("bounded"))
            throw new IllegalArgumentException("Unsupported original function repair mode");
        Path output=Paths.get(args[0]);
        Path input=Paths.get(args[1]);
        int timeout=Integer.parseInt(args[2]);
        if(timeout<1||timeout>120)throw new IllegalArgumentException("Invalid Ghidra timeout");
        Files.createDirectories(output.resolve("records"));
        List<Extent> pdata=originalPdata();
        List<Target> jobs=targets(input,pdata);
        String filename=String.format("records/retry_%06d_%06d.jsonl.gz",
            jobs.get(0).index,jobs.get(jobs.size()-1).index);
        Path destination=output.resolve(filename);
        Path part=Paths.get(destination.toString()+".part");
        int successes=0,failed=0,missing=0,containing=0,parentsRemoved=0,instructionsRepaired=0;
        int originalBodiesBounded=0, bodyBoundFailures=0;
        Address base=currentProgram.getImageBase();
        DecompInterface dec=new DecompInterface();
        dec.toggleCCode(true);
        dec.toggleSyntaxTree(true);
        dec.setSimplificationStyle("decompile");
        if(!dec.openProgram(currentProgram))
            throw new IllegalStateException("Ghidra decompiler open failed");
        long started=System.currentTimeMillis();
        try(BufferedWriter out=new BufferedWriter(new OutputStreamWriter(
            new GZIPOutputStream(Files.newOutputStream(part)),StandardCharsets.UTF_8))){
            for(Target t:jobs){
                if(monitor.isCancelled())throw new InterruptedException("Cancelled");
                Address entry=base.add(t.start);
                Function fn=currentProgram.getFunctionManager().getFunctionAt(entry);
                String diagnostics=null,source=null,err=null;
                String status="missing_function";
                if(fn==null){
                    Function owner=currentProgram.getFunctionManager().getFunctionContaining(entry);
                    if(owner!=null){
                        containing++;
                        diagnostics="original .pdata entry lies inside "+owner.getName()+
                            " at "+owner.getEntryPoint().toString();
                        if((strategy.equals("split")||strategy.equals("bounded")) &&
                           owner.getEntryPoint().compareTo(entry)<0){
                            try{
                                Address parentStart=owner.getEntryPoint();
                                if(currentProgram.getFunctionManager().removeFunction(parentStart)){
                                    parentsRemoved++;
                                    diagnostics+="; overlapping inferred parent removed";
                                    Instruction crossed=currentProgram.getListing()
                                        .getInstructionContaining(entry);
                                    if(crossed!=null && !crossed.getMinAddress().equals(entry)){
                                        currentProgram.getListing().clearCodeUnits(
                                            crossed.getMinAddress(),crossed.getMaxAddress(),false);
                                        instructionsRepaired++;
                                        diagnostics+="; misaligned crossing instruction cleared";
                                    }
                                }
                            }catch(Exception repairError){
                                diagnostics+="; boundary repair failed: "+repairError.toString();
                            }
                        }
                    }
                    try{
                        disassemble(entry);
                        fn=createFunction(entry,null);
                        if(fn==null)fn=currentProgram.getFunctionManager().getFunctionAt(entry);
                    }catch(Exception ex){
                        err="Recovery function creation: "+ex.toString();
                    }
                }
                boolean bodyBounded=false;
                if(fn!=null && strategy.equals("bounded")){
                    try {
                        // Original Win64 .pdata gives the actual low/high native
                        // function unwind interval. Never infer an extended
                        // body from Ghidra speculative cross-section flows.
                        AddressSet originalBody=new AddressSet(entry,base.add(t.end-1));
                        fn.setBody(originalBody);
                        bodyBounded=true;
                        originalBodiesBounded++;
                    }catch(Exception boundError){
                        bodyBoundFailures++;
                        String explanation="Original .pdata body clipping failed: "+boundError.toString();
                        diagnostics=(diagnostics==null?explanation:diagnostics+"; "+explanation);
                    }
                }
                String name=null,signature=null;
                if(fn!=null){
                    name=fn.getName();
                    try{signature=fn.getSignature().toString();}catch(Exception ex){}
                    try{
                        DecompileResults res=dec.decompileFunction(fn,timeout,monitor);
                        if(res.decompileCompleted() && res.getDecompiledFunction()!=null &&
                           res.getDecompiledFunction().getC()!=null &&
                           !res.getDecompiledFunction().getC().isBlank()){
                            source=res.getDecompiledFunction().getC();
                            status="decompiled";
                            successes++;
                        }else{
                            status="decompiler_failed";
                            err=res.getErrorMessage();
                            failed++;
                        }
                    }catch(Exception ex){
                        status="decompiler_failed";
                        err="Recovery decompiler exception: "+ex.toString();
                        failed++;
                    }
                }else{
                    missing++;
                    if(err==null)err="Could not create function at original .pdata entry";
                }
                out.write("{\"index\":"+t.index+
                    ",\"rva\":"+json(hex(t.start))+
                    ",\"end_rva\":"+json(hex(t.end))+
                    ",\"name\":"+json(name)+
                    ",\"signature\":"+json(signature)+
                    ",\"status\":"+json(status)+
                    ",\"error\":"+json(err)+
                    ",\"diagnostics\":"+json(diagnostics)+
                    ",\"body_bounded\":"+bodyBounded+
                    ",\"c\":"+json(source)+"}\n");
            }
        }finally{dec.dispose();}
        Files.move(part,destination,StandardCopyOption.REPLACE_EXISTING);
        String summary="{\"original_pdata_functions\":"+pdata.size()+
            ",\"retry_count\":"+jobs.size()+
            ",\"recovered\":"+successes+
            ",\"decompiler_failed\":"+failed+
            ",\"missing\":"+missing+
            ",\"overlapping_parent_functions\":"+containing+
            ",\"removed_inferred_parent_functions\":"+parentsRemoved+
            ",\"repaired_crossing_instructions\":"+instructionsRepaired+
            ",\"strategy\":"+json(strategy)+
            ",\"original_pdata_bodies_applied\":"+originalBodiesBounded+
            ",\"original_pdata_body_failures\":"+bodyBoundFailures+
            ",\"first_original_index\":"+jobs.get(0).index+
            ",\"last_original_index\":"+jobs.get(jobs.size()-1).index+
            ",\"elapsed_ms\":"+(System.currentTimeMillis()-started)+
            ",\"file\":"+json(filename)+"}\n";
        Files.writeString(output.resolve("recovery_summary.json"),
            summary,StandardCharsets.UTF_8);
        println("FORTNITE541_GHIDRA_RECOVERY_COMPLETE "+summary.trim());
    }
}
