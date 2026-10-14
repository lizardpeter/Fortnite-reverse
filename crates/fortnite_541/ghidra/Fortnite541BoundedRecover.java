// Source-authenticated bounded recovery for the last original .pdata entries.
// In Ghidra 12.1.4 the last material/engine functions frequently fail with
// "Trying to construct memory range beyond end of address space: ram".
// Constrain their body to the REAL original PE unwind function extent.
// Only actual successful DecompInterface C code is counted as recovered.
// Never manufacture C, patch source binary, or change prior successful shards.
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

public class Fortnite541BoundedRecover extends GhidraScript {
    private static class Span {
        final long start,end;
        Span(long a,long b){start=a;end=b;}
    }
    private static class Target {
        final int index;
        final Span span;
        Target(int i,Span s){index=i;span=s;}
    }
    private static long unsigned(Memory mem,Address address)throws Exception{
        return Integer.toUnsignedLong(mem.getInt(address));
    }
    private static String hex(long n){return String.format("0x%08x",n);}
    private static String q(String value){
        if(value==null)return "null";
        StringBuilder result=new StringBuilder("\"");
        for(int i=0;i<value.length();i++){
            char c=value.charAt(i);
            switch(c){
                case '"':result.append("\\\"");break;
                case '\\':result.append("\\\\");break;
                case '\n':result.append("\\n");break;
                case '\r':result.append("\\r");break;
                case '\t':result.append("\\t");break;
                default:if(c<32)result.append(String.format("\\u%04x",(int)c));
                        else result.append(c);
            }
        }
        return result.append("\"").toString();
    }
    private List<Span> authenticatedPdata()throws Exception{
        Memory mem=currentProgram.getMemory();
        MemoryBlock pdata=mem.getBlock(".pdata");
        if(pdata==null)throw new IllegalStateException("Original retail .pdata missing");
        Address base=currentProgram.getImageBase();
        Set<Long> unique=new HashSet<>();
        List<Span> spans=new ArrayList<>();
        for(long j=0;j<pdata.getSize()/12;j++){
            Address a=pdata.getStart().add(j*12);
            long start=unsigned(mem,a),end=unsigned(mem,a.add(4));
            if(start>=end || end-start>10_000_000L)continue;
            if(!mem.contains(base.add(start)) || !mem.contains(base.add(end-1)))continue;
            if(unique.add(start))spans.add(new Span(start,end));
        }
        Collections.sort(spans,Comparator.comparingLong(s->s.start));
        if(spans.size()!=291757)throw new IllegalStateException(
            "Untrusted source original .pdata count "+spans.size());
        return spans;
    }
    private static long parse(String value){
        if(!value.startsWith("0x"))throw new IllegalArgumentException("Missing hex RVA");
        return Long.parseUnsignedLong(value.substring(2),16);
    }
    private List<Target> sourceTargets(Path input,List<Span> original)throws Exception{
        List<Target> result=new ArrayList<>();
        Set<Integer> indexes=new HashSet<>();
        for(String line:Files.readAllLines(input,StandardCharsets.UTF_8)){
            if(line.isBlank())continue;
            String[] parts=line.split("\\t",-1);
            if(parts.length!=3)throw new IllegalArgumentException("Expected index/start/end");
            int index=Integer.parseInt(parts[0]);
            if(index<0||index>=original.size()||!indexes.add(index))
                throw new IllegalArgumentException("Duplicate original .pdata ordinal");
            Span found=original.get(index);
            if(found.start!=parse(parts[1])||found.end!=parse(parts[2]))
                throw new IllegalStateException("Wrong original retail function entry at "+index);
            result.add(new Target(index,found));
        }
        if(result.isEmpty()||result.size()>56)
            throw new IllegalArgumentException("Expected bounded original remaining queue");
        return result;
    }
    @Override public void run()throws Exception{
        String[] args=getScriptArgs();
        if(args.length!=3)throw new IllegalArgumentException(
            "Expected OUTPUT_DIR ORIGINAL_PDATA_TSV TIMEOUT_SECONDS");
        Path output=Paths.get(args[0]);
        Path targetsFile=Paths.get(args[1]);
        int timeout=Integer.parseInt(args[2]);
        if(timeout<1||timeout>120)throw new IllegalArgumentException("Timeout outside 1..120");
        Files.createDirectories(output.resolve("records"));
        List<Target> targets=sourceTargets(targetsFile,authenticatedPdata());
        Address base=currentProgram.getImageBase();
        Memory mem=currentProgram.getMemory();
        DecompInterface decompiler=new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        if(!decompiler.openProgram(currentProgram))
            throw new IllegalStateException("Cannot initialize original retail C decompiler");
        int success=0,failed=0,missing=0,removed=0,clipped=0,conflicts=0;
        long started=System.currentTimeMillis();
        String name=String.format("records/retry_%06d_%06d.jsonl.gz",
            targets.get(0).index,targets.get(targets.size()-1).index);
        Path destination=output.resolve(name);
        Path temp=Paths.get(destination.toString()+".part");
        try(BufferedWriter out=new BufferedWriter(new OutputStreamWriter(
            new GZIPOutputStream(Files.newOutputStream(temp)),StandardCharsets.UTF_8))){
            for(Target target:targets){
                if(monitor.isCancelled())throw new InterruptedException("Cancelled");
                Address entry=base.add(target.span.start);
                Address last=base.add(target.span.end-1);
                MemoryBlock block=mem.getBlock(entry);
                if(block==null||!block.isExecute()||!mem.contains(last))
                    throw new IllegalStateException("Source .pdata not executable "+hex(target.span.start));
                String diagnostics=null,error=null,code=null,fnName=null,signature=null;
                Function fn=currentProgram.getFunctionManager().getFunctionAt(entry);
                boolean narrowed=false;
                if(fn==null){
                    Function parent=currentProgram.getFunctionManager().getFunctionContaining(entry);
                    if(parent!=null&&!parent.getEntryPoint().equals(entry) &&
                       parent.getEntryPoint().compareTo(entry)<0){
                        try{
                            if(currentProgram.getFunctionManager()
                                  .removeFunction(parent.getEntryPoint())){
                                removed++;
                                diagnostics="Removed conflicting inferred parent "+
                                    parent.getEntryPoint();
                            }
                        }catch(Exception ex){diagnostics="Parent collision: "+ex;}
                    }
                    Instruction crossing=currentProgram.getListing()
                        .getInstructionContaining(entry);
                    if(crossing!=null&&!crossing.getMinAddress().equals(entry)){
                        currentProgram.getListing().clearCodeUnits(
                            crossing.getMinAddress(),crossing.getMaxAddress(),false);
                    }
                    try{
                        disassemble(entry);
                        fn=createFunction(entry,null);
                        if(fn==null)fn=currentProgram.getFunctionManager().getFunctionAt(entry);
                    }catch(Exception ex){
                        error="Original boundary function creation failed: "+ex;
                    }
                }
                // Critical change versus prior full/fast/split Ghidra:
                // constrain the FunctionDB body to the original .pdata
                // [BeginAddress,EndAddress). This is authenticated native
                // unwind metadata, NOT an arbitrary code-length heuristic.
                if(fn!=null){
                    try{
                        fn.setBody(new AddressSet(entry,last));
                        clipped++;
                        narrowed=true;
                    }catch(Exception ex){
                        conflicts++;
                        diagnostics=(diagnostics==null?"":diagnostics+"; ")+
                            "Original bounded body was rejected: "+ex;
                        // Never count an unbounded source call as recovered
                        // in this mode; the previous Ghidra passes already
                        // tried the original unbounded representation.
                    }
                }
                String status="missing_function";
                if(fn!=null){
                    fnName=fn.getName();
                    try{signature=fn.getSignature().toString();}catch(Exception ignored){}
                    if(narrowed){
                        try{
                            DecompileResults result=decompiler.decompileFunction(
                                fn,timeout,monitor);
                            if(result.decompileCompleted() &&
                               result.getDecompiledFunction()!=null &&
                               result.getDecompiledFunction().getC()!=null &&
                               !result.getDecompiledFunction().getC().isBlank()){
                                code=result.getDecompiledFunction().getC();
                                status="decompiled";
                            }else{
                                status="decompiler_failed";
                                error=result.getErrorMessage();
                            }
                        }catch(Exception ex){
                            status="decompiler_failed";
                            error="Original bounded decompilation error: "+ex;
                        }
                    }else{
                        status="decompiler_failed";
                        if(error==null)error="Function body could not be bounded to original .pdata";
                    }
                }else if(error==null){
                    error="Original function at authenticated .pdata entry was not created";
                }
                if(status.equals("decompiled"))success++;
                else if(status.equals("decompiler_failed"))failed++;
                else missing++;
                out.write("{\"index\":"+target.index+
                    ",\"rva\":"+q(hex(target.span.start))+
                    ",\"end_rva\":"+q(hex(target.span.end))+
                    ",\"status\":"+q(status)+
                    ",\"name\":"+q(fnName)+
                    ",\"signature\":"+q(signature)+
                    ",\"error\":"+q(error)+
                    ",\"diagnostics\":"+q(diagnostics)+
                    ",\"original_pdata_body_bounded\":"+narrowed+
                    ",\"c\":"+q(code)+"}\n");
            }
        }finally{decompiler.dispose();}
        Files.move(temp,destination,StandardCopyOption.REPLACE_EXISTING);
        String summary="{\"original_pdata_functions\":291757"+
            ",\"retry_count\":"+targets.size()+
            ",\"recovered\":"+success+
            ",\"decompiler_failed\":"+failed+
            ",\"missing\":"+missing+
            ",\"bounded_body_attempts\":"+clipped+
            ",\"body_conflicts\":"+conflicts+
            ",\"removed_inferred_parents\":"+removed+
            ",\"first_original_index\":"+targets.get(0).index+
            ",\"last_original_index\":"+targets.get(targets.size()-1).index+
            ",\"elapsed_ms\":"+(System.currentTimeMillis()-started)+
            ",\"file\":"+q(name)+"}\n";
        Files.writeString(output.resolve("recovery_summary.json"),summary,StandardCharsets.UTF_8);
        println("FORTNITE541_GHIDRA_BOUNDED_COMPLETE "+summary.trim());
    }
}