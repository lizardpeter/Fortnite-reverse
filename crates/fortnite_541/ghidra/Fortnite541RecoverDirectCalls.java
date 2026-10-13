// Source-verified Fortnite 5.41 direct-call native function recovery.
// These are candidate leaf/thunk routines OUTSIDE every original .pdata span.
// C pseudocode is emitted only if a real decoded CALL witness is validated,
// a real native function is created, and Ghidra decompilation succeeds.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
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

public class Fortnite541RecoverDirectCalls extends GhidraScript {
    private static class Extent {
        final long start,end;
        Extent(long s,long e){start=s;end=e;}
    }
    private static class Target {
        final int index,calls;
        final long rva,callsite;
        Target(int i,long r,long s,int c){index=i;rva=r;callsite=s;calls=c;}
    }
    private static long u32(Memory m,Address a)throws Exception{
        return Integer.toUnsignedLong(m.getInt(a));
    }
    private static String hex(long n){return String.format("0x%08x",n);}
    private static String json(String s){
        if(s==null)return "null";
        StringBuilder b=new StringBuilder("\"");
        for(int i=0;i<s.length();i++){
            char c=s.charAt(i);
            if(c=='\\')b.append("\\\\");
            else if(c=='"')b.append("\\\"");
            else if(c=='\n')b.append("\\n");
            else if(c=='\r')b.append("\\r");
            else if(c=='\t')b.append("\\t");
            else if(c<32)b.append(String.format("\\u%04x",(int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
    private List<Extent> pdata()throws Exception{
        Memory mem=currentProgram.getMemory();
        MemoryBlock block=mem.getBlock(".pdata");
        if(block==null)throw new IllegalStateException("Original .pdata absent");
        Address image=currentProgram.getImageBase();
        Set<Long> seen=new HashSet<>();
        List<Extent> spans=new ArrayList<>();
        for(long k=0;k<block.getSize()/12;k++){
            Address at=block.getStart().add(k*12);
            long start=u32(mem,at),end=u32(mem,at.add(4));
            if(start>=end||end-start>10000000L)continue;
            if(!mem.contains(image.add(start))||!mem.contains(image.add(end-1)))continue;
            if(seen.add(start))spans.add(new Extent(start,end));
        }
        Collections.sort(spans,Comparator.comparingLong(x->x.start));
        if(spans.size()!=291757)throw new IllegalStateException(
            "Original retail .pdata count incorrect: "+spans.size());
        return spans;
    }
    private static boolean covered(List<Extent> spans,long[] prefix,long rva){
        int lo=0,hi=spans.size();
        while(lo<hi){
            int mid=(lo+hi)/2;
            if(spans.get(mid).start<=rva)lo=mid+1;
            else hi=mid;
        }
        return lo>0&&prefix[lo-1]>rva;
    }
    private static long parseRva(String s){
        if(!s.startsWith("0x"))throw new IllegalArgumentException("Missing original RVA");
        return Long.parseUnsignedLong(s.substring(2),16);
    }
    private List<Target> targets(Path file)throws Exception{
        List<Target> result=new ArrayList<>();
        Set<Integer> seenIndex=new HashSet<>();
        Set<Long> seenRva=new HashSet<>();
        for(String line:Files.readAllLines(file,StandardCharsets.UTF_8)){
            if(line.isBlank())continue;
            String[] parts=line.split("\\t",-1);
            if(parts.length!=4)throw new IllegalArgumentException("Bad original CALL target row");
            int i=Integer.parseInt(parts[0]),calls=Integer.parseInt(parts[3]);
            long r=parseRva(parts[1]),callsite=parseRva(parts[2]);
            if(i<0||i>=58||calls<1||!seenIndex.add(i)||!seenRva.add(r))
                throw new IllegalArgumentException("Duplicate/invalid original source CALL candidate");
            result.add(new Target(i,r,callsite,calls));
        }
        if(result.size()<1||result.size()>58)
            throw new IllegalArgumentException("Expected bounded source-backed CALL retry batch");
        return result;
    }
    private boolean witness(Memory mem,Address image,Target target){
        Address source=image.add(target.callsite),dst=image.add(target.rva);
        try{
            MemoryBlock block=mem.getBlock(source);
            if(block==null||!block.isExecute())return false;
            // x86-64 E8 rel32 is an unambiguous source-byte direct CALL
            // witness even before the Ghidra auto-analyzer has run.
            if(Byte.toUnsignedInt(mem.getByte(source))==0xe8){
                int delta=mem.getInt(source.add(1));
                long expected=target.callsite+5+(long)delta;
                if(expected==target.rva)return true;
            }
            Instruction ins=currentProgram.getListing().getInstructionAt(source);
            if(ins==null){
                disassemble(source);
                ins=currentProgram.getListing().getInstructionAt(source);
            }
            if(ins!=null && ins.getFlowType().isCall()){
                for(Address dest:ins.getFlows()){
                    if(dest.equals(dst))return true;
                }
            }
        }catch(Exception ignored){}
        return false;
    }
    @Override public void run()throws Exception{
        String[] args=getScriptArgs();
        if(args.length!=3)
            throw new IllegalArgumentException("Expected OUTPUT_DIR SOURCE_CALL_TSV TIMEOUT_SECONDS");
        Path root=Paths.get(args[0]),input=Paths.get(args[1]);
        int timeout=Integer.parseInt(args[2]);
        if(timeout<1||timeout>120)throw new IllegalArgumentException("Invalid decompiler timeout");
        Files.createDirectories(root.resolve("records"));
        List<Target> work=targets(input);
        List<Extent> spans=pdata();
        long[] prefix=new long[spans.size()];
        long high=0;
        for(int i=0;i<spans.size();i++){
            high=Math.max(high,spans.get(i).end);
            prefix[i]=high;
        }
        DecompInterface dec=new DecompInterface();
        dec.toggleCCode(true);
        dec.toggleSyntaxTree(true);
        dec.setSimplificationStyle("decompile");
        if(!dec.openProgram(currentProgram))
            throw new IllegalStateException("Original retail PE decompiler unavailable");
        Address image=currentProgram.getImageBase();
        Memory mem=currentProgram.getMemory();
        int success=0,failed=0,missing=0,badWitness=0,overlapRemoved=0;
        String name=String.format("records/direct_calls_%03d_%03d.jsonl.gz",
            work.get(0).index,work.get(work.size()-1).index);
        Path dst=root.resolve(name);
        Path part=Paths.get(dst.toString()+".part");
        try(BufferedWriter out=new BufferedWriter(new OutputStreamWriter(
            new GZIPOutputStream(Files.newOutputStream(part)),StandardCharsets.UTF_8))){
            for(Target t:work){
                if(monitor.isCancelled())throw new InterruptedException("Original call recovery cancelled");
                Address entry=image.add(t.rva);
                MemoryBlock block=mem.getBlock(entry);
                if(block==null||!block.isExecute()||covered(spans,prefix,t.rva))
                    throw new IllegalStateException("Candidate not truly outside original executable .pdata "+hex(t.rva));
                boolean authentic=witness(mem,image,t);
                String status="invalid_witness",error=null,c=null,fnName=null;
                if(!authentic){
                    badWitness++;
                    error="Original executable did not verify a decoded direct CALL to target RVA";
                }else{
                    Function fn=currentProgram.getFunctionManager().getFunctionAt(entry);
                    if(fn==null){
                        Function owner=currentProgram.getFunctionManager().getFunctionContaining(entry);
                        if(owner!=null && owner.getEntryPoint().compareTo(entry)<0){
                            if(currentProgram.getFunctionManager().removeFunction(owner.getEntryPoint()))
                                overlapRemoved++;
                        }
                        try{
                            disassemble(entry);
                            fn=createFunction(entry,null);
                            if(fn==null)fn=currentProgram.getFunctionManager().getFunctionAt(entry);
                        }catch(Exception ex){error=ex.toString();}
                    }
                    if(fn==null){
                        status="missing_function";
                        missing++;
                        if(error==null)error="Original direct-call target could not be defined as a Ghidra function";
                    }else{
                        fnName=fn.getName();
                        try{
                            DecompileResults r=dec.decompileFunction(fn,timeout,monitor);
                            if(r.decompileCompleted()&&r.getDecompiledFunction()!=null&&
                               r.getDecompiledFunction().getC()!=null&&
                               !r.getDecompiledFunction().getC().isBlank()){
                                c=r.getDecompiledFunction().getC();
                                status="decompiled";
                                success++;
                            }else{
                                status="decompiler_failed";
                                error=r.getErrorMessage();
                                failed++;
                            }
                        }catch(Exception ex){
                            status="decompiler_failed";
                            error=ex.toString();
                            failed++;
                        }
                    }
                }
                out.write("{\"index\":"+t.index+
                    ",\"rva\":"+json(hex(t.rva))+
                    ",\"callsite_rva\":"+json(hex(t.callsite))+
                    ",\"original_direct_calls\":"+t.calls+
                    ",\"witness_valid\":"+authentic+
                    ",\"status\":"+json(status)+
                    ",\"name\":"+json(fnName)+
                    ",\"error\":"+json(error)+
                    ",\"c\":"+json(c)+"}\n");
            }
        }finally{dec.dispose();}
        Files.move(part,dst,StandardCopyOption.REPLACE_EXISTING);
        String summary="{\"source_direct_call_targets\":58"+
            ",\"batch_start\":"+work.get(0).index+
            ",\"batch_end_exclusive\":"+(work.get(work.size()-1).index+1)+
            ",\"attempted\":"+work.size()+
            ",\"decompiled\":"+success+
            ",\"decompiler_failed\":"+failed+
            ",\"missing_function\":"+missing+
            ",\"invalid_witness\":"+badWitness+
            ",\"inferred_parents_removed\":"+overlapRemoved+
            ",\"file\":"+json(name)+"}\n";
        Files.writeString(root.resolve("source_directcall_recovery_summary.json"),summary,StandardCharsets.UTF_8);
        println("FORTNITE541_NONPDATA_RECOVERY_COMPLETE "+summary.trim());
    }
}