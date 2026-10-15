// Fortnite 5.41: retry ONLY unresolved original .pdata entries with explicit
// source-authenticated, exactly bounded bodies. Any output is real Ghidra C;
// no missing function or synthetic stub can increase completion.
// Temporary project only. Retail executable bytes never enter Git.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
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

public class Fortnite541RecoverBoundedPdata extends GhidraScript {
    private static class Extent {
        final long begin, end;
        Extent(long b, long e) { begin=b; end=e; }
    }
    private static class Target {
        final int index;
        final long begin, end;
        Target(int i, long b, long e) { index=i; begin=b; end=e; }
    }
    private static String asHex(long n) { return String.format("0x%08x", n); }
    private static long parseRva(String s) {
        if (!s.startsWith("0x")) throw new IllegalArgumentException("Invalid source RVA");
        return Long.parseUnsignedLong(s.substring(2), 16);
    }
    private static String quoted(String s) {
        if (s==null) return "null";
        StringBuilder v=new StringBuilder("\"");
        for(int i=0;i<s.length();i++) {
            char x=s.charAt(i);
            if(x=='\\') v.append("\\\\");
            else if(x=='"') v.append("\\\"");
            else if(x=='\n') v.append("\\n");
            else if(x=='\r') v.append("\\r");
            else if(x=='\t') v.append("\\t");
            else if(x<32) v.append(String.format("\\u%04x",(int)x));
            else v.append(x);
        }
        return v.append('"').toString();
    }
    private long u32(Memory m, Address a) throws Exception {
        return Integer.toUnsignedLong(m.getInt(a));
    }
    private List<Extent> inventory() throws Exception {
        Memory m=currentProgram.getMemory();
        MemoryBlock block=m.getBlock(".pdata");
        if(block==null) throw new IllegalStateException("Original retail .pdata absent");
        Address image=currentProgram.getImageBase();
        Set<Long> seen=new HashSet<>();
        List<Extent> values=new ArrayList<>();
        for(long i=0; i<block.getSize()/12; i++) {
            Address at=block.getStart().add(i*12);
            long begin=u32(m,at),end=u32(m,at.add(4));
            if(begin>=end || end-begin>10000000L) continue;
            if(!m.contains(image.add(begin)) || !m.contains(image.add(end-1))) continue;
            if(seen.add(begin)) values.add(new Extent(begin,end));
        }
        Collections.sort(values,Comparator.comparingLong(x->x.begin));
        if(values.size()!=291757) throw new IllegalStateException("Original PE .pdata inventory mismatch "+values.size());
        return values;
    }
    private List<Target> readJobs(Path path,List<Extent> originals) throws Exception {
        List<Target> jobs=new ArrayList<>();
        Set<Integer> seen=new HashSet<>();
        for(String row: Files.readAllLines(path,StandardCharsets.UTF_8)) {
            if(row.isBlank()) continue;
            String[] parts=row.split("\\t",-1);
            if(parts.length!=3) throw new IllegalArgumentException("Expected 3 source .pdata columns");
            int index=Integer.parseInt(parts[0]);
            if(index<0||index>=originals.size()||!seen.add(index)) throw new IllegalArgumentException("Invalid original ordinal");
            long begin=parseRva(parts[1]),end=parseRva(parts[2]);
            Extent original=originals.get(index);
            if(begin!=original.begin||end!=original.end) throw new IllegalStateException("Original PE source address contradiction at "+index);
            jobs.add(new Target(index,begin,end));
        }
        if(jobs.isEmpty()||jobs.size()>56) throw new IllegalArgumentException("Unexpected original unresolved shard size");
        return jobs;
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=3) throw new IllegalArgumentException("Expected OUT_DIR ORIGINAL_UNRESOLVED_TSV DECOMP_TIMEOUT");
        Path out=Paths.get(args[0]),queue=Paths.get(args[1]);
        int timeout=Integer.parseInt(args[2]);
        if(timeout<1||timeout>120) throw new IllegalArgumentException("Bad decompiler timeout");
        Files.createDirectories(out.resolve("records"));
        List<Extent> inventory=inventory();
        List<Target> jobs=readJobs(queue,inventory);
        Address image=currentProgram.getImageBase();
        Memory memory=currentProgram.getMemory();
        DecompInterface decoder=new DecompInterface();
        decoder.toggleCCode(true);
        decoder.toggleSyntaxTree(true);
        decoder.setSimplificationStyle("decompile");
        if(!decoder.openProgram(currentProgram)) throw new IllegalStateException("Ghidra native decompiler unavailable");
        int decompiled=0,missing=0,failed=0,removed=0,entryInstructions=0;
        String name=String.format("records/bounded_%06d_%06d.jsonl.gz",jobs.get(0).index,jobs.get(jobs.size()-1).index);
        Path target=out.resolve(name),temp=Paths.get(target+".part");
        try(BufferedWriter writer=new BufferedWriter(new OutputStreamWriter(
                new GZIPOutputStream(Files.newOutputStream(temp)),StandardCharsets.UTF_8))) {
            for(Target job: jobs) {
                if(monitor.isCancelled()) throw new InterruptedException("Original source bounded decompilation cancelled");
                Address entry=image.add(job.begin),last=image.add(job.end-1);
                String error=null,c=null,signature=null,fnName=null,diagnostic=null;
                String status="missing_function";
                boolean entryDisassembled=false, exactBody=false, executable=false;
                try {
                    MemoryBlock section=memory.getBlock(entry);
                    executable=section!=null && section.isExecute() && memory.contains(last);
                    if(!executable) throw new IllegalStateException("Original .pdata source is not executable/mapped");
                    Function prev=currentProgram.getFunctionManager().getFunctionAt(entry);
                    Function owner=currentProgram.getFunctionManager().getFunctionContaining(entry);
                    if(prev==null && owner!=null && owner.getEntryPoint().compareTo(entry)<0) {
                        if(currentProgram.getFunctionManager().removeFunction(owner.getEntryPoint())) removed++;
                    }
                    Instruction crossed=currentProgram.getListing().getInstructionContaining(entry);
                    if(crossed!=null && !crossed.getMinAddress().equals(entry)) {
                        currentProgram.getListing().clearCodeUnits(crossed.getMinAddress(),crossed.getMaxAddress(),false);
                        diagnostic="Crossing inferred instruction cleared in temporary Ghidra database";
                    }
                    if(currentProgram.getListing().getInstructionAt(entry)==null) disassemble(entry);
                    entryDisassembled=currentProgram.getListing().getInstructionAt(entry)!=null;
                    if(entryDisassembled) {
                        entryInstructions++;
                        Function fn=currentProgram.getFunctionManager().getFunctionAt(entry);
                        AddressSet bounded=new AddressSet(entry,last);
                        if(fn==null) {
                            fn=currentProgram.getFunctionManager().createFunction(null,entry,bounded,SourceType.ANALYSIS);
                        }else{
                            fn.setBody(bounded);
                        }
                        exactBody=fn!=null && fn.getBody().getNumAddresses()==job.end-job.begin &&
                                  fn.getBody().contains(entry) && fn.getBody().contains(last);
                        if(!exactBody) throw new IllegalStateException("Could not establish exact original source-bounded function body");
                        fnName=fn.getName();
                        try { signature=fn.getSignature().toString(); }catch(Exception ignored) {}
                        DecompileResults result=decoder.decompileFunction(fn,timeout,monitor);
                        if(result.decompileCompleted() && result.getDecompiledFunction()!=null &&
                           result.getDecompiledFunction().getC()!=null &&
                           !result.getDecompiledFunction().getC().isBlank()) {
                            c=result.getDecompiledFunction().getC();
                            status="decompiled";
                            decompiled++;
                        } else {
                            status="decompiler_failed";
                            error=result.getErrorMessage();
                            failed++;
                        }
                    }else {
                        missing++;
                        error="No original source entry instruction could be decoded";
                    }
                }catch(Exception ex) {
                    error=ex.toString();
                    if(entryDisassembled) {status="decompiler_failed";failed++;}
                    else {status="missing_function";missing++;}
                }
                writer.write("{\"index\":"+job.index+
                    ",\"rva\":"+quoted(asHex(job.begin))+
                    ",\"end_rva\":"+quoted(asHex(job.end))+
                    ",\"status\":"+quoted(status)+
                    ",\"name\":"+quoted(fnName)+
                    ",\"signature\":"+quoted(signature)+
                    ",\"c\":"+quoted(c)+
                    ",\"error\":"+quoted(error)+
                    ",\"diagnostics\":"+quoted(diagnostic)+
                    ",\"retail_entry_instruction_decoded\":"+entryDisassembled+
                    ",\"exact_original_pdata_body_applied\":"+exactBody+
                    ",\"original_pdata_executable\":"+executable+
                    ",\"recovery_mode\":\"bounded_v1\"}\n");
            }
        }finally { decoder.dispose(); }
        Files.move(temp,target,StandardCopyOption.REPLACE_EXISTING);
        String report="{\"original_pdata_functions\":291757"+
            ",\"retry_count\":"+jobs.size()+
            ",\"recovered\":"+decompiled+
            ",\"missing\":"+missing+
            ",\"decompiler_failed\":"+failed+
            ",\"first_original_index\":"+jobs.get(0).index+
            ",\"last_original_index\":"+jobs.get(jobs.size()-1).index+
            ",\"removed_inferred_parent_functions\":"+removed+
            ",\"entries_with_decoded_original_instruction\":"+entryInstructions+
            ",\"strategy\":\"bounded_v1\""+
            ",\"file\":"+quoted(name)+"}\n";
        Files.writeString(out.resolve("recovery_summary.json"),report,StandardCharsets.UTF_8);
        println("FORTNITE541_ORIGINAL_BOUNDED_PDATA_RECOVERY_COMPLETE "+report.trim());
    }
}
