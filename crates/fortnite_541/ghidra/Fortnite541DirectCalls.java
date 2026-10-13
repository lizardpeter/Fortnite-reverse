// Evidence-based direct CALL target inventory for original Fortnite 5.41.
//
// Original .pdata does not necessarily include every leaf function. This
// exporter inspects DECODABLE original PE call instructions, records direct
// destinations not contained in any original .pdata extent, and separates
// candidate targets from confirmed routines; no source code is synthesized.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
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
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.zip.GZIPOutputStream;

public class Fortnite541DirectCalls extends GhidraScript {
    private static class Extent {
        final long begin, end;
        Extent(long b,long e) {begin=b;end=e;}
    }
    private static class Witness {
        int count;
        long firstCallRva;
        Witness(long from){firstCallRva=from;}
    }
    private static long u32(Memory m,Address a)throws Exception {
        return Integer.toUnsignedLong(m.getInt(a));
    }
    private static String hex(long n){return String.format("0x%08x",n);}
    private static String json(String s){
        StringBuilder b=new StringBuilder("\"");
        for(int i=0;i<s.length();i++){
            char c=s.charAt(i);
            if(c=='\\')b.append("\\\\");
            else if(c=='"')b.append("\\\"");
            else if(c=='\n')b.append("\\n");
            else if(c<32)b.append(String.format("\\u%04x",(int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
    private List<Extent> originalPdata()throws Exception {
        Memory m=currentProgram.getMemory();
        MemoryBlock b=m.getBlock(".pdata");
        if(b==null)throw new IllegalStateException("Original .pdata absent");
        Address image=currentProgram.getImageBase();
        List<Extent> extents=new ArrayList<>();
        Set<Long> starts=new HashSet<>();
        for(long i=0;i<b.getSize()/12;i++){
            Address a=b.getStart().add(i*12);
            long first=u32(m,a),last=u32(m,a.add(4));
            if(first>=last || last-first>10000000L)continue;
            if(!m.contains(image.add(first))||!m.contains(image.add(last-1)))continue;
            if(starts.add(first))extents.add(new Extent(first,last));
        }
        Collections.sort(extents,Comparator.comparingLong(x->x.begin));
        if(extents.size()!=291757)
            throw new IllegalStateException("Wrong authenticated original .pdata count: "+extents.size());
        return extents;
    }
    private static boolean inside(List<Extent> extents,long[] highEnds,long rva){
        int lo=0,hi=extents.size();
        while(lo<hi){
            int mid=(lo+hi)/2;
            if(extents.get(mid).begin<=rva)lo=mid+1;
            else hi=mid;
        }
        return lo>0&&highEnds[lo-1]>rva;
    }
    @Override public void run()throws Exception{
        String[] args=getScriptArgs();
        if(args.length!=1)throw new IllegalArgumentException("Expected OUTPUT_DIRECTORY");
        Path output=Paths.get(args[0]);
        Files.createDirectories(output);
        Memory memory=currentProgram.getMemory();
        Address image=currentProgram.getImageBase();
        List<Extent> extents=originalPdata();
        long[] highEnds=new long[extents.size()];
        long high=0;
        for(int i=0;i<extents.size();i++){
            high=Math.max(high,extents.get(i).end);
            highEnds[i]=high;
        }
        TreeMap<Long,Witness> destinations=new TreeMap<>();
        long executableInstructions=0,callInstructions=0,eligibleCallEdges=0;
        for(InstructionIterator iter=currentProgram.getListing().getInstructions(true);iter.hasNext();){
            if(monitor.isCancelled())throw new InterruptedException("Instruction scan cancelled");
            Instruction instruction=iter.next();
            MemoryBlock sourceBlock=memory.getBlock(instruction.getAddress());
            if(sourceBlock==null || !sourceBlock.isExecute())continue;
            executableInstructions++;
            if(!instruction.getFlowType().isCall())continue;
            callInstructions++;
            Address[] flows=instruction.getFlows();
            for(Address address:flows){
                MemoryBlock block=memory.getBlock(address);
                if(block==null || !block.isExecute())continue;
                long rva=address.subtract(image);
                if(rva<0||rva>0xffffffffL||inside(extents,highEnds,rva))continue;
                long callerRva=instruction.getAddress().subtract(image);
                Witness witness=destinations.get(rva);
                if(witness==null){
                    witness=new Witness(callerRva);
                    destinations.put(rva,witness);
                }
                witness.count++;
                eligibleCallEdges++;
            }
        }
        Path destination=output.resolve("nonpdata_direct_calls.jsonl.gz");
        Path part=Paths.get(destination.toString()+".part");
        long decoded=0,functions=0,thunks=0;
        try(BufferedWriter out=new BufferedWriter(new OutputStreamWriter(
            new GZIPOutputStream(Files.newOutputStream(part)),StandardCharsets.UTF_8))){
            for(Map.Entry<Long,Witness> candidate:destinations.entrySet()){
                long rva=candidate.getKey();
                Address address=image.add(rva);
                boolean hasInstruction=currentProgram.getListing().getInstructionAt(address)!=null;
                ghidra.program.model.listing.Function function=
                    currentProgram.getFunctionManager().getFunctionAt(address);
                boolean hasFunction=function!=null;
                boolean thunk=hasFunction&&function.isThunk();
                if(hasInstruction)decoded++;
                if(hasFunction)functions++;
                if(thunk)thunks++;
                out.write("{\"target_rva\":"+json(hex(rva))+
                    ",\"first_callsite_rva\":"+json(hex(candidate.getValue().firstCallRva))+
                    ",\"direct_calls\":"+candidate.getValue().count+
                    ",\"has_entry_instruction\":"+hasInstruction+
                    ",\"ghidra_function\":"+hasFunction+
                    ",\"is_thunk\":"+thunk+"}\n");
            }
        }
        Files.move(part,destination,StandardCopyOption.REPLACE_EXISTING);
        String summary="{\"original_pdata_entries\":"+extents.size()+
            ",\"executable_decoded_instructions\":"+executableInstructions+
            ",\"decoded_call_instructions\":"+callInstructions+
            ",\"nonpdata_direct_call_edges\":"+eligibleCallEdges+
            ",\"nonpdata_unique_call_targets\":"+destinations.size()+
            ",\"target_entry_instruction_decoded\":"+decoded+
            ",\"target_ghidra_functions\":"+functions+
            ",\"target_ghidra_thunks\":"+thunks+"}\n";
        Files.writeString(output.resolve("nonpdata_direct_calls_report.json"),
            summary,StandardCharsets.UTF_8);
        println("FORTNITE541_NONPDATA_DIRECT_CALLS_COMPLETE "+summary.trim());
    }
}