// Inventory Ghidra-discovered executable function starts not listed in the
// authenticated original Fortnite 5.41 Win64 .pdata unwind table.
//
// This is candidate discovery, not proof of all leaf functions, not C++ source.
// All original .pdata entries retain their independent, immutable inventory.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
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

public class Fortnite541LeafDiscovery extends GhidraScript {
    private static class Extent {
        final long start, end;
        Extent(long s,long e){start=s;end=e;}
    }
    private static long u32(Memory memory,Address address)throws Exception {
        return Integer.toUnsignedLong(memory.getInt(address));
    }
    private static String hex(long value){return String.format("0x%08x",value);}
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
                default:
                    if(c<32)b.append(String.format("\\u%04x",(int)c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }
    private List<Extent> originalPdata()throws Exception {
        Memory mem=currentProgram.getMemory();
        MemoryBlock b=mem.getBlock(".pdata");
        if(b==null)throw new IllegalStateException("Original .pdata missing");
        Address base=currentProgram.getImageBase();
        Set<Long> seen=new HashSet<>();
        List<Extent> results=new ArrayList<>();
        for(long i=0;i<b.getSize()/12;i++){
            Address item=b.getStart().add(i*12);
            long s=u32(mem,item),e=u32(mem,item.add(4));
            if(s>=e||e-s>10000000L)continue;
            if(!mem.contains(base.add(s))||!mem.contains(base.add(e-1)))continue;
            if(seen.add(s))results.add(new Extent(s,e));
        }
        Collections.sort(results,Comparator.comparingLong(x->x.start));
        if(results.size()!=291757)
            throw new IllegalStateException("Authenticated original .pdata size mismatch: "+results.size());
        return results;
    }
    private static boolean insideOriginal(List<Extent> spans,long[] prefixEnd,long rva){
        int low=0,high=spans.size();
        while(low<high){
            int mid=(low+high)/2;
            if(spans.get(mid).start<=rva)low=mid+1;
            else high=mid;
        }
        int floor=low-1;
        return floor>=0 && prefixEnd[floor]>rva;
    }
    @Override public void run()throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=1)throw new IllegalArgumentException("Expected OUTPUT_DIR");
        Path base=Paths.get(args[0]);
        Files.createDirectories(base);
        List<Extent> pdata=originalPdata();
        Set<Long> starts=new HashSet<>();
        long[] prefixEnd=new long[pdata.size()];
        long max=0;
        for(int i=0;i<pdata.size();i++){
            Extent e=pdata.get(i);
            starts.add(e.start);
            max=Math.max(max,e.end);
            prefixEnd[i]=max;
        }
        Memory mem=currentProgram.getMemory();
        Address image=currentProgram.getImageBase();
        List<String> candidates=new ArrayList<>();
        int nativeFunctions=0, originalFunctionsSeen=0, embedded=0, outside=0;
        int thunks=0, noInstruction=0;
        for(FunctionIterator iter=currentProgram.getFunctionManager().getFunctions(true);iter.hasNext();){
            if(monitor.isCancelled())throw new InterruptedException("Inventory cancelled");
            Function fn=iter.next();
            if(fn.isExternal())continue;
            Address address=fn.getEntryPoint();
            MemoryBlock block=mem.getBlock(address);
            if(block==null||!block.isExecute())continue;
            long rva=address.subtract(image);
            if(rva<0||rva>0xffffffffL)continue;
            nativeFunctions++;
            if(starts.contains(rva)){
                originalFunctionsSeen++;
                continue;
            }
            boolean within=insideOriginal(pdata,prefixEnd,rva);
            if(within)embedded++;
            else outside++;
            boolean thunk=fn.isThunk();
            if(thunk)thunks++;
            boolean instruction=currentProgram.getListing().getInstructionAt(address)!=null;
            if(!instruction)noInstruction++;
            long bodyBytes=fn.getBody().getNumAddresses();
            String classification=within?"inside_existing_pdata":"outside_original_pdata";
            String record="{\"rva\":"+json(hex(rva))+
                ",\"ghidra_name\":"+json(fn.getName())+
                ",\"classification\":"+json(classification)+
                ",\"memory_block\":"+json(block.getName())+
                ",\"body_bytes\":"+bodyBytes+
                ",\"is_thunk\":"+thunk+
                ",\"has_entry_instruction\":"+instruction+"}\n";
            candidates.add(record);
        }
        Path path=base.resolve("nonpdata_candidates.jsonl.gz");
        Path part=Paths.get(path.toString()+".part");
        try(BufferedWriter out=new BufferedWriter(new OutputStreamWriter(
            new GZIPOutputStream(Files.newOutputStream(part)),StandardCharsets.UTF_8))){
            for(String row:candidates)out.write(row);
        }
        Files.move(part,path,StandardCopyOption.REPLACE_EXISTING);
        String summary="{\"original_pdata_entries\":"+pdata.size()+
            ",\"ghidra_native_executable_functions\":"+nativeFunctions+
            ",\"ghidra_pdata_starts_seen\":"+originalFunctionsSeen+
            ",\"additional_ghidra_candidates\":"+candidates.size()+
            ",\"inside_existing_pdata\":"+embedded+
            ",\"outside_original_pdata\":"+outside+
            ",\"candidate_thunks\":"+thunks+
            ",\"candidate_missing_entry_instruction\":"+noInstruction+"}\n";
        Files.writeString(base.resolve("nonpdata_report.json"),
            summary,StandardCharsets.UTF_8);
        println("FORTNITE541_NONPDATA_COMPLETE "+summary.trim());
    }
}
