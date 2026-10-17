// Bounded direct call-site instruction windows, not a decompilation export.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class TraceLoaderCallers extends GhidraScript {
    public void run() throws Exception {
        String[] targets = {"0040bb40", "0040bcf0", "0040bf30", "0041e470", "0042aef0", "00436eb0", "00437960"};
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis direct xrefs with bounded instruction windows; confidence=database-dependent");
        for (String target : targets) {
            Address addr = toAddr(target);
            Function function = getFunctionAt(addr);
            println("TARGET " + target + " function=" + (function == null ? "missing" : function.getName()));
            int count = 0;
            for (Reference ref : getReferencesTo(addr)) {
                if (!ref.getReferenceType().isCall()) continue;
                if (++count > 40) { println("TRUNCATED at 40 callsites"); break; }
                Address site = ref.getFromAddress();
                Function owner = getFunctionContaining(site);
                println("CALLSITE " + site + " owner=" + (owner == null ? "unknown" : owner.getEntryPoint()));
                Instruction instruction = getInstructionAt(site);
                if (instruction == null) continue;
                for (int i = 0; i < 10; ++i) {
                    Instruction prev = instruction.getPrevious();
                    if (prev == null || owner == null || !owner.getBody().contains(prev.getAddress())) break;
                    instruction = prev;
                }
                while (instruction != null && instruction.getAddress().compareTo(site) <= 0) {
                    println("  " + instruction.getAddress() + " " + instruction);
                    instruction = instruction.getNext();
                }
            }
            println("CALLSITE_COUNT " + Math.min(count, 40));
        }
    }
}
