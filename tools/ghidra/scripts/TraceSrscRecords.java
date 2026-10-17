// Bounded instruction windows for SRSC record selection and reading.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class TraceSrscRecords extends GhidraScript {
    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis bounded instruction windows and direct xrefs; confidence=database-dependent");
        String[][] windows = {
            {"0045eec2", "0045ef10"}, // read raw record table
            {"0045f17c", "0045f225"}, // unsorted triple comparison and selection
            {"0045f270", "0045f2cd"}, // index selection, file seek and count
            {"0045f2d0", "0045f36b"}, // bounded reads
            {"0045fa10", "0045fb20"}  // alternate lookup, bounded end
        };
        for (String[] window : windows) {
            Address start = toAddr(window[0]);
            Address end = toAddr(window[1]);
            Function owner = getFunctionContaining(start);
            println("WINDOW " + start + ".." + end + " owner=" +
                (owner == null ? "unknown" : owner.getEntryPoint()));
            Instruction instruction = getInstructionAt(start);
            int count = 0;
            while (instruction != null && instruction.getAddress().compareTo(end) <= 0 && count++ < 110) {
                println("  " + instruction.getAddress() + " " + instruction);
                instruction = instruction.getNext();
            }
            if (count >= 110) println("TRUNCATED at 110 instructions");
        }
        for (String target : new String[]{"0045f0d0", "0045f230", "0045f270", "0045f2d0"}) {
            Address addr = toAddr(target);
            println("DIRECT_CALLERS " + addr);
            int count = 0;
            for (Reference ref : getReferencesTo(addr)) {
                if (!ref.getReferenceType().isCall()) continue;
                if (++count > 40) { println("TRUNCATED at 40 callsites"); break; }
                Function owner = getFunctionContaining(ref.getFromAddress());
                println("  " + ref.getFromAddress() + " owner=" +
                    (owner == null ? "unknown" : owner.getEntryPoint()));
            }
            println("COUNT " + Math.min(count, 40));
        }
    }
}
