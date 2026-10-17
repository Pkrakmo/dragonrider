// Bounded selector 0x0040 lookup and texture-header instruction windows.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class TraceSelector0040 extends GhidraScript {
    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis bounded instruction windows and direct xrefs; confidence=database-dependent");
        String[][] windows = {
            {"004358a7", "0043591a"},
            {"0043591f", "00435a1b"},
            {"00435a40", "00435a68"},
            {"00435bc4", "00435c18"},
            {"00435cf6", "00435d28"},
            {"0045f230", "0045f268"},
            {"0045f370", "0045f3ca"},
            {"0045fa10", "0045fac7"}
        };
        for (String[] window : windows) {
            Address start = toAddr(window[0]), end = toAddr(window[1]);
            Function owner = getFunctionContaining(start);
            println("WINDOW " + start + ".." + end + " owner=" +
                (owner == null ? "unknown" : owner.getEntryPoint()));
            Instruction instruction = getInstructionAt(start);
            int count = 0;
            while (instruction != null && instruction.getAddress().compareTo(end) <= 0 && count++ < 120) {
                println("  " + instruction.getAddress() + " " + instruction);
                instruction = instruction.getNext();
            }
            if (count >= 120) println("TRUNCATED at 120 instructions");
        }
        Address addr = toAddr("00435840");
        println("DIRECT_CALLERS " + addr);
        int count = 0;
        for (Reference ref : getReferencesTo(addr)) {
            if (!ref.getReferenceType().isCall()) continue;
            if (++count > 30) { println("TRUNCATED at 30 callsites"); break; }
            Function owner = getFunctionContaining(ref.getFromAddress());
            println("  " + ref.getFromAddress() + " owner=" +
                (owner == null ? "unknown" : owner.getEntryPoint()));
        }
        println("COUNT " + Math.min(count, 30));
    }
}
