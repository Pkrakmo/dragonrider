// Bounded direct call sites for SRSC selector paths.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class TraceSrscSelectorCalls extends GhidraScript {
    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis direct callsites with bounded instructions; confidence=database-dependent");
        for (String target : new String[]{"0045f0d0", "0045f230", "0045fad0", "0045f910", "0042b1a0",
                "0045f4d0", "0045f5d0", "0045f600", "0045f7a0", "0045fa70", "0045faa0",
                "0045fb00", "0045fa10"}) {
            Address address = toAddr(target);
            int count = 0;
            println("TARGET " + target);
            for (Reference ref : getReferencesTo(address)) {
                if (!ref.getReferenceType().isCall()) continue;
                if (count++ >= 80) { println("TRUNCATED at 80 callsites"); break; }
                Address site = ref.getFromAddress();
                Function owner = getFunctionContaining(site);
                println("CALLSITE " + site + " owner=" + (owner == null ? "unknown" : owner.getEntryPoint()));
                Instruction instruction = getInstructionAt(site);
                if (instruction == null || owner == null) continue;
                for (int i = 0; i < 14; i++) {
                    Instruction previous = instruction.getPrevious();
                    if (previous == null || !owner.getBody().contains(previous.getAddress())) break;
                    instruction = previous;
                }
                while (instruction != null && instruction.getAddress().compareTo(site) <= 0) {
                    println("  " + instruction.getAddress() + " " + instruction);
                    instruction = instruction.getNext();
                }
            }
            println("COUNT " + Math.min(count, 80));
        }
        for (String[] window : new String[][]{
                {"004246ea", "004247a1"}, {"0042481d", "00424891"},
                {"004355ea", "00435622"}, {"0042b0b0", "0042b0e9"},
                {"0042b074", "0042b0fb"}, {"0042b1d0", "0042b2ab"},
                {"00429c17", "00429c30"}, {"00429db9", "00429dd1"},
                {"0042c140", "0042c15e"}, {"0045f910", "0045fa0a"},
                {"0045fa10", "0045fa6c"}, {"0045f5d0", "0045f5f5"},
                {"0045f600", "0045f6e1"}, {"0045f7a0", "0045f803"}}) {
            Address start = toAddr(window[0]), end = toAddr(window[1]);
            println("WINDOW " + start + ".." + end);
            Instruction instruction = getInstructionAt(start);
            if (instruction == null) { println("NO INSTRUCTION AT START"); continue; }
            int count = 0;
            while (instruction != null && instruction.getAddress().compareTo(end) <= 0 && count++ < 100) {
                println("  " + instruction.getAddress() + " " + instruction);
                instruction = instruction.getNext();
            }
            if (instruction != null && instruction.getAddress().compareTo(end) <= 0) println("TRUNCATED at 100 instructions");
        }
    }
}
