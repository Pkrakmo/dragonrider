// Bounded record-ordering and lookup instruction windows.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class TraceSrscLookup extends GhidraScript {
    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis bounded instructions and direct calls; confidence=database-dependent");
        String[][] windows = {
            {"0045ed40", "0045ed63"}, {"0045eef3", "0045ef15"},
            {"0045ef70", "0045f0c1"}, {"0045f0d0", "0045f225"},
            {"00468f71", "00468ffb"}
        };
        for (String[] window : windows) {
            Address start = toAddr(window[0]);
            Address end = toAddr(window[1]);
            println("WINDOW " + start + ".." + end);
            Instruction instruction = getInstructionAt(start);
            if (instruction == null) {
                println("NO INSTRUCTION AT START");
                continue;
            }
            int count = 0;
            while (instruction != null && instruction.getAddress().compareTo(end) <= 0 && count < 160) {
                println("  " + instruction.getAddress() + " " + instruction);
                instruction = instruction.getNext();
                count++;
            }
            if (instruction != null && instruction.getAddress().compareTo(end) <= 0) println("TRUNCATED at 160 instructions");
        }
        Address target = toAddr("0045ef70");
        println("DIRECT_CALLERS " + target);
        int count = 0;
        for (Reference ref : getReferencesTo(target)) {
            if (!ref.getReferenceType().isCall()) continue;
            if (count++ == 40) { println("TRUNCATED at 40 callsites"); break; }
            println("  " + ref.getFromAddress());
        }
        println("COUNT " + Math.min(count, 40));
    }
}
