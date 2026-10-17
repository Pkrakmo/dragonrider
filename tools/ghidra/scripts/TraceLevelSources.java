// Bounded trace of level directory values and runtime source identifiers.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class TraceLevelSources extends GhidraScript {
    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis bounded instructions; confidence=database-dependent");
        String[][] windows = {
            {"004370d8", "00437142"}, {"0041e800", "0041e88a"},
            {"0041e8e5", "0041e92a"}, {"00435800", "004358e3"}
        };
        for (String[] window : windows) {
            Address start = toAddr(window[0]), end = toAddr(window[1]);
            Function owner = getFunctionContaining(start);
            println("WINDOW " + start + ".." + end + " owner=" +
                (owner == null ? "unknown" : owner.getEntryPoint()));
            Instruction instruction = getInstructionAt(start);
            int count = 0;
            while (instruction != null && instruction.getAddress().compareTo(end) <= 0 && count++ < 100) {
                println("  " + instruction.getAddress() + " " + instruction);
                instruction = instruction.getNext();
            }
            if (count >= 100) println("TRUNCATED at 100 instructions");
        }
    }
}
