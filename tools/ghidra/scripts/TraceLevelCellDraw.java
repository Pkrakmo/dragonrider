// Bounded loader-to-draw trace for level cell fields.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class TraceLevelCellDraw extends GhidraScript {
    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis bounded instructions; confidence=database-dependent");
        String[][] windows = {
            {"00422484", "00422543"}, {"00440805", "004408e3"},
            {"00440940", "00440a2e"}, {"00440a33", "00440a6f"},
            {"00440b29", "00440b6b"}, {"0043b15b", "0043b1a6"}
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
