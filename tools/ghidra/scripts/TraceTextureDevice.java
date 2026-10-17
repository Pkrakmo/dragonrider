// Bounded trace of standard texture surface creation and palette attachment.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class TraceTextureDevice extends GhidraScript {
    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis bounded instructions; confidence=database-dependent");
        String[][] windows = {
            {"00433591", "004335fc"}, {"00433619", "0043366a"},
            {"0043386a", "00433923"}, {"00433923", "004339d2"},
            {"00435b08", "00435ba0"}, {"0043349d", "004334be"}
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
    }
}
