// Bounded investigation of palette count, missing lookup and keyed conversion.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class TraceTextureFallback extends GhidraScript {
    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis bounded instructions and direct xrefs; confidence=database-dependent");
        String[][] windows = {
            {"0043561f", "00435633"}, {"0043569d", "0043574d"},
            {"00435780", "004357bb"}, {"00433480", "004334be"},
            {"0043539c", "004353c5"}, {"0043597c", "004359c7"},
            {"00435b08", "00435b3c"},
            {"00435ba5", "00435bb6"}, {"004339e0", "00433a1e"},
            {"00433a30", "00433a5c"}, {"00433ba1", "00433c3b"},
            {"00435d75", "00435da0"}, {"00435df3", "00435e10"},
            {"00435f6b", "00435f86"}
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
        for (String target : new String[]{"00433480", "004339e0", "00433a30", "00435780"}) {
            println("REFERENCES " + target);
            int count = 0;
            for (Reference ref : getReferencesTo(toAddr(target))) {
                if (++count > 30) { println("TRUNCATED at 30 references"); break; }
                Function owner = getFunctionContaining(ref.getFromAddress());
                println("  " + ref.getFromAddress() + " type=" + ref.getReferenceType() +
                    " owner=" + (owner == null ? "unknown" : owner.getEntryPoint()));
            }
            println("COUNT " + Math.min(count, 30));
        }
    }
}
