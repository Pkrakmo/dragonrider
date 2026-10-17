// Bounded investigation of palette record loading and indexed conversion.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class TraceTexturePalette extends GhidraScript {
    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis bounded instructions and direct xrefs; confidence=database-dependent");
        String[][] windows = {
            {"00435540", "0043562e"}, {"0043569d", "0043574d"},
            {"00435780", "004357bb"}, {"0043597c", "004359a0"},
            {"00435b08", "00435b3c"}, {"00435d75", "00435e10"},
            {"00435f4f", "00435f86"}, {"00433480", "004334bb"},
            {"0045fa70", "0045fa93"}, {"0045fad0", "0045faf4"},
            {"00433ba1", "00433c3b"}, {"00433ca6", "00433d13"},
            {"00433db5", "00433e0b"}
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
        for (String target : new String[]{"00435540", "00435780", "00433af0"}) {
            println("DIRECT_CALLERS " + target);
            int count = 0;
            for (Reference ref : getReferencesTo(toAddr(target))) {
                if (!ref.getReferenceType().isCall()) continue;
                if (++count > 30) { println("TRUNCATED at 30 callsites"); break; }
                Function owner = getFunctionContaining(ref.getFromAddress());
                println("  " + ref.getFromAddress() + " owner=" +
                    (owner == null ? "unknown" : owner.getEntryPoint()));
            }
            println("COUNT " + Math.min(count, 30));
        }
    }
}
