// Bounded texture surface, stream and zlib-header investigation.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class TraceTexturePipeline extends GhidraScript {
    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis bounded instructions and direct xrefs; confidence=database-dependent");
        String[][] windows = {
            {"00435a6d", "00435b41"}, {"00435bc4", "00435c70"},
            {"00435c8c", "00435cc6"}, {"00435cf6", "00435d3d"},
            {"0043366a", "00433728"}, {"0043372d", "004337be"},
            {"004629e0", "004629f9"}, {"00462a48", "00462ab6"},
            {"00462acc", "00462af7"}
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
        for (String target : new String[]{"004629e0", "00462a00", "00435840"}) {
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
