// Bounded direct references for functions associated with level block data.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class TraceLevelBlockConsumers extends GhidraScript {
    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis direct references; confidence=database-dependent");
        for (String target : new String[]{"00421c30", "004226c0", "00422760", "004234c0"}) {
            println("DIRECT_REFERENCES " + target);
            int count = 0;
            for (Reference ref : getReferencesTo(toAddr(target))) {
                if (++count > 40) { println("TRUNCATED at 40 references"); break; }
                Function owner = getFunctionContaining(ref.getFromAddress());
                println("  " + ref.getFromAddress() + " type=" + ref.getReferenceType() + " owner=" +
                    (owner == null ? "unknown" : owner.getEntryPoint()));
            }
            println("COUNT " + Math.min(count, 40));
        }
    }
}
