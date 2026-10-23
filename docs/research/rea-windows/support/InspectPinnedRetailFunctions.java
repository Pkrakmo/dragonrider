import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

// Private-output bounded research. Never executes the input program.
public class InspectPinnedRetailFunctions extends GhidraScript {
    public void run() throws Exception {
        String hash = currentProgram.getExecutableSHA256();
        if (!"23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648".equals(hash) && !"9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3".equals(hash))
            throw new IllegalStateException("Unexpected input hash");
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        try {
            for (String value : getScriptArgs()) {
                Address address = toAddr(value);
                Function f = getFunctionAt(address);
                println("TARGET " + value + " originally_defined=" + (f != null));
                if (f == null) {
                    if (getFunctionContaining(address) != null)
                        throw new IllegalStateException("Address already belongs to another function");
                    disassemble(address);
                    f = createFunction(address, "candidate_" + value);
                }
                if (f == null) throw new IllegalStateException("Could not define candidate");
                println("BODY " + f.getBody().toString());
                DecompileResults result = d.decompileFunction(f, 60, monitor);
                if (!result.decompileCompleted()) throw new IllegalStateException(result.getErrorMessage());
                println(result.getDecompiledFunction().getC());
                var iterator = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (iterator.hasNext()) {
                    var instruction = iterator.next();
                    if (instruction.getFlowType().isCall()) println("CALL " + instruction.getAddress() + " " + instruction);
                }
            }
        } finally { d.dispose(); }
    }
}
