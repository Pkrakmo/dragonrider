// Bounded, read-only evidence for the retail file-loader investigation.
// @category DragonRider
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class InvestigateFileLoader extends GhidraScript {
    private String q(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r") + "\"";
    }
    private String addr(Address a) { return a == null ? null : a.toString(); }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Expected output JSON path");
        Address target = toAddr("0045edc0"), magic = toAddr("0047d900");
        Function f = getFunctionAt(target);
        if (f == null) throw new IllegalStateException("No function at " + target);
        byte[] bytes = new byte[4];
        if (currentProgram.getMemory().getBytes(magic, bytes) != 4)
            throw new IllegalStateException("Cannot read magic");
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) hex.append(String.format("%02x", b & 255));
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(Path.of(args[0]), StandardCharsets.UTF_8))) {
            out.println("{");
            out.println("  \"edition\": \"US retail (verify imported executable hash)\",");
            out.println("  \"method\": \"Ghidra read-only noanalysis; memory bytes and direct references\",");
            out.println("  \"confidence\": \"observed database state; caller completeness depends on prior analysis\",");
            out.println("  \"ghidra_version\": " + q(Application.getApplicationVersion()) + ",");
            out.println("  \"program\": " + q(currentProgram.getName()) + ",");
            out.println("  \"executable_sha256\": " + q(currentProgram.getExecutableSHA256()) + ",");
            out.println("  \"function\": " + q(addr(target)) + ",");
            out.println("  \"function_name\": " + q(f.getName()) + ",");
            out.println("  \"function_body\": " + q(f.getBody().toString()) + ",");
            out.println("  \"magic_address\": " + q(addr(magic)) + ",");
            out.println("  \"magic_hex\": " + q(hex.toString()) + ",");
            out.println("  \"magic_block\": " + q(currentProgram.getMemory().getBlock(magic).getName()) + ",");
            out.println("  \"references_to_function\": [");
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(target);
            boolean first = true;
            while (refs.hasNext()) {
                Reference r = refs.next(); Function caller = getFunctionContaining(r.getFromAddress());
                if (!first) out.println(","); first = false;
                out.print("    {\"from\": " + q(addr(r.getFromAddress())) + ", \"type\": " + q(r.getReferenceType().toString()) + ", \"caller\": " + q(caller == null ? null : addr(caller.getEntryPoint())) + "}");
            }
            out.println("\n  ],");
            out.println("  \"calls\": [");
            first = true;
            InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (it.hasNext()) {
                Instruction ins = it.next();
                for (Reference r : ins.getReferencesFrom()) if (r.getReferenceType().isCall()) {
                    Function callee = getFunctionAt(r.getToAddress());
                    if (!first) out.println(","); first = false;
                    out.print("    {\"from\": " + q(addr(ins.getAddress())) + ", \"to\": " + q(addr(r.getToAddress())) + ", \"name\": " + q(callee == null ? null : callee.getName()) + "}");
                }
            }
            out.println("\n  ]\n}");
            if (out.checkError()) throw new IllegalStateException("Failed writing JSON");
        }
        println("Wrote bounded loader evidence to " + args[0]);
    }
}
