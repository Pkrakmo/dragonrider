// Bounded static candidates for selector (0x20,0,0) frame production/consumption.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class TraceConditionalFrameProducer extends GhidraScript {
    private static final int MAX_REFS = 40;
    private static final int MAX_CONTEXT = 10;
    private static final int MAX_WINDOW = 80;

    private String owner(Address address) {
        Function function = getFunctionContaining(address);
        return function == null ? "unknown" : function.getEntryPoint().toString();
    }

    private boolean withinOwner(Instruction instruction, Function owner) {
        return instruction != null && owner != null && owner.getBody().contains(instruction.getAddress());
    }

    private boolean isBarrier(Instruction instruction) {
        String mnemonic = instruction.getMnemonicString().toUpperCase();
        // A backward argument scan must not borrow pushes from a completed
        // sequential path. Conditional branches retain fall-through and are
        // intentionally not treated as barriers here.
        return mnemonic.equals("CALL") || mnemonic.equals("RET") || mnemonic.equals("RETF") ||
            mnemonic.equals("JMP") || mnemonic.equals("JMPF");
    }

    private boolean isPush20(Instruction instruction) {
        if (!instruction.getMnemonicString().equalsIgnoreCase("PUSH")) return false;
        String text = instruction.toString().toLowerCase();
        return text.matches(".*\\b0x20\\b.*");
    }

    private boolean isDirectCall(Reference reference) {
        if (!reference.getReferenceType().isCall()) return false;
        Instruction instruction = getInstructionAt(reference.getFromAddress());
        return instruction != null && instruction.getMnemonicString().equalsIgnoreCase("CALL");
    }

    private void reportOwner(String text) {
        Address address = toAddr(text);
        Function function = getFunctionContaining(address);
        println("OWNER address=" + address + " entry=" + owner(address) +
            " body=" + (function == null ? "unknown" : function.getBody()));
    }

    private void reportCallContexts(String label, String targetText) {
        Address target = toAddr(targetText);
        int calls = 0;
        println("CALL_TARGET label=" + label + " target=" + target + " direct-call-cap=" + MAX_REFS);
        for (Reference reference : getReferencesTo(target)) {
            if (!isDirectCall(reference)) continue;
            if (calls++ >= MAX_REFS) {
                println("CALLS_TRUNCATED cap=" + MAX_REFS);
                break;
            }
            Address site = reference.getFromAddress();
            Function function = getFunctionContaining(site);
            println("CALLSITE label=" + label + " site=" + site + " owner=" + owner(site));

            Instruction[] context = new Instruction[MAX_CONTEXT];
            int count = 0;
            Instruction cursor = getInstructionBefore(site);
            while (withinOwner(cursor, function) && count < MAX_CONTEXT) {
                context[count++] = cursor;
                if (isBarrier(cursor)) {
                    println("  CONTEXT_BARRIER address=" + cursor.getAddress() + " instruction=" + cursor);
                    break;
                }
                cursor = getInstructionBefore(cursor.getAddress());
            }
            for (int index = count - 1; index >= 0; --index) {
                Instruction instruction = context[index];
                println("  CONTEXT address=" + instruction.getAddress() + " instruction=" + instruction);
                if (isPush20(instruction))
                    println("  IMMEDIATE_SELECTOR_0020 address=" + instruction.getAddress());
            }
        }
        println("CALL_COUNT label=" + label + " count=" + Math.min(calls, MAX_REFS));
    }

    private void reportReferences(String label, String targetText) {
        Address target = toAddr(targetText);
        int refs = 0;
        println("REFERENCES label=" + label + " target=" + target + " cap=" + MAX_REFS);
        for (Reference reference : getReferencesTo(target)) {
            if (refs++ >= MAX_REFS) {
                println("REFERENCES_TRUNCATED cap=" + MAX_REFS);
                break;
            }
            Address site = reference.getFromAddress();
            println("REFERENCE label=" + label + " site=" + site + " type=" +
                reference.getReferenceType() + " owner=" + owner(site));
        }
        println("REFERENCE_COUNT label=" + label + " count=" + Math.min(refs, MAX_REFS));
    }

    private void reportWindow(String label, String first, String last) {
        Address start = toAddr(first);
        Address end = toAddr(last);
        Instruction instruction = getInstructionContaining(start);
        int count = 0;
        println("WINDOW label=" + label + " range=" + start + ".." + end + " cap=" + MAX_WINDOW);
        while (instruction != null && instruction.getAddress().compareTo(end) <= 0 && count++ < MAX_WINDOW) {
            println("  INSTRUCTION address=" + instruction.getAddress() + " instruction=" + instruction);
            instruction = instruction.getNext();
        }
        if (count == 0) println("WINDOW_NO_INSTRUCTION_AT_START");
        if (instruction != null && instruction.getAddress().compareTo(end) <= 0)
            println("WINDOW_TRUNCATED cap=" + MAX_WINDOW);
    }

    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis bounded direct xrefs/context/windows" +
            "; confidence=static database-dependent");
        println("scope=selector-(0x20,0,0)-consumer; direct-initializer-candidates; conditional-consumer-and-forwarder-boundaries");

        for (String address : new String[]{"00437290", "0045f0d0", "0045f600", "004294d0", "00445bd0", "0040dd30", "0040e113"})
            reportOwner(address);

        reportCallContexts("full_record_selector", "0045f0d0");
        reportCallContexts("record_initializer", "0045f600");
        reportCallContexts("conditional_manager_traversal", "004294d0");
        reportCallContexts("independent_field_gate", "00445bd0");
        reportReferences("loaded_rfl_table_global", "00483bf4");

        for (String[] window : new String[][]{
            {"selector_0020_lookup", "004372a6", "004372c7"},
            {"selector_0020_object_fields", "00437378", "004373d5"},
            {"manager_conditional_consumer", "00429508", "004295ac"},
            {"independent_conditional_consumer", "00445e80", "00445ed0"},
            {"candidate_forwarder_early", "0040dd30", "0040dd70"},
            {"candidate_forwarder_rfl_slot_9c", "0040e0e0", "0040e126"},
            {"direct_initializer_0022", "0040e150", "0040e17a"}
        }) reportWindow(window[0], window[1], window[2]);

        println("LIMITS=no decompiler output; direct xrefs omit indirect/virtual calls; immediate-push context is not control-flow feasibility; no execution or producer identity inferred");
    }
}
