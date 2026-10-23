// Bounded writer-state and record-third-word static trace.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class TraceSrscWriterState extends GhidraScript {
    private static final int MAX_CALLS = 48;
    private static final int MAX_REFERENCES = 48;
    private static final int CONTEXT_BEFORE = 12;
    private static final int CONTEXT_AFTER = 5;
    private static final int MAX_WINDOW = 100;

    private String owner(Address address) {
        Function function = getFunctionContaining(address);
        return function == null ? "unknown" : function.getEntryPoint().toString();
    }

    private boolean belongsTo(Instruction instruction, Function function) {
        return instruction != null && function != null &&
            function.getBody().contains(instruction.getAddress());
    }

    private boolean isDirectCall(Reference reference) {
        if (!reference.getReferenceType().isCall()) return false;
        Instruction instruction = getInstructionAt(reference.getFromAddress());
        return instruction != null && instruction.getMnemonicString().equalsIgnoreCase("CALL");
    }

    private void reportOwner(String label, String text) {
        Address address = toAddr(text);
        Function function = getFunctionContaining(address);
        println("OWNER label=" + label + " address=" + address + " entry=" + owner(address) +
            " body=" + (function == null ? "unknown" : function.getBody()));
    }

    private void reportWindow(String label, String startText, String endText) {
        Address start = toAddr(startText);
        Address end = toAddr(endText);
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

    private void reportCallContexts(String label, String targetText) {
        Address target = toAddr(targetText);
        int calls = 0;
        println("CALL_TARGET label=" + label + " target=" + target + " direct-call-cap=" + MAX_CALLS);
        for (Reference reference : getReferencesTo(target)) {
            if (!isDirectCall(reference)) continue;
            if (calls++ >= MAX_CALLS) {
                println("CALLS_TRUNCATED cap=" + MAX_CALLS);
                break;
            }
            Address site = reference.getFromAddress();
            Function function = getFunctionContaining(site);
            println("CALLSITE label=" + label + " site=" + site + " owner=" + owner(site));
            Instruction[] before = new Instruction[CONTEXT_BEFORE];
            int beforeCount = 0;
            Instruction cursor = getInstructionBefore(site);
            while (belongsTo(cursor, function) && beforeCount < CONTEXT_BEFORE) {
                before[beforeCount++] = cursor;
                cursor = getInstructionBefore(cursor.getAddress());
            }
            for (int index = beforeCount - 1; index >= 0; --index) {
                Instruction instruction = before[index];
                println("  BEFORE address=" + instruction.getAddress() + " instruction=" + instruction);
            }
            Instruction after = getInstructionAt(site);
            for (int count = 0; belongsTo(after, function) && count < CONTEXT_AFTER; ++count) {
                println("  AFTER address=" + after.getAddress() + " instruction=" + after);
                after = after.getNext();
            }
        }
        println("CALL_COUNT label=" + label + " count=" + Math.min(calls, MAX_CALLS));
    }

    private void reportDirectReferences(String label, String targetText) {
        Address target = toAddr(targetText);
        int references = 0;
        println("REFERENCES label=" + label + " target=" + target + " cap=" + MAX_REFERENCES);
        for (Reference reference : getReferencesTo(target)) {
            if (references++ >= MAX_REFERENCES) {
                println("REFERENCES_TRUNCATED cap=" + MAX_REFERENCES);
                break;
            }
            Address site = reference.getFromAddress();
            println("  REFERENCE site=" + site + " type=" + reference.getReferenceType() +
                " owner=" + owner(site));
        }
        println("REFERENCE_COUNT label=" + label + " count=" + Math.min(references, MAX_REFERENCES));
    }

    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis bounded writer helper windows/direct xrefs/call contexts" +
            "; confidence=static database-dependent");
        println("scope=writer-state-plus-8 and table-record-third-word; no execution or runtime producer claim");

        reportOwner("constructor", "0045f4d0");
        reportOwner("state_setter", "0045f5d0");
        reportOwner("record_initializer", "0045f600");
        reportOwner("record_closer", "0045f7a0");

        reportCallContexts("constructor", "0045f4d0");
        reportCallContexts("state_setter", "0045f5d0");
        reportCallContexts("record_initializer", "0045f600");
        reportCallContexts("record_closer", "0045f7a0");

        reportDirectReferences("constructor", "0045f4d0");
        reportDirectReferences("state_setter", "0045f5d0");
        reportDirectReferences("record_initializer", "0045f600");
        reportDirectReferences("record_closer", "0045f7a0");

        for (String[] window : new String[][]{
                {"constructor_initializes_state_plus_8", "0045f57b", "0045f5c1"},
                {"setter_writes_state_plus_8", "0045f5d0", "0045f5f5"},
                {"initializer_copies_state_to_record_word_4", "0045f600", "0045f6e1"},
                {"closer_writes_record_length", "0045f7a0", "0045f803"},
                {"known_zero_setter_then_0051_initializer", "00441e20", "00441e48"},
                {"stack_local_writer_setup_and_first_records", "0040b4f4", "0040b5a2"},
                {"candidate_0102_initializer", "0040dd30", "0040dd62"},
                {"candidate_0022_initializer", "0040e150", "0040e17c"},
                {"candidate_0302_initializer", "004315e0", "00431608"}
        }) reportWindow(window[0], window[1], window[2]);

        println("LIMITS=direct xrefs omit indirect/virtual calls and direct stores through aliases; bounded contexts do not prove control-flow feasibility, successful returns, object identity, state continuity, file production, or third-word semantics");
    }
}
