// Bounded static trace for the common SRSC record-closing helper.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class TraceSrscRecordCloser extends GhidraScript {
    private static final int MAX_CALLS = 48;
    private static final int CONTEXT_BEFORE = 10;
    private static final int CONTEXT_AFTER = 6;
    private static final int MAX_WINDOW = 96;

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
        Address end = toAddr(endText);
        Instruction instruction = getInstructionContaining(toAddr(startText));
        int count = 0;
        println("WINDOW label=" + label + " range=" + startText + ".." + endText +
            " cap=" + MAX_WINDOW);
        while (instruction != null && instruction.getAddress().compareTo(end) <= 0 && count++ < MAX_WINDOW) {
            println("  INSTRUCTION address=" + instruction.getAddress() + " instruction=" + instruction);
            instruction = instruction.getNext();
        }
        if (count == 0) println("WINDOW_NO_INSTRUCTION_AT_START");
        if (instruction != null && instruction.getAddress().compareTo(end) <= 0)
            println("WINDOW_TRUNCATED cap=" + MAX_WINDOW);
    }

    private void reportContext(String label, String siteText) {
        Address site = toAddr(siteText);
        Function function = getFunctionContaining(site);
        Instruction cursor = getInstructionBefore(site);
        Instruction[] before = new Instruction[CONTEXT_BEFORE];
        int beforeCount = 0;
        println("CONTEXT label=" + label + " site=" + site + " owner=" + owner(site));
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

    private void reportDirectCalls(String label, String targetText) {
        Address target = toAddr(targetText);
        int calls = 0;
        println("DIRECT_CALLS label=" + label + " target=" + target + " cap=" + MAX_CALLS);
        for (Reference reference : getReferencesTo(target)) {
            if (!isDirectCall(reference)) continue;
            if (calls++ >= MAX_CALLS) {
                println("DIRECT_CALLS_TRUNCATED cap=" + MAX_CALLS);
                break;
            }
            Address site = reference.getFromAddress();
            println("CALLSITE site=" + site + " owner=" + owner(site));
            reportContext("direct_closer_call", site.toString());
        }
        println("DIRECT_CALL_COUNT count=" + Math.min(calls, MAX_CALLS));
    }

    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis bounded closer body/direct CALL xrefs/caller contexts" +
            "; confidence=static database-dependent");
        println("scope=0045f7a0 record closer plus documented initializer sites; no execution, runtime, or producer claim");

        reportOwner("record_closer", "0045f7a0");
        reportWindow("closer_full_body", "0045f7a0", "0045f803");
        reportDirectCalls("record_closer", "0045f7a0");

        reportContext("initializer_0102_call", "0040dd4c");
        reportContext("initializer_0022_call", "0040e166");
        reportContext("initializer_0302_call", "004315f4");
        // Explicit bounded windows preserve the 0x0040dd4c context even if
        // this database has not recovered its containing function.
        reportWindow("initializer_0102_call_window", "0040dd30", "0040dd5f");
        reportWindow("initializer_0022_call_window", "0040e150", "0040e17c");
        reportWindow("initializer_0302_call_window", "004315e0", "00431601");

        println("LIMITS=direct CALL xrefs omit indirect, virtual, thunked, missing, and database-unrecovered callers; contexts do not prove control-flow feasibility, successful returns, object identity, state continuity, file production, or record/field semantics");
    }
}
