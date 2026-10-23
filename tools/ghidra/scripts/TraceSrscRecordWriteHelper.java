// Bounded static trace for the common SRSC record-payload helper.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class TraceSrscRecordWriteHelper extends GhidraScript {
    private static final int MAX_CALLS = 64;
    private static final int CONTEXT_BEFORE = 10;
    private static final int CONTEXT_AFTER = 8;
    private static final int MAX_WINDOW = 112;

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
            println("CALLSITE label=" + label + " site=" + site + " owner=" + owner(site));
            reportContext("direct_payload_helper_call", site.toString());
        }
        println("DIRECT_CALL_COUNT label=" + label + " count=" + Math.min(calls, MAX_CALLS));
    }

    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis bounded payload-helper body/direct CALL xrefs/caller contexts" +
            "; confidence=static database-dependent");
        println("scope=0045f6f0 common payload helper and three bounded candidate caller sequences; no execution, runtime, or file-production claim");

        reportOwner("record_payload_helper", "0045f6f0");
        reportWindow("payload_helper_full_body", "0045f6f0", "0045f741");
        reportDirectCalls("record_payload_helper", "0045f6f0");

        reportContext("candidate_0102_first_payload", "0040dd7f");
        reportWindow("candidate_0102_payload_sequence", "0040dd60", "0040de52");
        reportContext("candidate_0022_first_payload", "0040e1de");
        reportWindow("candidate_0022_payload_prefix", "0040e1b0", "0040e210");
        reportContext("candidate_0302_first_payload", "0043160d");
        reportWindow("candidate_0302_payload_prefix", "004315e0", "00431678");

        println("LIMITS=direct CALL xrefs omit indirect, virtual, thunked, missing, and database-unrecovered callers; instruction windows and contexts do not prove control-flow feasibility, successful writes, object identity, active-record continuity, file production, payload encoding, or selector/field semantics");
    }
}
