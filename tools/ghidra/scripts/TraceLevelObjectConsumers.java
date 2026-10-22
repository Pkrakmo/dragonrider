// Bounded caller and ownership report for conditional level-object consumers.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class TraceLevelObjectConsumers extends GhidraScript {
    private void reportOwner(String text) {
        Address address = toAddr(text);
        Function owner = getFunctionContaining(address);
        println("OWNER " + address + " entry=" + (owner == null ? "unknown" : owner.getEntryPoint()) +
            " body=" + (owner == null ? "unknown" : owner.getBody()));
    }

    private void reportCalls(String text) {
        Address target = toAddr(text);
        int count = 0;
        println("TARGET " + target);
        for (Reference ref : getReferencesTo(target)) {
            if (!ref.getReferenceType().isCall()) continue;
            if (count++ >= 40) { println("TRUNCATED at 40 callsites"); break; }
            Address site = ref.getFromAddress();
            Function owner = getFunctionContaining(site);
            println("CALLSITE " + site + " owner=" + (owner == null ? "unknown" : owner.getEntryPoint()));
        }
        println("COUNT " + Math.min(count, 40));
    }

    private void reportReferences(String text) {
        Address target = toAddr(text);
        int count = 0;
        println("REFERENCES " + target);
        for (Reference ref : getReferencesTo(target)) {
            if (count++ >= 40) { println("TRUNCATED at 40 references"); break; }
            Address site = ref.getFromAddress();
            Function owner = getFunctionContaining(site);
            println("REFERENCE " + site + " type=" + ref.getReferenceType() +
                " owner=" + (owner == null ? "unknown" : owner.getEntryPoint()));
        }
        println("REFERENCE_COUNT " + Math.min(count, 40));
    }

    private void reportWindow(String first, String last) {
        Address start = toAddr(first), end = toAddr(last);
        Instruction instruction = getInstructionAt(start);
        int count = 0;
        println("WINDOW " + start + ".." + end);
        while (instruction != null && instruction.getAddress().compareTo(end) <= 0 && count++ < 80) {
            println("  " + instruction.getAddress() + " " + instruction);
            instruction = instruction.getNext();
        }
        if (count == 0) println("NO INSTRUCTION AT START");
        if (instruction != null && instruction.getAddress().compareTo(end) <= 0) println("TRUNCATED at 80 instructions");
    }

    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis bounded owners/calls/instructions; confidence=database-dependent");
        for (String address : new String[]{"004294d0", "0042957a", "00445eb6", "004213f0", "00408a70", "0043c4f0", "0045afb0", "00420960", "00420dd6", "00428000", "00428445", "0042972d", "0040df40", "0040e113"}) reportOwner(address);
        for (String target : new String[]{"004294d0", "004213f0", "0040bf30", "00445bd0", "0045afb0", "00420960", "00428000", "004291a0", "00428340", "00429640", "0040dd30"}) reportCalls(target);
        reportReferences("004086f0");
        reportReferences("00408a70");
        reportReferences("00475520");
        reportCalls("0043c4f0");
        for (String[] window : new String[][]{
                {"0040cb38", "0040cb69"}, {"00429544", "004295a9"},
                {"00445e54", "00445eee"}, {"00420d76", "00420df8"}, {"004213f0", "00421430"},
                {"00428060", "004280e0"}, {"00428436", "00428462"}, {"0042971a", "0042977e"},
                {"0045afb0", "0045afef"}}) reportWindow(window[0], window[1]);
    }
}
