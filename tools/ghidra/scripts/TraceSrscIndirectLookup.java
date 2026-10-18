// Bounded evidence for selected indirect SRSC lookup paths.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class TraceSrscIndirectLookup extends GhidraScript {
    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=read-only noanalysis instruction and table windows; confidence=static paths only");
        for (String table : new String[]{"004756ec", "004757ac"}) {
            Address base = toAddr(table);
            println("TABLE " + base + " slot+8=" + Integer.toUnsignedString(getInt(base.add(8)), 16) +
                " slot+40=" + Integer.toUnsignedString(getInt(base.add(0x40)), 16));
        }
        for (String site : new String[]{"0040bf6f", "0040cb74", "0040b515", "0040ba27", "0040bab6"}) {
            Address address = toAddr(site);
            Function owner = getFunctionContaining(address);
            println("OWNER " + address + "=" + (owner == null ? "unknown" : owner.getEntryPoint()));
        }
        for (String[] window : new String[][]{
                {"004265e7", "004265ec"}, {"0042ae00", "0042ae3b"},
                {"0042b1a0", "0042b1c4"}, {"0042b640", "0042b662"},
                {"0042b700", "0042b718"}, {"00432fc0", "00432fd0"},
                {"00433022", "00433050"}, {"0045fa26", "0045fa52"},
                {"0042c240", "0042c27b"}, {"0042c27d", "0042c2b7"},
                {"0042a31f", "0042a338"}, {"00437a60", "00437a71"},
                {"004312e5", "0043133a"}, {"004315e0", "00431625"},
                {"0043308b", "004330a8"}, {"00433179", "00433188"},
                {"0045f49f", "0045f4b8"}, {"00441e20", "00441e3f"},
                {"0045f5d0", "0045f5f5"}, {"0045f600", "0045f619"},
                {"0040bf53", "0040bf76"}, {"0040cb69", "0040cb8d"},
                {"0045f970", "0045f988"}}) {
            Address start = toAddr(window[0]), end = toAddr(window[1]);
            println("WINDOW " + start + ".." + end);
            Instruction ins = getInstructionAt(start);
            int count = 0;
            while (ins != null && ins.getAddress().compareTo(end) <= 0 && count++ < 40) {
                println("  " + ins.getAddress() + " " + ins);
                ins = ins.getNext();
            }
            if (count == 0) println("NO INSTRUCTION AT START");
        }
    }
}
