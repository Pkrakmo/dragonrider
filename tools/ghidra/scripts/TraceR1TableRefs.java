// Bounded references to the full-tuple reader and its function table.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import java.util.Set;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;

public class TraceR1TableRefs extends GhidraScript {
    public void run() throws Exception {
        println("sha256=" + currentProgram.getExecutableSHA256() + "; Ghidra=" + Application.getApplicationVersion() + "; mode=read-only noanalysis");
        Set<String> globalOwners = new TreeSet<>();
        for (String text : new String[]{"0040bf30", "004754ec", "00475514", "00483928"}) {
            Address target = toAddr(text);
            println("TARGET " + target);
            int count = 0;
            for (Reference ref : getReferencesTo(target)) {
                if (++count > 100) { println("TRUNCATED"); break; }
                Function owner = getFunctionContaining(ref.getFromAddress());
                if (target.equals(toAddr("00483928")) && owner != null) {
                    globalOwners.add(owner.getEntryPoint().toString());
                    Instruction site = getInstructionAt(ref.getFromAddress());
                    if (site != null) {
                        Instruction context = site;
                        for (int i = 0; i < 2; ++i) {
                            Instruction previous = context.getPrevious();
                            if (previous == null || !owner.getBody().contains(previous.getAddress())) break;
                            context = previous;
                        }
                        println("GLOBAL_REF_CONTEXT site=" + ref.getFromAddress() + " owner=" + owner.getEntryPoint());
                        for (int i = 0; context != null && i < 8 && owner.getBody().contains(context.getAddress()); ++i) {
                            println("    " + context.getAddress() + " " + context);
                            context = context.getNext();
                        }
                    }
                }
                println("  REF " + ref.getFromAddress() + " type=" + ref.getReferenceType() + " owner=" + (owner == null ? "unknown" : owner.getEntryPoint()));
            }
            println("  COUNT " + Math.min(count, 100));
        }
        for (String entry : globalOwners) {
            Function owner = getFunctionAt(toAddr(entry));
            if (owner == null) continue;
            Instruction ins = getInstructionAt(owner.getEntryPoint());
            int limit = 0;
            while (ins != null && owner.getBody().contains(ins.getAddress()) && limit++ < 2000) {
                String rendered = ins.toString();
                if (ins.getMnemonicString().equalsIgnoreCase("CALL") &&
                    (rendered.contains("0x28") || rendered.contains("0x2c") || rendered.contains("0x30")))
                    println("GLOBAL_OWNER_TABLE_CALL owner=" + entry + " site=" + ins.getAddress() + " instruction=" + ins);
                if (ins.getMnemonicString().equalsIgnoreCase("CALL")) {
                    for (Reference callRef : getReferencesFrom(ins.getAddress())) {
                        if (!callRef.getReferenceType().isCall()) continue;
                        Function callee = getFunctionAt(callRef.getToAddress());
                        if (callee == null || callee.getEntryPoint().equals(owner.getEntryPoint())) continue;
                        Instruction child = getInstructionAt(callee.getEntryPoint());
                        int childLimit = 0;
                        while (child != null && callee.getBody().contains(child.getAddress()) && childLimit++ < 2000) {
                            String childText = child.toString();
                            if (child.getMnemonicString().equalsIgnoreCase("CALL") &&
                                (childText.contains("0x28") || childText.contains("0x2c") || childText.contains("0x30")))
                                println("GLOBAL_OWNER_CALLEE_TABLE_CALL owner=" + entry + " callsite=" + ins.getAddress() +
                                    " callee=" + callee.getEntryPoint() + " site=" + child.getAddress() + " instruction=" + child);
                            child = child.getNext();
                        }
                    }
                }
                ins = ins.getNext();
            }
        }
        // Bounded two-edge direct-call reachability probe. This reports only
        // candidate slot dispatches; it does not infer receiver identity.
        for (String rootEntry : globalOwners) {
            ArrayDeque<String> queue = new ArrayDeque<>();
            Map<String, Integer> depthByEntry = new HashMap<>();
            Map<String, String> parentByEntry = new HashMap<>();
            queue.add(rootEntry);
            depthByEntry.put(rootEntry, 0);
            int visited = 0;
            while (!queue.isEmpty() && visited++ < 250) {
                String entry = queue.removeFirst();
                int depth = depthByEntry.get(entry);
                Function owner = getFunctionAt(toAddr(entry));
                if (owner == null) continue;
                Instruction ins = getInstructionAt(owner.getEntryPoint());
                int limit = 0;
                while (ins != null && owner.getBody().contains(ins.getAddress()) && limit++ < 2000) {
                    String rendered = ins.toString();
                    if (depth > 0 && ins.getMnemonicString().equalsIgnoreCase("CALL") &&
                        (rendered.contains("0x28") || rendered.contains("0x2c") || rendered.contains("0x30"))) {
                        String path = entry;
                        String parent = parentByEntry.get(entry);
                        while (parent != null) {
                            path = parent + " -> " + path;
                            parent = parentByEntry.get(parent);
                        }
                        println("DEPTH_CANDIDATE root=" + rootEntry + " depth=" + depth + " path=" + path +
                            " site=" + ins.getAddress() + " instruction=" + ins);
                    }
                    if (depth < 2 && ins.getMnemonicString().equalsIgnoreCase("CALL")) {
                        for (Reference callRef : getReferencesFrom(ins.getAddress())) {
                            if (!callRef.getReferenceType().isCall()) continue;
                            Function callee = getFunctionAt(callRef.getToAddress());
                            if (callee == null) continue;
                            String childEntry = callee.getEntryPoint().toString();
                            if (!depthByEntry.containsKey(childEntry)) {
                                depthByEntry.put(childEntry, depth + 1);
                                parentByEntry.put(childEntry, entry);
                                queue.addLast(childEntry);
                            }
                        }
                    }
                    ins = ins.getNext();
                }
            }
            if (visited >= 250) println("DEPTH_SCAN_TRUNCATED root=" + rootEntry + " cap=250");
        }
    }
}
