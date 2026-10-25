// Report bounded database references to the retail read helper.
// @category DragonRider
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class TraceBoundedReadHelperRefs extends GhidraScript {
    public void run() throws Exception {
        println("edition=US retail; sha256=" + currentProgram.getExecutableSHA256() +
            "; Ghidra=" + Application.getApplicationVersion() +
            "; method=analyzed disposable import; read-only reference-manager query; " +
            "confidence=database-dependent");
        Address target = toAddr("0045f2d0");
        println("REFERENCES_TO " + target);
        List<Reference> references = new ArrayList<>();
        for (Reference reference : getReferencesTo(target)) references.add(reference);
        references.sort(Comparator.comparing(Reference::getFromAddress));
        int count = 0;
        for (Reference reference : references) {
            if (count == 128) {
                println("TRUNCATED at 128 references");
                break;
            }
            println("  " + reference.getFromAddress() + " " +
                reference.getReferenceType() + " " + reference.getOperandIndex());
            count++;
        }
        println("COUNT " + count);
    }
}
