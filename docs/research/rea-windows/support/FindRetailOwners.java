import ghidra.app.script.GhidraScript;
public class FindRetailOwners extends GhidraScript {
 public void run() throws Exception {
  if (!"9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3".equals(currentProgram.getExecutableSHA256())) throw new IllegalStateException("hash");
  for (String a:getScriptArgs()) {
   var f=getFunctionContaining(toAddr(a));
   println(a+" OWNER "+(f==null ? "NONE" : f.getEntryPoint()+" "+f.getBody()));
  }
 }
}
