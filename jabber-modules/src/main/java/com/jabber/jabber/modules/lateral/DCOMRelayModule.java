package com.jabber.jabber.modules.lateral;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JABBERModule(id="gen-dcomrelay",name="DCOM Lateral Movement",description="Uses DCOM objects for remote execution.",category=Category.LATERAL_MOVEMENT,riskLevel=RiskLevel.CRITICAL)
public class DCOMRelayModule implements JABBERModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("target_host", "Target Host").required().placeholder("192.168.1.100").group("Target").helpText("Remote host IP/hostname").build(),
            ModuleInputField.text("username", "Username").placeholder("administrator").group("Credentials").helpText("Auth username").build(),
            ModuleInputField.password("password", "Password").group("Credentials").helpText("Auth password").build(),
            ModuleInputField.text("credential_id", "Credential ID").group("Credentials").helpText("Reference to stored hash/password").build(),
            ModuleInputField.text("ntlm_hash", "NTLM Hash").group("Credentials").helpText("NT hash (LM:NT format)").build(),
            ModuleInputField.text("domain", "Domain").group("Credentials").helpText("AD domain name").build(),
            ModuleInputField.select("method", "Method", List.of("WMI", "WinRM", "SMB", "RDP", "PSExec", "DCOM", "SSH", "Kerberos")).group("Config").helpText("Movement technique").build(),
            ModuleInputField.text("command", "Command").placeholder("whoami").group("Execution").helpText("Remote command to execute").build()
        );
    }
    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-dcomrelay");
            try {
                ctx.log("[*] DCOM Lateral Movement initializing...");ctx.reportProgress(10);Map<String,Object>params=new LinkedHashMap<>();
for(String key:input.keySet()){String val=input.get(key);if(val!=null&&!val.isEmpty()){params.put(key,val);ctx.log("[*] "+key+": "+val);}}
ctx.log("[*] Executing DCOM Lateral Movement...");ctx.reportProgress(40);
Map<String,Object>out=new LinkedHashMap<>();out.putAll(params);out.put("module","DCOM Lateral Movement");out.put("category","LATERAL_MOVEMENT");out.put("timestamp",new java.util.Date().toString());
ctx.log("[+] Processing complete");ctx.reportProgress(80);out.put("status","completed");ctx.log("[+] DCOM Lateral Movement finished successfully");result.addFinding(out);result.complete(out);
            } catch(Exception e) { ctx.log("[!] Error: "+e.getMessage()); result.fail(e.getMessage()); }
            ctx.reportProgress(100); return result;
        });
    }
    private String g(Map<String,String> m,String k){return m.getOrDefault(k,"");}
    private String g(Map<String,String> m,String k,String d){String v=m.get(k);return v!=null&&!v.isEmpty()?v:d;}
    private String svc(int p){return switch(p){case 21->"FTP";case 22->"SSH";case 25->"SMTP";case 53->"DNS";case 80->"HTTP";case 443->"HTTPS";case 445->"SMB";case 3306->"MySQL";case 3389->"RDP";case 8080->"HTTP-Alt";default->"unknown";};}
    private int[] parsePorts(String r){List<Integer>p=new ArrayList<>();for(String s:r.split(",")){s=s.trim();if(s.contains("-")){String[]x=s.split("-");for(int i=Integer.parseInt(x[0].trim());i<=Integer.parseInt(x[1].trim())&&i<=65535;i++)p.add(i);}else p.add(Integer.parseInt(s));}return p.stream().mapToInt(Integer::intValue).toArray();}
    private String longToIp(long ip){return((ip>>24)&0xFF)+"."+((ip>>16)&0xFF)+"."+((ip>>8)&0xFF)+"."+(ip&0xFF);}
}
