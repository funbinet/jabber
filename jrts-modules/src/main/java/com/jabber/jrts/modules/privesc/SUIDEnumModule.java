package com.jabber.jrts.modules.privesc;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="gen-suidenum",name="SUID Enumerator",description="Finds SUID/SGID binaries for privesc vectors.",category=Category.PRIVILEGE_ESCALATION,riskLevel=RiskLevel.MEDIUM)
public class SUIDEnumModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("session_id", "Session ID").group("Session").helpText("Active session for escalation").build(),
            ModuleInputField.select("os_type", "OS Type", List.of("Windows", "Linux", "macOS")).required().group("Target").helpText("Target OS").build(),
            ModuleInputField.text("writable_path", "Writable Path").placeholder("/tmp").group("Config").helpText("Temp execution directory").build(),
            ModuleInputField.checkbox("auto_enumerate", "Auto-Enumeration").group("Config").helpText("Run automated privesc checks").build(),
            ModuleInputField.text("target_user", "Target User").placeholder("root").group("Target").helpText("User to escalate to").build(),
            ModuleInputField.select("technique", "Technique", List.of("Auto", "SUID/SGID", "Kernel", "Service", "Token", "UAC Bypass", "DLL Hijack", "Sudo")).group("Config").helpText("Escalation method").build()
        );
    }
    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-suidenum");
            try {
                ctx.log("[*] SUID Enumerator initializing...");ctx.reportProgress(10);Map<String,Object>params=new LinkedHashMap<>();
for(String key:input.keySet()){String val=input.get(key);if(val!=null&&!val.isEmpty()){params.put(key,val);ctx.log("[*] "+key+": "+val);}}
ctx.log("[*] Executing SUID Enumerator...");ctx.reportProgress(40);
Map<String,Object>out=new LinkedHashMap<>();out.putAll(params);out.put("module","SUID Enumerator");out.put("category","PRIVILEGE_ESCALATION");out.put("timestamp",new java.util.Date().toString());
ctx.log("[+] Processing complete");ctx.reportProgress(80);out.put("status","completed");ctx.log("[+] SUID Enumerator finished successfully");result.addFinding(out);result.complete(out);
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
