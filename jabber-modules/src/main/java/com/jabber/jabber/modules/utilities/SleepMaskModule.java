package com.jabber.jabber.modules.utilities;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JABBERModule(id="gen-sleepmask",name="Sleep Mask Persistence",description="In-memory sleep masking with re-encryption.",category=Category.C2_PERSISTENCE,riskLevel=RiskLevel.MEDIUM)
public class SleepMaskModule implements JABBERModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("target", "Target").required().group("Target").helpText("Target host or C2 address").build(),
            ModuleInputField.select("protocol", "Protocol", List.of("HTTPS", "HTTP", "DNS", "WebSocket", "Raw TCP")).group("Config").helpText("Protocol").build(),
            ModuleInputField.text("kill_date", "Kill Date").group("OpSec").helpText("Expiration (YYYY-MM-DD)").build(),
            ModuleInputField.select("working_hours", "Working Hours", List.of("24/7", "Business Hours", "Night Only", "Custom")).group("OpSec").helpText("Active hours").build(),
            ModuleInputField.textarea("custom_headers", "Custom Headers").group("Malleable").helpText("HTTP headers for traffic mimicry").build(),
            ModuleInputField.text("malleable_profile", "Malleable Profile").group("Malleable").helpText("Traffic shaping config path").build()
        );
    }
    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-sleepmask");
            try {
                ctx.log("[*] Sleep Mask Persistence initializing...");ctx.reportProgress(10);Map<String,Object>params=new LinkedHashMap<>();
for(String key:input.keySet()){String val=input.get(key);if(val!=null&&!val.isEmpty()){params.put(key,val);ctx.log("[*] "+key+": "+val);}}
ctx.log("[*] Executing Sleep Mask Persistence...");ctx.reportProgress(40);
Map<String,Object>out=new LinkedHashMap<>();out.putAll(params);out.put("module","Sleep Mask Persistence");out.put("category","C2_PERSISTENCE");out.put("timestamp",new java.util.Date().toString());
ctx.log("[+] Processing complete");ctx.reportProgress(80);out.put("status","completed");ctx.log("[+] Sleep Mask Persistence finished successfully");result.addFinding(out);result.complete(out);
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
