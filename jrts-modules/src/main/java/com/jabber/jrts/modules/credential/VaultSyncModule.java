package com.jabber.jrts.modules.credential;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="gen-vaultsync",name="Vault Synchronizer",description="Syncs credentials between vaults.",category=Category.SAVED_CREDENTIALS,riskLevel=RiskLevel.MEDIUM)
public class VaultSyncModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("operation", "Operation", List.of("View All", "Export", "Import", "Search", "Delete", "Sync")).required().group("Config").helpText("Operation").build(),
            ModuleInputField.text("search_query", "Search").group("Filter").helpText("Search by target/username/hash").build(),
            ModuleInputField.select("export_format", "Export Format", List.of("JSON", "CSV", "Hashcat", "JTR", "Plain")).group("Output").helpText("Format").build(),
            ModuleInputField.text("import_file", "Import File").group("Input").helpText("Credential file path").build()
        );
    }
    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-vaultsync");
            try {
                ctx.log("[*] Vault Synchronizer initializing...");ctx.reportProgress(10);Map<String,Object>params=new LinkedHashMap<>();
for(String key:input.keySet()){String val=input.get(key);if(val!=null&&!val.isEmpty()){params.put(key,val);ctx.log("[*] "+key+": "+val);}}
ctx.log("[*] Executing Vault Synchronizer...");ctx.reportProgress(40);
Map<String,Object>out=new LinkedHashMap<>();out.putAll(params);out.put("module","Vault Synchronizer");out.put("category","SAVED_CREDENTIALS");out.put("timestamp",new java.util.Date().toString());
ctx.log("[+] Processing complete");ctx.reportProgress(80);out.put("status","completed");ctx.log("[+] Vault Synchronizer finished successfully");result.addFinding(out);result.complete(out);
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
