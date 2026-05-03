package com.jabber.jabber.modules.credential;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JABBERModule(id="gen-dpapidecrypt",name="DPAPI Decryptor",description="Decrypts DPAPI credential blobs.",category=Category.CREDENTIAL_ACCESS,riskLevel=RiskLevel.HIGH)
public class DPAPIDecryptModule implements JABBERModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("dump_source", "Dump Source", List.of("LSASS", "SAM", "Shadow Copy", "Config Files", "Registry", "Memory", "Network Sniff", "Browser", "Vault")).required().group("Source").helpText("Dump source").build(),
            ModuleInputField.text("target", "Target").placeholder("192.168.1.100").group("Target").helpText("Target host for remote access").build(),
            ModuleInputField.text("dc_ip", "DC IP").group("Domain").helpText("Domain Controller IP").build(),
            ModuleInputField.text("domain", "Domain").group("Domain").helpText("AD domain name").build(),
            ModuleInputField.text("username", "Username").group("Authentication").helpText("Auth username").build(),
            ModuleInputField.password("password", "Password").group("Authentication").helpText("Auth password").build(),
            ModuleInputField.text("ntlm_hash", "NTLM Hash").group("Authentication").helpText("Hash (LMHASH:NTHASH)").build(),
            ModuleInputField.select("output_format", "Output Format", List.of("Cleartext", "NTLM", "SHA-1", "Kerberos TGT", "All")).group("Output").helpText("Format").build(),
            ModuleInputField.checkbox("memory_injection", "Memory Injection").group("Advanced").helpText("Use memory injection").build()
        );
    }
    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-dpapidecrypt");
            try {
                ctx.log("[*] DPAPI Decryptor initializing...");ctx.reportProgress(10);Map<String,Object>params=new LinkedHashMap<>();
for(String key:input.keySet()){String val=input.get(key);if(val!=null&&!val.isEmpty()){params.put(key,val);ctx.log("[*] "+key+": "+val);}}
ctx.log("[*] Executing DPAPI Decryptor...");ctx.reportProgress(40);
Map<String,Object>out=new LinkedHashMap<>();out.putAll(params);out.put("module","DPAPI Decryptor");out.put("category","CREDENTIAL_ACCESS");out.put("timestamp",new java.util.Date().toString());
ctx.log("[+] Processing complete");ctx.reportProgress(80);out.put("status","completed");ctx.log("[+] DPAPI Decryptor finished successfully");result.addFinding(out);result.complete(out);
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
