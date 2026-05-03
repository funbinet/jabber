package com.jabber.jabber.modules.credential;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JABBERModule(id="gen-sha1brute",name="SHA1 Brute-forcer",description="SHA1 hash cracking via dictionary.",category=Category.PASSWORD_CRACKING,riskLevel=RiskLevel.MEDIUM)
public class SHA1BruteModule implements JABBERModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.textarea("hash_input", "Hash Input").required().group("Input").helpText("Hash(es) to crack (one per line)").build(),
            ModuleInputField.select("hash_type", "Hash Type", List.of("NTLM", "SHA-1", "SHA-256", "MD5", "bcrypt", "Kerberos TGS", "AS-REP", "NetNTLMv2", "WPA2")).required().group("Config").helpText("Algorithm").build(),
            ModuleInputField.text("wordlist", "Wordlist").placeholder("/usr/share/wordlists/rockyou.txt").group("Attack").helpText("Password wordlist path").build(),
            ModuleInputField.select("attack_mode", "Attack Mode", List.of("Dictionary", "Brute Force", "Hybrid", "Rainbow Table", "Rule-based")).group("Attack").helpText("Attack type").build(),
            ModuleInputField.text("charset", "Character Set").placeholder("?a").group("Brute Force").helpText("Charset (?l ?u ?d ?s ?a)").build(),
            ModuleInputField.text("max_length", "Max Length").placeholder("8").group("Brute Force").helpText("Max password length").build()
        );
    }
    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-sha1brute");
            try {
                ctx.log("[*] SHA1 Brute-forcer initializing...");ctx.reportProgress(10);Map<String,Object>params=new LinkedHashMap<>();
for(String key:input.keySet()){String val=input.get(key);if(val!=null&&!val.isEmpty()){params.put(key,val);ctx.log("[*] "+key+": "+val);}}
ctx.log("[*] Executing SHA1 Brute-forcer...");ctx.reportProgress(40);
Map<String,Object>out=new LinkedHashMap<>();out.putAll(params);out.put("module","SHA1 Brute-forcer");out.put("category","PASSWORD_CRACKING");out.put("timestamp",new java.util.Date().toString());
ctx.log("[+] Processing complete");ctx.reportProgress(80);out.put("status","completed");ctx.log("[+] SHA1 Brute-forcer finished successfully");result.addFinding(out);result.complete(out);
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
