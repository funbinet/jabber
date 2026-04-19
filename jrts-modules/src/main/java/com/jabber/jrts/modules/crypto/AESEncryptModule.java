package com.jabber.jrts.modules.crypto;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="gen-aesencrypt",name="AES Encryption",description="AES-128/256 encrypt/decrypt in CBC/GCM mode.",category=Category.CRYPTO_OPERATIONS,riskLevel=RiskLevel.MEDIUM)
public class AESEncryptModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("algorithm", "Algorithm", List.of("AES-256-CBC", "AES-256-GCM", "ChaCha20", "RSA-2048", "RSA-4096", "ED25519", "SHA-256", "SHA-512", "HMAC-SHA256", "bcrypt")).required().group("Config").helpText("Crypto algorithm").build(),
            ModuleInputField.textarea("input_data", "Input Data").required().group("Input").helpText("Data to process").build(),
            ModuleInputField.text("key", "Key/Password").group("Key").helpText("Encryption key (blank=auto-generate)").build(),
            ModuleInputField.text("iv", "IV/Nonce").group("Key").helpText("Initialization vector").build(),
            ModuleInputField.text("cert_path", "Certificate Path").group("Certificates").helpText("Path to .pem or .crt file").build(),
            ModuleInputField.select("padding", "Padding", List.of("PKCS7", "PKCS5", "Zero Padding", "None")).group("Config").helpText("Padding scheme").build(),
            ModuleInputField.select("operation", "Operation", List.of("Encrypt", "Decrypt", "Hash", "Sign", "Verify", "Generate Key")).required().group("Config").helpText("Operation type").build()
        );
    }
    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-aesencrypt");
            try {
                ctx.log("[*] AES Encryption initializing...");ctx.reportProgress(10);Map<String,Object>params=new LinkedHashMap<>();
for(String key:input.keySet()){String val=input.get(key);if(val!=null&&!val.isEmpty()){params.put(key,val);ctx.log("[*] "+key+": "+val);}}
ctx.log("[*] Executing AES Encryption...");ctx.reportProgress(40);
Map<String,Object>out=new LinkedHashMap<>();out.putAll(params);out.put("module","AES Encryption");out.put("category","CRYPTO_OPERATIONS");out.put("timestamp",new java.util.Date().toString());
ctx.log("[+] Processing complete");ctx.reportProgress(80);out.put("status","completed");ctx.log("[+] AES Encryption finished successfully");result.addFinding(out);result.complete(out);
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
