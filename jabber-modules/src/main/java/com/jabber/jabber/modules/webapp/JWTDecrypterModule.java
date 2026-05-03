package com.jabber.jabber.modules.webapp;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JABBERModule(id="gen-jwtdecrypter",name="JWT Analyzer",description="Decodes JWT tokens and checks for weak algorithms and missing claims.",category=Category.WEB_ASSESSMENT,riskLevel=RiskLevel.MEDIUM)
public class JWTDecrypterModule implements JABBERModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("base_url", "Base URL").required().placeholder("https://target.com").group("Target").helpText("Web application base URL").build(),
            ModuleInputField.text("auth_cookie", "Session Cookie").group("Auth").helpText("Session cookie for authenticated testing").build(),
            ModuleInputField.text("auth_token", "Bearer Token").group("Auth").helpText("JWT/Bearer token").build(),
            ModuleInputField.text("wordlist", "Wordlist Path").placeholder("/usr/share/wordlists/dirb/common.txt").group("Fuzzing").helpText("Wordlist for fuzzing").build(),
            ModuleInputField.textarea("parameter_map", "Parameter Map").placeholder("id=1").group("Fuzzing").helpText("GET/POST params to fuzz (key=value)").build(),
            ModuleInputField.text("threads", "Threads").placeholder("10").group("Performance").helpText("Concurrent request threads").build(),
            ModuleInputField.text("user_agent", "User Agent").group("Stealth").helpText("Custom user-agent string").build()
        );
    }
    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-jwtdecrypter");
            try {
                String token=g(input,"token");ctx.log("[*] JWT Analysis...");ctx.reportProgress(10);
String[]parts=token.split("\\.");if(parts.length!=3){ctx.log("[!] Invalid JWT");result.fail("Invalid JWT format");return result;}
String header=new String(java.util.Base64.getUrlDecoder().decode(parts[0]));String payload=new String(java.util.Base64.getUrlDecoder().decode(parts[1]));ctx.log("[+] Header: "+header);ctx.log("[+] Payload: "+payload);
boolean weak=header.contains("\"none\"")||header.contains("\"HS256\"");Map<String,Object>out=new LinkedHashMap<>();out.put("header",header);out.put("payload",payload);out.put("signature",parts[2]);out.put("weak_algorithm",weak);ctx.log("[+] Weak alg: "+weak);result.addFinding(out);result.complete(out);
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
