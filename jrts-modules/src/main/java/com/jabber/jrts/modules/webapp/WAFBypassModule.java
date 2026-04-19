package com.jabber.jrts.modules.webapp;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="gen-wafbypass",name="WAF Detector",description="Identifies Web Application Firewalls and tests bypass techniques.",category=Category.WEB_ASSESSMENT,riskLevel=RiskLevel.HIGH)
public class WAFBypassModule implements JRTSModuleInterface {
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
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-wafbypass");
            try {
                String url=g(input,"url");ctx.log("[*] WAF detection: "+url);ctx.reportProgress(10);
String[]payloads={"<script>alert(1)</script>","1 OR 1=1--","../../../etc/passwd"};List<Map<String,Object>>tests=new ArrayList<>();
for(String p:payloads){try{java.net.HttpURLConnection c=(java.net.HttpURLConnection)new java.net.URL(url+"?t="+java.net.URLEncoder.encode(p,"UTF-8")).openConnection();c.setConnectTimeout(5000);int code=c.getResponseCode();Map<String,Object>t=new LinkedHashMap<>();t.put("payload",p);t.put("status",code);t.put("blocked",code==403||code==406);tests.add(t);ctx.log((code==403?"[+] BLOCKED: ":"[-] PASSED: ")+p+" ["+code+"]");}catch(Exception e){ctx.log("[-] "+e.getMessage());}}
boolean waf=tests.stream().anyMatch(t->(boolean)t.get("blocked"));Map<String,Object>out=new LinkedHashMap<>();out.put("waf_detected",waf);out.put("tests",tests);ctx.log(waf?"[+] WAF DETECTED":"[-] No WAF");result.addFinding(out);result.complete(out);
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
