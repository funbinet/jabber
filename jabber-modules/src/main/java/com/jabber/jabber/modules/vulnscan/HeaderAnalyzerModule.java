package com.jabber.jabber.modules.vulnscan;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JABBERModule(id="gen-headeranalyzer",name="HTTP Security Header Analyzer",description="Checks HTTP response headers for missing security controls and misconfigurations.",category=Category.VULNERABILITY_SCANNING,riskLevel=RiskLevel.MEDIUM)
public class HeaderAnalyzerModule implements JABBERModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("target", "Target").required().placeholder("192.168.1.0/24").group("Target").helpText("Target host, IP, or URL").build(),
            ModuleInputField.select("scan_profile", "Scan Profile", List.of("Quick Scan", "Full Scan", "Deep Scan", "Stealth Scan")).group("Config").helpText("Scan intensity").build(),
            ModuleInputField.text("service_version", "Service Version Filter").group("Filter").helpText("Filter by service version").build(),
            ModuleInputField.text("exclude_list", "Exclude List").group("Filter").helpText("IPs/ports to exclude (comma-separated)").build(),
            ModuleInputField.text("script_selection", "Scripts/Templates").group("Scripts").helpText("NSE scripts, CVE templates, or custom").build(),
            ModuleInputField.text("concurrency", "Concurrency").placeholder("10").group("Performance").helpText("Concurrent scan threads").build(),
            ModuleInputField.text("timeout", "Timeout (ms)").placeholder("10000").group("Config").helpText("Per-target scan timeout").build()
        );
    }
    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-headeranalyzer");
            try {
                String url=g(input,"url");ctx.log("[*] Analyzing: "+url);ctx.reportProgress(10);
                java.net.HttpURLConnection c=(java.net.HttpURLConnection)new java.net.URL(url).openConnection();c.setRequestMethod("GET");c.setConnectTimeout(5000);c.setInstanceFollowRedirects("true".equals(input.get("follow_redirects")));c.connect();
                ctx.log("[+] Status: "+c.getResponseCode());List<Map<String,Object>>findings=new ArrayList<>();
                String[]headers={"Strict-Transport-Security","Content-Security-Policy","X-Frame-Options","X-Content-Type-Options","X-XSS-Protection","Referrer-Policy","Permissions-Policy"};
                for(String h:headers){String v=c.getHeaderField(h);Map<String,Object>f=new LinkedHashMap<>();f.put("header",h);f.put("present",v!=null);f.put("value",v!=null?v:"MISSING");f.put("severity",v==null?"HIGH":"INFO");findings.add(f);result.addFinding(f);ctx.log((v!=null?"[+] ":"[!] ")+h+": "+(v!=null?v:"MISSING"));}
                Map<String,Object>out=new LinkedHashMap<>();out.put("url",url);out.put("status",c.getResponseCode());out.put("findings",findings);result.complete(out);
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
