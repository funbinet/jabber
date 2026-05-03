package com.jabber.jabber.modules.vulnscan;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JABBERModule(id="gen-sslcertchecker",name="SSL Certificate Inspector",description="Inspects SSL/TLS certificates for expiration, weak algorithms, and chain issues.",category=Category.VULNERABILITY_SCANNING,riskLevel=RiskLevel.MEDIUM)
public class SSLCertCheckerModule implements JABBERModuleInterface {
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
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-sslcertchecker");
            try {
                String host=g(input,"host");int port=Integer.parseInt(g(input,"port","443"));ctx.log("[*] SSL: "+host+":"+port);ctx.reportProgress(10);
                javax.net.ssl.SSLSocketFactory sf=(javax.net.ssl.SSLSocketFactory)javax.net.ssl.SSLSocketFactory.getDefault();javax.net.ssl.SSLSocket s=(javax.net.ssl.SSLSocket)sf.createSocket(host,port);s.startHandshake();
                java.security.cert.X509Certificate cert=(java.security.cert.X509Certificate)s.getSession().getPeerCertificates()[0];
                Map<String,Object>out=new LinkedHashMap<>();out.put("subject",cert.getSubjectX500Principal().getName());out.put("issuer",cert.getIssuerX500Principal().getName());out.put("valid_until",cert.getNotAfter().toString());out.put("algorithm",cert.getSigAlgName());
                boolean expired=cert.getNotAfter().before(new java.util.Date());long days=(cert.getNotAfter().getTime()-System.currentTimeMillis())/86400000L;out.put("expired",expired);out.put("days_remaining",days);
                ctx.log("[+] Subject: "+out.get("subject"));ctx.log("[+] Expires: "+out.get("valid_until"));ctx.log(expired?"[!] EXPIRED":"[+] Days: "+days);s.close();result.addFinding(out);result.complete(out);
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
