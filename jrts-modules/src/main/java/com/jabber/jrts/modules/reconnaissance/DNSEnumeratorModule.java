package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="gen-dnsenumerator",name="DNS Enumerator",description="DNS enumeration with forward lookups, reverse DNS, and subdomain brute-forcing.",category=Category.RECONNAISSANCE,riskLevel=RiskLevel.MEDIUM)
public class DNSEnumeratorModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("target", "Target Host/IP").required().placeholder("192.168.1.0/24").group("Target").helpText("Target host, IP, or CIDR range").build(),
            ModuleInputField.text("domain", "Domain").placeholder("example.com").group("Target").helpText("Target domain name").build(),
            ModuleInputField.text("port_range", "Port Range").placeholder("1-1024").group("Scan Config").helpText("Port range (e.g. 1-1024, 80,443)").build(),
            ModuleInputField.text("api_key", "API Key").group("Authentication").helpText("API key for external services").build(),
            ModuleInputField.text("user_agent", "User Agent").placeholder("Mozilla/5.0 (JRTS Scanner)").group("Stealth").helpText("Custom user-agent for stealth").build(),
            ModuleInputField.text("depth", "Scan Depth").placeholder("3").group("Scan Config").helpText("Enumeration depth level").build(),
            ModuleInputField.text("timeout", "Timeout (ms)").placeholder("5000").group("Scan Config").helpText("Connection timeout").build(),
            ModuleInputField.checkbox("aggressive", "Aggressive Mode").group("Scan Config").helpText("Faster but noisier scanning").build()
        );
    }
    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-dnsenumerator");
            try {
                String domain=g(input,"domain");ctx.log("[*] DNS Enumeration: "+domain);ctx.reportProgress(5);
                List<Map<String,Object>>recs=new ArrayList<>();
                try{java.net.InetAddress[]addrs=java.net.InetAddress.getAllByName(domain);for(var a:addrs){Map<String,Object>r=new LinkedHashMap<>();r.put("type","A");r.put("name",domain);r.put("ip",a.getHostAddress());recs.add(r);result.addFinding(r);ctx.log("[+] A: "+domain+" -> "+a.getHostAddress());}}catch(Exception e){ctx.log("[-] Cannot resolve "+domain);}
                ctx.reportProgress(20);String[]subs=g(input,"wordlist","www\nmail\nftp\nadmin").split("\\n");
                for(int i=0;i<subs.length;i++){String sub=subs[i].trim()+"."+domain;try{var addr=java.net.InetAddress.getByName(sub);Map<String,Object>r=new LinkedHashMap<>();r.put("type","SUB");r.put("name",sub);r.put("ip",addr.getHostAddress());recs.add(r);result.addFinding(r);ctx.log("[+] "+sub+" -> "+addr.getHostAddress());}catch(Exception ignored){}ctx.reportProgress(20+70*i/subs.length);}
                Map<String,Object>out=new LinkedHashMap<>();out.put("domain",domain);out.put("total",recs.size());out.put("records",recs);ctx.log("[+] "+recs.size()+" records found");result.complete(out);
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
