package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="gen-portscanner",name="Port Scanner",description="Multi-threaded TCP port scanner with service detection across configurable port ranges.",category=Category.RECONNAISSANCE,riskLevel=RiskLevel.HIGH)
public class PortScannerModule implements JRTSModuleInterface {
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
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-portscanner");
            try {
                String target=g(input,"target");int timeout=Integer.parseInt(g(input,"timeout","2000"));
                ctx.log("[*] Scanning "+target+" ports "+g(input,"ports","1-1024"));ctx.reportProgress(5);
                int[]ports=parsePorts(g(input,"ports","1-1024"));List<Map<String,Object>>open=new ArrayList<>();
                for(int i=0;i<ports.length;i++){try{java.net.Socket s=new java.net.Socket();s.connect(new java.net.InetSocketAddress(target,ports[i]),timeout);s.close();
                    Map<String,Object>e=new LinkedHashMap<>();e.put("port",ports[i]);e.put("state","OPEN");e.put("service",svc(ports[i]));open.add(e);result.addFinding(e);
                    ctx.log("[+] "+ports[i]+"/tcp OPEN - "+svc(ports[i]));}catch(Exception ignored){}if(i%(ports.length/10+1)==0)ctx.reportProgress(5+85*i/ports.length);}
                Map<String,Object>out=new LinkedHashMap<>();out.put("target",target);out.put("scanned",ports.length);out.put("open",open.size());out.put("open_ports",open);
                ctx.log("[+] Scan complete: "+open.size()+"/"+ports.length+" open");result.complete(out);
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
