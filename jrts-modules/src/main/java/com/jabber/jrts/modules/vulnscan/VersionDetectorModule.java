package com.jabber.jrts.modules.vulnscan;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="gen-versiondetector",name="Service Version Detector",description="Banner-grabs services to identify software versions for vulnerability correlation.",category=Category.VULNERABILITY_SCANNING,riskLevel=RiskLevel.MEDIUM)
public class VersionDetectorModule implements JRTSModuleInterface {
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
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-versiondetector");
            try {
                String target=g(input,"target");String[]ports=g(input,"ports","22,80,443").split(",");int timeout=Integer.parseInt(g(input,"timeout","3000"));
                ctx.log("[*] Banner grabbing "+target);List<Map<String,Object>>svcs=new ArrayList<>();
                for(int i=0;i<ports.length;i++){int port=Integer.parseInt(ports[i].trim());try{java.net.Socket s=new java.net.Socket();s.connect(new java.net.InetSocketAddress(target,port),timeout);s.setSoTimeout(timeout);byte[]buf=new byte[1024];int n=s.getInputStream().read(buf);String banner=n>0?new String(buf,0,n).trim():"No banner";s.close();Map<String,Object>svc=new LinkedHashMap<>();svc.put("port",port);svc.put("banner",banner);svc.put("service",svc(port));svcs.add(svc);result.addFinding(svc);ctx.log("[+] "+port+": "+banner);}catch(Exception e){ctx.log("[-] "+port+": closed");}ctx.reportProgress(10+80*i/ports.length);}
                Map<String,Object>out=new LinkedHashMap<>();out.put("target",target);out.put("services",svcs);out.put("total",svcs.size());ctx.log("[+] "+svcs.size()+" services");result.complete(out);
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
