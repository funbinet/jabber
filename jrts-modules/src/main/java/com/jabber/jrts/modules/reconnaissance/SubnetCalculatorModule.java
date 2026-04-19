package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="gen-subnetcalculator",name="Subnet Calculator",description="CIDR calculator computing masks, host ranges, and broadcast addresses.",category=Category.RECONNAISSANCE,riskLevel=RiskLevel.LOW)
public class SubnetCalculatorModule implements JRTSModuleInterface {
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
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-subnetcalculator");
            try {
                String cidr=g(input,"cidr");ctx.log("[*] Calculating: "+cidr);String[]p=cidr.split("/");int prefix=Integer.parseInt(p[1]);
                long mask=(0xFFFFFFFFL<<(32-prefix))&0xFFFFFFFFL;String[]o=p[0].split("\\.");long ip=0;for(String s:o)ip=(ip<<8)|Integer.parseInt(s);
                long net=ip&mask;long bcast=net|(~mask&0xFFFFFFFFL);long hosts=(long)Math.pow(2,32-prefix)-2;
                Map<String,Object>out=new LinkedHashMap<>();out.put("network",longToIp(net));out.put("broadcast",longToIp(bcast));out.put("netmask",longToIp(mask));
                out.put("first_host",longToIp(net+1));out.put("last_host",longToIp(bcast-1));out.put("total_hosts",hosts);out.put("prefix",prefix);
                ctx.log("[+] Network: "+longToIp(net));ctx.log("[+] Broadcast: "+longToIp(bcast));ctx.log("[+] Range: "+longToIp(net+1)+" - "+longToIp(bcast-1));ctx.log("[+] Hosts: "+hosts);result.complete(out);
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
