package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="gen-pingsweeper",name="Ping Sweeper",description="ICMP sweep to identify live hosts across a target subnet.",category=Category.RECONNAISSANCE,riskLevel=RiskLevel.LOW)
public class PingSweeperModule implements JRTSModuleInterface {
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
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-pingsweeper");
            try {
                String subnet=g(input,"subnet");int timeout=Integer.parseInt(g(input,"timeout","1000"));
                ctx.log("[*] Sweeping "+subnet);String[]p=subnet.split("/");int prefix=Integer.parseInt(p[1]);
                int count=Math.min((int)Math.pow(2,32-prefix),256);String[]oct=p[0].split("\\.");
                long base=((long)Integer.parseInt(oct[0])<<24)|((long)Integer.parseInt(oct[1])<<16)|((long)Integer.parseInt(oct[2])<<8)|Integer.parseInt(oct[3]);
                List<Map<String,Object>>alive=new ArrayList<>();
                for(int i=1;i<count-1;i++){String host=longToIp(base+i);try{if(java.net.InetAddress.getByName(host).isReachable(timeout)){Map<String,Object>h=new LinkedHashMap<>();h.put("ip",host);h.put("status","UP");alive.add(h);result.addFinding(h);ctx.log("[+] ALIVE: "+host);}}catch(Exception ignored){}if(i%(count/10+1)==0)ctx.reportProgress(10+80*i/count);}
                Map<String,Object>out=new LinkedHashMap<>();out.put("subnet",subnet);out.put("scanned",count-2);out.put("alive",alive.size());out.put("hosts",alive);ctx.log("[+] "+alive.size()+" alive");result.complete(out);
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
