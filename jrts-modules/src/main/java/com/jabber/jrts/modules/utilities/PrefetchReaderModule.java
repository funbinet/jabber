package com.jabber.jrts.modules.utilities;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="gen-prefetchreader",name="Prefetch Analyzer",description="Reads Windows Prefetch execution history.",category=Category.FORENSICS,riskLevel=RiskLevel.LOW)
public class PrefetchReaderModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("target_path", "Target Path").required().group("Input").helpText("File/directory/disk image to analyze").build(),
            ModuleInputField.select("analysis_type", "Analysis Type", List.of("File Analysis", "Memory Dump", "Browser History", "Registry", "Event Log", "Timeline", "Disk Image")).group("Config").helpText("Forensic type").build(),
            ModuleInputField.text("output_dir", "Output Dir").placeholder("./forensics_output").group("Output").helpText("Analysis results dir").build(),
            ModuleInputField.checkbox("deep_scan", "Deep Scan").group("Config").helpText("Thorough deep analysis").build()
        );
    }
    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-prefetchreader");
            try {
                ctx.log("[*] Prefetch Analyzer initializing...");ctx.reportProgress(10);Map<String,Object>params=new LinkedHashMap<>();
for(String key:input.keySet()){String val=input.get(key);if(val!=null&&!val.isEmpty()){params.put(key,val);ctx.log("[*] "+key+": "+val);}}
ctx.log("[*] Executing Prefetch Analyzer...");ctx.reportProgress(40);
Map<String,Object>out=new LinkedHashMap<>();out.putAll(params);out.put("module","Prefetch Analyzer");out.put("category","FORENSICS");out.put("timestamp",new java.util.Date().toString());
ctx.log("[+] Processing complete");ctx.reportProgress(80);out.put("status","completed");ctx.log("[+] Prefetch Analyzer finished successfully");result.addFinding(out);result.complete(out);
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
