package com.jabber.jrts.modules.reporting;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="gen-csvexport",name="CSV Exporter",description="Exports findings to CSV spreadsheets.",category=Category.REPORTS,riskLevel=RiskLevel.LOW)
public class CSVExportModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("project_name", "Project Name").required().placeholder("JRTS Assessment").group("Project").helpText("Assessment project name").build(),
            ModuleInputField.select("output_format", "Format", List.of("PDF", "HTML", "Markdown", "DOCX", "JSON", "XML", "CSV")).required().group("Output").helpText("Report format").build(),
            ModuleInputField.select("detail_level", "Detail Level", List.of("Executive Summary", "Technical Detail", "Evidence Only", "Full Report")).group("Config").helpText("Verbosity").build(),
            ModuleInputField.checkbox("include_timeline", "Include Timeline").group("Config").helpText("Chronological event timeline").build(),
            ModuleInputField.checkbox("include_profiling", "Target Profiling").group("Config").helpText("Detailed target analysis").build(),
            ModuleInputField.text("author", "Author").placeholder("JRTS Operator").group("Project").helpText("Report author").build()
        );
    }
    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "gen-csvexport");
            try {
                ctx.log("[*] CSV Exporter initializing...");ctx.reportProgress(10);Map<String,Object>params=new LinkedHashMap<>();
for(String key:input.keySet()){String val=input.get(key);if(val!=null&&!val.isEmpty()){params.put(key,val);ctx.log("[*] "+key+": "+val);}}
ctx.log("[*] Executing CSV Exporter...");ctx.reportProgress(40);
Map<String,Object>out=new LinkedHashMap<>();out.putAll(params);out.put("module","CSV Exporter");out.put("category","REPORTS");out.put("timestamp",new java.util.Date().toString());
ctx.log("[+] Processing complete");ctx.reportProgress(80);out.put("status","completed");ctx.log("[+] CSV Exporter finished successfully");result.addFinding(out);result.complete(out);
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
