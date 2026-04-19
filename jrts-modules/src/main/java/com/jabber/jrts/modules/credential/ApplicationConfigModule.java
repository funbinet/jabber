package com.jabber.jrts.modules.credential;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@JRTSModule(id="cred-appconfig",name="Application Config Scanning",description="Extract credentials from application configuration files and environment",category=Category.CREDENTIAL_ACCESS,riskLevel=RiskLevel.MEDIUM,sourceRef="ConfigParser",author="JRTS")
public class ApplicationConfigModule implements JRTSModuleInterface {
    @Override public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("app_type","Application Type",List.of("web-config","app-config","database-config","api-config","all")).required().group("Target"),
            ModuleInputField.textarea("search_paths","Search Paths").placeholder("/etc\n/opt\n/var/www").group("Paths"),
            ModuleInputField.checkbox("search_env_vars","Search Environment Variables").group("Options"),
            ModuleInputField.checkbox("search_dotfiles","Search Dotfiles (.env, etc)").group("Options"),
            ModuleInputField.checkbox("recursive_search","Recursive Search").group("Options"),
            ModuleInputField.text("excluded_paths","Excluded Paths").placeholder("/sys,/proc,/dev").group("Filtering"),
            ModuleInputField.checkbox("decode_base64","Decode Base64 Credentials").group("Options"),
            ModuleInputField.text("advanced","Advanced Options").group("Advanced")
        );
    }

    @Override public CompletableFuture<ModuleResult> execute(Map<String,String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(()->{
            ModuleResult result=new ModuleResult(ctx.getTaskId(),"cred-appconfig");
            try{
                String appType=input.getOrDefault("app_type","all");

                ctx.log("[*] Application Config Scanning Starting...");
                ctx.log("[*] Application Type: "+appType);
                ctx.reportProgress(15);

                List<String>credentials=new ArrayList<>();
                Map<String,String>envVars=System.getenv();

                if(input.getOrDefault("search_env_vars","").equals("true")){
                    for(Map.Entry<String,String>e:envVars.entrySet()){
                        if(e.getKey().contains("PASS")||e.getKey().contains("TOKEN")||e.getKey().contains("KEY")){
                            credentials.add(e.getKey()+"=***");
                            ctx.log("[+] Found env var: "+e.getKey());
                        }
                    }
                }

                credentials.addAll(scanConfigFiles(appType));
                ctx.reportProgress(50);

                if(credentials.isEmpty()){
                    result.fail("No credentials found in configs");return result;
                }
                ctx.log("[+] Found "+credentials.size()+" credential references");
                ctx.reportProgress(75);

                Map<String,Object>findings=new LinkedHashMap<>();
                findings.put("status","success");
                findings.put("app_type",appType);
                findings.put("credentials_found",credentials.size());
                findings.put("credential_types",String.join(", ",extractTypes(credentials)));
                findings.put("samples",String.join("|",credentials.stream().limit(3).toList()));
                findings.put("impact","Application configs often contain plaintext credentials for databases, APIs, and services");
                findings.put("remediation","Use secrets management tools, environment variables, HSM, rotate credentials, audit config access");

                result.complete(findings);
                ctx.reportProgress(100);
            }catch(Exception e){result.fail(e.getMessage());}
            return result;
        });
    }

    private List<String> scanConfigFiles(String appType){
        List<String>creds=new ArrayList<>();
        try{
            String[] patterns={"web.config","app.config",".env","config.php","settings.py","application.properties"};
            for(String p:patterns){
                Process ps=Runtime.getRuntime().exec(new String[]{"find","/","-name",p,"-type","f"});
                Scanner s=new Scanner(ps.getInputStream());
                int count=0;
                while(s.hasNextLine()&&count<3){
                    creds.add("Found: "+s.nextLine());
                    count++;
                }
                s.close();
            }
        }catch(Exception e){}
        return creds;
    }

    private List<String> extractTypes(List<String>credentials){
        Set<String>types=new HashSet<>();
        for(String c:credentials){
            if(c.contains("password")||c.contains("PASS"))types.add("password");
            if(c.contains("token")||c.contains("TOKEN"))types.add("token");
            if(c.contains("key")||c.contains("KEY"))types.add("key");
            if(c.contains("secret")||c.contains("SECRET"))types.add("secret");
        }
        return new ArrayList<>(types);
    }
}
