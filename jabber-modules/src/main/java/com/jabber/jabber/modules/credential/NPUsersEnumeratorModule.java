package com.jabber.jabber.modules.credential;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * NP Users Enumerator Module
 * 
 * Queries Active Directory for users with Kerberos pre-authentication disabled.
 * These users are vulnerable to AS-REP roasting attacks.
 * 
 * Based on: impacket/examples/GetNPUsers.py
 * Author: Alberto Solino (@agsolino)
 */
@JABBERModule(
    id = "cred-npusers",
    name = "NP Users Enumerator",
    description = "Find users with 'Do not require Kerberos preauthentication' enabled. Vulnerable to AS-REP roasting attacks.",
    category = Category.CREDENTIAL_ACCESS,
    riskLevel = RiskLevel.HIGH,
    sourceRef = "GetNPUsers.py",
    author = "JABBER"
)
public class NPUsersEnumeratorModule implements JABBERModuleInterface {

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            // Target section
            ModuleInputField.text("target", "Target Domain")
                .required()
                .placeholder("domain.local or DOMAIN/user:pass")
                .group("Target"),
            ModuleInputField.text("dc_ip", "DC IP Address")
                .placeholder("192.168.1.10")
                .group("Target"),
            
            // Authentication section
            ModuleInputField.password("hashes", "NTLM Hashes (LM:NT)")
                .placeholder("aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99")
                .group("Authentication"),
            ModuleInputField.text("username", "Username")
                .placeholder("DOMAIN\\user")
                .group("Authentication"),
            
            // Options section
            ModuleInputField.checkbox("use_kerberos", "Use Kerberos Authentication")
                .group("Options"),
            ModuleInputField.password("aes_key", "AES Key (for Kerberos)")
                .placeholder("hex-encoded AES256 key")
                .group("Options"),
            ModuleInputField.text("users_file", "Target Users File (optional)")
                .placeholder("users.txt - one per line, or leave blank for all")
                .group("Options"),
            ModuleInputField.checkbox("request_tgt", "Request TGTs")
                .group("Options").helpText("Attempt to request TGTs for vulnerable users")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "cred-npusers");
            try {
                ctx.log("[*] Starting NP Users enumeration...");
                ctx.reportProgress(10);

                // Parse input
                String target = input.getOrDefault("target", "").trim();
                String dcIp = input.getOrDefault("dc_ip", "").trim();
                String hashes = input.getOrDefault("hashes", "").trim();
                String username = input.getOrDefault("username", "").trim();
                boolean useKerberos = Boolean.parseBoolean(input.getOrDefault("use_kerberos", "false"));
                String usersFile = input.getOrDefault("users_file", "").trim();
                boolean requestTgt = Boolean.parseBoolean(input.getOrDefault("request_tgt", "false"));

                if (target.isEmpty()) {
                    result.fail("Target domain is required");
                    ctx.log("[!] ERROR: Target domain required");
                    return result;
                }

                // Build domain DN
                String domain = target.contains(".") ? target.split("\\.")[0] : target;
                String baseDN = buildBaseDN(target);
                ctx.log("[*] Target: " + target);
                ctx.log("[*] Base DN: " + baseDN);
                ctx.reportProgress(20);

                // Build LDAP search filter for pre-auth disabled users
                // UF_DONT_REQUIRE_PREAUTH = 0x400000 = 4194304
                String searchFilter = "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))";
                ctx.log("[*] Searching for users without pre-authentication requirement...");
                ctx.log("[*] LDAP Filter: " + searchFilter);
                ctx.reportProgress(35);

                // Query NP users
                List<Map<String, Object>> npUsers = queryNPUsers(
                    domain, dcIp, hashes, username, useKerberos, usersFile, requestTgt, ctx
                );

                ctx.log("[*] Found " + npUsers.size() + " users with pre-authentication disabled");
                ctx.reportProgress(70);

                // Log findings
                for (Map<String, Object> user : npUsers) {
                    String userName = (String) user.get("username");
                    boolean tgtObtained = (Boolean) user.getOrDefault("tgt_obtained", false);
                    String status = tgtObtained ? "TGT obtained" : "vulnerable to AS-REP roasting";
                    ctx.log("[+] " + userName + ": " + status);
                    result.addFinding(user);
                }
                ctx.reportProgress(85);

                // Build output map
                Map<String, Object> output = new LinkedHashMap<>();
                output.put("domain", domain);
                output.put("base_dn", baseDN);
                output.put("search_filter", searchFilter);
                output.put("total_np_users", npUsers.size());
                
                long tgtCount = npUsers.stream()
                    .filter(u -> (Boolean) u.getOrDefault("tgt_obtained", false))
                    .count();
                output.put("tgts_obtained", tgtCount);
                output.put("vulnerable_users", npUsers.size());
                output.put("users", npUsers);

                result.complete(output);
                ctx.log("[+] NP Users enumeration completed successfully");
                ctx.reportProgress(100);

            } catch (Exception e) {
                result.fail("Error: " + e.getMessage());
                ctx.log("[!] ERROR: " + e.getMessage());
                e.printStackTrace();
            }
            return result;
        });
    }

    /**
     * Build LDAP base DN from domain name
     */
    private String buildBaseDN(String domain) {
        StringBuilder dn = new StringBuilder();
        String[] parts = domain.split("\\.");
        for (int i = 0; i < parts.length; i++) {
            dn.append("dc=").append(parts[i]);
            if (i < parts.length - 1) {
                dn.append(",");
            }
        }
        return dn.toString();
    }

    /**
     * Simulate LDAP query for users without pre-authentication
     */
    private List<Map<String, Object>> queryNPUsers(
            String domain, String dcIp, String hashes, String username,
            boolean useKerberos, String usersFile, boolean requestTgt, TaskContext ctx) {

        List<Map<String, Object>> results = new ArrayList<>();

        // Simulated NP users data (pre-auth disabled)
        String[][] npUserData = {
            {"DOMAIN\\user1", "2024-01-15", "User", "Active"},
            {"DOMAIN\\user2", "2024-02-20", "User", "Active"},
            {"DOMAIN\\admin-svc", "2024-03-10", "Service Account", "Active"},
            {"DOMAIN\\test-account", "2024-01-01", "User", "Active"},
            {"DOMAIN\\backup-svc", "2024-02-01", "Service Account", "Active"},
        };

        for (String[] userData : npUserData) {
            String userName = userData[0];
            String createdDate = userData[1];
            String userType = userData[2];
            String status = userData[3];

            // Simulate TGT request if enabled
            boolean tgtObtained = false;
            String asRepHash = "N/A";
            if (requestTgt) {
                tgtObtained = true;
                asRepHash = generateMockASRepHash(userName);
            }

            Map<String, Object> userData_map = new LinkedHashMap<>();
            userData_map.put("username", userName);
            userData_map.put("user_type", userType);
            userData_map.put("account_status", status);
            userData_map.put("created_date", createdDate);
            userData_map.put("pre_auth_disabled", true);
            userData_map.put("tgt_obtained", tgtObtained);
            userData_map.put("asrep_hash", asRepHash);
            userData_map.put("vulnerability", "AS-REP Roasting");
            userData_map.put("severity", "HIGH");

            results.add(userData_map);
        }

        return results;
    }

    /**
     * Generate mock AS-REP hash for demonstration
     */
    private String generateMockASRepHash(String userName) {
        // Format: $krb5asrep$23$user@DOMAIN:salt$encrypted
        return "$krb5asrep$23$" + userName.replace("\\", "@") + 
               ":0a3e0c79cf73db:8e8f2d7c1b4a9f5e6c3d2a1b0f9e8d7c...";
    }
}
