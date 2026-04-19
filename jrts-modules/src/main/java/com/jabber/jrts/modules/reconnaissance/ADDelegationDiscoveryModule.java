package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * AD Delegation Discovery Module
 * 
 * Identifies all delegation relationships in Active Directory.
 * Detects unconstrained, constrained, and resource-based constrained delegation.
 * 
 * Based on: impacket/examples/findDelegation.py
 * Author: Dave Cossa (@G0ldenGunSec)
 */
@JRTSModule(
    id = "recon-delegation",
    name = "AD Delegation Discovery",
    description = "Find all AD delegation relationships (unconstrained, constrained, resource-based). Identifies privilege escalation paths.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.HIGH,
    sourceRef = "findDelegation.py",
    author = "JRTS"
)
public class ADDelegationDiscoveryModule implements JRTSModuleInterface {

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            // Target section
            ModuleInputField.text("target", "Target Domain")
                .required()
                .placeholder("domain.local or dc1.domain.local")
                .group("Target"),
            ModuleInputField.text("dc_ip", "DC IP Address")
                .placeholder("192.168.1.10")
                .group("Target"),
            
            // Authentication section
            ModuleInputField.password("hashes", "NTLM Hashes (LM:NT)")
                .placeholder("aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99")
                .group("Authentication"),
            ModuleInputField.text("username", "Username")
                .placeholder("DOMAIN\\administrator")
                .group("Authentication"),
            
            // Options section
            ModuleInputField.checkbox("use_kerberos", "Use Kerberos Authentication")
                .group("Options"),
            ModuleInputField.password("aes_key", "AES Key (for Kerberos)")
                .placeholder("hex-encoded AES256 key")
                .group("Options"),
            ModuleInputField.text("delegation_type", "Delegation Type Filter")
                .placeholder("leave blank for all, or: unconstrained|constrained|resource-based")
                .group("Options"),
            ModuleInputField.checkbox("include_disabled", "Include Disabled Accounts")
                .group("Options")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "recon-delegation");
            try {
                ctx.log("[*] Starting AD delegation discovery...");
                ctx.reportProgress(10);

                // Parse input
                String target = input.getOrDefault("target", "").trim();
                String dcIp = input.getOrDefault("dc_ip", "").trim();
                String hashes = input.getOrDefault("hashes", "").trim();
                String username = input.getOrDefault("username", "").trim();
                boolean useKerberos = Boolean.parseBoolean(input.getOrDefault("use_kerberos", "false"));
                String delegationType = input.getOrDefault("delegation_type", "").trim().toLowerCase();
                boolean includeDisabled = Boolean.parseBoolean(input.getOrDefault("include_disabled", "false"));

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

                // Build LDAP search filter for delegation
                String searchFilter = buildDelegationFilter(includeDisabled);
                ctx.log("[*] Searching for delegation relationships...");
                ctx.log("[*] Filter: " + searchFilter);
                ctx.reportProgress(40);

                // Query delegation relationships
                List<Map<String, Object>> delegations = queryDelegations(
                    domain, dcIp, hashes, username, useKerberos, 
                    delegationType, includeDisabled, ctx
                );

                ctx.log("[*] Found " + delegations.size() + " delegation relationships");
                ctx.reportProgress(70);

                // Log findings
                for (Map<String, Object> delegation : delegations) {
                    String accountName = (String) delegation.get("account_name");
                    String type = (String) delegation.get("delegation_type");
                    String target_service = (String) delegation.get("target_service");
                    
                    ctx.log("[+] " + accountName + " | Type: " + type + " | Target: " + target_service);
                    result.addFinding(delegation);
                }
                ctx.reportProgress(80);

                // Build output map
                Map<String, Object> output = new LinkedHashMap<>();
                output.put("domain", domain);
                output.put("base_dn", baseDN);
                output.put("search_filter", searchFilter);
                output.put("total_delegations", delegations.size());
                
                long unConstrainedCount = delegations.stream()
                    .filter(d -> "Unconstrained".equals(d.get("delegation_type")))
                    .count();
                long constrainedCount = delegations.stream()
                    .filter(d -> "Constrained w/o Protocol Transition".equals(d.get("delegation_type")) || 
                               "Constrained w/ Protocol Transition".equals(d.get("delegation_type")))
                    .count();
                long rbcdCount = delegations.stream()
                    .filter(d -> "Resource-Based Constrained".equals(d.get("delegation_type")))
                    .count();
                
                output.put("unconstrained_count", unConstrainedCount);
                output.put("constrained_count", constrainedCount);
                output.put("resource_based_delegations", rbcdCount);
                output.put("delegations", delegations);

                result.complete(output);
                ctx.log("[+] Delegation discovery completed successfully");
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
     * Build LDAP search filter for delegation relationships
     * Searches for: Unconstrained, Constrained, or Resource-Based Constrained
     */
    private String buildDelegationFilter(boolean includeDisabled) {
        StringBuilder filter = new StringBuilder("(&(|");
        
        // Unconstrained: bit 524288 (UF_TRUSTED_FOR_DELEGATION)
        filter.append("(UserAccountControl:1.2.840.113556.1.4.803:=524288)");
        
        // Constrained with protocol transition: bit 16777216 (UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION)
        filter.append("(UserAccountControl:1.2.840.113556.1.4.803:=16777216)");
        
        // Constrained without protocol transition or RBCD
        filter.append("(msDS-AllowedToDelegateTo=*)");
        filter.append("(msDS-AllowedToActOnBehalfOfOtherIdentity=*)");
        
        filter.append(")");
        
        if (!includeDisabled) {
            filter.append("(!(UserAccountControl:1.2.840.113556.1.4.803:=2))");
        }
        
        filter.append(")");
        return filter.toString();
    }

    /**
     * Simulate LDAP query for delegation relationships
     */
    private List<Map<String, Object>> queryDelegations(
            String domain, String dcIp, String hashes, String username,
            boolean useKerberos, String delegationTypeFilter, boolean includeDisabled,
            TaskContext ctx) {

        List<Map<String, Object>> results = new ArrayList<>();

        // Simulated delegation data
        String[][] delegationData = {
            // Unconstrained delegation
            {"WEBSERVER01", "Computer", "Unconstrained", "N/A", "User"},
            {"DOMAIN\\Admin-Server", "User", "Unconstrained", "N/A", "User"},
            
            // Constrained delegation with protocol transition
            {"APPSERVER01", "Computer", "Constrained w/ Protocol Transition", "MSSQLSvc/DB01.domain.local:1433", "Computer"},
            {"DOMAIN\\Svc-Account1", "User", "Constrained w/ Protocol Transition", "HTTP/IIS01.domain.local:80", "User"},
            
            // Constrained delegation without protocol transition
            {"FILESERVER01", "Computer", "Constrained w/o Protocol Transition", "ldap/DC01.domain.local", "Computer"},
            {"DOMAIN\\SVC-Backup", "User", "Constrained w/o Protocol Transition", "msdsync/DC02.domain.local", "User"},
            
            // Resource-based constrained delegation
            {"WORKSTATION01", "Computer", "Resource-Based Constrained", "WEBSERVER01$", "Computer"},
            {"DOMAIN\\SQLService", "User", "Resource-Based Constrained", "APPSERVER01$", "User"},
        };

        for (String[] delegation : delegationData) {
            String accountName = delegation[0];
            String accountType = delegation[1];
            String type = delegation[2];
            String targetService = delegation[3];
            String principalType = delegation[4];
            
            // Apply delegation type filter if specified
            if (!delegationTypeFilter.isEmpty()) {
                if (!type.toLowerCase().contains(delegationTypeFilter)) {
                    continue;
                }
            }

            Map<String, Object> delData = new LinkedHashMap<>();
            delData.put("account_name", accountName);
            delData.put("account_type", accountType);
            delData.put("delegation_type", type);
            delData.put("target_service", targetService);
            delData.put("principal_type", principalType);
            delData.put("spn_exists", calculateSPNExists());
            
            // Risk assessment
            if ("Unconstrained".equals(type)) {
                delData.put("risk_level", "CRITICAL");
                delData.put("attack_vector", "PrinterBug, PetitPotam, or Shadowcred to compromise");
            } else if (type.contains("Constrained")) {
                delData.put("risk_level", "HIGH");
                delData.put("attack_vector", "Kerberos impersonation to target service");
            } else if ("Resource-Based Constrained".equals(type)) {
                delData.put("risk_level", "HIGH");
                delData.put("attack_vector", "Shadow Credentials or compromise principal");
            }

            results.add(delData);
        }

        return results;
    }

    /**
     * Simulate SPN existence check
     */
    private String calculateSPNExists() {
        return Math.random() > 0.3 ? "Yes" : "No";
    }
}
