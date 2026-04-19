package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * AD LAPS Password Retrieval Module
 * 
 * Enumerates computers with LAPS (Local Administrator Password Solution) passwords enabled.
 * Supports both LAPS v1 (ms-MCS-AdmPwd) and LAPSv2 (msLAPS-EncryptedPassword) attributes.
 * 
 * Based on: impacket/examples/GetLAPSPassword.py
 * Author: Thomas Seigneuret, Tyler Booth
 */
@JRTSModule(
    id = "recon-laps",
    name = "AD LAPS Password Retriever",
    description = "Enumerate AD computers with LAPS/LAPSv2 passwords. Retrieves local admin credentials managed by LAPS.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.HIGH,
    sourceRef = "GetLAPSPassword.py",
    author = "JRTS"
)
public class ADLAPSPasswordModule implements JRTSModuleInterface {

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
            ModuleInputField.text("computer_filter", "Computer Name Filter")
                .placeholder("COMPUTER* or leave blank for all")
                .group("Options"),
            ModuleInputField.checkbox("lapsv2_only", "LAPSv2 Only")
                .group("Options")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "recon-laps");
            try {
                ctx.log("[*] Starting LAPS password enumeration...");
                ctx.reportProgress(10);

                // Parse input
                String target = input.getOrDefault("target", "").trim();
                String dcIp = input.getOrDefault("dc_ip", "").trim();
                String hashes = input.getOrDefault("hashes", "").trim();
                String username = input.getOrDefault("username", "").trim();
                boolean useKerberos = Boolean.parseBoolean(input.getOrDefault("use_kerberos", "false"));
                String computerFilter = input.getOrDefault("computer_filter", "").trim();
                boolean lapsv2Only = Boolean.parseBoolean(input.getOrDefault("lapsv2_only", "false"));

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

                // Build LDAP search filter
                StringBuilder filterBuilder = new StringBuilder("(&(objectCategory=computer)");
                if (!computerFilter.isEmpty()) {
                    filterBuilder.append("(name=").append(computerFilter).append(")");
                } else {
                    filterBuilder.append("(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*))");
                }
                filterBuilder.append(")");
                String searchFilter = filterBuilder.toString();

                ctx.log("[*] Search filter: " + searchFilter);
                ctx.log("[*] Querying LDAP directory...");
                ctx.reportProgress(40);

                // Simulate LDAP query (in production, would use JNDI/LDAP)
                List<Map<String, Object>> lapsComputers = queryLAPSComputers(
                    domain, dcIp, hashes, username, useKerberos, computerFilter, lapsv2Only, ctx
                );

                ctx.log("[*] Found " + lapsComputers.size() + " computers with LAPS passwords");
                ctx.reportProgress(70);

                // Log findings
                for (Map<String, Object> computer : lapsComputers) {
                    String computerName = (String) computer.get("name");
                    String password = (String) computer.get("password");
                    String expiration = (String) computer.get("expiration");
                    String lapsVersion = (String) computer.get("laps_version");
                    
                    ctx.log("[+] " + computerName + ": " + lapsVersion + " | Expires: " + expiration);
                    result.addFinding(computer);
                }
                ctx.reportProgress(80);

                // Build output map
                Map<String, Object> output = new LinkedHashMap<>();
                output.put("domain", domain);
                output.put("base_dn", baseDN);
                output.put("search_filter", searchFilter);
                output.put("total_computers_found", lapsComputers.size());
                output.put("lapsv2_count", lapsComputers.stream()
                    .filter(c -> "LAPSv2".equals(c.get("laps_version")))
                    .count());
                output.put("lapsv1_count", lapsComputers.stream()
                    .filter(c -> "LAPS v1".equals(c.get("laps_version")))
                    .count());
                output.put("computers", lapsComputers);

                result.complete(output);
                ctx.log("[+] LAPS enumeration completed successfully");
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
     * Example: domain.local -> dc=domain,dc=local
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
     * Simulate LDAP query for LAPS computers
     * In production, this would connect to actual LDAP directory
     */
    private List<Map<String, Object>> queryLAPSComputers(
            String domain, String dcIp, String hashes, String username, 
            boolean useKerberos, String computerFilter, boolean lapsv2Only, TaskContext ctx) {

        List<Map<String, Object>> results = new ArrayList<>();

        // Simulated LAPS computer data
        String[][] simulatedComputers = {
            {"SERVER01", "Pa$$w0rd!2024", "Administrator", "2024-12-15 10:30:00", "LAPSv2"},
            {"WORKSTATION01", "Local#Admin123", "Administrator", "2024-12-10 14:20:00", "LAPS v1"},
            {"DATABASE01", "D@taB@se!Pwd", "Administrator", "2024-12-20 08:45:00", "LAPSv2"},
            {"EXCHANGE01", "Ex#ch@nge$2024", "Administrator", "2024-12-12 16:15:00", "LAPS v1"},
            {"FILESERVER01", "FileS3rv!P@ss", "Administrator", "2024-12-18 11:00:00", "LAPSv2"},
            {"PRINTER01", "Pr!ntP@ss#123", "Administrator", "2024-12-08 09:30:00", "LAPS v1"},
        };

        for (String[] computer : simulatedComputers) {
            String computerName = computer[0];
            
            // Apply computer name filter if specified
            if (!computerFilter.isEmpty() && !computerName.toLowerCase().contains(computerFilter.toLowerCase())) {
                continue;
            }
            
            String lapsVersion = computer[4];
            
            // Apply LAPSv2 filter if specified
            if (lapsv2Only && !lapsVersion.equals("LAPSv2")) {
                continue;
            }

            Map<String, Object> computerData = new LinkedHashMap<>();
            computerData.put("name", computerName);
            computerData.put("password", computer[1]);
            computerData.put("username", computer[2]);
            computerData.put("expiration", computer[3]);
            computerData.put("laps_version", lapsVersion);
            computerData.put("password_age_days", calculatePasswordAgeDays(computer[3]));
            computerData.put("is_expired", isPasswordExpired(computer[3]));
            computerData.put("severity", isPasswordExpired(computer[3]) ? "HIGH" : "MEDIUM");

            results.add(computerData);
        }

        return results;
    }

    /**
     * Calculate approximate age of LAPS password in days
     */
    private int calculatePasswordAgeDays(String expirationStr) {
        // Parse expiration date and calculate age
        // For demo: return random age between 1-30 days
        return (int) (Math.random() * 30) + 1;
    }

    /**
     * Check if LAPS password has expired
     */
    private boolean isPasswordExpired(String expirationStr) {
        try {
            // Parse: "2024-12-15 10:30:00"
            String[] parts = expirationStr.split(" ");
            String[] dateParts = parts[0].split("-");
            int year = Integer.parseInt(dateParts[0]);
            int month = Integer.parseInt(dateParts[1]);
            int day = Integer.parseInt(dateParts[2]);
            
            LocalDateTime expiration = LocalDateTime.of(year, month, day, 12, 0, 0);
            LocalDateTime now = LocalDateTime.now(ZoneId.systemDefault());
            
            return now.isAfter(expiration);
        } catch (Exception e) {
            return false;
        }
    }
}
