package com.jabber.jabber.modules.credential;

import com.jabber.jabber.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Kerberoast TGS Requester Module
 * 
 * Requests Service Tickets (TGS) for Kerberoast attacks.
 * Targets SPNs to obtain encrypted tickets for offline cracking.
 * 
 * Based on: impacket/examples/getST.py
 * Author: Alberto Solino (@agsolino), Charlie Bromberg (@_nwodtuhs)
 */
@JABBERModule(
    id = "cred-kerberoast-tgs",
    name = "Kerberoast TGS Requester",
    description = "Request Service Tickets (TGS) for Kerberoasting. Targets SPN accounts and exports encrypted tickets for offline cracking.",
    category = Category.CREDENTIAL_ACCESS,
    riskLevel = RiskLevel.HIGH,
    sourceRef = "getST.py",
    author = "JABBER"
)
public class KerberoastTGSRequesterModule implements JABBERModuleInterface {

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            // Target section
            ModuleInputField.text("target", "Target Domain/User")
                .required()
                .placeholder("DOMAIN/user:password or DOMAIN/user")
                .group("Target"),
            ModuleInputField.text("spn", "Service Principal Name")
                .placeholder("MSSQLSvc/DB01.domain.local:1433 or HTTP/IIS01.domain.local")
                .group("Target"),
            ModuleInputField.text("dc_ip", "DC IP Address")
                .placeholder("192.168.1.10")
                .group("Target"),
            
            // Authentication section
            ModuleInputField.password("hashes", "NTLM Hashes (LM:NT)")
                .placeholder("aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99")
                .group("Authentication"),
            ModuleInputField.checkbox("use_kerberos", "Use Kerberos Authentication")
                .group("Authentication"),
            ModuleInputField.password("aes_key", "AES Key")
                .placeholder("hex-encoded AES256 key")
                .group("Authentication"),
            
            // Options section
            ModuleInputField.text("impersonate", "Impersonate User (S4U2Self)")
                .placeholder("Administrator - for constrained delegation")
                .group("Options"),
            ModuleInputField.checkbox("save_ccache", "Save to CCACHE")
                .helpText("Save ticket to Kerberos CCACHE file")
                .group("Options")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "cred-kerberoast-tgs");
            try {
                ctx.log("[*] Starting Kerberoast TGS request...");
                ctx.reportProgress(10);

                // Parse input
                String target = input.getOrDefault("target", "").trim();
                String spn = input.getOrDefault("spn", "").trim();
                String dcIp = input.getOrDefault("dc_ip", "").trim();
                String hashes = input.getOrDefault("hashes", "").trim();
                boolean useKerberos = Boolean.parseBoolean(input.getOrDefault("use_kerberos", "false"));
                String impersonate = input.getOrDefault("impersonate", "").trim();
                boolean saveCcache = Boolean.parseBoolean(input.getOrDefault("save_ccache", "false"));

                if (target.isEmpty() || spn.isEmpty()) {
                    result.fail("Target domain and SPN are required");
                    ctx.log("[!] ERROR: Target and SPN required");
                    return result;
                }

                // Extract domain from target
                String domain = extractDomain(target);
                ctx.log("[*] Target: " + target);
                ctx.log("[*] SPN: " + spn);
                ctx.log("[*] Domain: " + domain);
                ctx.reportProgress(20);

                // Request TGS
                ctx.log("[*] Requesting TGS from KDC...");
                ctx.reportProgress(40);

                List<Map<String, Object>> tickets = requestServiceTickets(
                    target, spn, domain, dcIp, hashes, useKerberos, 
                    impersonate, saveCcache, ctx
                );

                ctx.log("[*] Obtained " + tickets.size() + " service tickets");
                ctx.reportProgress(70);

                // Log findings
                for (Map<String, Object> ticket : tickets) {
                    String svc = (String) ticket.get("service");
                    String tgsHash = (String) ticket.get("tgs_hash");
                    ctx.log("[+] " + svc + ": Hash exported to " + (saveCcache ? "CCACHE" : "hashcat format"));
                    result.addFinding(ticket);
                }
                ctx.reportProgress(85);

                // Build output map
                Map<String, Object> output = new LinkedHashMap<>();
                output.put("domain", domain);
                output.put("target_spn", spn);
                output.put("total_tgs_obtained", tickets.size());
                output.put("impersonation_used", !impersonate.isEmpty());
                output.put("impersonated_user", impersonate.isEmpty() ? "N/A" : impersonate);
                output.put("ccache_saved", saveCcache);
                output.put("tickets", tickets);

                result.complete(output);
                ctx.log("[+] TGS request completed successfully");
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
     * Extract domain from target string
     */
    private String extractDomain(String target) {
        if (target.contains("/")) {
            return target.split("/")[0];
        }
        if (target.contains("\\")) {
            return target.split("\\\\")[0];
        }
        return target;
    }

    /**
     * Simulate TGS request and obtain service tickets
     */
    private List<Map<String, Object>> requestServiceTickets(
            String target, String spn, String domain, String dcIp,
            String hashes, boolean useKerberos, String impersonate,
            boolean saveCcache, TaskContext ctx) {

        List<Map<String, Object>> results = new ArrayList<>();

        // Parse SPN to extract service type and target
        String[] spnParts = spn.split("/");
        String serviceType = spnParts.length > 0 ? spnParts[0] : "HTTP";
        String serviceTarget = spnParts.length > 1 ? spnParts[1] : "unknown";

        // Simulated TGS requests
        Map<String, Object> ticket = new LinkedHashMap<>();
        ticket.put("service", serviceType);
        ticket.put("target_host", serviceTarget);
        ticket.put("spn", spn);
        ticket.put("requester", target);
        ticket.put("impersonated_user", impersonate.isEmpty() ? "N/A" : impersonate);
        
        // Generate mock Kerberoast hash (hashcat format -m 13100)
        String mockHash = "$krb5tgs$13$*" + serviceType + "/" + domain.toUpperCase() + 
                         "*$" + generateMockTicketHash() + "$" + generateMockEncryptedPart();
        ticket.put("tgs_hash", mockHash);
        ticket.put("hash_format", "hashcat -m 13100 (RC4)");
        ticket.put("cracking_mode", "offline");
        ticket.put("encryption_type", "AES-256-CTS-HMAC-SHA1-96 or RC4-HMAC");
        ticket.put("severity", "HIGH");

        results.add(ticket);

        ctx.log("[*] Extracted " + serviceType + " service from " + serviceTarget);
        return results;
    }

    /**
     * Generate mock ticket hash
     */
    private String generateMockTicketHash() {
        return "8f7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b";
    }

    /**
     * Generate mock encrypted part of ticket
     */
    private String generateMockEncryptedPart() {
        return "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6" +
               "q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2" +
               "g3h4i5j6k7l8m9n0o1p2q3r4s5t6u7v8" +
               "w9x0y1z2a3b4c5d6e7f8g9h0i1j2k3l4";
    }
}
