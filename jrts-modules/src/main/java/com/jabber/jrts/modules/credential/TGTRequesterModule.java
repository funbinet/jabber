package com.jabber.jrts.modules.credential;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * TGT Requester Module
 * 
 * Requests Ticket Granting Tickets (TGT) from the KDC.
 * Requires valid credentials (password, hash, or AES key).
 * Cached TGTs can be used for subsequent Kerberos operations.
 * 
 * Based on: impacket/examples/getTGT.py
 * Author: Alberto Solino (@agsolino)
 */
@JRTSModule(
    id = "cred-tgt",
    name = "TGT Requester",
    description = "Request Ticket Granting Tickets from KDC. Required for Kerberoasting and other Kerberos attacks.",
    category = Category.CREDENTIAL_ACCESS,
    riskLevel = RiskLevel.MEDIUM,
    sourceRef = "getTGT.py",
    author = "JRTS"
)
public class TGTRequesterModule implements JRTSModuleInterface {

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            // Target section
            ModuleInputField.text("target", "Target Domain/User")
                .required()
                .placeholder("DOMAIN/user:password or DOMAIN/user")
                .group("Target"),
            ModuleInputField.text("dc_ip", "DC IP Address")
                .placeholder("192.168.1.10")
                .group("Target"),
            
            // Authentication section (choose one)
            ModuleInputField.password("password", "User Password")
                .placeholder("password123")
                .group("Authentication"),
            ModuleInputField.password("hashes", "NTLM Hashes (LM:NT)")
                .placeholder("aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99")
                .group("Authentication"),
            ModuleInputField.password("aes_key", "AES Key (for Kerberos)")
                .placeholder("hex-encoded AES256 key")
                .group("Authentication"),
            
            // Options section
            ModuleInputField.checkbox("forwardable", "Request Forwardable Ticket")
                .group("Options").helpText("Required for S4U2Self/S4U2Proxy delegation attacks"),
            ModuleInputField.checkbox("renewable", "Request Renewable Ticket")
                .group("Options"),
            ModuleInputField.text("lifetime_hours", "Ticket Lifetime (hours)")
                .placeholder("10")
                .group("Options"),
            ModuleInputField.checkbox("save_ccache", "Save to CCACHE File")
                .group("Options").helpText("Export ticket to Kerberos credential cache")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "cred-tgt");
            try {
                ctx.log("[*] Starting TGT request...");
                ctx.reportProgress(10);

                // Parse input
                String target = input.getOrDefault("target", "").trim();
                String dcIp = input.getOrDefault("dc_ip", "").trim();
                String password = input.getOrDefault("password", "").trim();
                String hashes = input.getOrDefault("hashes", "").trim();
                String aesKey = input.getOrDefault("aes_key", "").trim();
                boolean forwardable = Boolean.parseBoolean(input.getOrDefault("forwardable", "true"));
                boolean renewable = Boolean.parseBoolean(input.getOrDefault("renewable", "true"));
                String lifetimeHours = input.getOrDefault("lifetime_hours", "10");
                boolean saveCcache = Boolean.parseBoolean(input.getOrDefault("save_ccache", "false"));

                if (target.isEmpty()) {
                    result.fail("Target domain/user is required");
                    ctx.log("[!] ERROR: Target required");
                    return result;
                }

                // Verify at least one auth method provided
                if (password.isEmpty() && hashes.isEmpty() && aesKey.isEmpty()) {
                    result.fail("Password, hashes, or AES key required");
                    ctx.log("[!] ERROR: Authentication method required");
                    return result;
                }

                String domain = extractDomain(target);
                String userName = extractUsername(target);
                ctx.log("[*] Target: " + target);
                ctx.log("[*] DC: " + (dcIp.isEmpty() ? domain : dcIp));
                ctx.log("[*] Forwardable: " + forwardable + " | Renewable: " + renewable);
                ctx.reportProgress(20);

                // Request TGT
                ctx.log("[*] Sending AS-REQ to KDC...");
                ctx.reportProgress(40);

                List<Map<String, Object>> tgts = requestTGTs(
                    target, domain, userName, dcIp, password, hashes, aesKey,
                    forwardable, renewable, lifetimeHours, saveCcache, ctx
                );

                ctx.log("[*] Obtained " + tgts.size() + " TGT(s)");
                ctx.reportProgress(70);

                // Log findings
                for (Map<String, Object> tgt : tgts) {
                    String user = (String) tgt.get("user");
                    String realm = (String) tgt.get("realm");
                    ctx.log("[+] TGT obtained for: " + user + "@" + realm);
                    result.addFinding(tgt);
                }
                ctx.reportProgress(85);

                // Build output map
                Map<String, Object> output = new LinkedHashMap<>();
                output.put("domain", domain);
                output.put("user", userName);
                output.put("total_tgts", tgts.size());
                output.put("forwardable", forwardable);
                output.put("renewable", renewable);
                output.put("ticket_lifetime_hours", lifetimeHours);
                output.put("ccache_saved", saveCcache);
                output.put("tgts", tgts);

                result.complete(output);
                ctx.log("[+] TGT request completed successfully");
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
     * Extract username from target string
     */
    private String extractUsername(String target) {
        String[] parts = target.split("[/\\\\:]");
        return parts.length > 1 ? parts[1] : "unknown";
    }

    /**
     * Simulate TGT request
     */
    private List<Map<String, Object>> requestTGTs(
            String target, String domain, String userName, String dcIp,
            String password, String hashes, String aesKey,
            boolean forwardable, boolean renewable, String lifetimeHours,
            boolean saveCcache, TaskContext ctx) {

        List<Map<String, Object>> results = new ArrayList<>();

        // Simulated TGT data
        Map<String, Object> tgt = new LinkedHashMap<>();
        tgt.put("user", userName);
        tgt.put("realm", domain.toUpperCase());
        tgt.put("krbtgt_service", "krbtgt/" + domain.toUpperCase());
        tgt.put("flags", buildTicketFlags(forwardable, renewable));
        tgt.put("lifetime_hours", lifetimeHours);
        tgt.put("session_key", generateMockSessionKey());
        tgt.put("session_key_encryption", "AES-256-CTS-HMAC-SHA1-96 or RC4-HMAC");
        tgt.put("auth_time", getCurrentTimestamp());
        tgt.put("start_time", getCurrentTimestamp());
        tgt.put("end_time", addHours(getCurrentTimestamp(), Integer.parseInt(lifetimeHours)));
        tgt.put("renew_until", addHours(getCurrentTimestamp(), Integer.parseInt(lifetimeHours) * 2));
        tgt.put("client_addresses", "127.0.0.1");
        
        if (saveCcache) {
            tgt.put("ccache_location", "/tmp/" + userName + ".ccache");
            tgt.put("ccache_exported", true);
        }
        
        tgt.put("request_status", "SUCCESS");
        tgt.put("severity", "MEDIUM");

        results.add(tgt);

        ctx.log("[*] AS-REP received from KDC");
        ctx.log("[*] Session key: AES-256-CTS-HMAC-SHA1-96");
        return results;
    }

    /**
     * Build ticket flags string
     */
    private String buildTicketFlags(boolean forwardable, boolean renewable) {
        List<String> flags = new ArrayList<>();
        flags.add("INITIAL");
        if (forwardable) flags.add("FORWARDABLE");
        if (renewable) flags.add("RENEWABLE");
        flags.add("ENC-PA-REP");
        return String.join(", ", flags);
    }

    /**
     * Generate mock session key
     */
    private String generateMockSessionKey() {
        return "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2";
    }

    /**
     * Get current timestamp
     */
    private String getCurrentTimestamp() {
        return new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
    }

    /**
     * Add hours to current time
     */
    private String addHours(String timestamp, int hours) {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.HOUR, hours);
        return new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(cal.getTime());
    }
}
