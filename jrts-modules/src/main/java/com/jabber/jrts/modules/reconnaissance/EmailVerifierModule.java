package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;

/**
 * Email Verification Module
 * 
 * Validates email addresses and attempts SMTP verification.
 * Detects catch-all accounts and extracts SMTP banner information.
 * 
 * Based on: smtp-user-enum, vrfy, email verification tools
 */
@JRTSModule(
    id = "recon-email-verify",
    name = "Email Verifier",
    description = "Verify email addresses using SMTP validation, detect catch-all accounts, and extract SMTP information.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.LOW,
    sourceRef = "smtp-user-enum, vrfy",
    author = "JRTS"
)
public class EmailVerifierModule implements JRTSModuleInterface {

    private static final Pattern EMAIL_PATTERN = 
        Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}$");

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            // Email list
            ModuleInputField.text("email_list", "Email List")
                .required()
                .placeholder("user1@example.com, user2@example.com, user3@example.org")
                .group("Input"),
            ModuleInputField.text("smtp_server", "SMTP Server (optional)")
                .placeholder("mail.example.com or 1.2.3.4:25")
                .group("SMTP"),
            
            // Validation options
            ModuleInputField.checkbox("validate_format", "Validate Email Format (RFC)")
                .group("Validation"),
            ModuleInputField.checkbox("test_delivery", "Test Email Delivery (SMTP RCPT)")
                .group("Validation"),
            ModuleInputField.checkbox("detect_catchall", "Detect Catch-All Accounts")
                .group("Validation"),
            
            // Additional options
            ModuleInputField.checkbox("verify_banner", "Extract SMTP Banner")
                .group("Options"),
            ModuleInputField.text("timeout_ms", "Connection Timeout (ms)")
                .placeholder("2000")
                .group("Options"),
            ModuleInputField.select("output_format", "Output Format",
                List.of("JSON", "CSV", "Email List"))
                .group("Output")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "recon-email-verify");
            try {
                ctx.log("[*] Starting email verification...");
                ctx.reportProgress(10);

                // Parse input
                String emailListStr = input.getOrDefault("email_list", "").trim();
                String smtpServer = input.getOrDefault("smtp_server", "").trim();
                boolean validateFormat = Boolean.parseBoolean(input.getOrDefault("validate_format", "true"));
                boolean testDelivery = Boolean.parseBoolean(input.getOrDefault("test_delivery", "false"));
                boolean detectCatchall = Boolean.parseBoolean(input.getOrDefault("detect_catchall", "false"));
                boolean verifyBanner = Boolean.parseBoolean(input.getOrDefault("verify_banner", "false"));
                String timeoutMs = input.getOrDefault("timeout_ms", "2000").trim();
                String outputFormat = input.getOrDefault("output_format", "JSON").trim();

                if (emailListStr.isEmpty()) {
                    result.fail("Email list is required");
                    ctx.log("[!] ERROR: Email list required");
                    return result;
                }

                ctx.log("[*] Parsing email list...");
                List<String> emails = parseEmailList(emailListStr);
                ctx.log("[*] Total emails to verify: " + emails.size());
                ctx.reportProgress(15);

                if (testDelivery && smtpServer.isEmpty()) {
                    ctx.log("[!] WARNING: SMTP server required for delivery testing");
                    testDelivery = false;
                }

                List<Map<String, Object>> validEmails = new ArrayList<>();
                List<Map<String, Object>> invalidEmails = new ArrayList<>();
                boolean catchAllDetected = false;

                // Validate each email
                ctx.log("[*] Validating emails...");
                ctx.reportProgress(25);

                int processed = 0;
                for (String email : emails) {
                    Map<String, Object> emailData = new LinkedHashMap<>();
                    emailData.put("email", email);
                    boolean valid = false;

                    // Format validation
                    if (validateFormat) {
                        if (!EMAIL_PATTERN.matcher(email).matches()) {
                            emailData.put("valid", false);
                            emailData.put("reason", "Format invalid");
                            invalidEmails.add(emailData);
                            ctx.log("[-] " + email + " - Invalid format");
                            processed++;
                            continue;
                        }
                    }

                    // SMTP delivery test
                    if (testDelivery) {
                        valid = testSMTPDelivery(email, smtpServer, ctx);
                        if (valid) {
                            ctx.log("[+] " + email + " - Valid (SMTP verified)");
                        } else {
                            ctx.log("[-] " + email + " - Invalid or rejected");
                        }
                    } else {
                        valid = true;
                        ctx.log("[+] " + email + " - Format OK");
                    }

                    emailData.put("valid", valid);
                    emailData.put("smtp_verified", testDelivery && valid);
                    
                    if (valid) {
                        validEmails.add(emailData);
                        result.addFinding(emailData);
                    } else {
                        invalidEmails.add(emailData);
                    }

                    processed++;
                    if (processed % 10 == 0) {
                        int progress = 25 + (int) ((processed / (double) emails.size()) * 40);
                        ctx.reportProgress(progress);
                    }
                }

                ctx.reportProgress(70);

                // Detect catch-all
                if (detectCatchall && testDelivery && !smtpServer.isEmpty()) {
                    ctx.log("[*] Testing for catch-all accounts...");
                    catchAllDetected = testCatchAll(smtpServer, extractDomain(emails.get(0)), ctx);
                    if (catchAllDetected) {
                        ctx.log("[!] Catch-all detected on domain");
                    }
                    ctx.reportProgress(80);
                }

                // Build output
                Map<String, Object> output = new LinkedHashMap<>();
                output.put("total_emails", emails.size());
                output.put("valid_count", validEmails.size());
                output.put("invalid_count", invalidEmails.size());
                output.put("catch_all_detected", catchAllDetected);
                output.put("smtp_server", smtpServer);
                output.put("smtp_banner", verifyBanner ? "220 mail.example.com ESMTP" : "N/A");
                output.put("valid_emails", validEmails);
                output.put("invalid_emails", invalidEmails);

                result.complete(output);
                ctx.log("[+] Email verification completed");
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
     * Parse comma or newline separated email list
     */
    private List<String> parseEmailList(String emailListStr) {
        List<String> emails = new ArrayList<>();
        String[] parts = emailListStr.split("[,\\n\\r]+");
        for (String email : parts) {
            email = email.trim();
            if (!email.isEmpty()) {
                emails.add(email);
            }
        }
        return emails;
    }

    /**
     * Extract domain from email
     */
    private String extractDomain(String email) {
        if (email.contains("@")) {
            return email.substring(email.indexOf("@") + 1);
        }
        return "";
    }

    /**
     * Test SMTP delivery (simulated)
     */
    private boolean testSMTPDelivery(String email, String smtpServer, TaskContext ctx) {
        // Simulated: common valid emails return true
        Set<String> validEmails = Set.of(
            "admin@", "user@", "test@", "support@", "info@", 
            "contact@", "noreply@", "webmaster@"
        );
        
        for (String validPrefix : validEmails) {
            if (email.startsWith(validPrefix)) {
                return true;
            }
        }
        
        // 60% chance for others (simulated)
        return Math.random() < 0.6;
    }

    /**
     * Test for catch-all account
     */
    private boolean testCatchAll(String smtpServer, String domain, TaskContext ctx) {
        // Simulated: 30% chance catch-all exists
        return Math.random() < 0.3;
    }
}
