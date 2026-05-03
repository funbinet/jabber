package com.jabber.jabber.modules.reconnaissance.emailverify;

import com.jabber.jabber.data.model.ModuleResult;
import com.jabber.jabber.data.model.TaskContext;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * EmailVerifierEngine — Hardcore 4-Step OSINT & Breach Engine.
 */
public class EmailVerifierEngine {

    private static final String MODULE_ID = "recon-email-verify";
    private final ToolManager toolManager;

    public EmailVerifierEngine(ToolManager toolManager) {
        this.toolManager = toolManager;
    }

    public ModuleResult execute(Map<String, String> input, TaskContext ctx) {
        String modeRaw = input.getOrDefault("mode", "PROB").toUpperCase().trim();
        String targetInput = input.getOrDefault("domain", input.getOrDefault("email", input.getOrDefault("username", "unknown")));
        List<String> selectedTools = input.containsKey("selectedTools")
            ? (input.get("selectedTools").isBlank() ? new ArrayList<>() : Arrays.asList(input.get("selectedTools").split(",")))
            : new ArrayList<>();
        
        ModuleResult result = new ModuleResult(ctx.getTaskId(), MODULE_ID);
        result.setTarget(targetInput);

        if (selectedTools.isEmpty() || (selectedTools.size() == 1 && selectedTools.get(0).isBlank())) {
            result.fail("[Must select a tool for execution]");
            return result;
        }

        if (targetInput == null || targetInput.isBlank() || "unknown".equalsIgnoreCase(targetInput)) {
            result.fail("[Input required for execution]");
            return result;
        }
        long startedAt = System.currentTimeMillis();
        List<CommandRecord> allRecords = new ArrayList<>();
        List<Map<String, Object>> allFindings = new ArrayList<>();

        try {
            // ── Step 1: Validate Mode ──
            ctx.log("[*] Step 1/8 — Validating execution mode...");
            List<String> validModes = List.of("PROB", "HUNT", "SOCI", "BRCH", "SMTP");
            if (!validModes.contains(modeRaw)) {
                result.fail("Unsupported mode: " + modeRaw);
                return result;
            }
            ctx.log("[+] Mode validated: " + modeRaw);
            ctx.reportProgress(5);

            // ── Step 2: Sanitize Schema ──
            ctx.log("[*] Step 2/8 — Sanitizing inputs...");
            String domain = "";
            String email = "";
            String username = "";

            if ("PROB".equals(modeRaw) || "SMTP".equals(modeRaw)) domain = InputSanitizer.validateDomain(input.getOrDefault("domain", ""));
            if ("HUNT".equals(modeRaw) || "BRCH".equals(modeRaw) || "SMTP".equals(modeRaw)) email = InputSanitizer.validateEmail(input.getOrDefault("email", ""));
            if ("SOCI".equals(modeRaw)) username = InputSanitizer.validateUsername(input.getOrDefault("username", ""));

            // ── Step 3: Target Intelligence ──
            ctx.log("[*] Step 3/8 — Target intelligence...");
            Map<String, Object> intelligence = new LinkedHashMap<>();
            if (!domain.isBlank()) intelligence.put("domain", domain);
            if (!email.isBlank()) intelligence.put("email", email);
            if (!username.isBlank()) intelligence.put("username", username);
            ctx.reportProgress(20);

            // ── Step 4: Tool Readiness ──
            ctx.log("[*] Step 4/8 — Verifying tool arsenal readiness...");
            Map<String, String> toolPaths = new LinkedHashMap<>();
            for (ToolManager.ToolDefinition def : toolManager.getRequiredTools()) {
                ToolManager.ToolStatus status = toolManager.getToolStatus(def.id);
                if (status.isInstalled()) toolPaths.put(def.id, status.getPath());
                else ctx.log("[~] Tool missing: " + def.id);
            }
            ctx.reportProgress(30);

            // ── Step 5 & 6: Dynamic Command Pipeline Orchestration ──
            ctx.log("[*] Step 5/8 — Executing pipeline for mode " + modeRaw + "...");
            switch (modeRaw) {
                case "PROB": executeProbePipeline(domain, toolPaths, selectedTools, ctx, allRecords, allFindings); break;
                case "HUNT": executeHuntPipeline(email, toolPaths, selectedTools, ctx, allRecords, allFindings); break;
                case "SOCI": executeSocialPipeline(username, toolPaths, selectedTools, ctx, allRecords, allFindings); break;
                case "BRCH": executeBreachPipeline(email, toolPaths, selectedTools, ctx, allRecords, allFindings); break;
                case "SMTP": executeSmtpPipeline(email, domain, toolPaths, selectedTools, ctx, allRecords, allFindings); break;
            }
            ctx.reportProgress(85);

            // ── Step 7: Findings Extraction ──
            ctx.log("[*] Step 7/8 — Aggregating findings...");
            for (Map<String, Object> finding : allFindings) {
                result.addFinding(finding);
            }

            // ── Step 8: Full Telemetry ──
            ctx.log("[*] Step 8/8 — Recording telemetry...");
            ReportGenerator reportGenerator = new ReportGenerator();
            
            String displayTarget = domain;
            if (displayTarget.isBlank()) {
                if (!email.isBlank()) displayTarget = email;
                else displayTarget = username;
            }

            ReportGenerator.ReportPayload payload = reportGenerator.buildReport(
                modeRaw, displayTarget, 
                allRecords, allFindings, intelligence, startedAt
            );
            result.setNormalizedOutput(payload.normalizedOutput);
            result.complete(payload.output);

            ctx.log("[+] EmailVerifier completed: " + allFindings.size() + " findings extracted.");
            ctx.reportProgress(100);

        } catch (java.util.concurrent.CancellationException e) {
            ctx.log("[!] Execution cancelled by user.");
            throw e;
        } catch (Exception e) {
            result.fail("Execution failed: " + e.getMessage());
            ctx.log("[!] FATAL: " + e.getMessage());
        }

        return result;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  PIPELINES
    // ═══════════════════════════════════════════════════════════════════

    private void executeProbePipeline(String domain, Map<String, String> tools, List<String> selectedTools, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {
        if (shouldRun("curl", selectedTools) && tools.containsKey("curl")) {
            ctx.log("[*] Executing cURL landing page scrape for " + domain + "...");
            CommandRecord rec = ProcessExecutor.execute("curl", tools.get("curl"), List.of("-sL", "https://" + domain, "--max-time", "15"), 20000, ctx, null, null);
            records.add(rec);
            if (rec.exitCode == 0) findings.addAll(parseCorporateEmails(domain, rec.stdout, "cURL Scrape"));
        }

        if (shouldRun("katana", selectedTools) && tools.containsKey("katana")) {
            ctx.log("[*] Executing Katana mailto crawler...");
            CommandRecord rec = ProcessExecutor.execute("katana", tools.get("katana"), 
                List.of("-u", "https://" + domain, "-jc", "-d", "2", "-fs", "rdn", "-em", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"), 60000, ctx, null, null);
            records.add(rec);
            if (rec.stdout != null && !rec.stdout.isBlank()) {
                findings.addAll(parseCorporateEmails(domain, rec.stdout, "Katana Crawler"));
            }
        }

        if (shouldRun("recon-ng", selectedTools) && tools.containsKey("recon-ng")) {
            ctx.log("[*] Executing recon-ng contact extraction...");
            CommandRecord rec = ProcessExecutor.execute("recon-ng", tools.get("recon-ng"), 
                List.of("-w", "jabber_recon", "-r", "echo 'modules load recon/domains-contacts/whois_pwned\nset source " + domain + "\nrun\nshow contacts\nexit'"), 60000, ctx, null, null);
            records.add(rec);
            findings.addAll(parseCorporateEmails(domain, rec.stdout, "Recon-ng"));
        }
    }

    private void executeHuntPipeline(String email, Map<String, String> tools, List<String> selectedTools, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {
        if (shouldRun("emailrep", selectedTools) && tools.containsKey("emailrep")) {
            ctx.log("[*] Executing EmailRep profiling...");
            CommandRecord rec = ProcessExecutor.execute("emailrep", tools.get("emailrep"), List.of(email), 20000, ctx, null, null);
            records.add(rec);
            if (rec.exitCode == 0) findings.add(parseEmailRep(email, rec.stdout));
        }
    }

    private void executeSocialPipeline(String username, Map<String, String> tools, List<String> selectedTools, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {
        if (shouldRun("sherlock", selectedTools) && tools.containsKey("sherlock")) {
            ctx.log("[*] Executing Sherlock username hunt for " + username + "...");
            CommandRecord rec = ProcessExecutor.execute("sherlock", tools.get("sherlock"), List.of("--timeout", "5", "--no-color", username), 300000, ctx, null, null);
            records.add(rec);
            if (rec.exitCode == 0) findings.addAll(parseSherlockProfiles(rec.stdout));
        }

        if (shouldRun("maigret", selectedTools) && tools.containsKey("maigret")) {
            ctx.log("[*] Executing Maigret dossier building on: " + username + "...");
            CommandRecord rec = ProcessExecutor.execute("maigret", tools.get("maigret"), List.of(username, "--timeout", "5", "--no-color", "--json", "simple"), 300000, ctx, null, null);
            records.add(rec);
            if (rec.exitCode == 0) findings.addAll(parseMaigretProfiles(rec.stdout));
        }
    }

    private void executeBreachPipeline(String email, Map<String, String> tools, List<String> selectedTools, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {
        if (shouldRun("holehe", selectedTools) && tools.containsKey("holehe")) {
            ctx.log("[*] Executing Holehe account checks for " + email + "...");
            CommandRecord rec = ProcessExecutor.execute("holehe", tools.get("holehe"), List.of("--only-used", email), 60000, ctx, null, null);
            records.add(rec);
            if (rec.exitCode == 0) findings.addAll(parseHoleheAccounts(email, rec.stdout));
        }

        if (shouldRun("h8mail", selectedTools) && tools.containsKey("h8mail")) {
            ctx.log("[*] Executing h8mail breach hunting for " + email + "...");
            CommandRecord rec = ProcessExecutor.execute("h8mail", tools.get("h8mail"), List.of("-t", email), 60000, ctx, null, null);
            records.add(rec);
            if (rec.exitCode == 0) findings.addAll(parseH8mailBreaches(email, rec.stdout));
        }

        if (shouldRun("ignorant", selectedTools) && tools.containsKey("ignorant")) {
            ctx.log("[*] Executing Ignorant platform hunt for " + email + "...");
            CommandRecord rec = ProcessExecutor.execute("ignorant", tools.get("ignorant"), List.of(email), 30000, ctx, null, null);
            records.add(rec);
            if (rec.exitCode == 0) findings.addAll(parseIgnorantResults(email, rec.stdout));
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  PARSERS
    // ═══════════════════════════════════════════════════════════════════

    private List<Map<String, Object>> parseCorporateEmails(String domain, String stdout, String source) {
        List<Map<String, Object>> findings = new ArrayList<>();
        if (stdout == null || stdout.isBlank()) return findings;

        Pattern p = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
        Matcher m = p.matcher(stdout);
        Set<String> uniqueEmails = new HashSet<>();
        
        while (m.find()) {
            String email = m.group().toLowerCase().trim();
            if (uniqueEmails.add(email)) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("type", "corporate_email");
                f.put("domain", domain);
                f.put("email", email);
                f.put("source", source);
                findings.add(f);
            }
        }
        return findings;
    }

    private Map<String, Object> parseEmailRep(String email, String stdout) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("type", "email_reputation");
        f.put("email", email);
        
        Matcher rep = Pattern.compile("Reputation:\\s*(.*)").matcher(stdout);
        f.put("reputation", rep.find() ? rep.group(1).trim() : "Unknown");
        
        Matcher susp = Pattern.compile("Suspicious:\\s*(.*)").matcher(stdout);
        f.put("suspicious", susp.find() ? susp.group(1).trim() : "Unknown");
        
        return f;
    }

    private List<Map<String, Object>> parseMaigretProfiles(String stdout) {
        List<Map<String, Object>> findings = new ArrayList<>();
        if (stdout == null || stdout.isBlank()) return findings;

        Pattern p = Pattern.compile("\\[\\+\\]\\s+([^:]+):\\s+(https?://\\S+)");
        Matcher m = p.matcher(stdout);
        while (m.find()) {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("type", "persona_profile");
            f.put("platform", m.group(1).trim());
            f.put("url", m.group(2).trim());
            f.put("status", "Confirmed");
            findings.add(f);
        }
        return findings;
    }

    private List<Map<String, Object>> parseSherlockProfiles(String stdout) {
        List<Map<String, Object>> findings = new ArrayList<>();
        if (stdout == null || stdout.isBlank()) return findings;

        Pattern p = Pattern.compile("\\[\\+\\]\\s+([^:]+):\\s+(https?://\\S+)");
        Matcher m = p.matcher(stdout);
        while (m.find()) {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("type", "persona_profile");
            f.put("platform", m.group(1).trim());
            f.put("url", m.group(2).trim());
            f.put("status", "Confirmed (Sherlock)");
            findings.add(f);
        }
        return findings;
    }

    private List<Map<String, Object>> parseHoleheAccounts(String email, String stdout) {
        List<Map<String, Object>> findings = new ArrayList<>();
        if (stdout == null) return findings;
        
        String[] lines = stdout.split("\\n");
        for (String line : lines) {
            if (line.contains("[+]")) {
                Matcher m = Pattern.compile("\\[\\+\\]\\s*(.*)").matcher(line);
                if (m.find()) {
                    Map<String, Object> f = new LinkedHashMap<>();
                    f.put("type", "registered_account");
                    f.put("email", email);
                    f.put("platform", m.group(1).trim());
                    f.put("status", "Registered");
                    findings.add(f);
                }
            }
        }
        return findings;
    }

    private List<Map<String, Object>> parseH8mailBreaches(String email, String stdout) {
        List<Map<String, Object>> findings = new ArrayList<>();
        if (stdout != null && stdout.contains("Found")) {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("type", "data_breach");
            f.put("email", email);
            f.put("source", "H8mail Aggregator");
            f.put("details", "Credential leak detected in public databases");
            findings.add(f);
        }
        return findings;
    }

    private List<Map<String, Object>> parseIgnorantResults(String email, String stdout) {
        List<Map<String, Object>> findings = new ArrayList<>();
        if (stdout == null) return findings;

        String[] platforms = {"Snapchat", "Instagram", "Microsoft", "Yahoo"};
        for (String p : platforms) {
            if (stdout.contains(p) && stdout.contains("is used")) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("type", "registered_account");
                f.put("email", email);
                f.put("platform", p);
                f.put("status", "Registered");
                findings.add(f);
            }
        }
        return findings;
    }

    private void executeSmtpPipeline(String email, String domain, Map<String, String> tools, List<String> selectedTools, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {
        ctx.log("[*] Phase 1/2: SMTP Relay & Delivery check (swaks)...");
        if (shouldRun("swaks", selectedTools) && tools.containsKey("swaks")) {
            CommandRecord rec = ProcessExecutor.execute("swaks", tools.get("swaks"), List.of("--to", email, "--server", domain, "--quit-after", "RCPT"), 30000, ctx, null, null);
            records.add(rec);
        }

        ctx.log("[*] Phase 2/2: SMTP Vulnerability Scanning (nmap)...");
        if (shouldRun("nmap", selectedTools) && tools.containsKey("nmap")) {
            CommandRecord rec = ProcessExecutor.execute("nmap", tools.get("nmap"), List.of("-p", "25,465,587", "--script=smtp-commands,smtp-open-relay", domain), 60000, ctx, null, null);
            records.add(rec);
        }
    }


    private boolean shouldRun(String toolId, List<String> selectedTools) {
        if (selectedTools.isEmpty()) return false;
        if (selectedTools.size() == 1 && selectedTools.get(0).isEmpty()) return false;
        return selectedTools.contains(toolId);
    }
}
