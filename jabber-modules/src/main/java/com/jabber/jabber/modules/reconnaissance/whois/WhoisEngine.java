package com.jabber.jabber.modules.reconnaissance.whois;

import com.jabber.jabber.data.model.ModuleResult;
import com.jabber.jabber.data.model.TaskContext;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WhoisEngine — Hardcore 8-Step Execution Doctrine Implementation.
 */
public class WhoisEngine {

    private static final String MODULE_ID = "recon-whois";
    private final ToolManager toolManager;

    public WhoisEngine(ToolManager toolManager) {
        this.toolManager = toolManager;
    }

    public ModuleResult execute(Map<String, String> input, TaskContext ctx) {
        String modeRaw = input.getOrDefault("mode", "RECO").toUpperCase().trim();
        String targetInput = input.getOrDefault("target", input.getOrDefault("handle", input.getOrDefault("email", input.getOrDefault("asn", "unknown"))));
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
            List<String> validModes = List.of("RECO", "ASST", "BGPR", "CORP", "PERS", "BRCH");
            if (!validModes.contains(modeRaw)) {
                result.fail("Unsupported mode: " + modeRaw);
                return result;
            }
            ctx.log("[+] Mode validated: " + modeRaw);
            ctx.reportProgress(5);

            // ── Step 2: Sanitize Schema ──
            ctx.log("[*] Step 2/8 — Sanitizing inputs...");
            String target = "";
            String cidr = "";
            String asn = "";
            String handle = "";
            String email = "";

            if ("RECO".equals(modeRaw) || "ASST".equals(modeRaw) || "CORP".equals(modeRaw)) target = InputSanitizer.validateTarget(input.getOrDefault("target", ""));
            if ("ASST".equals(modeRaw)) cidr = input.getOrDefault("cidr", "");
            if ("BGPR".equals(modeRaw)) asn = InputSanitizer.validateAsn(input.getOrDefault("asn", ""));
            if ("PERS".equals(modeRaw)) handle = InputSanitizer.validateHandle(input.getOrDefault("handle", ""));
            if ("BRCH".equals(modeRaw)) email = InputSanitizer.validateEmail(input.getOrDefault("email", ""));

            // ── Step 3: Target Intelligence ──
            ctx.log("[*] Step 3/8 — Target intelligence...");
            Map<String, Object> intelligence = new LinkedHashMap<>();
            intelligence.put("target", target);
            if (!asn.isBlank()) intelligence.put("asn", asn);
            if (!handle.isBlank()) intelligence.put("handle", handle);
            if (!email.isBlank()) intelligence.put("email", email);
            ctx.reportProgress(20);

            // ── Step 4: Tool Readiness ──
            ctx.log("[*] Step 4/8 — Verifying 11-tool arsenal readiness...");
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
                case "RECO": executeReconPipeline(target, toolPaths, selectedTools, ctx, allRecords, allFindings); break;
                case "ASST": executeAssetPipeline(target, cidr, toolPaths, selectedTools, ctx, allRecords, allFindings); break;
                case "BGPR": executeBgpPipeline(asn, toolPaths, selectedTools, ctx, allRecords, allFindings); break;
                case "CORP": executeCorpPipeline(target, toolPaths, selectedTools, ctx, allRecords, allFindings); break;
                case "PERS": executePersonaPipeline(handle, toolPaths, selectedTools, ctx, allRecords, allFindings); break;
                case "BRCH": executeBreachPipeline(email, toolPaths, selectedTools, ctx, allRecords, allFindings); break;
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
            
            String displayTarget = target;
            if (displayTarget.isBlank()) {
                if (!email.isBlank()) displayTarget = email;
                else if (!handle.isBlank()) displayTarget = handle;
                else displayTarget = asn;
            }

            ReportGenerator.ReportPayload payload = reportGenerator.buildReport(
                modeRaw, displayTarget, 
                allRecords, allFindings, intelligence, startedAt
            );
            result.setNormalizedOutput(payload.normalizedOutput);
            result.complete(payload.output);

            ctx.log("[+] Whois completed: " + allFindings.size() + " findings extracted.");
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

    private void executeReconPipeline(String target, Map<String, String> tools, List<String> selectedTools, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {
        if (shouldRun("whois", selectedTools) && tools.containsKey("whois")) {
            ctx.log("[*] Executing whois...");
            CommandRecord rec = ProcessExecutor.execute("whois", tools.get("whois"), List.of(target), 20000, ctx, null, null);
            records.add(rec);
            if (rec.exitCode == 0) findings.addAll(parseWhoisInfo(target, rec.stdout));
        }
        
        if (shouldRun("shodan", selectedTools) && tools.containsKey("shodan")) {
            ctx.log("[*] Executing Shodan Host Search...");
            CommandRecord rec = ProcessExecutor.execute("shodan", tools.get("shodan"), List.of("host", target), 30000, ctx, null, null);
            records.add(rec);
            if (rec.exitCode == 0) findings.addAll(parseShodanExposure(rec.stdout));
        }

        if (shouldRun("subfinder", selectedTools) && tools.containsKey("subfinder") && tools.containsKey("dnsx")) {
            ctx.log("[*] Executing Passive Subdomain Discovery & Resolution...");
            CommandRecord sub = ProcessExecutor.execute("subfinder", tools.get("subfinder"), List.of("-d", target, "-silent"), 60000, ctx, null, null);
            records.add(sub);
            if (!sub.stdout.isBlank()) {
                // In a real high-fidelity implementation, we would pipe sub.stdout into dnsx stdin.
                // For this orchestration, we use dnsx with the subfinder results via a temporary file or argument list.
                List<String> subdomains = Arrays.asList(sub.stdout.split("\\n"));
                if (subdomains.size() > 50) subdomains = subdomains.subList(0, 50); // Limit for CLI safety
                
                List<String> dnsArgs = new ArrayList<>(List.of("-silent", "-a", "-resp"));
                for (String s : subdomains) if (!s.isBlank()) dnsArgs.addAll(List.of("-d", s));

                CommandRecord dns = ProcessExecutor.execute("dnsx", tools.get("dnsx"), dnsArgs, 45000, ctx, null, null);
                records.add(dns);
                if (dns.exitCode == 0) findings.addAll(parseDnsResolution(dns.stdout));
            }
        }
    }

    private void executeAssetPipeline(String target, String cidr, Map<String, String> tools, List<String> selectedTools, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {
        if (shouldRun("whois", selectedTools) && tools.containsKey("whois")) {
            ctx.log("[*] Verifying ownership...");
            CommandRecord rec = ProcessExecutor.execute("whois", tools.get("whois"), List.of(target), 20000, ctx, null, null);
            records.add(rec);
        }

        if (shouldRun("nmap", selectedTools) && tools.containsKey("nmap")) {
            String sweepTarget = cidr.isBlank() ? target : cidr;
            ctx.log("[*] Executing Nmap CIDR Ping Sweep on " + sweepTarget + "...");
            CommandRecord rec = ProcessExecutor.execute("nmap", tools.get("nmap"), List.of("-sn", sweepTarget), 120000, ctx, null, null);
            records.add(rec);
            if (rec.exitCode == 0) findings.addAll(parseNmapSweep(rec.stdout));
        }
    }

    private void executeBgpPipeline(String asn, Map<String, String> tools, List<String> selectedTools, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {
        if (shouldRun("whois", selectedTools) && tools.containsKey("whois")) {
            ctx.log("[*] Executing whois on ASN...");
            CommandRecord rec = ProcessExecutor.execute("whois", tools.get("whois"), List.of(asn), 20000, ctx, null, null);
            records.add(rec);
        }
        
        if (shouldRun("bgpq4", selectedTools) && tools.containsKey("bgpq4")) {
            ctx.log("[*] Generating IPv4 routing prefixes for " + asn + "...");
            CommandRecord rec = ProcessExecutor.execute("bgpq4", tools.get("bgpq4"), List.of("-A", asn), 15000, ctx, null, null);
            records.add(rec);
            if (rec.exitCode == 0) findings.addAll(parseBgpBlocks(asn, rec.stdout));
        }
    }

    private void executeCorpPipeline(String target, Map<String, String> tools, List<String> selectedTools, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {
        if (shouldRun("amass", selectedTools) && tools.containsKey("amass")) {
            ctx.log("[*] Executing Amass Intel for related corporate domains...");
            CommandRecord rec = ProcessExecutor.execute("amass", tools.get("amass"), List.of("intel", "-whois", "-d", target), 180000, ctx, null, null);
            records.add(rec);
        }
    }

    private void executePersonaPipeline(String handle, Map<String, String> tools, List<String> selectedTools, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {
        if (shouldRun("sherlock", selectedTools) && tools.containsKey("sherlock")) {
            ctx.log("[*] Executing Sherlock hunt on handle: " + handle + "...");
            CommandRecord rec = ProcessExecutor.execute("sherlock", tools.get("sherlock"), List.of("--timeout", "5", "--no-color", handle), 300000, ctx, null, null);
            records.add(rec);
            if (rec.exitCode == 0) findings.addAll(parseSherlockProfiles(rec.stdout, "Sherlock"));
        }

        if (shouldRun("maigret", selectedTools) && tools.containsKey("maigret")) {
            ctx.log("[*] Executing Maigret dossier building on: " + handle + "...");
            CommandRecord rec = ProcessExecutor.execute("maigret", tools.get("maigret"), List.of(handle, "--timeout", "5", "--no-color", "--json", "simple"), 300000, ctx, null, null);
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

    private List<Map<String, Object>> parseWhoisInfo(String domain, String stdout) {
        List<Map<String, Object>> findings = new ArrayList<>();
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("type", "whois_info");
        f.put("domain", domain);
        
        Matcher r = Pattern.compile("Registrant Organization: (.*?)\\n").matcher(stdout);
        f.put("registrant", r.find() ? r.group(1).trim() : "Redacted/Private");
        
        Matcher e = Pattern.compile("Registrant Email: (.*?)\\n").matcher(stdout);
        f.put("emails", e.find() ? e.group(1).trim() : "");
        
        findings.add(f);
        return findings;
    }

    private List<Map<String, Object>> parseBgpBlocks(String asn, String stdout) {
        List<Map<String, Object>> findings = new ArrayList<>();
        if (stdout == null) return findings;
        
        String[] lines = stdout.split("\\n");
        for (String line : lines) {
            if (line.contains("/") && line.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+.*")) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("type", "network_block");
                f.put("asn", asn);
                f.put("cidr", line.trim());
                f.put("description", "BGP Advertised Route");
                findings.add(f);
            }
        }
        return findings;
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

    private List<Map<String, Object>> parseSherlockProfiles(String stdout, String source) {
        List<Map<String, Object>> findings = new ArrayList<>();
        if (stdout == null || stdout.isBlank()) return findings;
        Pattern p = Pattern.compile("\\[\\+\\]\\s+(.*?):\\s*(https?://\\S+)");
        Matcher m = p.matcher(stdout);
        while (m.find()) {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("type", "persona_profile");
            f.put("platform", m.group(1).trim());
            f.put("url", m.group(2).trim());
            f.put("status", "Confirmed (" + source + ")");
            findings.add(f);
        }
        return findings;
    }

    private List<Map<String, Object>> parseDnsResolution(String stdout) {
        List<Map<String, Object>> findings = new ArrayList<>();
        if (stdout == null || stdout.isBlank()) return findings;
        String[] lines = stdout.split("\\n");
        for (String line : lines) {
            if (line.contains("[A]")) {
                String[] parts = line.split("\\s+");
                if (parts.length >= 3) {
                    Map<String, Object> f = new LinkedHashMap<>();
                    f.put("type", "dns_resolution");
                    f.put("host", parts[0]);
                    f.put("record_type", "A");
                    f.put("address", parts[parts.length-1]);
                    findings.add(f);
                }
            }
        }
        return findings;
    }

    private List<Map<String, Object>> parseNmapSweep(String stdout) {
        List<Map<String, Object>> findings = new ArrayList<>();
        if (stdout == null) return findings;
        Matcher m = Pattern.compile("Nmap scan report for (.*?)\\nHost is up").matcher(stdout);
        while (m.find()) {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("type", "ping_sweep");
            f.put("target", m.group(1).trim());
            f.put("status", "Up");
            findings.add(f);
        }
        return findings;
    }

    private List<Map<String, Object>> parseShodanExposure(String stdout) {
        List<Map<String, Object>> findings = new ArrayList<>();
        if (stdout == null || !stdout.contains("Ports:")) return findings;

        Map<String, Object> f = new LinkedHashMap<>();
        f.put("type", "shodan_exposure");
        f.put("ip", "Target IP");
        
        Matcher p = Pattern.compile("Ports:\\s*(.*)").matcher(stdout);
        f.put("ports", p.find() ? p.group(1).trim() : "");
        
        Matcher v = Pattern.compile("Vulnerabilities:\\s*(.*)").matcher(stdout);
        f.put("vulns", v.find() ? v.group(1).trim() : "None Detected");
        
        findings.add(f);
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

    private boolean shouldRun(String toolId, List<String> selectedTools) {
        if (selectedTools.isEmpty()) return false;
        if (selectedTools.size() == 1 && selectedTools.get(0).isEmpty()) return false;
        return selectedTools.contains(toolId);
    }
}
