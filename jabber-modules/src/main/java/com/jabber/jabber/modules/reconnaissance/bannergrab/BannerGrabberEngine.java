package com.jabber.jabber.modules.reconnaissance.bannergrab;

import com.jabber.jabber.data.model.ModuleResult;
import com.jabber.jabber.data.model.TaskContext;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * BannerGrabberEngine — 8-Step Execution Doctrine Implementation.
 *
 * Modes:
 *   FINGER — Total technology stack identification and vulnerability correlation.
 *            Pipeline: nmap -sV → whatweb → searchsploit → httpx → dnsx
 *   INFRA  — Full infrastructure mapping and attribution.
 *            Pipeline: subfinder → dnsx → whois → dig ANY → httpx
 *
 * Dynamic Tool-Selection: Only tools explicitly selected by the user via
 * the frontend toggles are executed. The selectedTools list directly controls
 * which commands run.
 */
public class BannerGrabberEngine {

    private static final String MODULE_ID = "recon-banner-grab";
    private static final long DEFAULT_TIMEOUT_MS = 120_000L;

    private final ToolManager toolManager;

    public BannerGrabberEngine(ToolManager toolManager) {
        this.toolManager = toolManager;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  MAIN EXECUTION — 8-Step Doctrine
    // ═══════════════════════════════════════════════════════════════════

    public ModuleResult execute(Map<String, String> input, TaskContext ctx) {
        String targetInput = input.getOrDefault("target", "unknown");
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
            String modeRaw = input.getOrDefault("mode", "FINGER").toUpperCase().trim();
            if (!"FINGER".equals(modeRaw) && !"INFRA".equals(modeRaw)) {
                result.fail("Unsupported mode: " + modeRaw + ". Valid modes: FINGER, INFRA.");
                ctx.log("[!] Invalid mode: " + modeRaw);
                return result;
            }
            ctx.log("[+] Mode validated: " + modeRaw);
            ctx.reportProgress(5);

            // ── Step 2: Sanitize Schema ──
            ctx.log("[*] Step 2/8 — Sanitizing inputs...");
            String target = input.getOrDefault("target", "").trim();
            String domain = input.getOrDefault("domain", "").trim();
            long timeoutMs = parseTimeout(input.getOrDefault("timeout", "120"));

            if ("FINGER".equals(modeRaw) && target.isEmpty()) {
                result.fail("FINGER mode requires 'target' (host/IP).");
                ctx.log("[!] Validation failed: target is required for FINGER mode.");
                return result;
            }
            if ("INFRA".equals(modeRaw) && domain.isEmpty()) {
                result.fail("INFRA mode requires 'domain'.");
                ctx.log("[!] Validation failed: domain is required for INFRA mode.");
                return result;
            }

            // Auto-derive domain from target if not provided
            if (domain.isEmpty() && !target.isEmpty()) {
                domain = deriveDomain(target);
            }
            // Auto-derive target from domain if not provided
            if (target.isEmpty() && !domain.isEmpty()) {
                target = domain;
            }

            InputSanitizer.validateHostname(target.isEmpty() ? domain : target);
            if (!domain.isEmpty()) {
                InputSanitizer.validateHostname(domain);
            }

            ctx.log("[+] Target: " + target + " | Domain: " + domain);
            ctx.reportProgress(10);

            // ── Step 3: Target Intelligence ──
            ctx.log("[*] Step 3/8 — Target intelligence & infrastructure discovery...");
            


            Map<String, Object> intelligence = performTargetIntelligence(target, domain, timeoutMs, ctx, allRecords, selectedTools);
            allFindings.add(buildIntelligenceFinding(intelligence, target, domain));
            ctx.reportProgress(25);

            // ── Step 4: Tool Readiness & Selection Verification ──
            ctx.log("[*] Step 4/8 — Verifying tool readiness...");

            Map<String, String> toolPaths = new LinkedHashMap<>();
            for (String toolId : selectedTools) {
                ToolManager.ToolStatus status = toolManager.getToolStatus(toolId);
                if (status.isInstalled()) {
                    toolPaths.put(toolId, status.getPath());
                    ctx.log("[+] Tool ready: " + toolId + " → " + status.getPath());
                } else {
                    ctx.log("[~] Tool missing: " + toolId + " — will be skipped.");
                }
            }
            ctx.reportProgress(30);

            // ── Step 5: Dynamic Command Pipeline Orchestration ──
            ctx.log("[*] Step 5/8 — Building dynamic command pipeline for mode " + modeRaw + "...");
            ctx.log("[*] Selected tools: " + String.join(", ", selectedTools));

            if ("FINGER".equals(modeRaw)) {
                executeFINGERPipeline(target, domain, timeoutMs, toolPaths, selectedTools, ctx, allRecords, allFindings);
            } else {
                executeINFRAPipeline(domain, timeoutMs, toolPaths, selectedTools, ctx, allRecords, allFindings);
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
            ReportGenerator.ReportPayload payload = reportGenerator.buildReport(
                modeRaw, target, domain, allRecords, allFindings, intelligence, startedAt
            );
            result.setNormalizedOutput(payload.normalizedOutput);
            result.complete(payload.output);

            ctx.log("[+] Banner Grabber completed: " + allFindings.size() + " finding(s), "
                + allRecords.size() + " command(s) executed in "
                + (System.currentTimeMillis() - startedAt) + "ms.");
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
    //  STEP 3 — Target Intelligence (Mandatory Discovery)
    // ═══════════════════════════════════════════════════════════════════

    private Map<String, Object> performTargetIntelligence(
            String target, String domain, long timeoutMs, TaskContext ctx, List<CommandRecord> records, List<String> selectedTools) {

        Map<String, Object> intel = new LinkedHashMap<>();
        intel.put("target", target);
        intel.put("domain", domain);

        String activeTarget = domain.isEmpty() ? target : domain;

        // DNS Resolution via dnsx (fallback to dig)
        if (selectedTools.contains("dnsx") || selectedTools.contains("dig")) {
            ctx.log("[*]   DNS resolution...");
            ToolManager.ToolStatus dnsxStatus = toolManager.getToolStatus("dnsx");
            if (selectedTools.contains("dnsx") && dnsxStatus.isInstalled()) {
                CommandRecord rec = ProcessExecutor.execute("dnsx", dnsxStatus.getPath(),
                    List.of("-d", activeTarget, "-a", "-resp", "-silent"),
                    Math.min(timeoutMs, 30_000L), ctx,
                    line -> ctx.log("[dnsx] " + line), null);
                records.add(rec);
                intel.put("dns_resolution", rec.stdout.trim());
            } else if (selectedTools.contains("dig")) {
                ToolManager.ToolStatus digStatus = toolManager.getToolStatus("dig");
                if (digStatus.isInstalled()) {
                    CommandRecord rec = ProcessExecutor.execute("dig", digStatus.getPath(),
                        List.of(activeTarget, "ANY", "+short"),
                        Math.min(timeoutMs, 15_000L), ctx,
                        line -> ctx.log("[dig] " + line), null);
                    records.add(rec);
                    intel.put("dns_resolution", rec.stdout.trim());
                }
            }
        }

        // WHOIS Attribution
        if (selectedTools.contains("whois")) {
            ctx.log("[*]   WHOIS attribution...");
            ToolManager.ToolStatus whoisStatus = toolManager.getToolStatus("whois");
            if (whoisStatus.isInstalled()) {
                CommandRecord rec = ProcessExecutor.execute("whois", whoisStatus.getPath(),
                    List.of(activeTarget),
                    Math.min(timeoutMs, 20_000L), ctx, null, null);
                records.add(rec);
                intel.put("whois_raw", truncate(rec.stdout.trim(), 3000));
                intel.put("whois_org", extractWhoisField(rec.stdout, "OrgName", "Organization", "org-name"));
                intel.put("whois_netrange", extractWhoisField(rec.stdout, "NetRange", "inetnum", "CIDR"));
            }
        }

        // Infrastructure Fingerprinting via httpx
        if (selectedTools.contains("httpx")) {
            ctx.log("[*]   Infrastructure fingerprinting via httpx...");
            ToolManager.ToolStatus httpxStatus = toolManager.getToolStatus("httpx");
            if (httpxStatus.isInstalled()) {
                CommandRecord rec = ProcessExecutor.execute("httpx", httpxStatus.getPath(),
                    List.of("-u", target.isEmpty() ? domain : target, "-tech-detect", "-status-code", "-title", "-silent"),
                    Math.min(timeoutMs, 30_000L), ctx,
                    line -> ctx.log("[httpx] " + line), null);
                records.add(rec);
                intel.put("httpx_fingerprint", rec.stdout.trim());
            }
        }

        // Subdomain Discovery via subfinder
        if (!domain.isEmpty() && selectedTools.contains("subfinder")) {
            ctx.log("[*]   Subdomain discovery via subfinder...");
            ToolManager.ToolStatus subfinderStatus = toolManager.getToolStatus("subfinder");
            if (subfinderStatus.isInstalled()) {
                CommandRecord rec = ProcessExecutor.execute("subfinder", subfinderStatus.getPath(),
                    List.of("-d", domain, "-silent"),
                    Math.min(timeoutMs, 45_000L), ctx,
                    line -> ctx.log("[subfinder] " + line), null);
                records.add(rec);
                String[] subs = rec.stdout.trim().split("\\R");
                intel.put("subdomains_found", subs.length > 0 && !subs[0].isEmpty() ? subs.length : 0);
                intel.put("subdomains_sample", truncate(rec.stdout.trim(), 2000));
            }
        }

        ctx.log("[+] Target intelligence complete.");
        return intel;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  STEP 5/6 — FINGER Pipeline (Dynamic)
    //  Blueprint: nmap -sV → whatweb → searchsploit → httpx → dnsx
    // ═══════════════════════════════════════════════════════════════════

    private void executeFINGERPipeline(
            String target, String domain, long timeoutMs,
            Map<String, String> toolPaths, List<String> selectedTools,
            TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {

        String nmapXmlPath = "";

        // 1. nmap -sV -p- --script banner <target> -oX nmap.xml
        if (selectedTools.contains("nmap") && toolPaths.containsKey("nmap")) {
            ctx.log("[*] Step 6/8 — Executing nmap service version scan...");
            Path nmapOutput = resolveOutputPath("FINGER", "nmap.xml");
            nmapXmlPath = nmapOutput.toString();
            CommandRecord rec = ProcessExecutor.execute("nmap", toolPaths.get("nmap"),
                List.of("-sV", "-p", "21,22,25,53,80,110,143,443,445,587,993,995,1433,3306,3389,6379,8080",
                    "--script", "banner", "-oX", nmapXmlPath, "--open", "-Pn", target),
                timeoutMs, ctx,
                line -> ctx.log("[nmap] " + line), null);
            records.add(rec);

            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("nmap_banner_scan", "Nmap Banner & Service Scan",
                    "Service version detection and banner grabbing on " + target, rec, "medium"));
            } else {
                findings.add(buildToolFinding("nmap_banner_scan", "Nmap Banner Scan (Failed)",
                    "Nmap failed or returned no output. Exit=" + rec.exitCode, rec, "info"));
            }
        }

        // 2. whatweb <target>
        if (selectedTools.contains("whatweb") && toolPaths.containsKey("whatweb")) {
            ctx.log("[*] Step 6/8 — Executing whatweb technology detection...");
            CommandRecord rec = ProcessExecutor.execute("whatweb", toolPaths.get("whatweb"),
                List.of("--log-brief=-", target),
                Math.min(timeoutMs, 60_000L), ctx,
                line -> ctx.log("[whatweb] " + line), null);
            records.add(rec);

            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("whatweb_tech", "WhatWeb Technology Identification",
                    "Web technology stack detected on " + target, rec, "low"));
            }
        }

        // 3. searchsploit --nmap nmap.xml --json (or generic query)
        if (selectedTools.contains("searchsploit") && toolPaths.containsKey("searchsploit")) {
            ctx.log("[*] Step 6/8 — Executing searchsploit vulnerability correlation...");

            List<String> args;
            if (!nmapXmlPath.isEmpty() && Files.exists(Path.of(nmapXmlPath))) {
                args = List.of("--nmap", nmapXmlPath, "--json");
            } else {
                // Fallback: search by target
                args = List.of("--json", target);
            }

            CommandRecord rec = ProcessExecutor.execute("searchsploit", toolPaths.get("searchsploit"),
                args, Math.min(timeoutMs, 30_000L), ctx,
                line -> ctx.log("[searchsploit] " + line), null);
            records.add(rec);

            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("searchsploit_cve", "Searchsploit Vulnerability Correlation",
                    "Exploit-DB correlation for services on " + target, rec, "high"));
            }
        }

        // 4. httpx -u <target> -tech-detect -silent
        if (selectedTools.contains("httpx") && toolPaths.containsKey("httpx")) {
            ctx.log("[*] Step 6/8 — Executing httpx HTTP identity detection...");
            CommandRecord rec = ProcessExecutor.execute("httpx", toolPaths.get("httpx"),
                List.of("-u", target, "-tech-detect", "-status-code", "-title", "-json", "-silent"),
                Math.min(timeoutMs, 30_000L), ctx,
                line -> ctx.log("[httpx] " + line), null);
            records.add(rec);

            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("httpx_identity", "httpx HTTP Identity Fingerprint",
                    "HTTP technology detection on " + target, rec, "info"));
            }
        }

        // 5. dnsx -d <domain> -a -resp -silent
        if (selectedTools.contains("dnsx") && toolPaths.containsKey("dnsx") && !domain.isEmpty()) {
            ctx.log("[*] Step 6/8 — Executing dnsx DNS context resolution...");
            CommandRecord rec = ProcessExecutor.execute("dnsx", toolPaths.get("dnsx"),
                List.of("-d", domain, "-a", "-resp", "-silent"),
                Math.min(timeoutMs, 20_000L), ctx,
                line -> ctx.log("[dnsx] " + line), null);
            records.add(rec);

            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("dnsx_context", "dnsx DNS Context",
                    "DNS A record resolution for " + domain, rec, "info"));
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  STEP 5/6 — INFRA Pipeline (Dynamic)
    //  Blueprint: subfinder → dnsx → whois → dig ANY → httpx
    // ═══════════════════════════════════════════════════════════════════

    private void executeINFRAPipeline(
            String domain, long timeoutMs,
            Map<String, String> toolPaths, List<String> selectedTools,
            TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {

        String subsFile = "";

        // 1. subfinder -d <domain> -silent
        if (selectedTools.contains("subfinder") && toolPaths.containsKey("subfinder")) {
            ctx.log("[*] Step 6/8 — Executing subfinder subdomain discovery...");
            Path subsOutput = resolveOutputPath("INFRA", "subdomains.txt");
            subsFile = subsOutput.toString();
            CommandRecord rec = ProcessExecutor.execute("subfinder", toolPaths.get("subfinder"),
                List.of("-d", domain, "-silent", "-o", subsFile),
                timeoutMs, ctx,
                line -> ctx.log("[subfinder] " + line), null);
            records.add(rec);

            if (rec.exitCode == 0) {
                findings.add(buildToolFinding("subfinder_subs", "Subfinder Subdomain Discovery",
                    "Subdomain enumeration for " + domain, rec, "low"));
            }
        }

        // 2. dnsx -d <domain> -a -cname -mx -ns -soa -txt
        if (selectedTools.contains("dnsx") && toolPaths.containsKey("dnsx")) {
            ctx.log("[*] Step 6/8 — Executing dnsx full DNS record enumeration...");
            CommandRecord rec = ProcessExecutor.execute("dnsx", toolPaths.get("dnsx"),
                List.of("-d", domain, "-a", "-cname", "-mx", "-ns", "-soa", "-txt", "-resp", "-silent"),
                Math.min(timeoutMs, 30_000L), ctx,
                line -> ctx.log("[dnsx] " + line), null);
            records.add(rec);

            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("dnsx_records", "dnsx DNS Record Enumeration",
                    "Full DNS record resolution (A, CNAME, MX, NS, SOA, TXT) for " + domain, rec, "info"));
            }
        }

        // 3. whois <domain>
        if (selectedTools.contains("whois") && toolPaths.containsKey("whois")) {
            ctx.log("[*] Step 6/8 — Executing whois attribution lookup...");
            CommandRecord rec = ProcessExecutor.execute("whois", toolPaths.get("whois"),
                List.of(domain),
                Math.min(timeoutMs, 20_000L), ctx, null, null);
            records.add(rec);

            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("whois_attrib", "WHOIS Attribution",
                    "Domain ownership and registration data for " + domain, rec, "info"));
            }
        }

        // 4. dig <domain> ANY
        if (selectedTools.contains("dig") && toolPaths.containsKey("dig")) {
            ctx.log("[*] Step 6/8 — Executing dig ANY detailed query...");
            CommandRecord rec = ProcessExecutor.execute("dig", toolPaths.get("dig"),
                List.of(domain, "ANY"),
                Math.min(timeoutMs, 15_000L), ctx,
                line -> ctx.log("[dig] " + line), null);
            records.add(rec);

            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("dig_any", "dig ANY Query",
                    "Detailed DNS resource record query for " + domain, rec, "info"));
            }
        }

        // 5. httpx -l subs.txt -status-code -title
        if (selectedTools.contains("httpx") && toolPaths.containsKey("httpx")) {
            ctx.log("[*] Step 6/8 — Executing httpx asset validation...");

            List<String> args;
            if (!subsFile.isEmpty() && Files.exists(Path.of(subsFile))) {
                args = List.of("-l", subsFile, "-status-code", "-title", "-silent");
            } else {
                args = List.of("-u", domain, "-status-code", "-title", "-silent");
            }

            CommandRecord rec = ProcessExecutor.execute("httpx", toolPaths.get("httpx"),
                args, Math.min(timeoutMs, 60_000L), ctx,
                line -> ctx.log("[httpx] " + line), null);
            records.add(rec);

            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("httpx_validation", "httpx Asset Validation",
                    "HTTP validation of discovered subdomains/assets for " + domain, rec, "low"));
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  HELPERS
    // ═══════════════════════════════════════════════════════════════════

    private List<String> getDefaultToolsForMode(String mode) {
        if ("FINGER".equals(mode)) {
            return List.of("nmap", "whatweb", "searchsploit", "httpx", "dnsx");
        } else {
            return List.of("subfinder", "dnsx", "whois", "dig", "httpx");
        }
    }

    private Map<String, Object> buildToolFinding(String type, String title, String description,
                                                  CommandRecord rec, String severity) {
        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("type", type);
        finding.put("title", title);
        finding.put("description", description);
        finding.put("severity", severity);
        finding.put("status", rec.exitCode == 0 ? "confirmed" : "failed");
        finding.put("tool", rec.tool);
        finding.put("command", rec.command);
        finding.put("duration_ms", rec.durationMs);
        finding.put("exit_code", rec.exitCode);
        finding.put("stdout_preview", truncate(rec.stdoutPreview, 500));
        return finding;
    }

    private Map<String, Object> buildIntelligenceFinding(Map<String, Object> intel, String target, String domain) {
        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("type", "infrastructure_discovery");
        finding.put("title", "Target Intelligence: " + (domain.isEmpty() ? target : domain));
        finding.put("severity", "info");
        finding.put("status", "confirmed");
        finding.put("description", "Mandatory infrastructure discovery via dnsx/whois/httpx/subfinder.");
        finding.put("details", intel);
        return finding;
    }

    private Path resolveOutputPath(String mode, String fileName) {
        String ts = String.valueOf(System.currentTimeMillis() / 1000);
        String basePath = System.getProperty("user.dir", ".");
        Path outputDir = Path.of(basePath, "reports/outputs");
        try {
            Files.createDirectories(outputDir);
        } catch (Exception ignored) {}
        return outputDir.resolve(mode + "_" + ts + "_" + fileName);
    }

    private String deriveDomain(String target) {
        // If target looks like an IP, return empty
        if (target.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
            return "";
        }
        // Strip port if present
        int colonIdx = target.indexOf(':');
        return colonIdx > 0 ? target.substring(0, colonIdx) : target;
    }

    private long parseTimeout(String raw) {
        try {
            long seconds = Long.parseLong(raw.trim());
            return Math.max(10_000L, Math.min(seconds * 1000L, 600_000L));
        } catch (NumberFormatException e) {
            return DEFAULT_TIMEOUT_MS;
        }
    }

    private String extractWhoisField(String whoisOutput, String... fieldNames) {
        for (String line : whoisOutput.split("\\R")) {
            for (String field : fieldNames) {
                if (line.toLowerCase().startsWith(field.toLowerCase() + ":")) {
                    return line.substring(line.indexOf(':') + 1).trim();
                }
            }
        }
        return "";
    }

    private String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max) + "...";
    }
}