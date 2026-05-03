package com.jabber.jabber.modules.reconnaissance.crawler;

import com.jabber.jabber.data.model.ModuleResult;
import com.jabber.jabber.data.model.TaskContext;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * WebCrawlerEngine — 8-Step Execution Doctrine Implementation.
 *
 * Modes:
 *   SURVEY — Fast infrastructure discovery and surface-level crawling.
 *            Pipeline: subfinder → dnsx → httpx → gospider → whois
 *   DEEP   — Exhaustive asset mapping and historical URL analysis.
 *            Pipeline: katana → waybackurls → gau → httpx → dnsx
 *
 * Dynamic Tool-Selection: Only tools explicitly selected by the user via
 * the frontend toggles are executed.
 */
public class WebCrawlerEngine {

    private static final String MODULE_ID = "recon-web-crawler";
    private static final long DEFAULT_TIMEOUT_MS = 300_000L;

    private final ToolManager toolManager;

    public WebCrawlerEngine(ToolManager toolManager) {
        this.toolManager = toolManager;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  MAIN EXECUTION — 8-Step Doctrine
    // ═══════════════════════════════════════════════════════════════════

    public ModuleResult execute(Map<String, String> input, TaskContext ctx) {
        String targetInput = input.getOrDefault("url", input.getOrDefault("domain", "unknown"));
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
            String modeRaw = input.getOrDefault("mode", "SURVEY").toUpperCase().trim();
            if (!"SURVEY".equals(modeRaw) && !"DEEP".equals(modeRaw)) {
                result.fail("Unsupported mode: " + modeRaw + ". Valid modes: SURVEY, DEEP.");
                ctx.log("[!] Invalid mode: " + modeRaw);
                return result;
            }
            ctx.log("[+] Mode validated: " + modeRaw);
            ctx.reportProgress(5);

            // ── Step 2: Sanitize Schema ──
            ctx.log("[*] Step 2/8 — Sanitizing inputs...");
            String url = input.getOrDefault("url", input.getOrDefault("target_url", "")).trim();
            String domain = input.getOrDefault("domain", "").trim();
            int depth = parseQuietly(input.getOrDefault("depth", "2"), 2);
            long timeoutMs = parseTimeout(input.getOrDefault("timeout", "300"));

            if (url.isEmpty() && domain.isEmpty()) {
                result.fail("Execution requires either 'url' or 'domain'.");
                ctx.log("[!] Validation failed: url or domain is required.");
                return result;
            }

            // Derive values if missing
            if (url.isEmpty() && !domain.isEmpty()) {
                url = "http://" + domain;
            }
            if (domain.isEmpty() && !url.isEmpty()) {
                domain = deriveDomainFromUrl(url);
            }

            // Validate using strict patterns
            InputSanitizer.validateUrl(url);
            InputSanitizer.validateDomain(domain);

            ctx.log("[+] URL: " + url + " | Domain: " + domain + " | Depth: " + depth);
            ctx.reportProgress(10);

            // ── Step 3: Target Intelligence ──
            ctx.log("[*] Step 3/8 — Target intelligence & infrastructure discovery...");
            
            // Get selected tools early for Step 3 filtering

            Map<String, Object> intelligence = performTargetIntelligence(url, domain, timeoutMs, ctx, allRecords, selectedTools);
            allFindings.add(buildIntelligenceFinding(intelligence, url, domain));
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

            if ("SURVEY".equals(modeRaw)) {
                executeSURVEYPipeline(url, domain, depth, timeoutMs, toolPaths, selectedTools, ctx, allRecords, allFindings);
            } else {
                executeDEEPPipeline(url, domain, depth, timeoutMs, toolPaths, selectedTools, ctx, allRecords, allFindings);
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
                modeRaw, url, domain, allRecords, allFindings, intelligence, startedAt
            );
            result.setNormalizedOutput(payload.normalizedOutput);
            result.complete(payload.output);

            ctx.log("[+] Web Crawler completed: " + allFindings.size() + " finding(s), "
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
            String url, String domain, long timeoutMs, TaskContext ctx, List<CommandRecord> records, List<String> selectedTools) {

        Map<String, Object> intel = new LinkedHashMap<>();
        intel.put("url", url);
        intel.put("domain", domain);

        // DNS Resolution via dnsx
        if (shouldRun("dnsx", selectedTools)) {
            ctx.log("[*]   DNS resolution via dnsx...");
            ToolManager.ToolStatus dnsxStatus = toolManager.getToolStatus("dnsx");
            if (dnsxStatus.isInstalled()) {
                CommandRecord rec = ProcessExecutor.execute("dnsx", dnsxStatus.getPath(),
                    List.of("-d", domain, "-a", "-resp", "-silent"),
                    Math.min(timeoutMs, 30_000L), ctx,
                    line -> ctx.log("[dnsx] " + line), null);
                records.add(rec);
                intel.put("dns_resolution", rec.stdout.trim());
            }
        }

        // WHOIS Attribution
        if (shouldRun("whois", selectedTools)) {
            ctx.log("[*]   WHOIS attribution...");
            ToolManager.ToolStatus whoisStatus = toolManager.getToolStatus("whois");
            if (whoisStatus.isInstalled()) {
                CommandRecord rec = ProcessExecutor.execute("whois", whoisStatus.getPath(),
                    List.of(domain),
                    Math.min(timeoutMs, 20_000L), ctx, null, null);
                records.add(rec);
                intel.put("whois_raw", truncate(rec.stdout.trim(), 3000));
            }
        }

        // Subdomain Discovery via subfinder
        if (shouldRun("subfinder", selectedTools)) {
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
            }
        }

        ctx.log("[+] Target intelligence complete.");
        return intel;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  STEP 5/6 — SURVEY Pipeline
    //  Pipeline: subfinder → dnsx → httpx → gospider → whois
    // ═══════════════════════════════════════════════════════════════════

    private void executeSURVEYPipeline(
            String url, String domain, int depth, long timeoutMs,
            Map<String, String> toolPaths, List<String> selectedTools,
            TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {

        // 1. subfinder -d <domain> -silent
        if (shouldRun("subfinder", selectedTools) && toolPaths.containsKey("subfinder")) {
            ctx.log("[*] Step 6/8 — Executing subfinder discovery...");
            CommandRecord rec = ProcessExecutor.execute("subfinder", toolPaths.get("subfinder"),
                List.of("-d", domain, "-silent"),
                timeoutMs, ctx, line -> ctx.log("[subfinder] " + line), null);
            records.add(rec);
            findings.add(buildToolFinding("subfinder_discovery", "Subfinder Discovery", "Subdomain enumeration for " + domain, rec, "low"));
        }

        // 2. dnsx -d <domain> -a -resp -silent
        if (selectedTools.contains("dnsx") && toolPaths.containsKey("dnsx")) {
            ctx.log("[*] Step 6/8 — Executing dnsx resolution...");
            CommandRecord rec = ProcessExecutor.execute("dnsx", toolPaths.get("dnsx"),
                List.of("-d", domain, "-a", "-resp", "-silent"),
                Math.min(timeoutMs, 30_000L), ctx, line -> ctx.log("[dnsx] " + line), null);
            records.add(rec);
            findings.add(buildToolFinding("dnsx_resolution", "DNSx Resolution", "DNS resolution for " + domain, rec, "info"));
        }

        // 3. httpx -u <url> -tech-detect -status-code -silent
        if (shouldRun("httpx", selectedTools) && toolPaths.containsKey("httpx")) {
            ctx.log("[*] Step 6/8 — Executing httpx fingerprinting...");
            CommandRecord rec = ProcessExecutor.execute("httpx", toolPaths.get("httpx"),
                List.of("-u", url, "-tech-detect", "-status-code", "-silent"),
                Math.min(timeoutMs, 60_000L), ctx, line -> ctx.log("[httpx] " + line), null);
            records.add(rec);
            findings.add(buildToolFinding("httpx_fingerprint", "Httpx Fingerprinting", "Server technology detection on " + url, rec, "info"));
        }

        // 4. gospider -s <url> -d <depth> -c 10 -silent
        if (shouldRun("gospider", selectedTools) && toolPaths.containsKey("gospider")) {
            ctx.log("[*] Step 6/8 — Executing gospider surface crawl...");
            CommandRecord rec = ProcessExecutor.execute("gospider", toolPaths.get("gospider"),
                List.of("-s", url, "-d", String.valueOf(depth), "-c", "10", "-silent"),
                timeoutMs, ctx, line -> ctx.log("[gospider] " + line), null);
            records.add(rec);
            findings.add(buildToolFinding("gospider_crawl", "GoSpider Surface Crawl", "Fast surface-level crawl of " + url, rec, "low"));
        }

        // 5. whois <domain>
        if (shouldRun("whois", selectedTools) && toolPaths.containsKey("whois")) {
            ctx.log("[*] Step 6/8 — Executing whois lookup...");
            CommandRecord rec = ProcessExecutor.execute("whois", toolPaths.get("whois"),
                List.of(domain),
                Math.min(timeoutMs, 20_000L), ctx, null, null);
            records.add(rec);
            findings.add(buildToolFinding("whois_lookup", "Whois Ownership", "Ownership data for " + domain, rec, "info"));
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  STEP 5/6 — DEEP Pipeline
    //  Pipeline: katana → waybackurls → gau → httpx → dnsx
    // ═══════════════════════════════════════════════════════════════════

    private void executeDEEPPipeline(
            String url, String domain, int depth, long timeoutMs,
            Map<String, String> toolPaths, List<String> selectedTools,
            TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {

        Path urlsFile = resolveOutputPath("DEEP", "urls.txt");
        String urlsFilePath = urlsFile.toString();

        // 1. katana -u <url> -d <depth> -silent -o urls.txt
        if (shouldRun("katana", selectedTools) && toolPaths.containsKey("katana")) {
            ctx.log("[*] Step 6/8 — Executing katana deep crawl...");
            CommandRecord rec = ProcessExecutor.execute("katana", toolPaths.get("katana"),
                List.of("-u", url, "-d", String.valueOf(depth), "-silent", "-o", urlsFilePath),
                timeoutMs, ctx, line -> ctx.log("[katana] " + line), null);
            records.add(rec);
            findings.add(buildToolFinding("katana_deep_crawl", "Katana Deep Crawl", "Exhaustive crawl of " + url, rec, "medium"));
        }

        // 2. waybackurls <domain> >> urls.txt
        if (shouldRun("waybackurls", selectedTools) && toolPaths.containsKey("waybackurls")) {
            ctx.log("[*] Step 6/8 — Executing waybackurls history search...");
            CommandRecord rec = ProcessExecutor.execute("waybackurls", toolPaths.get("waybackurls"),
                List.of(domain),
                Math.min(timeoutMs, 60_000L), ctx, line -> appendToFile(urlsFile, line), null);
            records.add(rec);
            findings.add(buildToolFinding("waybackurls_history", "WaybackUrls History", "Historical URL analysis for " + domain, rec, "info"));
        }

        // 3. gau <domain> >> urls.txt
        if (shouldRun("gau", selectedTools) && toolPaths.containsKey("gau")) {
            ctx.log("[*] Step 6/8 — Executing gau aggregation...");
            CommandRecord rec = ProcessExecutor.execute("gau", toolPaths.get("gau"),
                List.of(domain),
                Math.min(timeoutMs, 60_000L), ctx, line -> appendToFile(urlsFile, line), null);
            records.add(rec);
            findings.add(buildToolFinding("gau_aggregation", "GAU Aggregation", "Multi-source URL aggregation for " + domain, rec, "info"));
        }

        // 4. httpx -l urls.txt -tech-detect -title -json -silent
        if (shouldRun("httpx", selectedTools) && toolPaths.containsKey("httpx") && Files.exists(urlsFile)) {
            ctx.log("[*] Step 6/8 — Executing httpx bulk validation...");
            CommandRecord rec = ProcessExecutor.execute("httpx", toolPaths.get("httpx"),
                List.of("-l", urlsFilePath, "-tech-detect", "-title", "-json", "-silent"),
                timeoutMs, ctx, line -> ctx.log("[httpx] " + line), null);
            records.add(rec);
            findings.add(buildToolFinding("httpx_bulk_validation", "Httpx Bulk Validation", "Technology validation for aggregated URLs", rec, "low"));
        }

        // 5. dnsx -d <domain> -a -resp -silent
        if (selectedTools.contains("dnsx") && toolPaths.containsKey("dnsx")) {
            ctx.log("[*] Step 6/8 — Executing dnsx active infra mapping...");
            CommandRecord rec = ProcessExecutor.execute("dnsx", toolPaths.get("dnsx"),
                List.of("-d", domain, "-a", "-resp", "-silent"),
                Math.min(timeoutMs, 30_000L), ctx, line -> ctx.log("[dnsx] " + line), null);
            records.add(rec);
            findings.add(buildToolFinding("dnsx_infra_map", "DNSx Infrastructure Mapping", "Active infrastructure mapping for " + domain, rec, "info"));
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  HELPERS
    // ═══════════════════════════════════════════════════════════════════

    private List<String> getDefaultToolsForMode(String mode) {
        if ("SURVEY".equals(mode)) {
            return List.of("subfinder", "dnsx", "httpx", "gospider", "whois");
        } else {
            return List.of("katana", "waybackurls", "gau", "httpx", "dnsx");
        }
    }

    private Map<String, Object> buildToolFinding(String type, String title, String description,
                                                  CommandRecord rec, String severity) {
        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("category", "Tool Execution");
        finding.put("title", title);
        finding.put("description", description);
        finding.put("severity", severity);
        finding.put("status", rec.exitCode == 0 ? "SUCCESS" : "FAILED");
        finding.put("tool", rec.tool);
        return finding;
    }

    private Map<String, Object> buildIntelligenceFinding(Map<String, Object> intel, String url, String domain) {
        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("category", "Infrastructure Discovery");
        finding.put("title", "Target Identity: " + domain);
        finding.put("severity", "info");
        finding.put("status", "CONFIRMED");
        finding.put("summary", "DNS: " + intel.getOrDefault("dns_resolution", "N/A") + " | Subdomains: " + intel.getOrDefault("subdomains_found", "0"));
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

    private String deriveDomainFromUrl(String url) {
        try {
            java.net.URI uri = new java.net.URI(url);
            String host = uri.getHost();
            return host != null ? host : "";
        } catch (Exception e) {
            return "";
        }
    }

    private void appendToFile(Path path, String line) {
        try {
            Files.writeString(path, line + "\n", java.nio.charset.StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception ignored) {}
    }

    private int parseQuietly(String raw, int defaultValue) {
        try {
            return Integer.parseInt(raw.trim());
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private long parseTimeout(String raw) {
        try {
            long seconds = Long.parseLong(raw.trim());
            return Math.max(10_000L, Math.min(seconds * 1000L, 1200_000L));
        } catch (Exception e) {
            return DEFAULT_TIMEOUT_MS;
        }
    }

    private String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max) + "...";
    }
    private boolean shouldRun(String toolId, List<String> selectedTools) {
        if (selectedTools.isEmpty()) return false;
        if (selectedTools.size() == 1 && selectedTools.get(0).isEmpty()) return false;
        return selectedTools.contains(toolId);
    }
}
