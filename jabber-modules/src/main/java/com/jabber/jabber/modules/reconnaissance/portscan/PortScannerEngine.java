package com.jabber.jabber.modules.reconnaissance.portscan;

import com.jabber.jabber.data.model.ModuleResult;
import com.jabber.jabber.data.model.TaskContext;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * PortScannerEngine — 8-Step Execution Doctrine Implementation.
 *
 * Modes:
 *   ACTIVE — Multi-layered port discovery and service validation.
 *            Pipeline: masscan → nmap -sV → httpx → dnsx -ptr → arp-scan
 *   SURVEY — Passive-first network mapping and host discovery.
 *            Pipeline: arp-scan → nmap -sn → dnsx -ptr → httpx → masscan (sample)
 *
 * Dynamic Tool-Selection: Only tools explicitly selected by the user via
 * the frontend toggles are executed. The selectedTools list controls
 * which commands run.
 */
public class PortScannerEngine {

    private static final String MODULE_ID = "recon-portscanner";
    private static final long DEFAULT_TIMEOUT_MS = 120_000L;

    private final ToolManager toolManager;

    public PortScannerEngine(ToolManager toolManager) {
        this.toolManager = toolManager;
    }

    public ModuleResult execute(Map<String, String> input, TaskContext ctx) {
        String targetInput = input.getOrDefault("target", input.getOrDefault("cidr", "unknown"));
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
            String modeRaw = input.getOrDefault("mode", "ACTIVE").toUpperCase().trim();
            if (!"ACTIVE".equals(modeRaw) && !"SURVEY".equals(modeRaw)) {
                result.fail("Unsupported mode: " + modeRaw + ". Valid modes: ACTIVE, SURVEY.");
                ctx.log("[!] Invalid mode: " + modeRaw);
                return result;
            }
            ctx.log("[+] Mode validated: " + modeRaw);
            ctx.reportProgress(5);

            // ── Step 2: Sanitize Schema ──
            ctx.log("[*] Step 2/8 — Sanitizing inputs...");
            String target, ports, sudoPassword;
            int rate;
            long timeoutMs = parseTimeout(input.getOrDefault("timeout", "120"));
            sudoPassword = input.getOrDefault("sudoPassword", "");

            if ("ACTIVE".equals(modeRaw)) {
                target = InputSanitizer.validateTarget(input.getOrDefault("target", "").trim());
                ports = InputSanitizer.validatePortSpec(input.getOrDefault("ports", ""));
                rate = InputSanitizer.validateInt(input.getOrDefault("rate", "1000"), 100, 100000, 1000);
            } else {
                target = InputSanitizer.validateCidr(input.getOrDefault("cidr", "").trim());
                ports = "";
                rate = 1000;
            }

            String iface = InputSanitizer.validateInterface(input.getOrDefault("interface", ""));
            ctx.log("[+] Target: " + target + " | Ports: " + (ports.isEmpty() ? "(default)" : ports) + " | Rate: " + rate);
            ctx.reportProgress(10);

            // ── Step 3: Target Intelligence ──
            ctx.log("[*] Step 3/8 — Target intelligence & infrastructure discovery...");


            Map<String, Object> intelligence = performTargetIntelligence(target, timeoutMs, ctx, allRecords, selectedTools, sudoPassword);
            allFindings.add(buildIntelligenceFinding(intelligence, target));
            ctx.reportProgress(25);

            // ── Step 4: Tool Readiness ──
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

            // Check sudo requirement
            List<String> sudoTools = toolManager.getSudoTools(selectedTools);
            if (!sudoTools.isEmpty() && (sudoPassword == null || sudoPassword.isBlank())) {
                ctx.log("[~] WARNING: Tools " + sudoTools + " require sudo but no password provided. They may fail.");
            }
            ctx.reportProgress(30);

            // ── Step 5: Dynamic Command Pipeline Orchestration ──
            ctx.log("[*] Step 5/8 — Building dynamic command pipeline for mode " + modeRaw + "...");
            ctx.log("[*] Selected tools: " + String.join(", ", selectedTools));

            if ("ACTIVE".equals(modeRaw)) {
                executeACTIVEPipeline(target, ports, rate, timeoutMs, toolPaths, selectedTools, ctx, allRecords, allFindings, sudoPassword);
            } else {
                executeSURVEYPipeline(target, iface, timeoutMs, toolPaths, selectedTools, ctx, allRecords, allFindings, sudoPassword);
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
                modeRaw, target, allRecords, allFindings, intelligence, startedAt
            );
            result.setNormalizedOutput(payload.normalizedOutput);
            result.complete(payload.output);

            ctx.log("[+] Port Scanner completed: " + allFindings.size() + " finding(s), "
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
    //  STEP 3 — Target Intelligence
    // ═══════════════════════════════════════════════════════════════════

    private Map<String, Object> performTargetIntelligence(
            String target, long timeoutMs, TaskContext ctx,
            List<CommandRecord> records, List<String> selectedTools, String sudoPassword) {

        Map<String, Object> intel = new LinkedHashMap<>();
        intel.put("target", target);

        // DNS Resolution via dnsx
        if (selectedTools.contains("dnsx")) {
            ToolManager.ToolStatus dnsxStatus = toolManager.getToolStatus("dnsx");
            if (dnsxStatus.isInstalled()) {
                ctx.log("[*]   DNS resolution via dnsx...");
                CommandRecord rec = ProcessExecutor.execute("dnsx", dnsxStatus.getPath(),
                    List.of("-d", target, "-a", "-resp", "-silent"),
                    Math.min(timeoutMs, 30_000L), ctx,
                    line -> ctx.log("[dnsx] " + line), null);
                records.add(rec);
                intel.put("dns_resolution", rec.stdout.trim());
            }
        }

        // httpx fingerprint
        if (selectedTools.contains("httpx")) {
            ToolManager.ToolStatus httpxStatus = toolManager.getToolStatus("httpx");
            if (httpxStatus.isInstalled()) {
                ctx.log("[*]   Infrastructure fingerprinting via httpx...");
                CommandRecord rec = ProcessExecutor.execute("httpx", httpxStatus.getPath(),
                    List.of("-u", target, "-status-code", "-title", "-silent"),
                    Math.min(timeoutMs, 30_000L), ctx,
                    line -> ctx.log("[httpx] " + line), null);
                records.add(rec);
                intel.put("httpx_fingerprint", rec.stdout.trim());
            }
        }

        ctx.log("[+] Target intelligence complete.");
        return intel;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  ACTIVE Pipeline: masscan → nmap -sV → httpx → dnsx -ptr → arp-scan
    // ═══════════════════════════════════════════════════════════════════

    private void executeACTIVEPipeline(
            String target, String ports, int rate, long timeoutMs,
            Map<String, String> toolPaths, List<String> selectedTools,
            TaskContext ctx, List<CommandRecord> records,
            List<Map<String, Object>> findings, String sudoPassword) {

        String defaultPorts = ports.isEmpty() ? "21,22,25,53,80,110,135,139,143,443,445,993,1433,1521,3306,3389,5900,8080" : ports;

        // 1. masscan (requires sudo)
        if (selectedTools.contains("masscan") && toolPaths.containsKey("masscan")) {
            ctx.log("[*] Step 6/8 — Executing masscan rapid port probe...");
            Path masscanOutput = resolveOutputPath("ACTIVE", "masscan.json");
            CommandRecord rec = ProcessExecutor.execute("masscan", toolPaths.get("masscan"),
                List.of(target, "-p" + defaultPorts, "--rate", String.valueOf(rate), "-oJ", masscanOutput.toString()),
                timeoutMs, ctx, line -> ctx.log("[masscan] " + line), null, sudoPassword);
            records.add(rec);
            if (rec.exitCode == 0) {
                findings.add(buildToolFinding("masscan_probe", "Masscan Rapid Port Probe",
                    "High-speed port discovery on " + target, rec, "medium"));
            } else {
                findings.add(buildToolFinding("masscan_probe", "Masscan Probe (Failed)",
                    "Masscan failed. Exit=" + rec.exitCode + ". May require sudo.", rec, "info"));
            }
        }

        // 2. nmap -sV
        if (selectedTools.contains("nmap") && toolPaths.containsKey("nmap")) {
            ctx.log("[*] Step 6/8 — Executing nmap service version scan...");
            Path nmapOutput = resolveOutputPath("ACTIVE", "nmap.xml");
            CommandRecord rec = ProcessExecutor.execute("nmap", toolPaths.get("nmap"),
                List.of("-sV", "-p", defaultPorts, "--version-intensity", "5", "-oX", nmapOutput.toString(), "--open", "-Pn", target),
                timeoutMs, ctx, line -> ctx.log("[nmap] " + line), null);
            records.add(rec);
            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("nmap_service_id", "Nmap Service Identification",
                    "Service version detection on " + target, rec, "medium"));
            }
        }

        // 3. httpx web probing
        if (selectedTools.contains("httpx") && toolPaths.containsKey("httpx")) {
            ctx.log("[*] Step 6/8 — Executing httpx web probing...");
            String[] portList = defaultPorts.split(",");
            List<String> httpxArgs = new ArrayList<>(List.of("-u", target, "-silent", "-status-code", "-title", "-json"));
            if (portList.length <= 20) {
                httpxArgs.add("-p"); httpxArgs.add(defaultPorts);
            }
            CommandRecord rec = ProcessExecutor.execute("httpx", toolPaths.get("httpx"),
                httpxArgs, Math.min(timeoutMs, 60_000L), ctx,
                line -> ctx.log("[httpx] " + line), null);
            records.add(rec);
            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("httpx_web_probe", "httpx Web Probing",
                    "Web service detection on " + target, rec, "low"));
            }
        }

        // 4. dnsx reverse DNS
        if (selectedTools.contains("dnsx") && toolPaths.containsKey("dnsx")) {
            ctx.log("[*] Step 6/8 — Executing dnsx reverse DNS...");
            CommandRecord rec = ProcessExecutor.execute("dnsx", toolPaths.get("dnsx"),
                List.of("-d", target, "-ptr", "-silent"),
                Math.min(timeoutMs, 20_000L), ctx,
                line -> ctx.log("[dnsx] " + line), null);
            records.add(rec);
            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("dnsx_ptr", "dnsx Reverse DNS",
                    "PTR record resolution for " + target, rec, "info"));
            }
        }

        // 5. arp-scan (requires sudo)
        if (selectedTools.contains("arp-scan") && toolPaths.containsKey("arp-scan")) {
            ctx.log("[*] Step 6/8 — Executing arp-scan local adjacency check...");
            CommandRecord rec = ProcessExecutor.execute("arp-scan", toolPaths.get("arp-scan"),
                List.of("-l"),
                Math.min(timeoutMs, 30_000L), ctx,
                line -> ctx.log("[arp-scan] " + line), null, sudoPassword);
            records.add(rec);
            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("arp_adjacency", "ARP Local Adjacency Map",
                    "Layer-2 neighbor discovery", rec, "info"));
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  SURVEY Pipeline: arp-scan → nmap -sn → dnsx -ptr → httpx → masscan (sample)
    // ═══════════════════════════════════════════════════════════════════

    private void executeSURVEYPipeline(
            String cidr, String iface, long timeoutMs,
            Map<String, String> toolPaths, List<String> selectedTools,
            TaskContext ctx, List<CommandRecord> records,
            List<Map<String, Object>> findings, String sudoPassword) {

        // 1. arp-scan L2 discovery (requires sudo)
        if (selectedTools.contains("arp-scan") && toolPaths.containsKey("arp-scan")) {
            ctx.log("[*] Step 6/8 — Executing arp-scan L2 discovery...");
            List<String> args = new ArrayList<>();
            if (!iface.isEmpty()) { args.add("-I"); args.add(iface); }
            args.add(cidr);
            CommandRecord rec = ProcessExecutor.execute("arp-scan", toolPaths.get("arp-scan"),
                args, Math.min(timeoutMs, 45_000L), ctx,
                line -> ctx.log("[arp-scan] " + line), null, sudoPassword);
            records.add(rec);
            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("arp_l2_discovery", "ARP L2 Discovery",
                    "Layer-2 MAC-to-IP mapping on " + cidr, rec, "info"));
            }
        }

        // 2. nmap ping sweep
        if (selectedTools.contains("nmap") && toolPaths.containsKey("nmap")) {
            ctx.log("[*] Step 6/8 — Executing nmap ping sweep...");
            CommandRecord rec = ProcessExecutor.execute("nmap", toolPaths.get("nmap"),
                List.of("-sn", cidr),
                Math.min(timeoutMs, 60_000L), ctx,
                line -> ctx.log("[nmap] " + line), null);
            records.add(rec);
            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("nmap_ping_sweep", "Nmap Ping Sweep",
                    "L3 host discovery on " + cidr, rec, "info"));
            }
        }

        // 3. dnsx reverse mapping
        if (selectedTools.contains("dnsx") && toolPaths.containsKey("dnsx")) {
            ctx.log("[*] Step 6/8 — Executing dnsx reverse mapping...");
            CommandRecord rec = ProcessExecutor.execute("dnsx", toolPaths.get("dnsx"),
                List.of("-d", cidr, "-ptr", "-silent"),
                Math.min(timeoutMs, 30_000L), ctx,
                line -> ctx.log("[dnsx] " + line), null);
            records.add(rec);
            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("dnsx_survey_ptr", "dnsx Reverse Mapping",
                    "PTR record mapping for " + cidr, rec, "info"));
            }
        }

        // 4. httpx web presence
        if (selectedTools.contains("httpx") && toolPaths.containsKey("httpx")) {
            ctx.log("[*] Step 6/8 — Executing httpx web presence check...");
            CommandRecord rec = ProcessExecutor.execute("httpx", toolPaths.get("httpx"),
                List.of("-u", cidr, "-status-code", "-silent"),
                Math.min(timeoutMs, 60_000L), ctx,
                line -> ctx.log("[httpx] " + line), null);
            records.add(rec);
            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("httpx_web_presence", "httpx Web Presence",
                    "Web service presence on " + cidr, rec, "low"));
            }
        }

        // 5. masscan fast sample (requires sudo)
        if (selectedTools.contains("masscan") && toolPaths.containsKey("masscan")) {
            ctx.log("[*] Step 6/8 — Executing masscan top-ports sample...");
            CommandRecord rec = ProcessExecutor.execute("masscan", toolPaths.get("masscan"),
                List.of(cidr, "--top-ports", "100", "--rate", "1000"),
                timeoutMs, ctx, line -> ctx.log("[masscan] " + line), null, sudoPassword);
            records.add(rec);
            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(buildToolFinding("masscan_sample", "Masscan Fast Sample",
                    "Top-100 port sampling on " + cidr, rec, "medium"));
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  HELPERS
    // ═══════════════════════════════════════════════════════════════════

    private Map<String, Object> buildToolFinding(String type, String title, String desc, CommandRecord rec, String severity) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("type", type); 
        f.put("title", title); 
        f.put("description", desc);
        f.put("severity", severity); 
        f.put("status", rec.exitCode == 0 ? "CONFIRMED" : "FAILED");
        return f;
    }

    private Map<String, Object> buildIntelligenceFinding(Map<String, Object> intel, String target) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("type", "infrastructure_discovery"); f.put("title", "Target Intelligence: " + target);
        f.put("severity", "info"); f.put("status", "confirmed");
        f.put("description", "Mandatory infrastructure discovery via dnsx/httpx.");
        f.put("details", intel);
        return f;
    }

    private Path resolveOutputPath(String mode, String fileName) {
        String ts = String.valueOf(System.currentTimeMillis() / 1000);
        Path outputDir = Path.of(System.getProperty("user.dir", "."), "reports/outputs");
        try { Files.createDirectories(outputDir); } catch (Exception ignored) {}
        return outputDir.resolve(mode + "_" + ts + "_" + fileName);
    }

    private long parseTimeout(String raw) {
        try { long s = Long.parseLong(raw.trim()); return Math.max(10_000L, Math.min(s * 1000L, 600_000L)); }
        catch (NumberFormatException e) { return DEFAULT_TIMEOUT_MS; }
    }

    private String truncate(String v, int max) { return v == null ? "" : v.length() <= max ? v : v.substring(0, max) + "..."; }
}
