package com.jabber.jabber.modules.reconnaissance.dnsenum;

import com.jabber.jabber.data.model.ModuleResult;
import com.jabber.jabber.data.model.TaskContext;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * DNSEnumeratorEngine — High-Fidelity DNS Intelligence Orchestrator.
 */
public class DNSEnumeratorEngine {

    private static final String MODULE_ID = "recon-dns-enum";
    private final ToolManager toolManager;

    public DNSEnumeratorEngine(ToolManager toolManager) {
        this.toolManager = toolManager;
    }

    public ModuleResult execute(Map<String, String> input, TaskContext ctx) {
        String mode = input.getOrDefault("mode", "SRVY").toUpperCase().trim();
        String domain = input.getOrDefault("domain", "").trim();
        List<String> selectedTools = input.containsKey("selectedTools")
            ? (input.get("selectedTools").isBlank() ? new ArrayList<>() : Arrays.asList(input.get("selectedTools").split(",")))
            : new ArrayList<>();

        ModuleResult result = new ModuleResult(ctx.getTaskId(), MODULE_ID);
        result.setTarget(domain);

        if (selectedTools.isEmpty() || (selectedTools.size() == 1 && selectedTools.get(0).isBlank())) {
            result.fail("[Must select a tool for execution]");
            return result;
        }

        if (domain == null || domain.isBlank()) {
            result.fail("[Input required for execution]");
            return result;
        }
        long startedAt = System.currentTimeMillis();
        List<CommandRecord> allRecords = new ArrayList<>();
        List<Map<String, Object>> allFindings = new ArrayList<>();

        try {
            // ── Step 1: Validate Mode ──
            ctx.log("[*] Step 1/8 — Validating execution mode...");
            if (!List.of("SRVY", "BRUT").contains(mode)) {
                result.fail("Unsupported mode: " + mode);
                return result;
            }

            // ── Step 2: Sanitize Schema ──
            ctx.log("[*] Step 2/8 — Sanitizing inputs...");
            List<String> errors = InputSanitizer.validate(mode, input);
            if (!errors.isEmpty()) {
                result.fail("Validation failed: " + String.join(", ", errors));
                return result;
            }

            // ── Step 3: Target Intelligence (Discovery) ──
            ctx.log("[*] Step 3/8 — Identifying target infrastructure: " + domain);
            ctx.reportProgress(10);

            // ── Step 4: Tool Readiness ──
            ctx.log("[*] Step 4/8 — Verifying tool arsenal readiness...");
            Map<String, String> toolPaths = new HashMap<>();
            for (ToolManager.ToolDefinition def : toolManager.getRequiredTools()) {
                ToolManager.ToolStatus status = toolManager.getToolStatus(def.id);
                if (status.isInstalled()) toolPaths.put(def.id, status.getPath());
            }

            // ── Step 5 & 6: Dynamic Command Orchestration ──
            ProcessExecutor executor = new ProcessExecutor();
            
            if ("SRVY".equals(mode)) {
                executeSurveyPipeline(domain, toolPaths, selectedTools, executor, ctx, allRecords, allFindings);
            } else {
                String wordlist = input.get("wordlist");
                executeBrutePipeline(domain, wordlist, toolPaths, selectedTools, executor, ctx, allRecords, allFindings);
            }

            // ── Step 7: Findings Extraction ──
            ctx.log("[*] Step 7/8 — Consolidating intelligence dossiers...");
            for (Map<String, Object> f : allFindings) result.addFinding(f);

            // ── Step 8: Full Telemetry ──
            ctx.log("[*] Step 8/8 — Finalizing reporting pipeline...");
            ReportGenerator gen = new ReportGenerator();
            ReportGenerator.ReportPayload payload = gen.buildReport(mode, domain, allRecords, allFindings, startedAt);
            
            result.setNormalizedOutput(payload.normalizedOutput);
            result.complete(payload.output);
            
            ctx.log("[+] DNS Enumeration completed: " + allFindings.size() + " findings extracted.");
            ctx.reportProgress(100);

        } catch (Exception e) {
            result.fail("Execution failed: " + e.getMessage());
            ctx.log("[!] FATAL: " + e.getMessage());
        }
        return result;
    }

    private void executeSurveyPipeline(String domain, Map<String, String> toolPaths, List<String> selectedTools, ProcessExecutor executor, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {
        // 1. Subfinder (Passive Discovery)
        if (shouldRun("subfinder", selectedTools) && toolPaths.containsKey("subfinder")) {
            ctx.log("[*] Phase 1/5: Passive discovery via Subfinder...");
            CommandRecord rec = executor.execute("subfinder", List.of(toolPaths.get("subfinder"), "-d", domain, "-silent", "-json"), ctx, 60000);
            records.add(rec);
            if (rec.exitCode() == 0) findings.addAll(parseSubfinderJson(rec.stdout()));
        }

        // 2. dnsx (Resolution)
        if (shouldRun("dnsx", selectedTools) && toolPaths.containsKey("dnsx")) {
            ctx.log("[*] Phase 2/5: Multi-record resolution via dnsx...");
            CommandRecord rec = executor.execute("dnsx", List.of(toolPaths.get("dnsx"), "-d", domain, "-a", "-aaaa", "-cname", "-mx", "-ns", "-soa", "-txt", "-resp", "-json", "-silent"), ctx, 30000);
            records.add(rec);
            if (rec.exitCode() == 0) findings.addAll(parseDnsxJson(rec.stdout()));
        }

        // 3. dig (ANY query)
        if (shouldRun("dig", selectedTools) && toolPaths.containsKey("dig")) {
            ctx.log("[*] Phase 3/5: Recursive query via dig...");
            CommandRecord rec = executor.execute("dig", List.of(toolPaths.get("dig"), domain, "ANY"), ctx, 10000);
            records.add(rec);
        }

        // 4. whois (Attribution)
        if (shouldRun("whois", selectedTools) && toolPaths.containsKey("whois")) {
            ctx.log("[*] Phase 4/5: Ownership attribution via Whois...");
            CommandRecord rec = executor.execute("whois", List.of(toolPaths.get("whois"), domain), ctx, 10000);
            records.add(rec);
        }

        // 5. nmap (Liveness)
        if (shouldRun("nmap", selectedTools) && toolPaths.containsKey("nmap")) {
            ctx.log("[*] Phase 5/5: Infrastructure liveness via Nmap...");
            CommandRecord rec = executor.execute("nmap", List.of(toolPaths.get("nmap"), "-sn", domain), ctx, 30000);
            records.add(rec);
        }
    }

    private void executeBrutePipeline(String domain, String wordlist, Map<String, String> toolPaths, List<String> selectedTools, ProcessExecutor executor, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings) {
        if (shouldRun("dnsx", selectedTools) && toolPaths.containsKey("dnsx")) {
            ctx.log("[*] Phase 1/3: Active DNS brute-forcing...");
            List<String> cmd = new ArrayList<>(List.of(toolPaths.get("dnsx"), "-d", domain, "-a", "-resp", "-json", "-silent"));
            if (wordlist != null && !wordlist.isBlank()) { cmd.add("-w"); cmd.add(wordlist); }
            CommandRecord rec = executor.execute("dnsx", cmd, ctx, 300000);
            records.add(rec);
            if (rec.exitCode() == 0) findings.addAll(parseDnsxJson(rec.stdout()));
        }
        
        if (shouldRun("dig", selectedTools) && toolPaths.containsKey("dig")) {
            ctx.log("[*] Phase 2/3: AXFR Zone Transfer attempt...");
            CommandRecord rec = executor.execute("dig", List.of(toolPaths.get("dig"), "@8.8.8.8", domain, "AXFR"), ctx, 20000);
            records.add(rec);
        }
    }

    private boolean shouldRun(String toolId, List<String> selected) {
        if (selected.isEmpty()) return false;
        if (selected.size() == 1 && selected.get(0).isEmpty()) return false;
        return selected.contains(toolId);
    }

    private List<Map<String, Object>> parseSubfinderJson(String stdout) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (stdout == null) return list;
        for (String line : stdout.split("\\R")) {
            if (line.trim().startsWith("{")) {
                String host = extractJsonValue(line, "host");
                if (host != null) {
                    Map<String, Object> f = new LinkedHashMap<>();
                    f.put("type", "subdomain_discovery");
                    f.put("hostname", host);
                    f.put("resolver", "Passive Source");
                    f.put("status", "Identified");
                    list.add(f);
                }
            }
        }
        return list;
    }

    private List<Map<String, Object>> parseDnsxJson(String stdout) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (stdout == null) return list;
        for (String line : stdout.split("\\R")) {
            if (line.trim().startsWith("{")) {
                String host = extractJsonValue(line, "host");
                String type = extractJsonValue(line, "type");
                String value = extractJsonArrayFirst(line, type != null ? type.toLowerCase() : "a");
                if (value == null) value = extractJsonArrayFirst(line, "a");
                
                if (host != null && type != null) {
                    Map<String, Object> f = new LinkedHashMap<>();
                    f.put("type", "dns_record");
                    f.put("name", host);
                    f.put("type", type);
                    f.put("value", value != null ? value : "-");
                    f.put("ttl", extractJsonValue(line, "ttl"));
                    list.add(f);
                }
            }
        }
        return list;
    }

    private String extractJsonValue(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\":\\s*\"?([^\",}]+)\"?");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1).trim() : null;
    }

    private String extractJsonArrayFirst(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\":\\s*\\[\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1).trim() : null;
    }
}
