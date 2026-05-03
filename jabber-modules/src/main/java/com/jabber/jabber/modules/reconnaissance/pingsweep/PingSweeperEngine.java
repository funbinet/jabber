package com.jabber.jabber.modules.reconnaissance.pingsweep;

import com.jabber.jabber.data.model.ModuleResult;
import com.jabber.jabber.data.model.TaskContext;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PingSweeperEngine — Elite Infrastructure Discovery Engine.
 * Orchestrates fping, hping3, masscan, rustscan, netdiscover, and enum4linux.
 */
public class PingSweeperEngine {

    private static final String MODULE_ID = "recon-pingsweep";
    private final ToolManager toolManager;

    public PingSweeperEngine(ToolManager toolManager) {
        this.toolManager = toolManager;
    }

    public ModuleResult execute(Map<String, String> input, TaskContext ctx) {
        String mode = input.getOrDefault("mode", "SRVY").toUpperCase().trim();
        String cidr = input.getOrDefault("cidr", "").trim();
        String sudoPassword = input.getOrDefault("_sudoPassword", "");
        List<String> selectedTools = input.containsKey("selectedTools")
            ? (input.get("selectedTools").isBlank() ? new ArrayList<>() : Arrays.asList(input.get("selectedTools").split(",")))
            : new ArrayList<>();
        
        ModuleResult result = new ModuleResult(ctx.getTaskId(), MODULE_ID);
        result.setTarget(cidr);

        if (selectedTools.isEmpty() || (selectedTools.size() == 1 && selectedTools.get(0).isBlank())) {
            result.fail("[Must select a tool for execution]");
            return result;
        }

        if (cidr == null || cidr.isBlank()) {
            result.fail("[Input required for execution]");
            return result;
        }
        long startedAt = System.currentTimeMillis();
        List<CommandRecord> allRecords = new ArrayList<>();
        List<Map<String, Object>> allFindings = new ArrayList<>();

        try {
            // ── Step 1: Mode Validation ──
            if (!List.of("SRVY", "STH", "AGGR", "ADVR").contains(mode)) {
                result.fail("Unsupported mode: " + mode);
                return result;
            }

            // ── Step 2: Sanitization ──
            List<String> errors = InputSanitizer.validate(mode, input);
            if (!errors.isEmpty()) {
                result.fail("Validation failed: " + String.join(", ", errors));
                return result;
            }

            // ── Step 3: Tool Readiness ──
            Map<String, String> toolPaths = new HashMap<>();
            for (ToolManager.ToolDefinition def : toolManager.getRequiredTools()) {
                ToolManager.ToolStatus status = toolManager.getToolStatus(def.id());
                if (status.isInstalled()) toolPaths.put(def.id(), status.getPath());
            }

            ProcessExecutor executor = new ProcessExecutor();

            // ── Step 4 & 5: Dynamic Pipelines ──
            switch (mode) {
                case "SRVY" -> executeSrvy(cidr, toolPaths, selectedTools, executor, ctx, allRecords, allFindings, sudoPassword);
                case "STH" -> executeSth(cidr, toolPaths, selectedTools, executor, ctx, allRecords, allFindings, sudoPassword);
                case "AGGR" -> executeAggr(cidr, toolPaths, selectedTools, executor, ctx, allRecords, allFindings, sudoPassword);
                case "ADVR" -> executeAdvr(cidr, toolPaths, selectedTools, executor, ctx, allRecords, allFindings, sudoPassword);
            }

            // ── Step 6: Findings Consolidation ──
            for (Map<String, Object> f : allFindings) result.addFinding(f);

            // ── Step 7: Premium Reporting ──
            ReportGenerator gen = new ReportGenerator();
            ReportGenerator.ReportPayload payload = gen.buildReport(mode, cidr, allRecords, allFindings, startedAt);
            
            result.setNormalizedOutput(payload.normalizedOutput());
            result.complete(payload.output());
            
            ctx.log("[+] Discovery completed: " + allFindings.size() + " intelligence items extracted.");
            ctx.reportProgress(100);

        } catch (Exception e) {
            result.fail("Execution failed: " + e.getMessage());
            ctx.log("[!] FATAL: " + e.getMessage());
        }
        return result;
    }

    private void executeSrvy(String cidr, Map<String, String> toolPaths, List<String> selectedTools, ProcessExecutor executor, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings, String sudo) {
        ctx.log("[*] Phase 1/3: Rapid ICMP discovery (fping)...");
        if (shouldRun("fping", selectedTools) && toolPaths.containsKey("fping")) {
            CommandRecord rec = executor.execute("fping", List.of(toolPaths.get("fping"), "-a", "-g", "-r", "1", cidr), ctx, 30000, null);
            records.add(rec);
            findings.addAll(parseFping(rec.stdout()));
        }

        ctx.log("[*] Phase 2/3: ARP mapping (arp-scan)...");
        if (shouldRun("arp-scan", selectedTools) && toolPaths.containsKey("arp-scan")) {
            CommandRecord rec = executor.execute("arp-scan", List.of(toolPaths.get("arp-scan"), "--localnet"), ctx, 30000, sudo);
            records.add(rec);
            findings.addAll(parseArpScan(rec.stdout()));
        }

        ctx.log("[*] Phase 3/3: Passive discovery (netdiscover)...");
        if (shouldRun("netdiscover", selectedTools) && toolPaths.containsKey("netdiscover")) {
            CommandRecord rec = executor.execute("netdiscover", List.of(toolPaths.get("netdiscover"), "-p", "-r", cidr, "-P"), ctx, 30000, sudo);
            records.add(rec);
            findings.addAll(parseNetdiscover(rec.stdout()));
        }
    }

    private void executeSth(String cidr, Map<String, String> toolPaths, List<String> selectedTools, ProcessExecutor executor, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings, String sudo) {
        ctx.log("[*] Phase 1/2: Surgical SYN probes (hping3)...");
        if (shouldRun("hping3", selectedTools) && toolPaths.containsKey("hping3")) {
            CommandRecord rec = executor.execute("hping3", List.of(toolPaths.get("hping3"), "-S", "-c", "1", cidr), ctx, 10000, sudo);
            records.add(rec);
        }

        ctx.log("[*] Phase 2/2: Stealth SYN scan (nmap)...");
        if (shouldRun("nmap", selectedTools) && toolPaths.containsKey("nmap")) {
            CommandRecord rec = executor.execute("nmap", List.of(toolPaths.get("nmap"), "-sS", "-Pn", cidr), ctx, 60000, sudo);
            records.add(rec);
        }
    }

    private void executeAggr(String cidr, Map<String, String> toolPaths, List<String> selectedTools, ProcessExecutor executor, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings, String sudo) {
        ctx.log("[*] Phase 1/3: High-speed sweep (masscan @ 1000/s)...");
        if (shouldRun("masscan", selectedTools) && toolPaths.containsKey("masscan")) {
            CommandRecord rec = executor.execute("masscan", List.of(toolPaths.get("masscan"), "-p1-65535", "--rate", "1000", cidr), ctx, 120000, sudo);
            records.add(rec);
            findings.addAll(parseMasscan(rec.stdout()));
        }

        ctx.log("[*] Phase 2/3: Rapid port discovery (rustscan)...");
        if (shouldRun("rustscan", selectedTools) && toolPaths.containsKey("rustscan")) {
            CommandRecord rec = executor.execute("rustscan", List.of(toolPaths.get("rustscan"), "-a", cidr), ctx, 60000, null);
            records.add(rec);
        }

        ctx.log("[*] Phase 3/3: ZMap infrastructure sweep...");
        if (shouldRun("zmap", selectedTools) && toolPaths.containsKey("zmap")) {
            CommandRecord rec = executor.execute("zmap", List.of(toolPaths.get("zmap"), "-p", "80", cidr, "-o", "-"), ctx, 60000, sudo);
            records.add(rec);
        }
    }

    private void executeAdvr(String cidr, Map<String, String> toolPaths, List<String> selectedTools, ProcessExecutor executor, TaskContext ctx, List<CommandRecord> records, List<Map<String, Object>> findings, String sudo) {
        ctx.log("[*] Phase 1/3: Service attribution & Fingerprinting (nmap)...");
        if (shouldRun("nmap", selectedTools) && toolPaths.containsKey("nmap")) {
            CommandRecord rec = executor.execute("nmap", List.of(toolPaths.get("nmap"), "-sV", "-O", "-p-", cidr), ctx, 600000, sudo);
            records.add(rec);
        }

        ctx.log("[*] Phase 2/3: Full SMB enumeration (enum4linux)...");
        if (shouldRun("enum4linux", selectedTools) && toolPaths.containsKey("enum4linux")) {
            CommandRecord rec = executor.execute("enum4linux", List.of(toolPaths.get("enum4linux"), "-a", cidr), ctx, 300000, null);
            records.add(rec);
        }

        ctx.log("[*] Phase 3/3: NetBIOS extraction (nbtscan)...");
        if (shouldRun("nbtscan", selectedTools) && toolPaths.containsKey("nbtscan")) {
            CommandRecord rec = executor.execute("nbtscan", List.of(toolPaths.get("nbtscan"), cidr), ctx, 30000, null);
            records.add(rec);
            findings.addAll(parseNbtscan(rec.stdout()));
        }
    }


    // ── Parsers ──

    private List<Map<String, Object>> parseFping(String stdout) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (stdout == null) return list;
        for (String line : stdout.split("\\R")) {
            String ip = line.trim();
            if (ip.matches("^(\\d{1,3}\\.){3}\\d{1,3}$")) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("type", "responsive_host");
                f.put("ip", ip);
                f.put("method", "ICMP (fping)");
                f.put("status", "ALIVE");
                list.add(f);
            }
        }
        return list;
    }

    private List<Map<String, Object>> parseArpScan(String stdout) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (stdout == null) return list;
        Pattern p = Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}\\s+([0-9a-fA-F:]{17})\\s+(.+)$");
        for (String line : stdout.split("\\R")) {
            Matcher m = p.matcher(line.trim());
            if (m.find()) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("type", "adjacency_map");
                f.put("ip", m.group(1));
                f.put("mac", m.group(2));
                f.put("vendor", m.group(3));
                list.add(f);
            }
        }
        return list;
    }

    private List<Map<String, Object>> parseNbtscan(String stdout) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (stdout == null) return list;
        Pattern p = Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}\\s+([^\\s]+)\\s+([^\\s]+)");
        for (String line : stdout.split("\\R")) {
            Matcher m = p.matcher(line.trim());
            if (m.find()) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("type", "netbios_inventory");
                f.put("ip", m.group(1));
                f.put("name", m.group(2));
                f.put("workgroup", m.group(3));
                list.add(f);
            }
        }
        return list;
    }

    private List<Map<String, Object>> parseMasscan(String stdout) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (stdout == null) return list;
        // Discovered open port 80/tcp on 192.168.1.1
        Pattern p = Pattern.compile("Discovered open port (\\d+)/(\\w+) on ((\\d{1,3}\\.){3}\\d{1,3})");
        for (String line : stdout.split("\\R")) {
            Matcher m = p.matcher(line.trim());
            if (m.find()) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("type", "open_port");
                f.put("ip", m.group(3));
                f.put("port", m.group(1));
                f.put("proto", m.group(2));
                f.put("method", "Masscan");
                list.add(f);
            }
        }
        return list;
    }

    private List<Map<String, Object>> parseNetdiscover(String stdout) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (stdout == null) return list;
        Pattern p = Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}\\s+([0-9a-fA-F:]{17})");
        for (String line : stdout.split("\\R")) {
            Matcher m = p.matcher(line.trim());
            if (m.find()) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("type", "responsive_host");
                f.put("ip", m.group(1));
                f.put("mac", m.group(2));
                f.put("method", "Passive ARP (Netdiscover)");
                f.put("status", "ALIVE");
                list.add(f);
            }
        }
        return list;
    }
    private boolean shouldRun(String toolId, List<String> selectedTools) {
        if (selectedTools.isEmpty()) return false;
        if (selectedTools.size() == 1 && selectedTools.get(0).isEmpty()) return false;
        return selectedTools.contains(toolId);
    }
}
