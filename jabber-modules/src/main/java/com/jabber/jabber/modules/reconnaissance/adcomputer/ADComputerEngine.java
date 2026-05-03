package com.jabber.jabber.modules.reconnaissance.adcomputer;

import com.jabber.jabber.data.model.ModuleResult;
import com.jabber.jabber.data.model.TaskContext;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ADComputerEngine — 8-Step Execution Doctrine Implementation.
 */
public class ADComputerEngine {

    private static final String MODULE_ID = "recon-ad-computers";
    private final ToolManager toolManager;

    public ADComputerEngine(ToolManager toolManager) {
        this.toolManager = toolManager;
    }

    public ModuleResult execute(Map<String, String> input, TaskContext ctx) {
        String targetInput = input.getOrDefault("dc", "unknown");
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
            if (!"ACTIVE".equals(modeRaw) && !"SURVEY".equals(modeRaw)) {
                result.fail("Unsupported mode: " + modeRaw + ". Valid modes: ACTIVE, SURVEY.");
                return result;
            }
            ctx.log("[+] Mode validated: " + modeRaw);
            ctx.reportProgress(5);

            // ── Step 2: Sanitize Schema ──
            ctx.log("[*] Step 2/8 — Sanitizing inputs...");
            String dc = InputSanitizer.validateTarget(input.getOrDefault("dc", ""));
            String domain = InputSanitizer.validateDomain(input.getOrDefault("domain", ""));
            String baseDn = InputSanitizer.validateBaseDn(input.getOrDefault("base_dn", ""));
            
            String user = "";
            String pass = "";
            if ("ACTIVE".equals(modeRaw)) {
                user = InputSanitizer.validateUsername(input.getOrDefault("user", ""));
                pass = InputSanitizer.validatePassword(input.getOrDefault("pass", ""));
            }
            ctx.log("[+] Target: " + dc + " | Domain: " + domain);
            ctx.reportProgress(10);

            // ── Step 3: Target Intelligence ──
            ctx.log("[*] Step 3/8 — Target intelligence...");
            Map<String, Object> intelligence = new LinkedHashMap<>();
            intelligence.put("dc", dc);
            intelligence.put("domain", domain);
            ctx.reportProgress(20);

            // ── Step 4: Tool Readiness ──
            ctx.log("[*] Step 4/8 — Verifying tool readiness...");
            Map<String, String> toolPaths = new LinkedHashMap<>();
            for (ToolManager.ToolDefinition def : toolManager.getRequiredTools()) {
                ToolManager.ToolStatus status = toolManager.getToolStatus(def.id);
                if (status.isInstalled()) {
                    toolPaths.put(def.id, status.getPath());
                    ctx.log("[+] Tool ready: " + def.id + " → " + status.getPath());
                } else {
                    ctx.log("[~] Tool missing: " + def.id + " — associated steps will be skipped.");
                }
            }
            ctx.reportProgress(30);

            // ── Step 5 & 6: Dynamic Command Pipeline Orchestration ──
            ctx.log("[*] Step 5/8 — Executing pipeline for mode " + modeRaw + "...");
            if ("ACTIVE".equals(modeRaw)) {
                executeACTIVEPipeline(dc, domain, baseDn, user, pass, toolPaths, selectedTools, ctx, allRecords, allFindings);
            } else {
                executeSURVEYPipeline(dc, domain, baseDn, toolPaths, selectedTools, ctx, allRecords, allFindings);
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
                modeRaw, dc, allRecords, allFindings, intelligence, startedAt
            );
            result.setNormalizedOutput(payload.normalizedOutput);
            result.complete(payload.output);

            ctx.log("[+] AD Computer Enumerator completed: " + allFindings.size() + " findings extracted.");
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
    //  SURVEY Pipeline
    // ═══════════════════════════════════════════════════════════════════

    private void executeSURVEYPipeline(
            String dc, String domain, String baseDn,
            Map<String, String> toolPaths, List<String> selectedTools,
            TaskContext ctx, List<CommandRecord> records,
            List<Map<String, Object>> findings) {

        // 1. ldapsearch (LDAP List)
        if (shouldRun("ldapsearch", selectedTools) && toolPaths.containsKey("ldapsearch")) {
            ctx.log("[*] Executing anonymous ldapsearch...");
            List<String> args = new ArrayList<>(List.of("-x", "-H", "ldap://" + dc));
            if (!baseDn.isBlank()) { args.add("-b"); args.add(baseDn); }
            args.add("(objectClass=computer)");
            args.add("dNSHostName");
            args.add("operatingSystem");
            args.add("sAMAccountName");

            CommandRecord rec = ProcessExecutor.execute("ldapsearch", toolPaths.get("ldapsearch"),
                args, 45_000L, ctx, line -> {}, null);
            records.add(rec);
            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(parseLdapOutput(rec.stdout));
            }
        }

        // 2. dig (SRV Discovery)
        if (shouldRun("dig", selectedTools) && toolPaths.containsKey("dig")) {
            ctx.log("[*] Executing dig SRV query...");
            CommandRecord rec = ProcessExecutor.execute("dig", toolPaths.get("dig"),
                List.of("-t", "SRV", "_ldap._tcp." + domain), 15_000L, ctx, line -> {}, null);
            records.add(rec);
            if (rec.exitCode == 0 && rec.stdout.contains("ANSWER SECTION:")) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("type", "srv_records");
                f.put("records", extractSrvAnswers(rec.stdout));
                findings.add(f);
            }
        }

        // 3. rpcclient (Null Session Probe)
        if (shouldRun("rpcclient", selectedTools) && toolPaths.containsKey("rpcclient")) {
            ctx.log("[*] Executing rpcclient null session probe...");
            CommandRecord rec = ProcessExecutor.execute("rpcclient", toolPaths.get("rpcclient"),
                List.of("-U", "", "-N", "-c", "enumprivs", dc), 20_000L, ctx, line -> {}, null);
            records.add(rec);
            // Ignore finding extraction for null probe unless it yields something, telemetry is enough
        }

        // 4. nmap -sn
        if (shouldRun("nmap", selectedTools) && toolPaths.containsKey("nmap")) {
            ctx.log("[*] Executing nmap ping sweep on DC subnet...");
            // assuming DC subnet is /24, just a probe
            String subnet = dc.replaceAll("\\.\\d+$", ".0/24");
            CommandRecord rec = ProcessExecutor.execute("nmap", toolPaths.get("nmap"),
                List.of("-sn", subnet), 45_000L, ctx, line -> {}, null);
            records.add(rec);
        }

        // 5. net ads info
        if (shouldRun("net", selectedTools) && toolPaths.containsKey("net")) {
            ctx.log("[*] Executing net ads info...");
            CommandRecord rec = ProcessExecutor.execute("net", toolPaths.get("net"),
                List.of("ads", "info", "-S", dc), 20_000L, ctx, line -> {}, null);
            records.add(rec);
            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("type", "domain_info");
                f.put("info", rec.stdout.trim());
                findings.add(f);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  ACTIVE Pipeline
    // ═══════════════════════════════════════════════════════════════════

    private void executeACTIVEPipeline(
            String dc, String domain, String baseDn, String user, String pass,
            Map<String, String> toolPaths, List<String> selectedTools,
            TaskContext ctx, List<CommandRecord> records,
            List<Map<String, Object>> findings) {

        // 1. Auth LDAP
        if (shouldRun("ldapsearch", selectedTools) && toolPaths.containsKey("ldapsearch")) {
            ctx.log("[*] Executing authenticated ldapsearch...");
            List<String> args = new ArrayList<>(List.of("-x", "-H", "ldap://" + dc, "-D", user, "-w", pass));
            if (!baseDn.isBlank()) { args.add("-b"); args.add(baseDn); }
            args.add("(objectClass=computer)");
            args.add("dNSHostName");
            args.add("operatingSystem");
            args.add("sAMAccountName");

            CommandRecord rec = ProcessExecutor.execute("ldapsearch", toolPaths.get("ldapsearch"),
                args, 45_000L, ctx, line -> {}, null);
            records.add(rec);
            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(parseLdapOutput(rec.stdout));
            }
        }

        // 2. rpcclient Enum Users
        if (shouldRun("rpcclient", selectedTools) && toolPaths.containsKey("rpcclient")) {
            ctx.log("[*] Executing rpcclient user enumeration...");
            CommandRecord rec = ProcessExecutor.execute("rpcclient", toolPaths.get("rpcclient"),
                List.of("-U", user + "%" + pass, "-c", "enumdomusers", dc), 30_000L, ctx, line -> {}, null);
            records.add(rec);
        }

        // 3. crackmapexec smb validation
        if (shouldRun("crackmapexec", selectedTools) && toolPaths.containsKey("crackmapexec")) {
            ctx.log("[*] Executing crackmapexec SMB validation on subnet...");
            String subnet = dc.replaceAll("\\.\\d+$", ".0/24");
            CommandRecord rec = ProcessExecutor.execute("crackmapexec", toolPaths.get("crackmapexec"),
                List.of("smb", subnet, "-u", user, "-p", pass), 90_000L, ctx, line -> {}, null);
            records.add(rec);
            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.add(parseCmeSmbOutput(rec.stdout));
            }
        }

        // 4. nmap -sV -O
        if (shouldRun("nmap", selectedTools) && toolPaths.containsKey("nmap")) {
            ctx.log("[*] Executing nmap OS fingerprinting...");
            String subnet = dc.replaceAll("\\.\\d+$", ".0/24");
            CommandRecord rec = ProcessExecutor.execute("nmap", toolPaths.get("nmap"),
                List.of("-sV", "-O", "-p", "445,139", subnet), 120_000L, ctx, line -> {}, null);
            records.add(rec);
        }

        // 5. dig A
        if (shouldRun("dig", selectedTools) && toolPaths.containsKey("dig")) {
            ctx.log("[*] Executing dig A query...");
            CommandRecord rec = ProcessExecutor.execute("dig", toolPaths.get("dig"),
                List.of("-t", "A", dc), 15_000L, ctx, line -> {}, null);
            records.add(rec);
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  PARSERS
    // ═══════════════════════════════════════════════════════════════════

    private Map<String, Object> parseLdapOutput(String stdout) {
        List<Map<String, String>> computers = new ArrayList<>();
        String[] lines = stdout.split("\\r?\\n");
        Map<String, String> current = null;

        for (String line : lines) {
            if (line.startsWith("dn: ")) {
                if (current != null && current.containsKey("hostname")) computers.add(current);
                current = new LinkedHashMap<>();
            } else if (current != null && line.startsWith("dNSHostName: ")) {
                current.put("hostname", line.substring("dNSHostName: ".length()).trim());
            } else if (current != null && line.startsWith("sAMAccountName: ") && !current.containsKey("hostname")) {
                current.put("hostname", line.substring("sAMAccountName: ".length()).trim());
            } else if (current != null && line.startsWith("operatingSystem: ")) {
                current.put("os", line.substring("operatingSystem: ".length()).trim());
            }
        }
        if (current != null && current.containsKey("hostname")) computers.add(current);

        Map<String, Object> f = new LinkedHashMap<>();
        f.put("type", "ldap_computers");
        f.put("computers", computers);
        return f;
    }

    private Map<String, Object> parseCmeSmbOutput(String stdout) {
        List<Map<String, String>> hosts = new ArrayList<>();
        // CME lines usually look like:
        // SMB         192.168.1.10    445    DC01      [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:contoso.local)
        // SMB         192.168.1.10    445    DC01      [+] contoso.local\\user:pass (Pwn3d!)
        
        String[] lines = stdout.split("\\r?\\n");
        for (String line : lines) {
            if (line.contains("SMB") && line.contains("445")) {
                Map<String, String> h = new LinkedHashMap<>();
                String target = extractIpOrHost(line);
                h.put("target", target);
                
                if (line.contains("(Pwn3d!)")) {
                    h.put("status", "Pwn3d!");
                    h.put("details", "Admin privileges acquired");
                } else if (line.contains("[+]")) {
                    h.put("status", "+");
                    h.put("details", "Login successful");
                } else if (line.contains("[-]")) {
                    h.put("status", "-");
                    h.put("details", "Login failed");
                } else if (line.contains("[*]")) {
                    h.put("status", "Info");
                    Matcher m = Pattern.compile("\\[\\*\\]\\s+(.*)").matcher(line);
                    if (m.find()) h.put("details", m.group(1));
                    else h.put("details", "Fingerprinted");
                }
                
                if (!h.containsKey("details")) h.put("details", "Unknown");
                hosts.add(h);
            }
        }

        Map<String, Object> f = new LinkedHashMap<>();
        f.put("type", "smb_validation");
        f.put("hosts", hosts);
        return f;
    }

    private String extractIpOrHost(String line) {
        Matcher m = Pattern.compile("SMB\\s+([a-zA-Z0-9.-]+)\\s+445").matcher(line);
        if (m.find()) return m.group(1);
        return "Unknown";
    }

    private String extractSrvAnswers(String stdout) {
        StringBuilder sb = new StringBuilder();
        boolean inAnswer = false;
        for (String line : stdout.split("\\r?\\n")) {
            if (line.startsWith(";; ANSWER SECTION:")) {
                inAnswer = true;
                continue;
            } else if (inAnswer && line.startsWith(";;")) {
                break;
            } else if (inAnswer && !line.isBlank()) {
                sb.append(line).append("\n");
            }
        }
        return sb.toString().trim();
    }
    private boolean shouldRun(String toolId, List<String> selectedTools) {
        if (selectedTools == null || selectedTools.isEmpty()) return false;
        if (selectedTools.size() == 1 && selectedTools.get(0).isEmpty()) return false;
        return selectedTools.contains(toolId);
    }
}
