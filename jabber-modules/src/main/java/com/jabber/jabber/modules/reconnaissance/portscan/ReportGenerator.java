package com.jabber.jabber.modules.reconnaissance.portscan;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * ReportGenerator — Artifact & findings aggregator for the Port Scanner module.
 * Optimized for Premium Intelligence Presentation.
 */
public class ReportGenerator {

    public static final class ReportPayload {
        public final Map<String, Object> output;
        public final List<Map<String, Object>> findings;
        public final Map<String, Object> normalizedOutput;

        public ReportPayload(Map<String, Object> output, List<Map<String, Object>> findings, Map<String, Object> normalizedOutput) {
            this.output = output;
            this.findings = findings;
            this.normalizedOutput = normalizedOutput;
        }
    }

    public ReportPayload buildReport(
            String mode,
            String target,
            List<CommandRecord> commandRecords,
            List<Map<String, Object>> findings,
            Map<String, Object> intelligence,
            long startedAt) {

        long elapsedMs = System.currentTimeMillis() - startedAt;

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", mode);
        summary.put("target", target);
        summary.put("total_findings", findings.size());
        summary.put("tools_executed", commandRecords.size());
        summary.put("successful_tools", commandRecords.stream().filter(r -> r.exitCode == 0).count());
        summary.put("elapsed_ms", elapsedMs);

        List<Map<String, Object>> telemetry = commandRecords.stream()
            .map(CommandRecord::toMap).collect(Collectors.toList());

        List<Map<String, Object>> artifacts = buildArtifactManifest(mode);

        Map<String, Object> output = new LinkedHashMap<>();
        output.put("module", "recon-portscanner");
        output.put("mode", mode);
        output.put("target", target);
        output.put("summary", summary);
        output.put("intelligence", intelligence);
        output.put("findings", findings);
        output.put("artifacts", artifacts);

        Map<String, Object> normalizedOutput = buildNormalizedOutput(mode, target, summary, findings, telemetry, artifacts);

        return new ReportPayload(output, findings, normalizedOutput);
    }

    private List<Map<String, Object>> buildArtifactManifest(String mode) {
        List<Map<String, Object>> manifest = new ArrayList<>();
        String basePath = System.getProperty("user.dir", ".");

        for (String dir : List.of("reports/outputs", "reports/artifacts", "reports/logs", "reports/analysis", "reports/payloads")) {
            Path dirPath = Path.of(basePath, dir);
            if (!Files.isDirectory(dirPath)) continue;
            try (var stream = Files.list(dirPath)) {
                stream.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().contains(mode + "_"))
                    .forEach(file -> {
                        Map<String, Object> entry = new LinkedHashMap<>();
                        entry.put("name", file.getFileName().toString());
                        entry.put("directory", dir);
                        entry.put("path", file.toAbsolutePath().toString());
                        try {
                            entry.put("size_bytes", Files.size(file));
                            entry.put("sha256", computeSHA256(file));
                        } catch (Exception e) {
                            entry.put("size_bytes", -1);
                            entry.put("sha256", "error: " + e.getMessage());
                        }
                        manifest.add(entry);
                    });
            } catch (Exception ignored) {}
        }
        return manifest;
    }

    private String computeSHA256(Path file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(Files.readAllBytes(file));
        StringBuilder sb = new StringBuilder(hash.length * 2);
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private Map<String, Object> buildNormalizedOutput(
            String mode, String target, Map<String, Object> summary,
            List<Map<String, Object>> findings, List<Map<String, Object>> telemetry,
            List<Map<String, Object>> artifacts) {

        Map<String, Object> normalized = new LinkedHashMap<>();

        Map<String, Object> parsed = new LinkedHashMap<>();
        parsed.put("status", findings.isEmpty() ? "NO_FINDINGS" : "INTELLIGENCE_EXTRACTED");
        parsed.put("mode", mode);
        parsed.put("target", target);
        parsed.put("details", summary);
        parsed.put("evidence", findings);
        
        parsed.put("html_report", generateHtmlReport(mode, target, summary, findings, telemetry, artifacts));

        normalized.put("parsed_output", parsed);

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("module", "recon-portscanner");
        meta.put("mode", mode);
        meta.put("version", "V 5.5");
        normalized.put("metadata", meta);

        return normalized;
    }

    @SuppressWarnings("unchecked")
    private String generateHtmlReport(String mode, String target, Map<String, Object> summary, List<Map<String, Object>> findings, List<Map<String, Object>> telemetry, List<Map<String, Object>> artifacts) {
        StringBuilder html = new StringBuilder();
        
        html.append("<style>");
        html.append(":root { --bg: #0b0e14; --panel: #1a1f29; --accent: #4bb3fd; --good: #3fb950; --warn: #f59e0b; --bad: #f85149; --muted: #8b949e; --line: #2d333b; }");
        html.append(".dossier { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: #adbac7; padding: 2.5rem; border-radius: 16px; border: 1px solid var(--line); }");
        html.append(".header { border-bottom: 2px solid var(--line); padding-bottom: 1.5rem; margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: flex-end; }");
        html.append(".header h1 { margin: 0; color: white; font-size: 1.75rem; letter-spacing: -0.5px; }");
        html.append(".grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; margin-bottom: 2.5rem; }");
        html.append(".stat-card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 1.25rem; }");
        html.append(".stat-card label { display: block; font-size: 0.65rem; text-transform: uppercase; letter-spacing: 1.2px; color: var(--muted); margin-bottom: 6px; }");
        html.append(".stat-card value { font-size: 1.6rem; font-weight: 800; color: var(--accent); }");
        html.append(".section-title { font-size: 1.2rem; font-weight: 700; color: white; margin: 2rem 0 1rem; padding-left: 12px; border-left: 4px solid var(--accent); }");
        html.append(".table { width: 100%; border-collapse: collapse; background: var(--panel); border-radius: 10px; overflow: hidden; border: 1px solid var(--line); }");
        html.append(".table th { background: rgba(0,0,0,0.2); text-align: left; padding: 14px; font-size: 0.7rem; text-transform: uppercase; color: var(--muted); border-bottom: 1px solid var(--line); }");
        html.append(".table td { padding: 14px; border-bottom: 1px solid rgba(45,51,59,0.5); font-size: 0.85rem; }");
        html.append(".state-badge { padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 0.7rem; text-transform: uppercase; }");
        html.append("details summary { cursor: pointer; color: var(--muted); font-size: 0.8rem; padding: 1rem; border: 1px dashed var(--line); border-radius: 8px; text-align: center; margin-top: 2rem; list-style: none; transition: 0.2s; }");
        html.append("details summary:hover { background: rgba(75,179,253,0.05); border-color: var(--accent); color: var(--accent); }");
        html.append("</style>");

        html.append("<div class=\"dossier\">");
        
        // Header
        html.append("<div class=\"header\">");
        html.append("<div><h1>Port Analysis Report: ").append(escapeHtml(target)).append("</h1>");
        html.append("<span style=\"color: var(--muted); font-size: 0.85rem;\">JABBER V 5.5.0 Advanced Network Prober</span></div>");
        html.append("<div style=\"background: var(--accent); color: var(--bg); padding: 4px 12px; border-radius: 4px; font-weight: 800; font-size: 0.8rem;\">").append(mode).append("</div>");
        html.append("</div>");

        // Stats
        html.append("<div class=\"grid\">");
        html.append("<div class=\"stat-card\"><label>Findings Detected</label><value>").append(summary.get("total_findings")).append("</value></div>");
        html.append("<div class=\"stat-card\"><label>Successful Probes</label><value>").append(summary.get("successful_tools")).append("/").append(summary.get("tools_executed")).append("</value></div>");
        html.append("<div class=\"stat-card\"><label>Elapsed Time</label><value>").append(String.format("%.2fs", (long)summary.get("elapsed_ms") / 1000.0)).append("</value></div>");
        html.append("</div>");

        // Infrastructure Summary
        html.append("<div class=\"section-title\">Discovered Ports & Services</div>");
        
        boolean foundPorts = false;
        html.append("<table class=\"table\"><thead><tr><th>PORT</th><th>STATE</th><th>SERVICE</th><th>VERSION / EXTRA</th></tr></thead><tbody>");
        
        java.util.regex.Pattern portPattern = java.util.regex.Pattern.compile("^(\\d+)/([a-zA-Z0-9]+)\\s+(open|filtered|closed)\\s+([^\\s]+)\\s*(.*)$");
        for (Map<String, Object> rec : telemetry) {
            if ("nmap".equals(rec.get("tool"))) {
                String stdout = (String) rec.getOrDefault("stdout", "");
                if (stdout == null || stdout.isBlank()) stdout = (String) rec.getOrDefault("stdout_preview", "");
                
                String[] lines = stdout.split("\\r?\\n");
                for (String line : lines) {
                    java.util.regex.Matcher m = portPattern.matcher(line.trim());
                    if (m.find()) {
                        foundPorts = true;
                        String port = m.group(1) + "/" + m.group(2);
                        String state = m.group(3);
                        String service = m.group(4);
                        String version = m.group(5).isEmpty() ? "-" : m.group(5);

                        String stateColor = "open".equals(state) ? "var(--good)" : ("filtered".equals(state) ? "var(--warn)" : "var(--bad)");
                        String stateBg = "open".equals(state) ? "rgba(63,185,80,0.1)" : ("filtered".equals(state) ? "rgba(245,158,11,0.1)" : "rgba(248,81,73,0.1)");

                        html.append("<tr>");
                        html.append("<td style=\"font-weight: 700; color: var(--accent);\">").append(escapeHtml(port)).append("</td>");
                        html.append("<td><span class=\"state-badge\" style=\"color: ").append(stateColor).append("; background: ").append(stateBg).append(";\">").append(state).append("</span></td>");
                        html.append("<td style=\"font-weight: 600;\">").append(escapeHtml(service)).append("</td>");
                        html.append("<td style=\"color: var(--muted); font-size: 0.8rem;\">").append(escapeHtml(version)).append("</td>");
                        html.append("</tr>");
                    }
                }
            }
        }

        if (!foundPorts) {
            html.append("<tr><td colspan=\"4\" style=\"text-align: center; color: var(--muted); padding: 2rem;\">No active ports identified in this scan.</td></tr>");
        }
        html.append("</tbody></table>");

        // Metadata Findings
        List<Map<String, Object>> metaFindings = findings.stream().filter(f -> !"nmap_service_id".equals(f.get("type")) && !"masscan_probe".equals(f.get("type"))).collect(Collectors.toList());
        if (!metaFindings.isEmpty()) {
            html.append("<div class=\"section-title\">Infrastructure Metadata</div>");
            html.append("<table class=\"table\"><thead><tr><th>FINDING TYPE</th><th>SUMMARY</th><th>REMARK</th></tr></thead><tbody>");
            for (Map<String, Object> f : metaFindings) {
                html.append("<tr>");
                html.append("<td style=\"font-weight: 700; color: #a78bfa;\">").append(escapeHtml((String)f.get("type"))).append("</td>");
                html.append("<td>").append(escapeHtml((String)f.get("title"))).append("</td>");
                html.append("<td style=\"color: var(--muted);\">").append(escapeHtml((String)f.get("description"))).append("</td>");
                html.append("</tr>");
            }
            html.append("</tbody></table>");
        }

        // Telemetry
        html.append("<details>");
        html.append("<summary>[+] VIEW SCAN TELEMETRY & PIPELINE LOGS</summary>");
        html.append("<div style=\"margin-top: 1.5rem;\">");
        html.append("<div class=\"section-title\">Execution Pipeline</div>");
        html.append("<table class=\"table\"><thead><tr><th>TOOL</th><th>COMMAND</th><th>STATUS</th><th>TIME</th></tr></thead><tbody>");
        for (Map<String, Object> t : telemetry) {
            html.append("<tr>");
            html.append("<td style=\"font-weight: 700;\">").append(t.get("tool")).append("</td>");
            html.append("<td style=\"font-family: monospace; font-size: 0.65rem; color: var(--muted);\">").append(escapeHtml((String)t.get("command"))).append("</td>");
            String status = (String)t.get("status");
            String color = "success".equals(status) ? "var(--good)" : "var(--bad)";
            html.append("<td style=\"font-weight: 800; color: ").append(color).append(";\">").append(status.toUpperCase()).append("</td>");
            html.append("<td>").append(t.get("duration_ms")).append("ms</td>");
            html.append("</tr>");
        }
        html.append("</tbody></table>");
        html.append("</div></details>");

        html.append("</div>"); // Close dossier
        return html.toString();
    }

    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
}
