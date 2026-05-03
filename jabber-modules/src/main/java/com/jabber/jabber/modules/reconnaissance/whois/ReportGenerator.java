package com.jabber.jabber.modules.reconnaissance.whois;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * ReportGenerator — Artifact & findings aggregator for the Whois module.
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
        output.put("module", "recon-whois");
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
        meta.put("module", "recon-whois");
        meta.put("mode", mode);
        meta.put("version", "V 5.5");
        normalized.put("metadata", meta);

        return normalized;
    }

    @SuppressWarnings("unchecked")
    private String generateHtmlReport(String mode, String target, Map<String, Object> summary, List<Map<String, Object>> findings, List<Map<String, Object>> telemetry, List<Map<String, Object>> artifacts) {
        StringBuilder html = new StringBuilder();
        
        // CSS Baseline - Premium Dark Theme
        html.append("<style>");
        html.append(":root { --bg: #0b0f19; --panel: #161b22; --accent: #58a6ff; --good: #3fb950; --warn: #d29922; --bad: #f85149; --muted: #8b949e; --line: #30363d; }");
        html.append("* { box-sizing: border-box; }");
        html.append(".dossier { font-family: 'Inter', -apple-system, sans-serif; background: var(--bg); color: #c9d1d9; padding: 2rem; border-radius: 12px; }");
        html.append(".header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--line); padding-bottom: 1rem; margin-bottom: 2rem; }");
        html.append(".header h1 { margin: 0; font-size: 1.5rem; color: white; letter-spacing: -0.5px; }");
        html.append(".mode-badge { padding: 4px 12px; border-radius: 6px; font-weight: 800; font-size: 0.75rem; text-transform: uppercase; background: var(--accent); color: var(--bg); }");
        
        html.append(".grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }");
        html.append(".stat-card { background: var(--panel); padding: 1.25rem; border-radius: 10px; border: 1px solid var(--line); }");
        html.append(".stat-card label { color: var(--muted); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px; display: block; margin-bottom: 4px; }");
        html.append(".stat-card value { font-size: 1.5rem; font-weight: 700; color: var(--accent); }");
        
        html.append(".section { margin-bottom: 2.5rem; }");
        html.append(".section-title { font-size: 1.1rem; font-weight: 700; color: white; margin-bottom: 1rem; display: flex; align-items: center; gap: 8px; }");
        html.append(".section-title::before { content: ''; width: 4px; height: 1.2rem; background: var(--accent); border-radius: 2px; }");
        
        html.append(".card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; margin-bottom: 1rem; }");
        html.append(".card-body { padding: 1rem; }");
        html.append(".table { width: 100%; border-collapse: collapse; }");
        html.append(".table th { text-align: left; padding: 10px; font-size: 0.75rem; color: var(--muted); border-bottom: 1px solid var(--line); }");
        html.append(".table td { padding: 12px 10px; font-size: 0.85rem; border-bottom: 1px solid rgba(48,54,61,0.5); }");
        
        html.append(".telemetry-toggle { cursor: pointer; color: var(--muted); font-size: 0.8rem; text-align: center; padding: 1rem; border: 1px dashed var(--line); border-radius: 8px; margin-top: 2rem; transition: 0.2s; }");
        html.append(".telemetry-toggle:hover { color: var(--accent); border-color: var(--accent); background: rgba(88,166,255,0.05); }");
        html.append("details summary { list-style: none; }");
        html.append("details summary::-webkit-details-marker { display: none; }");
        html.append("</style>");

        html.append("<div class=\"dossier\">");

        // Header
        html.append("<div class=\"header\">");
        html.append("<div><h1>Intelligence Dossier: ").append(escapeHtml(target)).append("</h1>");
        html.append("<span style=\"color: var(--muted); font-size: 0.8rem;\">JABBER V 5.5.0 Hardcore Reconnaissance Module</span></div>");
        html.append("<div class=\"mode-badge\">Mode: ").append(escapeHtml(mode)).append("</div>");
        html.append("</div>");

        // Summary Dashboard
        html.append("<div class=\"grid\">");
        html.append("<div class=\"stat-card\"><label>Total Findings</label><value>").append(summary.get("total_findings")).append("</value></div>");
        html.append("<div class=\"stat-card\"><label>Successful Tools</label><value>").append(summary.get("successful_tools")).append("/").append(summary.get("tools_executed")).append("</value></div>");
        html.append("<div class=\"stat-card\"><label>Execution Time</label><value>").append(String.format("%.2fs", (long)summary.get("elapsed_ms") / 1000.0)).append("</value></div>");
        html.append("</div>");

        // Mode-Specific Findings
        html.append("<div class=\"section\">");
        html.append("<div class=\"section-title\">Extracted Intelligence Findings</div>");

        if (findings.isEmpty()) {
            html.append("<div class=\"card\"><div class=\"card-body\" style=\"text-align: center; color: var(--muted);\">No actionable intelligence recovered during this operation.</div></div>");
        } else {
            // Group and Render findings by type
            renderFindingGroup(html, "Identity & Persona Profiles", findings, "persona_profile", f -> {
                StringBuilder rows = new StringBuilder();
                rows.append("<tr>");
                rows.append("<td style=\"color: #f472b6; font-weight: 700;\">").append(escapeHtml((String)f.get("platform"))).append("</td>");
                rows.append("<td><a href=\"").append(escapeHtml((String)f.get("url"))).append("\" target=\"_blank\" style=\"color: var(--accent); text-decoration: none;\">").append(escapeHtml((String)f.get("url"))).append("</a></td>");
                rows.append("<td style=\"color: var(--good); font-weight: 600;\">").append(escapeHtml((String)f.get("status"))).append("</td>");
                rows.append("</tr>");
                return rows.toString();
            }, "PLATFORM", "PROFILE URL", "STATUS");

            renderFindingGroup(html, "Account Registration Discovery", findings, "registered_account", f -> {
                StringBuilder rows = new StringBuilder();
                rows.append("<tr>");
                rows.append("<td style=\"color: #38bdf8; font-weight: 700;\">").append(escapeHtml((String)f.get("platform"))).append("</td>");
                rows.append("<td style=\"color: var(--good); font-weight: 600;\">").append(escapeHtml((String)f.get("status"))).append("</td>");
                rows.append("<td>Confirmed via ").append(escapeHtml((String)f.get("email"))).append("</td>");
                rows.append("</tr>");
                return rows.toString();
            }, "PLATFORM", "STATUS", "IDENTITY");

            renderFindingGroup(html, "Credential & Data Breach Alerts", findings, "data_breach", f -> {
                StringBuilder rows = new StringBuilder();
                rows.append("<tr>");
                rows.append("<td style=\"color: var(--bad); font-weight: 700;\">").append(escapeHtml((String)f.get("source"))).append("</td>");
                rows.append("<td style=\"color: var(--warn); font-weight: 600;\">").append(escapeHtml((String)f.get("details"))).append("</td>");
                rows.append("<td>").append(escapeHtml((String)f.get("email"))).append("</td>");
                rows.append("</tr>");
                return rows.toString();
            }, "SOURCE", "BREACH DATA", "TARGET EMAIL");

            renderFindingGroup(html, "DNS & Network Infrastructure", findings, "dns_resolution", f -> {
                StringBuilder rows = new StringBuilder();
                rows.append("<tr>");
                rows.append("<td style=\"font-family: monospace;\">").append(escapeHtml((String)f.get("host"))).append("</td>");
                rows.append("<td style=\"font-weight: 700; color: #f472b6;\">").append(escapeHtml((String)f.get("record_type"))).append("</td>");
                rows.append("<td style=\"font-family: monospace; color: var(--good);\">").append(escapeHtml((String)f.get("address"))).append("</td>");
                rows.append("</tr>");
                return rows.toString();
            }, "HOSTNAME", "TYPE", "RESOLVED IP");

            renderFindingGroup(html, "Network Infrastructure Blocks", findings, "network_block", f -> {
                StringBuilder rows = new StringBuilder();
                rows.append("<tr>");
                rows.append("<td style=\"font-weight: 700; color: var(--accent);\">").append(escapeHtml((String)f.get("cidr"))).append("</td>");
                rows.append("<td>").append(escapeHtml((String)f.get("asn"))).append("</td>");
                rows.append("<td style=\"color: var(--muted);\">").append(escapeHtml((String)f.get("description"))).append("</td>");
                rows.append("</tr>");
                return rows.toString();
            }, "CIDR BLOCK", "ASN", "DESCRIPTION");
        }
        html.append("</div>");

        // Operational Telemetry - Hidden by default
        html.append("<details>");
        html.append("<summary class=\"telemetry-toggle\">[+] VIEW OPERATIONAL TELEMETRY & COMMAND LOGS</summary>");
        html.append("<div class=\"section\" style=\"margin-top: 1rem;\">");
        
        html.append("<div class=\"section-title\">Tool Pipeline Execution Log</div>");
        html.append("<div class=\"card\"><div class=\"card-body\"><table class=\"table\">");
        html.append("<thead><tr><th>TOOL</th><th>COMMAND</th><th>STATUS</th><th>DURATION</th></tr></thead><tbody>");
        for (Map<String, Object> t : telemetry) {
            html.append("<tr>");
            html.append("<td style=\"font-weight: 700;\">").append(t.get("tool")).append("</td>");
            html.append("<td style=\"font-family: monospace; font-size: 0.7rem; color: var(--muted);\">").append(escapeHtml((String)t.get("command"))).append("</td>");
            String status = (String)t.get("status");
            String color = "success".equals(status) ? "var(--good)" : "failed".equals(status) ? "var(--bad)" : "var(--warn)";
            html.append("<td style=\"font-weight: 800; color: ").append(color).append(";\">").append(status.toUpperCase()).append("</td>");
            html.append("<td>").append(t.get("duration_ms")).append("ms</td>");
            html.append("</tr>");
        }
        html.append("</tbody></table></div></div>");

        if (!artifacts.isEmpty()) {
            html.append("<div class=\"section-title\">Generated Artifacts & Evidence Files</div>");
            html.append("<div class=\"card\"><div class=\"card-body\"><table class=\"table\">");
            html.append("<thead><tr><th>FILENAME</th><th>DIR</th><th>SIZE</th></tr></thead><tbody>");
            for (Map<String, Object> a : artifacts) {
                html.append("<tr>");
                html.append("<td style=\"color: var(--accent);\">").append(a.get("name")).append("</td>");
                html.append("<td>").append(a.get("directory")).append("</td>");
                html.append("<td>").append(a.get("size_bytes")).append(" B</td>");
                html.append("</tr>");
            }
            html.append("</tbody></table></div></div>");
        }

        html.append("</div></details>");

        html.append("</div>"); // Close dossier
        return html.toString();
    }

    private void renderFindingGroup(StringBuilder html, String groupTitle, List<Map<String, Object>> findings, String type, java.util.function.Function<Map<String, Object>, String> rowBuilder, String c1, String c2, String c3) {
        List<Map<String, Object>> group = findings.stream().filter(f -> type.equals(f.get("type"))).collect(Collectors.toList());
        if (group.isEmpty()) return;

        html.append("<div style=\"margin-bottom: 1.5rem;\">");
        html.append("<div style=\"font-size: 0.85rem; font-weight: 800; color: var(--accent); margin-bottom: 8px; text-transform: uppercase;\">").append(groupTitle).append("</div>");
        html.append("<div class=\"card\"><div class=\"card-body\"><table class=\"table\">");
        html.append("<thead><tr><th>").append(c1).append("</th><th>").append(c2).append("</th><th>").append(c3).append("</th></tr></thead><tbody>");
        for (Map<String, Object> f : group) {
            html.append(rowBuilder.apply(f));
        }
        html.append("</tbody></table></div></div></div>");
    }

    private String escapeHtml(String text) {
        if (text == null || text.isBlank()) return "-";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
}
