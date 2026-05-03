package com.jabber.jabber.modules.reconnaissance.crawler;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * ReportGenerator — Artifact & findings aggregator for the Web Crawler module.
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
            String url,
            String domain,
            List<CommandRecord> commandRecords,
            List<Map<String, Object>> findings,
            Map<String, Object> intelligence,
            long startedAt) {

        long elapsedMs = System.currentTimeMillis() - startedAt;

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", mode);
        summary.put("target", url);
        summary.put("domain", domain);
        summary.put("total_findings", findings.size());
        summary.put("tools_executed", commandRecords.size());
        summary.put("successful_tools", commandRecords.stream().filter(r -> r.exitCode == 0).count());
        summary.put("elapsed_ms", elapsedMs);

        List<Map<String, Object>> telemetry = commandRecords.stream()
            .map(CommandRecord::toMap).collect(Collectors.toList());

        List<Map<String, Object>> artifacts = buildArtifactManifest(mode);

        Map<String, Object> output = new LinkedHashMap<>();
        output.put("module", "recon-web-crawler");
        output.put("mode", mode);
        output.put("target", url);
        output.put("domain", domain);
        output.put("summary", summary);
        output.put("intelligence", intelligence);
        output.put("findings", findings);
        output.put("artifacts", artifacts);

        Map<String, Object> normalizedOutput = buildNormalizedOutput(mode, url, summary, findings, telemetry, artifacts);

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
        parsed.put("status", findings.isEmpty() ? "NO_FINDINGS" : "CRAWL_COMPLETE");
        parsed.put("mode", mode);
        parsed.put("target", target);
        parsed.put("details", summary);
        parsed.put("evidence", findings);
        
        parsed.put("html_report", generateHtmlReport(mode, target, summary, findings, telemetry, artifacts));

        normalized.put("parsed_output", parsed);

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("module", "recon-web-crawler");
        meta.put("mode", mode);
        meta.put("version", "V 5.5");
        normalized.put("metadata", meta);

        return normalized;
    }

    @SuppressWarnings("unchecked")
    private String generateHtmlReport(String mode, String target, Map<String, Object> summary, List<Map<String, Object>> findings, List<Map<String, Object>> telemetry, List<Map<String, Object>> artifacts) {
        StringBuilder html = new StringBuilder();
        
        html.append("<style>");
        html.append(":root { --bg: #0d1117; --panel: #161b22; --accent: #3fb950; --link: #58a6ff; --muted: #8b949e; --line: #30363d; }");
        html.append(".dossier { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: #c9d1d9; padding: 2rem; border-radius: 12px; }");
        html.append(".header { border-bottom: 2px solid var(--line); padding-bottom: 1rem; margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: center; }");
        html.append(".header h1 { margin: 0; color: white; font-size: 1.4rem; }");
        html.append(".grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 2rem; }");
        html.append(".stat-card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 1rem; }");
        html.append(".stat-card label { display: block; font-size: 0.65rem; text-transform: uppercase; color: var(--muted); margin-bottom: 4px; }");
        html.append(".stat-card value { font-size: 1.4rem; font-weight: 700; color: var(--accent); }");
        html.append(".table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }");
        html.append(".table th { text-align: left; padding: 10px; color: var(--muted); border-bottom: 1px solid var(--line); }");
        html.append(".table td { padding: 10px; border-bottom: 1px solid rgba(48,54,61,0.5); vertical-align: top; }");
        html.append(".tag { padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; margin-right: 4px; }");
        html.append("details summary { cursor: pointer; color: var(--muted); font-size: 0.8rem; text-align: center; padding: 1rem; border: 1px dashed var(--line); border-radius: 8px; margin-top: 2rem; list-style: none; }");
        html.append("</style>");

        html.append("<div class=\"dossier\">");

        // Header
        html.append("<div class=\"header\">");
        html.append("<div><h1>Attack Surface Discovery: ").append(escapeHtml(target)).append("</h1>");
        html.append("<span style=\"color: var(--muted); font-size: 0.8rem;\">JABBER V 5.5.0 High-Fidelity Web Crawler</span></div>");
        html.append("<div style=\"background: var(--accent); color: var(--bg); padding: 4px 12px; border-radius: 4px; font-weight: 800; font-size: 0.75rem;\">").append(mode).append("</div>");
        html.append("</div>");

        // Stats
        html.append("<div class=\"grid\">");
        html.append("<div class=\"stat-card\"><label>Endpoints Found</label><value>").append(findings.size()).append("</value></div>");
        html.append("<div class=\"stat-card\"><label>Successful Tools</label><value>").append(summary.get("successful_tools")).append("/").append(summary.get("tools_executed")).append("</value></div>");
        html.append("<div class=\"stat-card\"><label>Crawl Time</label><value>").append(summary.get("elapsed_ms")).append("ms</value></div>");
        html.append("</div>");

        // Discovery List
        html.append("<div style=\"font-weight: 700; color: white; margin-bottom: 1rem; font-size: 1.1rem;\">Identified Endpoints & Assets</div>");
        if (findings.isEmpty()) {
            html.append("<div style=\"text-align: center; color: var(--muted); padding: 2rem; background: var(--panel); border-radius: 8px;\">No assets identified during crawl.</div>");
        } else {
            html.append("<table class=\"table\"><thead><tr><th>TYPE</th><th>ENDPOINT / URL</th><th>DETAILS</th></tr></thead><tbody>");
            for (Map<String, Object> f : findings) {
                html.append("<tr>");
                String type = (String)f.get("type");
                String typeColor = "endpoint".equals(type) ? "#3fb950" : "subdomain".equals(type) ? "#58a6ff" : "#f59e0b";
                html.append("<td><span class=\"tag\" style=\"background: ").append(typeColor).append("; color: #0d1117;\">").append(type).append("</span></td>");
                html.append("<td><a href=\"").append(escapeHtml((String)f.get("url"))).append("\" target=\"_blank\" style=\"color: var(--link); text-decoration: none;\">").append(escapeHtml((String)f.get("url"))).append("</a></td>");
                html.append("<td style=\"color: var(--muted);\">").append(escapeHtml((String)f.get("description"))).append("</td>");
                html.append("</tr>");
            }
            html.append("</tbody></table>");
        }

        // Telemetry
        html.append("<details>");
        html.append("<summary>[+] VIEW PIPELINE LOGS</summary>");
        html.append("<div style=\"margin-top: 1rem;\">");
        html.append("<table class=\"table\"><thead><tr><th>TOOL</th><th>COMMAND</th><th>STATUS</th></tr></thead><tbody>");
        for (Map<String, Object> t : telemetry) {
            html.append("<tr>");
            html.append("<td style=\"font-weight: 700;\">").append(t.get("tool")).append("</td>");
            html.append("<td style=\"font-family: monospace; font-size: 0.65rem; color: var(--muted);\">").append(escapeHtml((String)t.get("command"))).append("</td>");
            String status = (String)t.get("status");
            String color = "success".equals(status) ? "var(--accent)" : "#f85149";
            html.append("<td style=\"color: ").append(color).append("; font-weight: 700;\">").append(status.toUpperCase()).append("</td>");
            html.append("</tr>");
        }
        html.append("</tbody></table>");
        html.append("</div></details>");

        html.append("</div>");
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
