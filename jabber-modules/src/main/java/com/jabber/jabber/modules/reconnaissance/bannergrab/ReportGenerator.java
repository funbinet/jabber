package com.jabber.jabber.modules.reconnaissance.bannergrab;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * ReportGenerator — Artifact & findings aggregator for the Banner Grabber module.
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
            String domain,
            List<CommandRecord> commandRecords,
            List<Map<String, Object>> findings,
            Map<String, Object> intelligence,
            long startedAt) {

        long elapsedMs = System.currentTimeMillis() - startedAt;

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", mode);
        summary.put("target", target);
        summary.put("domain", domain);
        summary.put("total_findings", findings.size());
        summary.put("tools_executed", commandRecords.size());
        summary.put("successful_tools", commandRecords.stream().filter(r -> r.exitCode == 0).count());
        summary.put("elapsed_ms", elapsedMs);

        List<Map<String, Object>> telemetry = commandRecords.stream()
            .map(CommandRecord::toMap).collect(Collectors.toList());

        List<Map<String, Object>> artifacts = buildArtifactManifest(mode);

        Map<String, Object> output = new LinkedHashMap<>();
        output.put("module", "recon-banner-grab");
        output.put("mode", mode);
        output.put("target", target);
        output.put("domain", domain);
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
        parsed.put("status", findings.isEmpty() ? "NO_FINDINGS" : "BANNERS_EXTRACTED");
        parsed.put("mode", mode);
        parsed.put("target", target);
        parsed.put("details", summary);
        parsed.put("evidence", findings);
        
        parsed.put("html_report", generateHtmlReport(mode, target, summary, findings, telemetry, artifacts));

        normalized.put("parsed_output", parsed);

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("module", "recon-banner-grab");
        meta.put("mode", mode);
        meta.put("version", "V 5.5");
        normalized.put("metadata", meta);

        return normalized;
    }

    @SuppressWarnings("unchecked")
    private String generateHtmlReport(String mode, String target, Map<String, Object> summary, List<Map<String, Object>> findings, List<Map<String, Object>> telemetry, List<Map<String, Object>> artifacts) {
        StringBuilder html = new StringBuilder();
        
        html.append("<style>");
        html.append(":root { --bg: #0d1117; --panel: #161b22; --accent: #ff7b72; --good: #3fb950; --warn: #d29922; --bad: #f85149; --muted: #8b949e; --line: #30363d; }");
        html.append(".dossier { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: #c9d1d9; padding: 2rem; border-radius: 12px; border: 1px solid var(--line); }");
        html.append(".header { border-bottom: 2px solid var(--line); padding-bottom: 1rem; margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: center; }");
        html.append(".header h1 { margin: 0; color: white; font-size: 1.5rem; }");
        html.append(".grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }");
        html.append(".stat-card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 1.25rem; }");
        html.append(".stat-card label { display: block; font-size: 0.7rem; text-transform: uppercase; color: var(--muted); margin-bottom: 4px; }");
        html.append(".stat-card value { font-size: 1.5rem; font-weight: 700; color: var(--accent); }");
        html.append(".section-title { font-size: 1.1rem; font-weight: 700; color: white; margin: 2rem 0 1rem; }");
        html.append(".banner-card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; margin-bottom: 1rem; padding: 1rem; }");
        html.append(".banner-header { display: flex; justify-content: space-between; margin-bottom: 8px; border-bottom: 1px solid var(--line); padding-bottom: 4px; }");
        html.append(".banner-text { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--good); background: rgba(0,0,0,0.3); padding: 10px; border-radius: 4px; white-space: pre-wrap; word-break: break-all; }");
        html.append("details summary { cursor: pointer; color: var(--muted); font-size: 0.8rem; text-align: center; padding: 1rem; border: 1px dashed var(--line); border-radius: 8px; margin-top: 2rem; list-style: none; }");
        html.append("</style>");

        html.append("<div class=\"dossier\">");
        
        // Header
        html.append("<div class=\"header\">");
        html.append("<div><h1>Banner Fingerprint: ").append(escapeHtml(target)).append("</h1>");
        html.append("<span style=\"color: var(--muted); font-size: 0.8rem;\">JABBER V 5.5.0 Service Identification Module</span></div>");
        html.append("<div style=\"background: var(--accent); color: var(--bg); padding: 4px 12px; border-radius: 4px; font-weight: 800; font-size: 0.75rem;\">MODE: ").append(mode).append("</div>");
        html.append("</div>");

        // Stats
        html.append("<div class=\"grid\">");
        html.append("<div class=\"stat-card\"><label>Banners Captured</label><value>").append(findings.size()).append("</value></div>");
        html.append("<div class=\"stat-card\"><label>Tools Deployed</label><value>").append(summary.get("tools_executed")).append("</value></div>");
        html.append("<div class=\"stat-card\"><label>Processing Time</label><value>").append(summary.get("elapsed_ms")).append("ms</value></div>");
        html.append("</div>");

        // Banners
        html.append("<div class=\"section-title\">Extracted Service Banners</div>");
        if (findings.isEmpty()) {
            html.append("<div style=\"text-align: center; color: var(--muted); padding: 2rem;\">No service banners were successfully captured.</div>");
        } else {
            for (Map<String, Object> f : findings) {
                html.append("<div class=\"banner-card\">");
                html.append("<div class=\"banner-header\">");
                html.append("<span style=\"font-weight: 700; color: var(--accent);\">Service: ").append(escapeHtml((String)f.get("service"))).append("</span>");
                html.append("<span style=\"color: var(--muted); font-size: 0.75rem;\">Tool: ").append(escapeHtml((String)f.get("tool"))).append("</span>");
                html.append("</div>");
                html.append("<div class=\"banner-text\">").append(escapeHtml((String)f.get("banner"))).append("</div>");
                html.append("</div>");
            }
        }

        // Telemetry
        html.append("<details>");
        html.append("<summary>[+] SHOW OPERATIONAL TELEMETRY</summary>");
        html.append("<div style=\"margin-top: 1rem;\">");
        html.append("<div style=\"font-weight: 700; color: white; margin-bottom: 8px;\">Command Execution History</div>");
        html.append("<table style=\"width: 100%; border-collapse: collapse; font-size: 0.8rem;\">");
        html.append("<thead style=\"color: var(--muted); border-bottom: 1px solid var(--line);\"><tr><th style=\"text-align: left; padding: 8px;\">TOOL</th><th style=\"text-align: left; padding: 8px;\">STATUS</th><th style=\"text-align: right; padding: 8px;\">TIME</th></tr></thead><tbody>");
        for (Map<String, Object> t : telemetry) {
            html.append("<tr style=\"border-bottom: 1px solid rgba(48,54,61,0.5);\">");
            html.append("<td style=\"padding: 8px; font-weight: 600;\">").append(t.get("tool")).append("</td>");
            String status = (String)t.get("status");
            String color = "success".equals(status) ? "var(--good)" : "var(--bad)";
            html.append("<td style=\"padding: 8px; color: ").append(color).append(";\">").append(status.toUpperCase()).append("</td>");
            html.append("<td style=\"padding: 8px; text-align: right; color: var(--muted);\">").append(t.get("duration_ms")).append("ms</td>");
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
