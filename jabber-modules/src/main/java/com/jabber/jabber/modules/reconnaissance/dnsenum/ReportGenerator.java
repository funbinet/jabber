package com.jabber.jabber.modules.reconnaissance.dnsenum;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * ReportGenerator — Artifact & findings aggregator for the DNS Enumerator module.
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
            long startedAt) {

        long elapsedMs = System.currentTimeMillis() - startedAt;

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", mode);
        summary.put("target", target);
        summary.put("total_findings", findings.size());
        summary.put("tools_executed", commandRecords.size());
        summary.put("successful_tools", commandRecords.stream().filter(r -> r.exitCode() == 0).count());
        summary.put("elapsed_ms", elapsedMs);

        List<Map<String, Object>> telemetry = commandRecords.stream()
            .map(CommandRecord::toMap).collect(Collectors.toList());

        List<Map<String, Object>> artifacts = buildArtifactManifest(mode);

        Map<String, Object> output = new LinkedHashMap<>();
        output.put("module", "recon-dns-enum");
        output.put("mode", mode);
        output.put("target", target);
        output.put("summary", summary);
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
        parsed.put("status", findings.isEmpty() ? "NO_FINDINGS" : "DNS_INTELLIGENCE_EXTRACTED");
        parsed.put("mode", mode);
        parsed.put("target", target);
        parsed.put("details", summary);
        parsed.put("evidence", findings);
        parsed.put("html_report", generateHtmlReport(mode, target, summary, findings, telemetry, artifacts));

        normalized.put("parsed_output", parsed);
        normalized.put("metadata", Map.of("module", "recon-dns-enum", "mode", mode, "version", "V 5.5"));
        return normalized;
    }

    private String generateHtmlReport(String mode, String target, Map<String, Object> summary, List<Map<String, Object>> findings, List<Map<String, Object>> telemetry, List<Map<String, Object>> artifacts) {
        StringBuilder html = new StringBuilder();
        html.append("<style>");
        html.append(":root { --bg: #0b0f19; --panel: #161b22; --accent: #58a6ff; --good: #3fb950; --warn: #d29922; --bad: #f85149; --muted: #8b949e; --line: #30363d; }");
        html.append(".dossier { font-family: 'Inter', sans-serif; background: var(--bg); color: #c9d1d9; padding: 2rem; border-radius: 12px; }");
        html.append(".header { display: flex; justify-content: space-between; border-bottom: 2px solid var(--line); padding-bottom: 1rem; margin-bottom: 2rem; }");
        html.append(".grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }");
        html.append(".stat-card { background: var(--panel); padding: 1rem; border-radius: 8px; border: 1px solid var(--line); }");
        html.append(".section { margin-bottom: 2rem; }");
        html.append(".section-title { font-size: 1.1rem; font-weight: 700; color: white; margin-bottom: 1rem; border-left: 4px solid var(--accent); padding-left: 10px; }");
        html.append(".table { width: 100%; border-collapse: collapse; background: var(--panel); border-radius: 8px; overflow: hidden; }");
        html.append(".table th { text-align: left; padding: 10px; font-size: 0.75rem; color: var(--muted); border-bottom: 1px solid var(--line); }");
        html.append(".table td { padding: 10px; font-size: 0.85rem; border-bottom: 1px solid rgba(48,54,61,0.5); }");
        html.append("</style>");

        html.append("<div class=\"dossier\">");
        html.append("<div class=\"header\"><h1>DNS Infrastructure Dossier: ").append(escapeHtml(target)).append("</h1></div>");

        html.append("<div class=\"grid\">");
        html.append("<div class=\"stat-card\"><label style=\"display:block;font-size:0.7rem;color:var(--muted);\">TOTAL RECORDS</label><span style=\"font-size:1.5rem;font-weight:700;color:var(--accent);\">").append(findings.size()).append("</span></div>");
        html.append("<div class=\"stat-card\"><label style=\"display:block;font-size:0.7rem;color:var(--muted);\">TOOLS RUN</label><span style=\"font-size:1.5rem;font-weight:700;color:var(--good);\">").append(summary.get("successful_tools")).append("/").append(summary.get("tools_executed")).append("</span></div>");
        html.append("<div class=\"stat-card\"><label style=\"display:block;font-size:0.7rem;color:var(--muted);\">ELAPSED</label><span style=\"font-size:1.5rem;font-weight:700;color:var(--warn);\">").append(String.format("%.2fs", (long)summary.get("elapsed_ms") / 1000.0)).append("</span></div>");
        html.append("</div>");

        // DNS Records
        renderFindingGroup(html, "Resource Record Resolution", findings, "dns_record", f -> {
            return "<tr><td>" + escapeHtml((String)f.get("name")) + "</td><td style=\"color:var(--accent);font-weight:700;\">" + escapeHtml((String)f.get("type")) + "</td><td style=\"font-family:monospace;\">" + escapeHtml((String)f.get("value")) + "</td><td>" + f.getOrDefault("ttl", "-") + "</td></tr>";
        }, "NAME", "TYPE", "VALUE", "TTL");

        // Subdomains
        renderFindingGroup(html, "Subdomain Discovery (Passive/Active)", findings, "subdomain_discovery", f -> {
            return "<tr><td>" + escapeHtml((String)f.get("hostname")) + "</td><td>" + escapeHtml((String)f.get("resolver")) + "</td><td style=\"color:var(--good);\">" + escapeHtml((String)f.get("status")) + "</td></tr>";
        }, "HOSTNAME", "RESOLVER", "STATUS");

        // Zone Transfers
        renderFindingGroup(html, "Zone Transfer (AXFR) Audit", findings, "zone_transfer", f -> {
            String color = "SUCCESS".equalsIgnoreCase((String)f.get("status")) ? "var(--good)" : "var(--bad)";
            return "<tr><td>" + escapeHtml((String)f.get("nameserver")) + "</td><td style=\"color:" + color + ";font-weight:700;\">" + escapeHtml((String)f.get("status")) + "</td><td>" + f.getOrDefault("count", 0) + " records</td></tr>";
        }, "NAMESERVER", "STATUS", "RECOVERY COUNT");

        html.append("</div>");
        return html.toString();
    }

    private void renderFindingGroup(StringBuilder html, String title, List<Map<String, Object>> findings, String type, java.util.function.Function<Map<String, Object>, String> rowBuilder, String... headers) {
        List<Map<String, Object>> group = findings.stream().filter(f -> type.equals(f.get("type"))).collect(Collectors.toList());
        if (group.isEmpty()) return;

        html.append("<div class=\"section\">");
        html.append("<div class=\"section-title\">").append(title).append("</div>");
        html.append("<table class=\"table\"><thead><tr>");
        for (String h : headers) html.append("<th>").append(h).append("</th>");
        html.append("</tr></thead><tbody>");
        for (Map<String, Object> f : group) html.append(rowBuilder.apply(f));
        html.append("</tbody></table></div>");
    }

    private String escapeHtml(String text) {
        if (text == null) return "-";
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }
}
