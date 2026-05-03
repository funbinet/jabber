package com.jabber.jabber.modules.reconnaissance.adlaps;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * ReportGenerator — Artifact & findings aggregator for the ADLAPS module.
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

        List<Map<String, Object>> pipeline = commandRecords.stream()
            .map(rec -> {
                Map<String, Object> step = new LinkedHashMap<>();
                step.put("tool", rec.tool);
                step.put("command", rec.command);
                step.put("status", rec.status);
                step.put("exit_code", rec.exitCode);
                step.put("duration_ms", rec.durationMs);
                return step;
            })
            .collect(Collectors.toList());

        List<Map<String, Object>> telemetry = commandRecords.stream()
            .map(CommandRecord::toMap).collect(Collectors.toList());

        List<Map<String, Object>> artifacts = buildArtifactManifest(mode);

        Map<String, Object> output = new LinkedHashMap<>();
        output.put("module", "recon-ad-laps");
        output.put("mode", mode);
        output.put("target", target);
        output.put("summary", summary);
        output.put("pipeline", pipeline);
        output.put("intelligence", intelligence);
        output.put("findings", findings);
        output.put("artifacts", artifacts);
        output.put("telemetry", telemetry);

        Map<String, Object> normalizedOutput = buildNormalizedOutput(mode, summary, findings, telemetry);

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
                    .filter(p -> p.getFileName().toString().startsWith(mode + "_"))
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
            String mode, Map<String, Object> summary,
            List<Map<String, Object>> findings, List<Map<String, Object>> telemetry) {

        Map<String, Object> normalized = new LinkedHashMap<>();

        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("summary", summary);
        raw.put("telemetry", telemetry);
        normalized.put("raw_output", raw);

        Map<String, Object> parsed = new LinkedHashMap<>();
        parsed.put("status", findings.isEmpty() ? "NO_FINDINGS" : "CREDENTIALS_EXTRACTED");
        parsed.put("mode", mode);
        parsed.put("details", summary);
        parsed.put("evidence", findings);
        
        parsed.put("html_report", generateHtmlReport(mode, findings));

        normalized.put("parsed_output", parsed);

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("module", "recon-ad-laps");
        meta.put("mode", mode);
        meta.put("version", "V 5.5");
        normalized.put("metadata", meta);

        return normalized;
    }

    @SuppressWarnings("unchecked")
    private String generateHtmlReport(String mode, List<Map<String, Object>> findings) {
        StringBuilder html = new StringBuilder();
        html.append("<div style=\"font-family: Inter, sans-serif; max-width: 100%; display: flex; flex-direction: column; gap: 24px;\">");

        if ("EXTRACT".equals(mode)) {
            // Extracted LAPS Credentials Table
            html.append("<div>");
            html.append("<h3 style=\"color: #eab308; font-weight: 600; margin-bottom: 12px; border-bottom: 1px solid #374151; padding-bottom: 8px;\">Extracted LAPS Credentials (LDAP)</h3>");
            html.append("<table style=\"width: 100%; border-collapse: collapse; text-align: left; background-color: #1f2937; color: #f3f4f6; border-radius: 8px; overflow: hidden;\">");
            html.append("<thead style=\"background-color: #111827; border-bottom: 2px solid #374151;\">");
            html.append("<tr>");
            html.append("<th style=\"padding: 12px 16px; font-weight: 600; color: #9ca3af;\">HOSTNAME</th>");
            html.append("<th style=\"padding: 12px 16px; font-weight: 600; color: #9ca3af;\">ADMIN ACCOUNT</th>");
            html.append("<th style=\"padding: 12px 16px; font-weight: 600; color: #9ca3af;\">CLEARTEXT PASSWORD</th>");
            html.append("<th style=\"padding: 12px 16px; font-weight: 600; color: #9ca3af;\">EXPIRES</th>");
            html.append("</tr>");
            html.append("</thead><tbody>");

            boolean hasCreds = false;
            for (Map<String, Object> f : findings) {
                if ("laps_credentials".equals(f.get("type"))) {
                    hasCreds = true;
                    html.append("<tr style=\"border-bottom: 1px solid #374151; transition: background-color 0.2s;\" onmouseover=\"this.style.backgroundColor='#374151'\" onmouseout=\"this.style.backgroundColor='transparent'\">");
                    html.append("<td style=\"padding: 12px 16px; font-weight: 500; color: #93c5fd;\">").append(escapeHtml((String) f.get("hostname"))).append("</td>");
                    html.append("<td style=\"padding: 12px 16px; color: #d1d5db;\">").append(escapeHtml((String) f.get("admin_account"))).append("</td>");
                    html.append("<td style=\"padding: 12px 16px; color: #fcd34d; font-family: monospace; font-size: 1.1em;\">").append(escapeHtml((String) f.get("password"))).append("</td>");
                    html.append("<td style=\"padding: 12px 16px; color: #9ca3af;\">").append(escapeHtml((String) f.get("expiration"))).append("</td>");
                    html.append("</tr>");
                }
            }
            if (!hasCreds) {
                html.append("<tr><td colspan=\"4\" style=\"padding: 16px; text-align: center; color: #9ca3af;\">No LAPS credentials extracted.</td></tr>");
            }
            html.append("</tbody></table></div>");
        }

        // SMB Validated Hosts Table (CrackMapExec)
        html.append("<div>");
        html.append("<h3 style=\"color: #10b981; font-weight: 600; margin-bottom: 12px; border-bottom: 1px solid #374151; padding-bottom: 8px;\">SMB Validation Results (CrackMapExec)</h3>");
        html.append("<table style=\"width: 100%; border-collapse: collapse; text-align: left; background-color: #1f2937; color: #f3f4f6; border-radius: 8px; overflow: hidden;\">");
        html.append("<thead style=\"background-color: #111827; border-bottom: 2px solid #374151;\">");
        html.append("<tr>");
        html.append("<th style=\"padding: 12px 16px; font-weight: 600; color: #9ca3af;\">IP / HOST</th>");
        html.append("<th style=\"padding: 12px 16px; font-weight: 600; color: #9ca3af;\">STATUS</th>");
        html.append("<th style=\"padding: 12px 16px; font-weight: 600; color: #9ca3af;\">DETAILS</th>");
        html.append("</tr>");
        html.append("</thead><tbody>");

        boolean hasSmb = false;
        for (Map<String, Object> f : findings) {
            if ("smb_validation".equals(f.get("type"))) {
                hasSmb = true;
                String status = (String) f.get("status");
                String statusColor = "Pwn3d!".equals(status) ? "#ef4444" : "VALID".equals(status) ? "#10b981" : "#f59e0b";
                html.append("<tr style=\"border-bottom: 1px solid #374151; transition: background-color 0.2s;\" onmouseover=\"this.style.backgroundColor='#374151'\" onmouseout=\"this.style.backgroundColor='transparent'\">");
                html.append("<td style=\"padding: 12px 16px; font-weight: 500; color: #60a5fa;\">").append(escapeHtml((String) f.get("target"))).append("</td>");
                html.append("<td style=\"padding: 12px 16px; font-weight: 600; color: ").append(statusColor).append(";\">").append(escapeHtml(status)).append("</td>");
                html.append("<td style=\"padding: 12px 16px; color: #d1d5db;\">").append(escapeHtml((String) f.get("details"))).append("</td>");
                html.append("</tr>");
            }
        }
        if (!hasSmb) {
            html.append("<tr><td colspan=\"3\" style=\"padding: 16px; text-align: center; color: #9ca3af;\">No SMB validation results.</td></tr>");
        }
        html.append("</tbody></table></div>");

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
