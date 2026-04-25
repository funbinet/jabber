package com.jabber.jrts.core.report;

import com.jabber.jrts.data.model.ModuleResult;
import com.google.gson.GsonBuilder;
import com.google.gson.Gson;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Multi-format report engine supporting JSON, XML, CSV, Markdown, TXT, and HTML.
 * V3.1: Hierarchical JSON, professional HTML with tables/badges, structured Markdown.
 */
@Service
public class ReportEngine {

    private static final String GENERATOR = "JABBER Red Teaming Suite v3.1.0";
    private static final String CREATOR = "Funbinet (dancan.tech)";
    private static final String FORMAT_VERSION = "3.1";

    private final Gson gson = new GsonBuilder().setPrettyPrinting()
        .serializeNulls().create();

    public String generate(ModuleResult result, String format) {
        String normalizedFormat = format == null ? "json" : format.toLowerCase(Locale.ROOT);
        return switch (normalizedFormat) {
            case "json" -> generateJSON(result);
            case "xml" -> generateXML(result);
            case "csv" -> generateCSV(result);
            case "markdown", "md" -> generateMarkdown(result);
            case "txt", "raw" -> generateTXT(result);
            case "html" -> generateHTML(result);
            default -> generateJSON(result);
        };
    }

    public Map<String, Object> buildExecutionLog(ModuleResult result) {
        Map<String, Object> output = safeMap(result.getOutput());
        Map<String, Object> metadata = safeMap(output.get("execution_metadata"));

        List<String> events = new ArrayList<>(safeStringList(result.getLogLines()));
        List<String> warnings = new ArrayList<>(safeStringList(metadata.get("warnings")));
        List<Map<String, Object>> commands = extractCommandRecords(metadata);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("event_count", events.size());
        summary.put("command_count", commands.size());
        summary.put("warning_count", warnings.size());

        Long elapsedMs = asLong(metadata.get("elapsed_ms"));
        if (elapsedMs != null && elapsedMs >= 0) {
            summary.put("elapsed_ms", elapsedMs);
        }
        summary.put("captured_at", Instant.now().toString());

        Map<String, Object> execution = new LinkedHashMap<>();
        execution.put("summary", summary);
        execution.put("commands", commands);
        execution.put("events", events);
        execution.put("warnings", warnings);
        execution.put("metadata", metadata);
        return execution;
    }

    public String generateExecutionLogText(ModuleResult result) {
        Map<String, Object> execution = buildExecutionLog(result);
        List<Map<String, Object>> commands = safeMapList(execution.get("commands"));
        List<String> events = safeStringList(execution.get("events"));
        List<String> warnings = safeStringList(execution.get("warnings"));

        StringBuilder text = new StringBuilder();
        text.append("JRTS Execution Log\n");
        text.append("Generated: ").append(Instant.now()).append("\n");
        text.append("Task ID: ").append(stringValue(result.getTaskId())).append("\n");
        text.append("Module: ").append(stringValue(result.getModuleId())).append("\n");
        text.append("Status: ").append(stringValue(result.getStatus())).append("\n\n");

        text.append("COMMAND RECORDS\n");
        text.append("---------------\n");
        if (commands.isEmpty()) {
            text.append("No command executions captured.\n");
        } else {
            for (int i = 0; i < commands.size(); i++) {
                Map<String, Object> cmd = commands.get(i);
                text.append('[').append(i + 1).append("] ")
                    .append(stringValue(cmd.get("command"))).append("\n");
                text.append("    status=").append(stringValue(cmd.get("status")))
                    .append(", exit_code=").append(stringValue(cmd.get("exit_code")))
                    .append(", timed_out=").append(stringValue(cmd.get("timed_out")))
                    .append(", duration_ms=").append(stringValue(cmd.get("duration_ms")))
                    .append("\n");
                String stdoutPreview = stringValue(cmd.get("stdout_preview"));
                if (!stdoutPreview.isBlank()) {
                    text.append("    stdout: ").append(stdoutPreview).append("\n");
                }
                String stderrPreview = stringValue(cmd.get("stderr_preview"));
                if (!stderrPreview.isBlank()) {
                    text.append("    stderr: ").append(stderrPreview).append("\n");
                }
            }
        }

        text.append("\nEVENT LOG\n");
        text.append("---------\n");
        if (events.isEmpty()) {
            text.append("No event log lines captured.\n");
        } else {
            for (String line : events) {
                text.append(line).append("\n");
            }
        }

        if (!warnings.isEmpty()) {
            text.append("\nWARNINGS\n");
            text.append("--------\n");
            for (String warning : warnings) {
                text.append("- ").append(warning).append("\n");
            }
        }

        return text.toString();
    }

    // ======================== JSON ========================

    private String generateJSON(ModuleResult result) {
        Map<String, Object> report = buildReportData(result);
        return gson.toJson(report);
    }

    /**
     * V3.1: Hierarchical, clean JSON structure.
     */
    private Map<String, Object> buildReportData(ModuleResult result) {
        Map<String, Object> executionLog = buildExecutionLog(result);

        Map<String, Object> report = new LinkedHashMap<>();

        // --- Metadata ---
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("generator", GENERATOR);
        metadata.put("creator", CREATOR);
        metadata.put("generated_at", Instant.now().toString());
        metadata.put("format_version", FORMAT_VERSION);
        report.put("metadata", metadata);

        // --- Task ---
        Map<String, Object> task = new LinkedHashMap<>();
        task.put("task_id", result.getTaskId());
        task.put("module_id", result.getModuleId());
        task.put("module_name", stringValue(result.getModuleName()));
        task.put("category", stringValue(result.getCategory()));
        task.put("target", stringValue(result.getTarget()));
        task.put("status", stringValue(result.getStatus()));
        task.put("start_time", stringValue(result.getStartTime()));
        task.put("end_time", stringValue(result.getEndTime()));
        task.put("duration_ms", computeDurationMs(result));
        report.put("task", task);

        // --- Summary ---
        List<Map<String, Object>> findings = normalizeFindings(result.getFindings());
        report.put("summary", buildSummary(result, findings));

        // --- Findings ---
        report.put("findings", findings);

        // --- Output ---
        report.put("output", safeMap(result.getOutput()));

        // --- Execution Log ---
        report.put("execution_log", executionLog);

        return report;
    }

    /**
     * Build a summary section with finding counts, severity breakdown, and key metrics.
     */
    private Map<String, Object> buildSummary(ModuleResult result, List<Map<String, Object>> findings) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("total_findings", findings.size());

        // Severity breakdown
        Map<String, Integer> severityBreakdown = new LinkedHashMap<>();
        severityBreakdown.put("critical", 0);
        severityBreakdown.put("high", 0);
        severityBreakdown.put("medium", 0);
        severityBreakdown.put("low", 0);
        severityBreakdown.put("info", 0);

        for (Map<String, Object> f : findings) {
            String sev = stringValue(f.get("severity")).toLowerCase();
            if (severityBreakdown.containsKey(sev)) {
                severityBreakdown.put(sev, severityBreakdown.get(sev) + 1);
            } else {
                severityBreakdown.put("info", severityBreakdown.get("info") + 1);
            }
        }
        summary.put("severity_breakdown", severityBreakdown);

        // Status label
        String statusStr = stringValue(result.getStatus()).toUpperCase();
        String statusLabel = switch (statusStr) {
            case "COMPLETED" -> "Operation completed successfully";
            case "FAILED" -> "Operation failed: " + stringValue(result.getErrorMessage());
            case "CANCELLED" -> "Operation was cancelled by user";
            default -> "Operation status: " + statusStr;
        };
        summary.put("status_label", statusLabel);

        // Duration
        long durationMs = computeDurationMs(result);
        if (durationMs > 0) {
            summary.put("duration_ms", durationMs);
            summary.put("duration_human", humanDuration(durationMs));
        }

        // Key metrics from output
        Map<String, Object> output = safeMap(result.getOutput());
        Map<String, Object> keyMetrics = new LinkedHashMap<>();
        for (String key : List.of("total_open", "ips_scanned", "ports_per_ip", "urls_crawled",
                "pages_found", "endpoints_discovered", "hosts_discovered")) {
            Object val = output.get(key);
            if (val != null) {
                keyMetrics.put(key, val);
            }
        }
        if (!keyMetrics.isEmpty()) {
            summary.put("key_metrics", keyMetrics);
        }

        return summary;
    }

    /**
     * Normalize raw findings into a consistent structure with id, type, severity, title, description, evidence, status.
     */
    private List<Map<String, Object>> normalizeFindings(List<Map<String, Object>> rawFindings) {
        if (rawFindings == null || rawFindings.isEmpty()) return List.of();

        List<Map<String, Object>> normalized = new ArrayList<>();
        for (int i = 0; i < rawFindings.size(); i++) {
            Map<String, Object> raw = rawFindings.get(i);
            Map<String, Object> finding = new LinkedHashMap<>();
            finding.put("id", i + 1);

            // Type
            String type = stringValue(raw.getOrDefault("type", raw.getOrDefault("finding_type", "")));
            if (type.isBlank()) {
                // Infer type from keys
                if (raw.containsKey("port")) type = "open_port";
                else if (raw.containsKey("url") || raw.containsKey("endpoint")) type = "endpoint";
                else if (raw.containsKey("cve") || raw.containsKey("vulnerability")) type = "vulnerability";
                else type = "finding";
            }
            finding.put("type", type);

            // Severity
            String severity = stringValue(raw.getOrDefault("severity", raw.getOrDefault("risk", "")));
            if (severity.isBlank()) {
                severity = inferSeverity(type, raw);
            }
            finding.put("severity", severity.toLowerCase());

            // Title
            String title = stringValue(raw.getOrDefault("title", raw.getOrDefault("name", "")));
            if (title.isBlank()) {
                title = buildFindingTitle(type, raw);
            }
            finding.put("title", title);

            // Description
            String desc = stringValue(raw.getOrDefault("description", raw.getOrDefault("details", "")));
            if (desc.isBlank()) {
                desc = buildFindingDescription(type, raw);
            }
            finding.put("description", desc);

            // Evidence — carry all original raw data
            Map<String, Object> evidence = new LinkedHashMap<>(raw);
            // Remove already-extracted keys to avoid duplication
            evidence.remove("type");
            evidence.remove("severity");
            evidence.remove("risk");
            evidence.remove("title");
            evidence.remove("name");
            evidence.remove("description");
            evidence.remove("details");
            evidence.remove("finding_type");
            finding.put("evidence", evidence);

            // Status
            String status = stringValue(raw.getOrDefault("status", raw.getOrDefault("state", "confirmed")));
            finding.put("status", status.toLowerCase());

            normalized.add(finding);
        }
        return normalized;
    }

    private String inferSeverity(String type, Map<String, Object> raw) {
        if ("vulnerability".equals(type)) return "high";
        if ("open_port".equals(type)) {
            Object port = raw.get("port");
            if (port instanceof Number p) {
                int pv = p.intValue();
                if (pv == 23 || pv == 21 || pv == 445 || pv == 3389) return "high";
                if (pv == 22 || pv == 80 || pv == 443) return "medium";
            }
            return "medium";
        }
        return "info";
    }

    private String buildFindingTitle(String type, Map<String, Object> raw) {
        return switch (type) {
            case "open_port" -> {
                String ip = stringValue(raw.get("ip"));
                String port = stringValue(raw.get("port"));
                String service = stringValue(raw.get("service"));
                yield ip + ":" + port + " (" + (service.isBlank() ? "unknown" : service) + ")";
            }
            case "endpoint" -> {
                String url = stringValue(raw.getOrDefault("url", raw.getOrDefault("endpoint", "")));
                yield url.isBlank() ? "Endpoint discovered" : url;
            }
            case "vulnerability" -> stringValue(raw.getOrDefault("cve", "Vulnerability detected"));
            default -> "Finding #" + stringValue(raw.getOrDefault("id", ""));
        };
    }

    private String buildFindingDescription(String type, Map<String, Object> raw) {
        return switch (type) {
            case "open_port" -> {
                String service = stringValue(raw.get("service"));
                String banner = stringValue(raw.get("banner"));
                String desc = "Port " + stringValue(raw.get("port")) + " is open";
                if (!service.isBlank()) desc += " running " + service;
                if (!banner.isBlank()) desc += " — banner: " + banner;
                yield desc;
            }
            case "endpoint" -> "Endpoint discovered at " + stringValue(raw.getOrDefault("url", raw.getOrDefault("path", "unknown")));
            default -> compactJson(raw);
        };
    }

    // ======================== HTML ========================

    private String generateHTML(ModuleResult result) {
        Map<String, Object> executionLog = buildExecutionLog(result);
        List<Map<String, Object>> commands = safeMapList(executionLog.get("commands"));
        List<String> events = safeStringList(executionLog.get("events"));
        List<String> warnings = safeStringList(executionLog.get("warnings"));
        List<Map<String, Object>> findings = normalizeFindings(result.getFindings());
        Map<String, Object> summaryData = buildSummary(result, findings);
        long durationMs = computeDurationMs(result);

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.append("<meta charset=\"UTF-8\">\n");
        html.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.append("<title>JRTS Report — ").append(escapeHtml(stringValue(result.getModuleName()))).append("</title>\n");
        html.append(getHTMLStyles());
        html.append("</head>\n<body>\n<div class=\"wrap\">\n");

        // --- Header ---
        html.append("<header class=\"rpt-header\">\n");
        html.append("  <div class=\"rpt-header__brand\">\n");
        html.append("    <div class=\"rpt-header__logo\"><img src=\"/jabber.png\" alt=\"Logo\" /></div>\n");
        html.append("    <div>\n");
        html.append("      <h1>").append(escapeHtml(stringValue(result.getModuleName()))).append("</h1>\n");
        html.append("      <p class=\"rpt-header__sub\">").append(escapeHtml(GENERATOR)).append(" &middot; Created by ").append(escapeHtml(CREATOR)).append("</p>\n");
        html.append("    </div>\n");
        html.append("  </div>\n");
        html.append("  <span class=\"status-badge status-badge--").append(statusClass(result)).append("\">")
            .append(escapeHtml(stringValue(result.getStatus()))).append("</span>\n");
        html.append("</header>\n\n");

        // --- Summary Cards ---
        html.append("<div class=\"summary-grid\">\n");
        html.append(summaryCard("Total Findings", String.valueOf(findings.size()), "var(--accent)"));
        @SuppressWarnings("unchecked")
        Map<String, Object> sevBreakdown = (Map<String, Object>) summaryData.get("severity_breakdown");
        int critical = ((Number) sevBreakdown.getOrDefault("critical", 0)).intValue();
        int high = ((Number) sevBreakdown.getOrDefault("high", 0)).intValue();
        int medium = ((Number) sevBreakdown.getOrDefault("medium", 0)).intValue();
        int low = ((Number) sevBreakdown.getOrDefault("low", 0)).intValue();
        html.append(summaryCard("Critical", String.valueOf(critical), "#f85149"));
        html.append(summaryCard("High", String.valueOf(high), "#f0883e"));
        html.append(summaryCard("Medium", String.valueOf(medium), "#d29922"));
        html.append(summaryCard("Low", String.valueOf(low), "#3fb950"));
        html.append(summaryCard("Duration", durationMs > 0 ? humanDuration(durationMs) : "—", "var(--muted)"));
        html.append("</div>\n\n");

        // --- Severity Distribution Bar ---
        int total = Math.max(findings.size(), 1);
        html.append("<div class=\"sev-bar-wrap\">\n");
        html.append("  <div class=\"sev-bar\">\n");
        if (critical > 0) html.append("    <div class=\"sev-bar__seg\" style=\"width:").append(pct(critical, total)).append("%;background:#f85149\" title=\"Critical: ").append(critical).append("\"></div>\n");
        if (high > 0) html.append("    <div class=\"sev-bar__seg\" style=\"width:").append(pct(high, total)).append("%;background:#f0883e\" title=\"High: ").append(high).append("\"></div>\n");
        if (medium > 0) html.append("    <div class=\"sev-bar__seg\" style=\"width:").append(pct(medium, total)).append("%;background:#d29922\" title=\"Medium: ").append(medium).append("\"></div>\n");
        if (low > 0) html.append("    <div class=\"sev-bar__seg\" style=\"width:").append(pct(low, total)).append("%;background:#3fb950\" title=\"Low: ").append(low).append("\"></div>\n");
        int info = findings.size() - critical - high - medium - low;
        if (info > 0) html.append("    <div class=\"sev-bar__seg\" style=\"width:").append(pct(info, total)).append("%;background:#8b949e\" title=\"Info: ").append(info).append("\"></div>\n");
        html.append("  </div>\n");
        html.append("  <div class=\"sev-bar-legend\">");
        html.append("<span><i style=\"background:#f85149\"></i> Critical</span>");
        html.append("<span><i style=\"background:#f0883e\"></i> High</span>");
        html.append("<span><i style=\"background:#d29922\"></i> Medium</span>");
        html.append("<span><i style=\"background:#3fb950\"></i> Low</span>");
        html.append("<span><i style=\"background:#8b949e\"></i> Info</span>");
        html.append("</div>\n</div>\n\n");

        // --- Task Details ---
        html.append("<h2>Task Details</h2>\n<div class=\"card\">\n<table class=\"kv-table\">\n");
        html.append(kvRow("Task ID", "<code>" + escapeHtml(stringValue(result.getTaskId())) + "</code>"));
        html.append(kvRow("Module", escapeHtml(stringValue(result.getModuleId()))));
        html.append(kvRow("Module Name", escapeHtml(stringValue(result.getModuleName()))));
        html.append(kvRow("Category", escapeHtml(stringValue(result.getCategory()))));
        html.append(kvRow("Target", escapeHtml(stringValue(result.getTarget()))));
        html.append(kvRow("Status", "<span class=\"status-badge status-badge--" + statusClass(result) + "\">" + escapeHtml(stringValue(result.getStatus())) + "</span>"));
        html.append(kvRow("Started", escapeHtml(stringValue(result.getStartTime()))));
        html.append(kvRow("Completed", escapeHtml(stringValue(result.getEndTime()))));
        if (durationMs > 0) {
            html.append(kvRow("Duration", humanDuration(durationMs)));
        }
        html.append("</table>\n</div>\n\n");

        // --- Findings Table ---
        if (!findings.isEmpty()) {
            html.append("<h2>Findings (").append(findings.size()).append(")</h2>\n");
            html.append("<div class=\"card\">\n<div class=\"table-scroll\"><table class=\"data-table\">\n");
            html.append("<thead><tr><th>#</th><th>Type</th><th>Severity</th><th>Title</th><th>Description</th><th>Status</th></tr></thead>\n<tbody>\n");
            for (Map<String, Object> f : findings) {
                String sev = stringValue(f.get("severity"));
                html.append("<tr>");
                html.append("<td>").append(f.get("id")).append("</td>");
                html.append("<td><span class=\"type-badge\">").append(escapeHtml(stringValue(f.get("type")))).append("</span></td>");
                html.append("<td><span class=\"sev-badge sev-badge--").append(sev).append("\">").append(escapeHtml(sev.toUpperCase())).append("</span></td>");
                html.append("<td>").append(escapeHtml(stringValue(f.get("title")))).append("</td>");
                html.append("<td class=\"desc-cell\">").append(escapeHtml(truncate(stringValue(f.get("description")), 120))).append("</td>");
                html.append("<td><span class=\"state-badge\">").append(escapeHtml(stringValue(f.get("status")))).append("</span></td>");
                html.append("</tr>\n");
            }
            html.append("</tbody>\n</table></div>\n");

            // Expandable evidence details
            html.append("<details class=\"evidence-details\"><summary>View Evidence Details</summary>\n");
            for (Map<String, Object> f : findings) {
                @SuppressWarnings("unchecked")
                Map<String, Object> evidence = f.get("evidence") instanceof Map ? (Map<String, Object>) f.get("evidence") : Map.of();
                if (!evidence.isEmpty()) {
                    html.append("<div class=\"evidence-block\"><strong>Finding #").append(f.get("id")).append("</strong>");
                    html.append(renderMapToHTMLTable(evidence));
                    html.append("</div>\n");
                }
            }
            html.append("</details>\n</div>\n\n");
        } else {
            html.append("<h2>Findings (0)</h2>\n<div class=\"card\"><p class=\"empty-msg\">No findings captured for this operation.</p></div>\n\n");
        }

        // --- Output Data ---
        Map<String, Object> output = safeMap(result.getOutput());
        if (!output.isEmpty()) {
            // Render key output metrics as cards if available
            Map<String, Object> displayOutput = new LinkedHashMap<>(output);
            displayOutput.remove("results"); // findings already shown above
            displayOutput.remove("execution_metadata");

            html.append("<h2>Processing Results</h2>\n<div class=\"card\">\n");
            html.append(renderMapToHTMLTable(displayOutput));
            html.append("</div>\n\n");
        }

        // --- Command Execution Log ---
        html.append("<h2>Command Execution Log (").append(commands.size()).append(")</h2>\n<div class=\"card\">\n");
        if (commands.isEmpty()) {
            html.append("<p class=\"empty-msg\">No external command executions were captured.</p>\n");
        } else {
            html.append("<div class=\"table-scroll\"><table class=\"data-table\">\n");
            html.append("<thead><tr><th>#</th><th>Tool</th><th>Command</th><th>Status</th><th>Exit</th><th>Duration (ms)</th><th>Stdout Preview</th></tr></thead>\n<tbody>\n");
            for (int i = 0; i < commands.size(); i++) {
                Map<String, Object> cmd = commands.get(i);
                String cmdStatus = stringValue(cmd.get("status")).toLowerCase();
                String statusCls = "success".equals(cmdStatus) ? "state-badge--ok" : "failed".equals(cmdStatus) || "timeout".equals(cmdStatus) ? "state-badge--err" : "";
                html.append("<tr>");
                html.append("<td>").append(i + 1).append("</td>");
                html.append("<td><code>").append(escapeHtml(stringValue(cmd.get("tool")))).append("</code></td>");
                html.append("<td class=\"cmd-cell\"><code>").append(escapeHtml(stringValue(cmd.get("command")))).append("</code></td>");
                html.append("<td><span class=\"state-badge ").append(statusCls).append("\">").append(escapeHtml(stringValue(cmd.get("status")))).append("</span></td>");
                html.append("<td>").append(escapeHtml(stringValue(cmd.get("exit_code")))).append("</td>");
                html.append("<td>").append(escapeHtml(stringValue(cmd.get("duration_ms")))).append("</td>");
                String stdoutPrev = stringValue(cmd.get("stdout_preview"));
                html.append("<td class=\"desc-cell\">").append(escapeHtml(truncate(stdoutPrev, 80))).append("</td>");
                html.append("</tr>\n");
            }
            html.append("</tbody>\n</table></div>\n");
        }
        html.append("</div>\n\n");

        // --- Execution Events ---
        html.append("<h2>Execution Events</h2>\n<div class=\"card\">\n<div class=\"log-block\"><pre>");
        if (events.isEmpty()) {
            html.append("No event log lines captured.");
        } else {
            for (String line : events) {
                String cls = "";
                if (line.startsWith("[!]")) cls = " class=\"log-err\"";
                else if (line.startsWith("[+]")) cls = " class=\"log-ok\"";
                else if (line.startsWith("[*]")) cls = " class=\"log-info\"";
                else if (line.startsWith("[~]")) cls = " class=\"log-warn\"";
                html.append("<span").append(cls).append(">").append(escapeHtml(line)).append("</span>\n");
            }
        }
        html.append("</pre></div>\n</div>\n\n");

        // --- Warnings ---
        if (!warnings.isEmpty()) {
            html.append("<h2>Execution Warnings</h2>\n<div class=\"card card--warn\">\n<ul>\n");
            for (String warning : warnings) {
                html.append("<li>").append(escapeHtml(warning)).append("</li>\n");
            }
            html.append("</ul>\n</div>\n\n");
        }

        // --- Footer ---
        html.append("<footer class=\"rpt-footer\">")
            .append(escapeHtml(GENERATOR)).append(" &middot; ")
            .append(escapeHtml(CREATOR)).append(" &middot; ")
            .append(Instant.now().toString())
            .append("</footer>\n");

        html.append("</div>\n</body>\n</html>");
        return html.toString();
    }

    private String getHTMLStyles() {
        return """
        <style>
          :root { color-scheme: dark; --bg:#0d1117; --panel:#141b27; --ink:#e6edf7; --muted:#8b949e; --line:#2b3648; --accent:#4bb3fd; --good:#3fb950; --warn:#d29922; --bad:#f85149; }
          * { box-sizing: border-box; margin: 0; padding: 0; }
          body { font-family: 'Segoe UI', -apple-system, system-ui, sans-serif; background: var(--bg); color: var(--ink); line-height: 1.6; }
          .wrap { max-width: 1200px; margin: 0 auto; padding: 2rem 2rem 3rem; }
          a { color: var(--accent); }
          code { font-family: 'JetBrains Mono', 'Consolas', monospace; font-size: 0.85em; background: rgba(255,255,255,0.06); padding: 0.15em 0.4em; border-radius: 4px; }

          /* Header */
          .rpt-header { display: flex; align-items: center; justify-content: space-between; padding: 1.5rem 0; border-bottom: 1px solid var(--line); margin-bottom: 1.5rem; }
          .rpt-header__brand { display: flex; align-items: center; gap: 1rem; }
          .rpt-header__logo { width: 48px; height: 48px; border-radius: 12px; overflow: hidden; background: #21262d; border: 2px solid #ff4444; flex-shrink: 0; display: flex; align-items: center; justify-content: center; box-shadow: 0 0 16px rgba(255, 68, 68, 0.4), inset 0 0 8px rgba(255, 68, 68, 0.2); }
          .rpt-header__logo img { width: 100%; height: 100%; object-fit: cover; }
          .rpt-header h1 { font-size: 1.6rem; font-weight: 800; color: white; }
          .rpt-header__sub { font-size: 0.82rem; color: var(--muted); }

          /* Status Badges */
          .status-badge { display: inline-flex; padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.02em; text-transform: uppercase; }
          .status-badge--completed { background: rgba(63,185,80,0.15); color: var(--good); border: 1px solid rgba(63,185,80,0.3); }
          .status-badge--failed { background: rgba(248,81,73,0.15); color: var(--bad); border: 1px solid rgba(248,81,73,0.3); }
          .status-badge--running, .status-badge--cancelled { background: rgba(210,153,34,0.15); color: var(--warn); border: 1px solid rgba(210,153,34,0.3); }

          /* Summary Grid */
          .summary-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 0.75rem; margin-bottom: 1.5rem; }
          .summary-card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 1rem; text-align: center; }
          .summary-card__val { font-size: 1.8rem; font-weight: 800; }
          .summary-card__label { font-size: 0.72rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.8px; margin-top: 0.2rem; }

          /* Severity Bar */
          .sev-bar-wrap { margin-bottom: 1.5rem; }
          .sev-bar { display: flex; height: 8px; border-radius: 4px; overflow: hidden; background: var(--line); }
          .sev-bar__seg { transition: width 0.3s; min-width: 2px; }
          .sev-bar-legend { display: flex; gap: 1rem; margin-top: 0.5rem; font-size: 0.72rem; color: var(--muted); }
          .sev-bar-legend i { display: inline-block; width: 8px; height: 8px; border-radius: 2px; margin-right: 4px; vertical-align: middle; }

          /* Headings */
          h2 { font-size: 1.05rem; font-weight: 700; color: var(--accent); margin: 1.75rem 0 0.75rem; }

          /* Cards */
          .card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 1.25rem; overflow: hidden; }
          .card--warn { border-color: rgba(210,153,34,0.4); background: rgba(210,153,34,0.05); }
          .card ul { margin: 0; padding-left: 1.2rem; }
          .card li { margin-bottom: 0.3rem; }

          /* Tables */
          .kv-table { width: 100%; border-collapse: collapse; }
          .kv-table td { padding: 0.5rem 0.75rem; border-bottom: 1px solid rgba(43,54,72,0.5); font-size: 0.88rem; vertical-align: top; }
          .kv-table td:first-child { color: var(--muted); font-weight: 600; width: 160px; white-space: nowrap; }
          .table-scroll { overflow-x: auto; }
          .data-table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
          .data-table th { padding: 0.6rem 0.75rem; text-align: left; background: rgba(27,38,55,0.8); color: #dbe7ff; font-weight: 700; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid var(--line); white-space: nowrap; }
          .data-table td { padding: 0.55rem 0.75rem; border-bottom: 1px solid rgba(43,54,72,0.4); vertical-align: top; }
          .data-table tbody tr:hover { background: rgba(88,166,255,0.04); }
          .desc-cell { max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
          .cmd-cell { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

          /* Badges */
          .sev-badge { display: inline-flex; padding: 0.15rem 0.55rem; border-radius: 4px; font-size: 0.68rem; font-weight: 700; letter-spacing: 0.04em; }
          .sev-badge--critical { background: rgba(248,81,73,0.2); color: #f85149; }
          .sev-badge--high { background: rgba(240,136,62,0.2); color: #f0883e; }
          .sev-badge--medium { background: rgba(210,153,34,0.2); color: #d29922; }
          .sev-badge--low { background: rgba(63,185,80,0.2); color: #3fb950; }
          .sev-badge--info { background: rgba(139,148,158,0.2); color: #8b949e; }
          .type-badge { background: rgba(75,179,253,0.12); color: var(--accent); padding: 0.12rem 0.5rem; border-radius: 4px; font-size: 0.72rem; font-weight: 600; text-transform: uppercase; }
          .state-badge { font-size: 0.72rem; font-weight: 600; padding: 0.12rem 0.45rem; border-radius: 3px; background: rgba(139,148,158,0.12); color: var(--muted); }
          .state-badge--ok { background: rgba(63,185,80,0.12); color: var(--good); }
          .state-badge--err { background: rgba(248,81,73,0.12); color: var(--bad); }

          /* Log Block */
          .log-block { max-height: 360px; overflow: auto; background: #010409; border: 1px solid var(--line); border-radius: 8px; padding: 0.75rem 1rem; }
          .log-block pre { white-space: pre-wrap; word-break: break-word; font-family: 'JetBrains Mono', 'Consolas', monospace; font-size: 0.78rem; line-height: 1.55; color: var(--muted); margin: 0; }
          .log-ok { color: #3fb950; }
          .log-err { color: #f85149; }
          .log-info { color: #00ff41; }
          .log-warn { color: #d29922; }

          /* Evidence */
          .evidence-details { margin-top: 0.75rem; border: 1px solid var(--line); border-radius: 8px; padding: 0.5rem 0.75rem; background: rgba(0,0,0,0.2); }
          .evidence-details summary { cursor: pointer; font-weight: 600; font-size: 0.82rem; color: var(--accent); padding: 0.3rem 0; }
          .evidence-block { margin-top: 0.5rem; padding: 0.5rem; border-bottom: 1px solid rgba(43,54,72,0.3); }
          .evidence-block pre { font-size: 0.75rem; white-space: pre-wrap; word-break: break-word; color: var(--muted); }
          .inline-json { font-size: 0.78rem; margin: 0; white-space: pre-wrap; word-break: break-word; }
          .empty-msg { color: var(--muted); font-size: 0.88rem; font-style: italic; }

          /* Footer */
          .rpt-footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--line); text-align: center; font-size: 0.72rem; color: rgba(139,148,158,0.6); }

          /* Responsive */
          @media (max-width: 900px) { .summary-grid { grid-template-columns: repeat(3, 1fr); } }
          @media (max-width: 600px) { .summary-grid { grid-template-columns: repeat(2, 1fr); } .wrap { padding: 1rem; } .desc-cell, .cmd-cell { max-width: 150px; } }
        </style>
        """;
    }

    private String summaryCard(String label, String value, String color) {
        return "<div class=\"summary-card\"><div class=\"summary-card__val\" style=\"color:" + color + "\">" + escapeHtml(value) + "</div><div class=\"summary-card__label\">" + escapeHtml(label) + "</div></div>\n";
    }

    private String kvRow(String label, String valueHtml) {
        return "<tr><td>" + label + "</td><td>" + valueHtml + "</td></tr>\n";
    }

    private double pct(int count, int total) {
        return Math.round((double) count / total * 1000.0) / 10.0;
    }

    private String truncate(String s, int max) {
        if (s.length() <= max) return s;
        return s.substring(0, max - 1) + "…";
    }

    private String tryParseStructuredHTML(String val) {
        if (val == null) return null;
        if (val.contains("Row: 0") && val.contains("=")) {
            String[] lines = val.split("\n");
            List<String> rowLines = new ArrayList<>();
            for (String l : lines) if (l.trim().startsWith("Row:")) rowLines.add(l.trim());
            
            if (!rowLines.isEmpty()) {
                String firstRow = rowLines.get(0);
                int spaceIdx = firstRow.indexOf(' ');
                if (spaceIdx == -1) return null;
                String[] parts = firstRow.substring(spaceIdx + 1).split(", ");
                List<String> headers = new ArrayList<>();
                for (String p : parts) {
                    String[] kv = p.split("=", 2);
                    if (kv.length > 0 && !kv[0].isBlank() && !kv[0].equals("Row:")) headers.add(kv[0].trim());
                }
                
                StringBuilder sb = new StringBuilder("<div class=\"table-scroll\"><table class=\"data-table\" style=\"margin:0; width:100%; border:none; font-family:-apple-system, sans-serif; font-size:0.75rem;\"><thead><tr>");
                for (String h : headers) sb.append("<th>").append(escapeHtml(h)).append("</th>");
                sb.append("</tr></thead><tbody>");
                
                for (String rLine : rowLines) {
                    sb.append("<tr>");
                    int sIdx = rLine.indexOf(' ');
                    if (sIdx != -1) {
                        String[] rParts = rLine.substring(sIdx + 1).split(", ");
                        Map<String, String> rowMap = new LinkedHashMap<>();
                        for (String rp : rParts) {
                            String[] kv = rp.split("=", 2);
                            if (kv.length == 2) rowMap.put(kv[0].trim(), kv[1].trim());
                        }
                        for (String h : headers) sb.append("<td>").append(escapeHtml(rowMap.getOrDefault(h, ""))).append("</td>");
                    }
                    sb.append("</tr>");
                }
                sb.append("</tbody></table></div>");
                return sb.toString();
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private String renderMapToHTMLTable(Map<String, Object> map) {
        if (map == null || map.isEmpty()) return "<i class=\"empty-msg\">Empty Dataset</i>";
        StringBuilder sb = new StringBuilder("<table class=\"data-table\" style=\"margin-top: 0.5rem; border: 1px solid var(--line); border-radius: 4px; overflow: hidden; display: table;\"><tbody>");
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            sb.append("<tr><td style=\"font-weight:700; width: 180px; background: rgba(27,38,55,0.4); text-transform: capitalize;\">").append(escapeHtml(entry.getKey().replace("_", " "))).append("</td><td style=\"font-family: 'JetBrains Mono', monospace;\">");
            if (entry.getValue() instanceof Map) {
                sb.append(renderMapToHTMLTable((Map<String, Object>) entry.getValue()));
            } else if (entry.getValue() instanceof List) {
                sb.append("<ul style=\"margin-left: 1rem;\">");
                for (Object item : (List<?>) entry.getValue()) {
                    sb.append("<li>").append(escapeHtml(String.valueOf(item))).append("</li>");
                }
                sb.append("</ul>");
            } else {
                String val = String.valueOf(entry.getValue());
                String structuredHtml = tryParseStructuredHTML(val);
                if (structuredHtml != null) {
                    sb.append(structuredHtml);
                } else if (val.matches(".*\\.(png|jpg|jpeg|gif)$")) {
                     sb.append("<img src=\"/api/reports/download?path=").append(escapeHtml(val)).append("\" style=\"max-width: 100%; max-height: 300px; border-radius: 4px; border: 1px solid var(--line);\" />");
                } else {
                     sb.append(escapeHtml(val));
                }
            }
            sb.append("</td></tr>");
        }
        sb.append("</tbody></table>");
        return sb.toString();
    }

    // ======================== Markdown ========================

    private String generateMarkdown(ModuleResult result) {
        Map<String, Object> executionLog = buildExecutionLog(result);
        List<Map<String, Object>> commands = safeMapList(executionLog.get("commands"));
        List<String> events = safeStringList(executionLog.get("events"));
        List<String> warnings = safeStringList(executionLog.get("warnings"));
        List<Map<String, Object>> findings = normalizeFindings(result.getFindings());
        long durationMs = computeDurationMs(result);

        StringBuilder md = new StringBuilder();
        md.append("# JRTS Operation Report\n\n");
        md.append("**Generator**: ").append(GENERATOR).append("  \n");
        md.append("**Created by**: ").append(CREATOR).append("  \n");
        md.append("**Timestamp**: ").append(Instant.now()).append("\n\n");

        // --- Summary ---
        md.append("## Summary\n\n");
        int critical = 0, high = 0, medium = 0, low = 0, info = 0;
        for (Map<String, Object> f : findings) {
            String sev = stringValue(f.get("severity"));
            switch (sev) {
                case "critical" -> critical++;
                case "high" -> high++;
                case "medium" -> medium++;
                case "low" -> low++;
                default -> info++;
            }
        }
        md.append("| Metric | Value |\n|---|---|\n");
        md.append("| Total Findings | **").append(findings.size()).append("** |\n");
        md.append("| Critical | ").append(critical).append(" |\n");
        md.append("| High | ").append(high).append(" |\n");
        md.append("| Medium | ").append(medium).append(" |\n");
        md.append("| Low | ").append(low).append(" |\n");
        md.append("| Info | ").append(info).append(" |\n");
        if (durationMs > 0) {
            md.append("| Duration | ").append(humanDuration(durationMs)).append(" |\n");
        }
        md.append("\n");

        // --- Task Information ---
        md.append("## Task Information\n\n");
        md.append("| Field | Value |\n|---|---|\n");
        md.append("| Task ID | `").append(result.getTaskId()).append("` |\n");
        md.append("| Module | `").append(result.getModuleId()).append("` |\n");
        md.append("| Module Name | ").append(stringValue(result.getModuleName())).append(" |\n");
        md.append("| Category | ").append(stringValue(result.getCategory())).append(" |\n");
        md.append("| Target | ").append(stringValue(result.getTarget())).append(" |\n");
        md.append("| Status | **").append(result.getStatus()).append("** |\n");
        md.append("| Start Time | ").append(result.getStartTime()).append(" |\n");
        md.append("| End Time | ").append(result.getEndTime()).append(" |\n\n");

        // --- Findings Table ---
        if (!findings.isEmpty()) {
            md.append("## Findings (").append(findings.size()).append(")\n\n");
            md.append("| # | Type | Severity | Title | Description | Status |\n");
            md.append("|---|---|---|---|---|---|\n");
            for (Map<String, Object> f : findings) {
                md.append("| ").append(f.get("id"))
                    .append(" | ").append(escapeMarkdownCell(stringValue(f.get("type"))))
                    .append(" | **").append(escapeMarkdownCell(stringValue(f.get("severity")).toUpperCase())).append("**")
                    .append(" | ").append(escapeMarkdownCell(truncate(stringValue(f.get("title")), 50)))
                    .append(" | ").append(escapeMarkdownCell(truncate(stringValue(f.get("description")), 60)))
                    .append(" | ").append(escapeMarkdownCell(stringValue(f.get("status"))))
                    .append(" |\n");
            }
            md.append("\n");

            // Evidence details
            md.append("<details><summary>Evidence Details</summary>\n\n");
            for (Map<String, Object> f : findings) {
                @SuppressWarnings("unchecked")
                Map<String, Object> evidence = f.get("evidence") instanceof Map ? (Map<String, Object>) f.get("evidence") : Map.of();
                if (!evidence.isEmpty()) {
                    md.append("#### Finding #").append(f.get("id")).append("\n\n");
                    md.append(renderMapToMarkdownTable(evidence)).append("\n\n");
                }
            }
            md.append("</details>\n\n");
        } else {
            md.append("## Findings (0)\n\n_No findings captured._\n\n");
        }

        // --- Output ---
        md.append("## Processing Results\n\n");
        Map<String, Object> displayOutput = new LinkedHashMap<>(safeMap(result.getOutput()));
        displayOutput.remove("results");
        displayOutput.remove("execution_metadata");
        md.append(renderMapToMarkdownTable(displayOutput)).append("\n\n");

        // --- Command Execution Log ---
        md.append("## Command Execution Log\n\n");
        if (commands.isEmpty()) {
            md.append("No external command executions were captured.\n\n");
        } else {
            md.append("| # | Tool | Command | Status | Exit | Duration (ms) |\n");
            md.append("|---|---|---|---|---|---|\n");
            for (int i = 0; i < commands.size(); i++) {
                Map<String, Object> cmd = commands.get(i);
                md.append("| ").append(i + 1)
                    .append(" | ").append(escapeMarkdownCell(stringValue(cmd.get("tool"))))
                    .append(" | ").append(escapeMarkdownCell(stringValue(cmd.get("command"))))
                    .append(" | ").append(escapeMarkdownCell(stringValue(cmd.get("status"))))
                    .append(" | ").append(escapeMarkdownCell(stringValue(cmd.get("exit_code"))))
                    .append(" | ").append(escapeMarkdownCell(stringValue(cmd.get("duration_ms"))))
                    .append(" |\n");
            }
            md.append("\n");
        }

        // --- Execution Events ---
        md.append("## Execution Events\n\n```text\n");
        if (events.isEmpty()) {
            md.append("No event log lines captured.\n");
        } else {
            events.forEach(line -> md.append(line).append("\n"));
        }
        md.append("```\n");

        // --- Warnings ---
        if (!warnings.isEmpty()) {
            md.append("\n## Execution Warnings\n\n");
            for (String warning : warnings) {
                md.append("- ").append(warning).append("\n");
            }
            md.append("\n");
        }

        return md.toString();
    }

    private String tryParseStructuredMD(String val) {
        if (val == null) return null;
        if (val.contains("Row: 0") && val.contains("=")) {
            String[] lines = val.split("\n");
            List<String> rowLines = new ArrayList<>();
            for (String l : lines) if (l.trim().startsWith("Row:")) rowLines.add(l.trim());
            
            if (!rowLines.isEmpty()) {
                String firstRow = rowLines.get(0);
                int spaceIdx = firstRow.indexOf(' ');
                if (spaceIdx == -1) return null;
                String[] parts = firstRow.substring(spaceIdx + 1).split(", ");
                List<String> headers = new ArrayList<>();
                for (String p : parts) {
                    String[] kv = p.split("=", 2);
                    if (kv.length > 0 && !kv[0].isBlank() && !kv[0].equals("Row:")) headers.add(kv[0].trim());
                }
                
                StringBuilder sb = new StringBuilder("\n|");
                for (String h : headers) sb.append(" ").append(escapeMarkdownCell(h)).append(" |");
                sb.append("\n|");
                for (int i = 0; i < headers.size(); i++) sb.append("---|");
                sb.append("\n");
                
                for (String rLine : rowLines) {
                    sb.append("|");
                    int sIdx = rLine.indexOf(' ');
                    if (sIdx != -1) {
                        String[] rParts = rLine.substring(sIdx + 1).split(", ");
                        Map<String, String> rowMap = new LinkedHashMap<>();
                        for (String rp : rParts) {
                            String[] kv = rp.split("=", 2);
                            if (kv.length == 2) rowMap.put(kv[0].trim(), kv[1].trim());
                        }
                        for (String h : headers) sb.append(" ").append(escapeMarkdownCell(rowMap.getOrDefault(h, ""))).append(" |");
                    }
                    sb.append("\n");
                }
                return sb.toString();
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private String renderMapToMarkdownTable(Map<String, Object> map) {
        if (map == null || map.isEmpty()) return "_Empty Dataset_";
        StringBuilder sb = new StringBuilder("| Key | Value |\n|---|---|\n");
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            sb.append("| **").append(escapeMarkdownCell(entry.getKey())).append("** | ");
            if (entry.getValue() instanceof Map || entry.getValue() instanceof List) {
                sb.append("`Nested Data Structure` |\n"); 
            } else {
                String val = String.valueOf(entry.getValue());
                String structuredMd = tryParseStructuredMD(val);
                if (structuredMd != null) {
                    // Because markdown tables cannot be nested inside cells seamlessly without breaking layout,
                    // we output a placeholder and append the sub-table below, or use HTML tags inside Markdown.
                    // For robust UI, injecting raw HTML table is generally safer in MD:
                    String structuredHtml = tryParseStructuredHTML(val);
                    sb.append(structuredHtml != null ? structuredHtml.replace("\n", "") : " `Extracted Table` ").append(" |\n");
                } else {
                    sb.append(escapeMarkdownCell(val)).append(" |\n");
                }
            }
        }
        return sb.toString();
    }

    // ======================== TXT ========================

    private String generateTXT(ModuleResult result) {
        Map<String, Object> executionLog = buildExecutionLog(result);
        List<Map<String, Object>> commands = safeMapList(executionLog.get("commands"));
        List<String> events = safeStringList(executionLog.get("events"));
        List<String> warnings = safeStringList(executionLog.get("warnings"));
        List<Map<String, Object>> findings = normalizeFindings(result.getFindings());
        long durationMs = computeDurationMs(result);

        // Severity counts
        int critical = 0, high = 0, medium = 0, low = 0;
        for (Map<String, Object> f : findings) {
            String sev = stringValue(f.get("severity"));
            switch (sev) {
                case "critical" -> critical++;
                case "high" -> high++;
                case "medium" -> medium++;
                case "low" -> low++;
            }
        }

        StringBuilder txt = new StringBuilder();
        txt.append("===============================================================\n");
        txt.append("  JRTS — JABBER Red Teaming Suite — Operation Report\n");
        txt.append("  Created by ").append(CREATOR).append("\n");
        txt.append("===============================================================\n\n");

        // Summary line
        txt.append("FINDINGS: ").append(findings.size());
        if (!findings.isEmpty()) {
            txt.append(" (");
            List<String> parts = new ArrayList<>();
            if (critical > 0) parts.add(critical + " CRITICAL");
            if (high > 0) parts.add(high + " HIGH");
            if (medium > 0) parts.add(medium + " MEDIUM");
            if (low > 0) parts.add(low + " LOW");
            txt.append(String.join(", ", parts));
            txt.append(")");
        }
        txt.append("\n");
        if (durationMs > 0) {
            txt.append("DURATION: ").append(humanDuration(durationMs)).append("\n");
        }
        txt.append("\n");

        txt.append("Task ID:      ").append(result.getTaskId()).append("\n");
        txt.append("Module:       ").append(result.getModuleId()).append("\n");
        txt.append("Module Name:  ").append(stringValue(result.getModuleName())).append("\n");
        txt.append("Category:     ").append(stringValue(result.getCategory())).append("\n");
        txt.append("Target:       ").append(stringValue(result.getTarget())).append("\n");
        txt.append("Status:       ").append(result.getStatus()).append("\n");
        txt.append("Started:      ").append(result.getStartTime()).append("\n");
        txt.append("Completed:    ").append(result.getEndTime()).append("\n\n");

        // --- Findings ---
        txt.append("--- FINDINGS ---\n\n");
        if (findings.isEmpty()) {
            txt.append("  No findings captured.\n\n");
        } else {
            for (Map<String, Object> f : findings) {
                txt.append("  [").append(f.get("id")).append("] ");
                txt.append(stringValue(f.get("severity")).toUpperCase()).append(" | ");
                txt.append(stringValue(f.get("type"))).append(" | ");
                txt.append(stringValue(f.get("title"))).append("\n");
                String desc = stringValue(f.get("description"));
                if (!desc.isBlank()) {
                    txt.append("      ").append(truncate(desc, 120)).append("\n");
                }
            }
            txt.append("\n");
        }

        // --- Output ---
        Map<String, Object> displayOutput = new LinkedHashMap<>(safeMap(result.getOutput()));
        displayOutput.remove("results");
        displayOutput.remove("execution_metadata");
        txt.append("--- PROCESSING RESULTS ---\n\n");
        if (displayOutput.isEmpty()) {
             txt.append("  No additional structured properties.\n");
        } else {
            for (Map.Entry<String, Object> entry : displayOutput.entrySet()) {
                txt.append("  [+] ").append(padRight(entry.getKey(), 20)).append(": ").append(compactJson(entry.getValue())).append("\n");
            }
        }
        txt.append("\n");

        // --- Command Execution Log ---
        txt.append("--- COMMAND EXECUTION LOG ---\n\n");
        if (commands.isEmpty()) {
            txt.append("  No external command executions captured.\n");
        } else {
            for (int i = 0; i < commands.size(); i++) {
                Map<String, Object> cmd = commands.get(i);
                txt.append("  [").append(i + 1).append("] ")
                    .append(stringValue(cmd.get("command"))).append("\n");
                txt.append("      status=").append(stringValue(cmd.get("status")))
                    .append(", exit_code=").append(stringValue(cmd.get("exit_code")))
                    .append(", timed_out=").append(stringValue(cmd.get("timed_out")))
                    .append(", duration_ms=").append(stringValue(cmd.get("duration_ms")))
                    .append("\n");
                String stdoutPreview = stringValue(cmd.get("stdout_preview"));
                if (!stdoutPreview.isBlank()) {
                    txt.append("      stdout: ").append(stdoutPreview).append("\n");
                }
                String stderrPreview = stringValue(cmd.get("stderr_preview"));
                if (!stderrPreview.isBlank()) {
                    txt.append("      stderr: ").append(stderrPreview).append("\n");
                }
            }
        }

        txt.append("\n--- EXECUTION EVENTS ---\n\n");
        if (events.isEmpty()) {
            txt.append("  No event log lines captured.\n");
        } else {
            events.forEach(line -> txt.append("  ").append(line).append("\n"));
        }

        if (!warnings.isEmpty()) {
            txt.append("\n--- EXECUTION WARNINGS ---\n\n");
            warnings.forEach(warning -> txt.append("  - ").append(warning).append("\n"));
        }

        return txt.toString();
    }

    // ======================== XML ========================

    private String generateXML(ModuleResult result) {
        Map<String, Object> execution = buildExecutionLog(result);
        List<Map<String, Object>> commandRecords = safeMapList(execution.get("commands"));
        List<String> events = safeStringList(execution.get("events"));
        List<String> warnings = safeStringList(execution.get("warnings"));

        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<JRTSReport>\n");
        xml.append("  <metadata>\n");
        xml.append("    <generator>").append(escapeXml(GENERATOR)).append("</generator>\n");
        xml.append("    <creator>").append(escapeXml(CREATOR)).append("</creator>\n");
        xml.append("    <timestamp>").append(Instant.now()).append("</timestamp>\n");
        xml.append("    <taskId>").append(result.getTaskId()).append("</taskId>\n");
        xml.append("    <moduleId>").append(result.getModuleId()).append("</moduleId>\n");
        xml.append("    <status>").append(result.getStatus()).append("</status>\n");
        xml.append("  </metadata>\n");
        xml.append("  <findings count=\"").append(result.getFindings().size()).append("\">\n");
        for (Map<String, Object> finding : result.getFindings()) {
            xml.append("    <finding>\n");
            for (Map.Entry<String, Object> e : finding.entrySet()) {
                xml.append("      <").append(escapeXml(e.getKey())).append(">");
                xml.append(escapeXml(String.valueOf(e.getValue())));
                xml.append("</").append(escapeXml(e.getKey())).append(">\n");
            }
            xml.append("    </finding>\n");
        }
        xml.append("  </findings>\n");

        xml.append("  <executionLog>\n");
        xml.append("    <commands>\n");
        for (Map<String, Object> command : commandRecords) {
            xml.append("      <command>\n");
            for (Map.Entry<String, Object> entry : command.entrySet()) {
                xml.append("        <").append(escapeXml(entry.getKey())).append(">")
                    .append(escapeXml(stringValue(entry.getValue())))
                    .append("</").append(escapeXml(entry.getKey())).append(">\n");
            }
            xml.append("      </command>\n");
        }
        xml.append("    </commands>\n");

        xml.append("    <events>\n");
        for (String line : events) {
            xml.append("    <entry>").append(escapeXml(line)).append("</entry>\n");
        }
        xml.append("    </events>\n");

        xml.append("    <warnings>\n");
        for (String warning : warnings) {
            xml.append("      <warning>").append(escapeXml(warning)).append("</warning>\n");
        }
        xml.append("    </warnings>\n");
        xml.append("  </executionLog>\n");
        xml.append("</JRTSReport>\n");
        return xml.toString();
    }

    // ======================== CSV ========================

    private String generateCSV(ModuleResult result) {
        StringBuilder csv = new StringBuilder();
        csv.append("# JRTS Report - Generated by Funbinet (dancan.tech)\n");
        csv.append("# Task: ").append(result.getTaskId()).append("\n");
        csv.append("# Module: ").append(result.getModuleId()).append("\n\n");

        if (!result.getFindings().isEmpty()) {
            Set<String> headers = new LinkedHashSet<>();
            result.getFindings().forEach(f -> headers.addAll(f.keySet()));
            csv.append(String.join(",", headers)).append("\n");
            for (Map<String, Object> finding : result.getFindings()) {
                List<String> values = new ArrayList<>();
                for (String h : headers) {
                    String val = compactJson(finding.getOrDefault(h, ""));
                    values.add("\"" + val.replace("\"", "\"\"") + "\"");
                }
                csv.append(String.join(",", values)).append("\n");
            }
        }
        return csv.toString();
    }

    // ======================== Helpers ========================

    private long computeDurationMs(ModuleResult result) {
        if (result.getStartTime() != null && result.getEndTime() != null) {
            return Duration.between(result.getStartTime(), result.getEndTime()).toMillis();
        }
        return -1;
    }

    private String humanDuration(long ms) {
        if (ms < 1000) return ms + "ms";
        if (ms < 60000) return String.format("%.1fs", ms / 1000.0);
        long minutes = ms / 60000;
        long seconds = (ms % 60000) / 1000;
        return minutes + "m " + seconds + "s";
    }

    private String padRight(String s, int width) {
        if (s.length() >= width) return s;
        return s + " ".repeat(width - s.length());
    }

    private List<Map<String, Object>> extractCommandRecords(Map<String, Object> metadata) {
        List<Map<String, Object>> commands = new ArrayList<>();

        for (Map<String, Object> record : safeMapList(metadata.get("command_log"))) {
            commands.add(normalizeCommandRecord(record));
        }

        if (commands.isEmpty()) {
            for (Map<String, Object> record : safeMapList(metadata.get("command_records"))) {
                commands.add(normalizeCommandRecord(record));
            }
        }

        if (commands.isEmpty()) {
            for (String command : safeStringList(metadata.get("executed_commands"))) {
                Map<String, Object> fallback = new LinkedHashMap<>();
                fallback.put("tool", firstToken(command));
                fallback.put("command", command);
                fallback.put("status", "unknown");
                fallback.put("exit_code", "n/a");
                fallback.put("timed_out", false);
                fallback.put("duration_ms", "n/a");
                commands.add(fallback);
            }
        }

        return commands;
    }

    private Map<String, Object> normalizeCommandRecord(Map<String, Object> raw) {
        Map<String, Object> record = new LinkedHashMap<>();
        String command = stringValue(raw.get("command"));
        if (command.isBlank()) {
            command = stringValue(raw.get("cmd"));
        }

        String tool = stringValue(raw.get("tool"));
        if (tool.isBlank()) {
            tool = firstToken(command);
        }

        Integer exitCode = asInteger(raw.get("exit_code"));
        if (exitCode == null) {
            exitCode = asInteger(raw.get("exitCode"));
        }

        Boolean timedOut = asBoolean(raw.get("timed_out"));
        if (timedOut == null) {
            timedOut = asBoolean(raw.get("timedOut"));
        }
        if (timedOut == null) {
            timedOut = false;
        }

        Long durationMs = asLong(raw.get("duration_ms"));
        if (durationMs == null) {
            durationMs = asLong(raw.get("durationMs"));
        }

        String status = stringValue(raw.get("status"));
        if (status.isBlank()) {
            if (timedOut) {
                status = "timeout";
            } else if (exitCode != null && exitCode != 0) {
                status = "failed";
            } else if (exitCode != null && exitCode == 0) {
                status = "success";
            } else {
                status = "unknown";
            }
        }

        String stdoutPreview = stringValue(raw.get("stdout_preview"));
        if (stdoutPreview.isBlank()) {
            stdoutPreview = stringValue(raw.get("stdoutPreview"));
        }
        if (stdoutPreview.isBlank()) {
            stdoutPreview = stringValue(raw.get("stdout"));
        }

        String stderrPreview = stringValue(raw.get("stderr_preview"));
        if (stderrPreview.isBlank()) {
            stderrPreview = stringValue(raw.get("stderrPreview"));
        }
        if (stderrPreview.isBlank()) {
            stderrPreview = stringValue(raw.get("stderr"));
        }

        record.put("tool", tool);
        record.put("command", command);
        record.put("status", status);
        record.put("exit_code", exitCode == null ? "n/a" : exitCode);
        record.put("timed_out", timedOut);
        record.put("duration_ms", durationMs == null ? "n/a" : durationMs);

        if (!stdoutPreview.isBlank()) {
            record.put("stdout_preview", truncateSingleLine(stdoutPreview, 300));
        }
        if (!stderrPreview.isBlank()) {
            record.put("stderr_preview", truncateSingleLine(stderrPreview, 300));
        }

        return record;
    }

    private String compactJson(Object value) {
        if (value == null) {
            return "";
        }
        if (value instanceof String s) {
            return s;
        }
        return gson.toJson(value);
    }

    private String truncateSingleLine(String value, int maxLength) {
        String collapsed = stringValue(value).replaceAll("\\s+", " ").trim();
        if (collapsed.length() <= maxLength) {
            return collapsed;
        }
        return collapsed.substring(0, maxLength - 3) + "...";
    }

    private String escapeMarkdownCell(String value) {
        return stringValue(value).replace("|", "\\|");
    }

    private String statusClass(ModuleResult result) {
        String status = stringValue(result.getStatus()).toLowerCase(Locale.ROOT);
        if (status.contains("complete")) {
            return "completed";
        }
        if (status.contains("fail")) {
            return "failed";
        }
        if (status.contains("cancel")) {
            return "cancelled";
        }
        return "running";
    }

    private String firstToken(String command) {
        String normalized = stringValue(command).trim();
        if (normalized.isBlank()) {
            return "";
        }
        int separator = normalized.indexOf(' ');
        return separator <= 0 ? normalized : normalized.substring(0, separator);
    }

    private String stringValue(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private Integer asInteger(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text) {
            try {
                return Integer.parseInt(text.trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private Long asLong(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String text) {
            try {
                return Long.parseLong(text.trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private Boolean asBoolean(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String text) {
            if ("true".equalsIgnoreCase(text)) {
                return true;
            }
            if ("false".equalsIgnoreCase(text)) {
                return false;
            }
        }
        return null;
    }

    private Map<String, Object> safeMap(Object value) {
        if (!(value instanceof Map<?, ?> rawMap)) {
            return new LinkedHashMap<>();
        }

        Map<String, Object> copy = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
            if (entry.getKey() != null) {
                copy.put(String.valueOf(entry.getKey()), entry.getValue());
            }
        }
        return copy;
    }

    private List<Map<String, Object>> safeMapList(Object value) {
        if (!(value instanceof List<?> list)) {
            return List.of();
        }

        List<Map<String, Object>> rows = new ArrayList<>();
        for (Object item : list) {
            if (item instanceof Map<?, ?> map) {
                rows.add(safeMap(map));
            }
        }
        return rows;
    }

    private List<String> safeStringList(Object value) {
        if (!(value instanceof List<?> list)) {
            return List.of();
        }

        List<String> items = new ArrayList<>();
        for (Object item : list) {
            if (item != null) {
                items.add(String.valueOf(item));
            }
        }
        return items;
    }

    private String escapeXml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }

    private String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
