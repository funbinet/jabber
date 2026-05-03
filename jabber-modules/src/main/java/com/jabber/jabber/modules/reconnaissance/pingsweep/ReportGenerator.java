package com.jabber.jabber.modules.reconnaissance.pingsweep;

import java.util.*;

/**
 * ReportGenerator — Intelligence-grade Network Dossier Generator.
 */
public class ReportGenerator {

    public record ReportPayload(Map<String, Object> output, Map<String, Object> normalizedOutput) {}

    public ReportPayload buildReport(String mode, String target, List<CommandRecord> records, List<Map<String, Object>> findings, long startedAt) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("module", "recon-pingsweep");
        output.put("mode", mode);
        output.put("target", target);
        output.put("summary", summarize(findings));
        output.put("findings", findings);
        output.put("execution_metadata", Map.of(
            "elapsed_ms", System.currentTimeMillis() - startedAt,
            "commands", records
        ));

        String html = generateHtmlReport(mode, target, findings, records);
        
        Map<String, Object> normalized = new LinkedHashMap<>();
        normalized.put("dossier_type", "Network Intelligence");
        normalized.put("host_count", findings.stream().filter(f -> "responsive_host".equals(f.get("type"))).count());
        normalized.put("parsed_output", Map.of("html_report", html));

        return new ReportPayload(output, normalized);
    }

    private Map<String, Object> summarize(List<Map<String, Object>> findings) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("total_discovered", findings.stream().filter(f -> "responsive_host".equals(f.get("type"))).count());
        s.put("open_ports", findings.stream().filter(f -> "open_port".equals(f.get("type"))).count());
        s.put("adjacency_records", findings.stream().filter(f -> "adjacency_map".equals(f.get("type"))).count());
        s.put("netbios_records", findings.stream().filter(f -> "netbios_inventory".equals(f.get("type"))).count());
        return s;
    }

    private String generateHtmlReport(String mode, String target, List<Map<String, Object>> findings, List<CommandRecord> records) {
        StringBuilder sb = new StringBuilder();
        sb.append("<style>")
          .append(":root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --text:#c9d1d9; --accent:#58a6ff; --dim:#8b949e; --success:#238636; }")
          .append("body { font-family: -apple-system, system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; margin: 0; padding: 20px; }")
          .append(".card { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 16px; margin-bottom: 20px; }")
          .append("h2 { color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-top: 0; font-size: 18px; text-transform: uppercase; letter-spacing: 1px; }")
          .append("table { width: 100%; border-collapse: collapse; font-size: 13px; }")
          .append("th { text-align: left; padding: 8px; border-bottom: 2px solid var(--border); color: var(--dim); }")
          .append("td { padding: 8px; border-bottom: 1px solid var(--border); }")
          .append(".badge { padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }")
          .append(".badge-alive { background: rgba(35,134,54,0.2); color: #3fb950; }")
          .append(".mono { font-family: 'JetBrains Mono', monospace; font-size: 12px; }")
          .append("</style>");

        sb.append("<h2>Network Intelligence Dossier — ").append(mode).append("</h2>");
        sb.append("<div class='card'>");
        sb.append("<strong>Target Range:</strong> <span class='mono'>").append(target).append("</span><br/>");
        sb.append("<strong>Discovery Mode:</strong> ").append(mode).append("<br/>");
        sb.append("<strong>Status:</strong> <span class='badge badge-alive'>COMPLETED</span>");
        sb.append("</div>");

        // ── Section 1: Responsive Hosts ──
        List<Map<String, Object>> hosts = findings.stream().filter(f -> "responsive_host".equals(f.get("type"))).toList();
        if (!hosts.isEmpty()) {
            sb.append("<h2>Discovered Responsive Hosts</h2>");
            sb.append("<div class='card'><table><thead><tr><th>IP Address</th><th>MAC Address</th><th>Discovery Method</th><th>Status</th></tr></thead><tbody>");
            for (Map<String, Object> h : hosts) {
                sb.append("<tr>")
                  .append("<td class='mono'>").append(h.getOrDefault("ip", "-")).append("</td>")
                  .append("<td class='mono'>").append(h.getOrDefault("mac", "—")).append("</td>")
                  .append("<td>").append(h.getOrDefault("method", "-")).append("</td>")
                  .append("<td><span class='badge badge-alive'>ALIVE</span></td>")
                  .append("</tr>");
            }
            sb.append("</tbody></table></div>");
        }

        // ── Section 2: Open Ports ──
        List<Map<String, Object>> ports = findings.stream().filter(f -> "open_port".equals(f.get("type"))).toList();
        if (!ports.isEmpty()) {
            sb.append("<h2>Discovered Open Ports (High-Speed Sweep)</h2>");
            sb.append("<div class='card'><table><thead><tr><th>IP Address</th><th>Port</th><th>Protocol</th><th>Method</th></tr></thead><tbody>");
            for (Map<String, Object> p : ports) {
                sb.append("<tr>")
                  .append("<td class='mono'>").append(p.getOrDefault("ip", "-")).append("</td>")
                  .append("<td class='mono'>").append(p.getOrDefault("port", "-")).append("</td>")
                  .append("<td>").append(p.getOrDefault("proto", "-")).append("</td>")
                  .append("<td>").append(p.getOrDefault("method", "-")).append("</td>")
                  .append("</tr>");
            }
            sb.append("</tbody></table></div>");
        }

        // ── Section 3: Adjacency Map (ARP) ──
        List<Map<String, Object>> adj = findings.stream().filter(f -> "adjacency_map".equals(f.get("type"))).toList();
        if (!adj.isEmpty()) {
            sb.append("<h2>Local Adjacency Map (L2 Discovery)</h2>");
            sb.append("<div class='card'><table><thead><tr><th>IP Address</th><th>MAC Address</th><th>Vendor / OUI Intelligence</th></tr></thead><tbody>");
            for (Map<String, Object> a : adj) {
                sb.append("<tr>")
                  .append("<td class='mono'>").append(a.getOrDefault("ip", "-")).append("</td>")
                  .append("<td class='mono'>").append(a.getOrDefault("mac", "-")).append("</td>")
                  .append("<td>").append(a.getOrDefault("vendor", "-")).append("</td>")
                  .append("</tr>");
            }
            sb.append("</tbody></table></div>");
        }

        // ── Section 3: NetBIOS Inventory ──
        List<Map<String, Object>> nbt = findings.stream().filter(f -> "netbios_inventory".equals(f.get("type"))).toList();
        if (!nbt.isEmpty()) {
            sb.append("<h2>NetBIOS & SMB Attribution</h2>");
            sb.append("<div class='card'><table><thead><tr><th>IP Address</th><th>Host Name</th><th>Workgroup / Domain</th></tr></thead><tbody>");
            for (Map<String, Object> n : nbt) {
                sb.append("<tr>")
                  .append("<td class='mono'>").append(n.getOrDefault("ip", "-")).append("</td>")
                  .append("<td class='mono'>").append(n.getOrDefault("name", "-")).append("</td>")
                  .append("<td>").append(n.getOrDefault("workgroup", "-")).append("</td>")
                  .append("</tr>");
            }
            sb.append("</tbody></table></div>");
        }

        // ── Section 4: Command Telemetry ──
        sb.append("<h2>Technical Telemetry</h2>");
        sb.append("<details><summary>View Raw Command Artifacts</summary>");
        for (CommandRecord rec : records) {
            sb.append("<div class='card'>");
            sb.append("<strong>Tool:</strong> ").append(rec.toolId()).append("<br/>");
            sb.append("<strong>Command:</strong> <code style='font-size:11px'>").append(String.join(" ", rec.command())).append("</code><br/>");
            sb.append("<strong>Exit Code:</strong> ").append(rec.exitCode()).append("<br/>");
            sb.append("<pre style='font-size:10px; background:#000; color:#0f0; padding:10px; overflow:auto; max-height:200px;'>")
              .append(rec.stdout()).append("</pre>");
            sb.append("</div>");
        }
        sb.append("</details>");

        return sb.toString();
    }
}
