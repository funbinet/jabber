package com.jabber.jabber.core.profiling;

import com.jabber.jabber.core.storage.ReportStorageService;
import com.jabber.jabber.data.model.TargetProfile;
import com.jabber.jabber.data.model.TargetProfile.*;
import com.google.gson.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.*;

/**
 * V5.5: Target Profiling Engine.
 * Parses multiple report files across formats, normalizes data, correlates findings,
 * and produces structured profiles with confidence scoring.
 */
@Service
public class TargetProfileEngine {

    private static final Logger log = LoggerFactory.getLogger(TargetProfileEngine.class);
    private final ReportStorageService storage;
    private final Gson gson = new GsonBuilder().create();

    // Regex patterns for data extraction
    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b");
    private static final Pattern PORT_PATTERN = Pattern.compile("(?:port|Port|PORT)[:\\s]*(\\d{1,5})");
    private static final Pattern CVE_PATTERN = Pattern.compile("CVE-\\d{4}-\\d{4,7}");
    private static final Pattern HOSTNAME_PATTERN = Pattern.compile("(?:hostname|host(?:name)?)[:\\s]*([a-zA-Z0-9][a-zA-Z0-9\\-_.]+\\.[a-zA-Z]{2,})", Pattern.CASE_INSENSITIVE);
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}");
    private static final Pattern MAC_PATTERN = Pattern.compile("(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}");
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[a-zA-Z0-9.\\-/:@?=&#%+_]+");
    private static final Pattern SERVICE_PATTERN = Pattern.compile("(\\d{1,5})/(tcp|udp)\\s+open\\s+([\\w\\-]+)(?:\\s+(.+))?");
    private static final Pattern TECH_PATTERN = Pattern.compile("(?:Server|X-Powered-By|Via)[:\\s]*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);

    public TargetProfileEngine(ReportStorageService storage) {
        this.storage = storage;
    }

    /**
     * Generate a target profile from multiple report IDs.
     */
    public TargetProfile generateProfile(List<String> reportIds) {
        TargetProfile profile = new TargetProfile();
        profile.setSourceReports(reportIds);

        List<String> allContent = new ArrayList<>();
        List<Map<String, Object>> jsonData = new ArrayList<>();

        // Phase 1: Load and parse all source reports
        for (String reportId : reportIds) {
            try {
                String content = storage.getReportContent(reportId);
                if (content == null) {
                    log.warn("Report not found: {}", reportId);
                    continue;
                }
                allContent.add(content);

                // Try JSON parsing for structured data
                try {
                    if (content.trim().startsWith("{") || content.trim().startsWith("[")) {
                        JsonElement el = JsonParser.parseString(content);
                        if (el.isJsonObject()) {
                            @SuppressWarnings("unchecked")
                            Map<String, Object> map = gson.fromJson(el, Map.class);
                            jsonData.add(map);
                        }
                    }
                } catch (Exception ignored) {}
            } catch (Exception e) {
                log.warn("Error reading report {}: {}", reportId, e.getMessage());
            }
        }

        if (allContent.isEmpty()) {
            log.warn("No valid reports found for profiling");
            return profile;
        }

        // Phase 2: Extract identifiers from all content
        String combinedText = String.join("\n", allContent);
        extractIdentifiers(profile, combinedText);

        // Phase 3: Extract services
        extractServices(profile, combinedText);

        // Phase 4: Extract technologies
        extractTechnologies(profile, combinedText, jsonData);

        // Phase 5: Extract vulnerabilities
        extractVulnerabilities(profile, combinedText, jsonData);

        // Phase 6: Extract behavioral insights
        extractBehavioralInsights(profile, combinedText, jsonData);

        // Phase 7: Calculate risk score and confidence
        calculateRiskScore(profile);
        calculateConfidence(profile, reportIds.size());

        log.info("Generated profile {} from {} reports: {} IPs, {} services, {} vulns",
                profile.getProfileId(), reportIds.size(),
                profile.getIpAddresses().size(),
                profile.getServices().size(),
                profile.getVulnerabilities().size());

        return profile;
    }

    private void extractIdentifiers(TargetProfile profile, String text) {
        // IPs
        Matcher m = IP_PATTERN.matcher(text);
        while (m.find()) {
            String ip = m.group();
            // Filter out common non-target IPs
            if (!ip.startsWith("127.") && !ip.equals("0.0.0.0") && !ip.startsWith("255.")) {
                profile.getIpAddresses().add(ip);
            }
        }

        // Emails
        m = EMAIL_PATTERN.matcher(text);
        while (m.find()) profile.getEmails().add(m.group());

        // MACs
        m = MAC_PATTERN.matcher(text);
        while (m.find()) profile.getMacAddresses().add(m.group().toUpperCase());

        // URLs
        m = URL_PATTERN.matcher(text);
        while (m.find()) profile.getUrls().add(m.group());

        // Hostnames
        m = HOSTNAME_PATTERN.matcher(text);
        while (m.find()) profile.getHostnames().add(m.group(1));

        // Domains - extract from URLs and hostnames
        m = DOMAIN_PATTERN.matcher(text);
        while (m.find()) {
            String domain = m.group();
            if (domain.contains(".") && !domain.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                profile.getDomains().add(domain);
            }
        }
    }

    private void extractServices(TargetProfile profile, String text) {
        // Nmap-style service detection: port/protocol state service version
        Matcher m = SERVICE_PATTERN.matcher(text);
        while (m.find()) {
            int port = Integer.parseInt(m.group(1));
            String proto = m.group(2);
            String service = m.group(3);
            String version = m.group(4) != null ? m.group(4).trim() : "";

            // Check if we already have this port
            boolean found = false;
            for (ServiceEntry existing : profile.getServices()) {
                if (existing.getPort() == port && existing.getProtocol().equals(proto)) {
                    existing.setSourceCount(existing.getSourceCount() + 1);
                    // Upgrade confidence based on multiple sources
                    if (existing.getSourceCount() >= 3) existing.setConfidence("HIGH");
                    else if (existing.getSourceCount() >= 2) existing.setConfidence("MEDIUM");
                    found = true;
                    break;
                }
            }
            if (!found) {
                profile.getServices().add(new ServiceEntry(port, proto, service, version, "open", "MEDIUM"));
            }
        }

        // Also look for port mentions in structured data
        Matcher portMatch = PORT_PATTERN.matcher(text);
        while (portMatch.find()) {
            int port = Integer.parseInt(portMatch.group(1));
            if (port > 0 && port <= 65535) {
                boolean exists = profile.getServices().stream().anyMatch(s -> s.getPort() == port);
                if (!exists) {
                    profile.getServices().add(new ServiceEntry(port, "tcp", "unknown", "", "open", "LOW"));
                }
            }
        }
    }

    private void extractTechnologies(TargetProfile profile, String text, List<Map<String, Object>> jsonData) {
        // From Server/X-Powered-By headers
        Matcher m = TECH_PATTERN.matcher(text);
        while (m.find()) {
            String techStr = m.group(1).trim();
            parseTechString(profile, techStr);
        }

        // Known technology keywords
        Map<String, String[]> techKeywords = Map.of(
            "Apache", new String[]{"web-server", "Apache httpd"},
            "nginx", new String[]{"web-server", "nginx"},
            "IIS", new String[]{"web-server", "Microsoft IIS"},
            "WordPress", new String[]{"cms", "WordPress"},
            "PHP", new String[]{"language", "PHP"},
            "Python", new String[]{"language", "Python"},
            "Java", new String[]{"language", "Java"},
            "Node.js", new String[]{"runtime", "Node.js"},
            "MySQL", new String[]{"database", "MySQL"},
            "PostgreSQL", new String[]{"database", "PostgreSQL"}
        );

        for (Map.Entry<String, String[]> entry : techKeywords.entrySet()) {
            if (text.toLowerCase().contains(entry.getKey().toLowerCase())) {
                String[] info = entry.getValue();
                boolean exists = profile.getTechnologies().stream()
                    .anyMatch(t -> t.getName().equalsIgnoreCase(info[1]));
                if (!exists) {
                    profile.getTechnologies().add(new TechEntry(info[1], "", info[0], "LOW"));
                }
            }
        }

        // From JSON data
        for (Map<String, Object> data : jsonData) {
            extractTechFromJson(profile, data, "");
        }
    }

    private void parseTechString(TargetProfile profile, String techStr) {
        // Parse "Apache/2.4.49" or "PHP/8.1.0"
        String[] parts = techStr.split("[/\\s]+");
        if (parts.length >= 1) {
            String name = parts[0];
            String version = parts.length >= 2 ? parts[1] : "";
            boolean exists = profile.getTechnologies().stream()
                .anyMatch(t -> t.getName().equalsIgnoreCase(name));
            if (!exists) {
                String category = categorizeTech(name);
                profile.getTechnologies().add(new TechEntry(name, version, category, "MEDIUM"));
            }
        }
    }

    private String categorizeTech(String name) {
        String lower = name.toLowerCase();
        if (lower.contains("apache") || lower.contains("nginx") || lower.contains("iis"))
            return "web-server";
        if (lower.contains("php") || lower.contains("python") || lower.contains("java"))
            return "language";
        if (lower.contains("mysql") || lower.contains("postgres") || lower.contains("mongo"))
            return "database";
        if (lower.contains("wordpress") || lower.contains("drupal") || lower.contains("joomla"))
            return "cms";
        return "other";
    }

    @SuppressWarnings("unchecked")
    private void extractTechFromJson(TargetProfile profile, Map<String, Object> data, String prefix) {
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            String key = entry.getKey().toLowerCase();
            if (key.contains("technology") || key.contains("product") || key.contains("server_type")
                    || key.contains("service_type")) {
                String val = String.valueOf(entry.getValue());
                if (!val.equals("null") && !val.isEmpty()) {
                    parseTechString(profile, val);
                }
            }
            if (entry.getValue() instanceof Map) {
                extractTechFromJson(profile, (Map<String, Object>) entry.getValue(), key + ".");
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void extractVulnerabilities(TargetProfile profile, String text, List<Map<String, Object>> jsonData) {
        // Extract CVEs from raw text
        Set<String> foundCves = new LinkedHashSet<>();
        Matcher m = CVE_PATTERN.matcher(text);
        while (m.find()) foundCves.add(m.group());

        for (String cve : foundCves) {
            boolean exists = profile.getVulnerabilities().stream()
                .anyMatch(v -> cve.equals(v.getCveId()));
            if (!exists) {
                VulnEntry vuln = new VulnEntry(cve, cve, "UNKNOWN", "Found in report text", "LOW");
                vuln.setStatus("POTENTIAL");
                profile.getVulnerabilities().add(vuln);
            }
        }

        // Extract structured vulnerability data from JSON
        for (Map<String, Object> data : jsonData) {
            extractVulnsFromJson(profile, data);
        }

        // Upgrade confidence for vulns found in multiple sources
        for (VulnEntry v : profile.getVulnerabilities()) {
            long count = text.split(Pattern.quote(v.getCveId() != null ? v.getCveId() : "NONE")).length - 1;
            if (count >= 3) {
                v.setConfidence("HIGH");
                v.setStatus("CONFIRMED");
            } else if (count >= 2) {
                v.setConfidence("MEDIUM");
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void extractVulnsFromJson(TargetProfile profile, Map<String, Object> data) {
        // Look for vulnerability indicators in JSON
        Boolean vulnerable = null;
        String cve = null;
        String severity = null;
        String evidence = null;

        for (Map.Entry<String, Object> e : data.entrySet()) {
            String key = e.getKey().toLowerCase();
            Object val = e.getValue();
            if (key.equals("vulnerable") && val instanceof Boolean) vulnerable = (Boolean) val;
            if (key.equals("cve") || key.equals("cve_id") || key.equals("cveid"))
                cve = String.valueOf(val);
            if (key.equals("severity")) severity = String.valueOf(val);
            if (key.equals("evidence") || key.equals("proof")) evidence = String.valueOf(val);
            if (key.equals("impact")) severity = guessSeverity(String.valueOf(val));
        }

        if (Boolean.TRUE.equals(vulnerable) && cve != null) {
            final String cveId = cve;
            boolean exists = profile.getVulnerabilities().stream()
                .anyMatch(v -> cveId.equals(v.getCveId()));
            if (!exists) {
                VulnEntry vuln = new VulnEntry(cveId, cveId,
                    severity != null ? severity : "UNKNOWN",
                    evidence != null ? evidence : "Confirmed vulnerable by module execution",
                    "HIGH");
                vuln.setStatus("CONFIRMED");
                profile.getVulnerabilities().add(vuln);
            } else {
                // Upgrade existing
                profile.getVulnerabilities().stream()
                    .filter(v -> cveId.equals(v.getCveId()))
                    .findFirst()
                    .ifPresent(v -> {
                        v.setConfidence("HIGH");
                        v.setStatus("CONFIRMED");
                        v.setSourceCount(v.getSourceCount() + 1);
                    });
            }
        }

        // Recurse into nested maps
        for (Object val : data.values()) {
            if (val instanceof Map) extractVulnsFromJson(profile, (Map<String, Object>) val);
            if (val instanceof List) {
                for (Object item : (List<?>) val) {
                    if (item instanceof Map) extractVulnsFromJson(profile, (Map<String, Object>) item);
                }
            }
        }
    }

    private String guessSeverity(String impact) {
        String lower = impact.toLowerCase();
        if (lower.contains("critical") || lower.contains("remote code execution")) return "CRITICAL";
        if (lower.contains("high") || lower.contains("rce")) return "HIGH";
        if (lower.contains("medium")) return "MEDIUM";
        if (lower.contains("low") || lower.contains("informational")) return "LOW";
        return "UNKNOWN";
    }

    @SuppressWarnings("unchecked")
    private void extractBehavioralInsights(TargetProfile profile, String text, List<Map<String, Object>> jsonData) {
        Map<String, Object> insights = profile.getBehavioralInsights();

        // OS detection heuristics
        if (text.toLowerCase().contains("windows")) insights.put("os_hint", "Windows");
        else if (text.toLowerCase().contains("linux")) insights.put("os_hint", "Linux");
        else if (text.toLowerCase().contains("freebsd")) insights.put("os_hint", "FreeBSD");

        // Protocol analysis
        Set<String> protocols = new LinkedHashSet<>();
        if (text.contains("HTTP")) protocols.add("HTTP");
        if (text.contains("HTTPS") || text.contains("SSL") || text.contains("TLS")) protocols.add("HTTPS/TLS");
        if (text.contains("SSH")) protocols.add("SSH");
        if (text.contains("FTP")) protocols.add("FTP");
        if (text.contains("SMB")) protocols.add("SMB");
        if (text.contains("RDP")) protocols.add("RDP");
        if (text.contains("DNS")) protocols.add("DNS");
        if (text.contains("LDAP")) protocols.add("LDAP");
        if (!protocols.isEmpty()) insights.put("protocols_detected", protocols);

        // Attack surface estimation
        int attackSurface = profile.getServices().size() * 10 +
                profile.getVulnerabilities().size() * 20 +
                profile.getTechnologies().size() * 5;
        insights.put("attack_surface_score", Math.min(attackSurface, 100));
        insights.put("total_services", profile.getServices().size());
        insights.put("total_vulns", profile.getVulnerabilities().size());
        insights.put("total_technologies", profile.getTechnologies().size());
        insights.put("source_report_count", profile.getSourceReports().size());
    }

    private void calculateRiskScore(TargetProfile profile) {
        int score = 0;
        for (VulnEntry v : profile.getVulnerabilities()) {
            switch (v.getSeverity().toUpperCase()) {
                case "CRITICAL" -> score += 25;
                case "HIGH" -> score += 15;
                case "MEDIUM" -> score += 8;
                case "LOW" -> score += 3;
                default -> score += 5;
            }
        }
        // Factor in attack surface
        score += profile.getServices().size() * 2;
        score += profile.getTechnologies().size();
        profile.setOverallRiskScore(Math.min(score, 100));
    }

    private void calculateConfidence(TargetProfile profile, int sourceCount) {
        int dataPoints = profile.getIpAddresses().size() + profile.getServices().size() +
                profile.getTechnologies().size() + profile.getVulnerabilities().size();

        if (sourceCount >= 3 && dataPoints >= 10) {
            profile.setConfidenceLevel("HIGH");
        } else if (sourceCount >= 2 && dataPoints >= 5) {
            profile.setConfidenceLevel("MEDIUM");
        } else {
            profile.setConfidenceLevel("LOW");
        }
    }
}
