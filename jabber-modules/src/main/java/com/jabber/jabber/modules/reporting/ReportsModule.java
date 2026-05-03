package com.jabber.jabber.modules.reporting;

import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.security.*;

/**
 * ReportsModule - Comprehensive reporting, profiling, and analytics
 * Generates intelligence reports, profiles entities, and analyzes collected data
 */
public class ReportsModule {

    /**
     * Report types
     */
    public enum ReportType {
        EXECUTIVE_SUMMARY, TECHNICAL_DETAILS, VULNERABILITY_ASSESSMENT,
        RISK_ANALYSIS, ENTITY_PROFILE, TIMELINE_ANALYSIS, NETWORK_MAP,
        CREDENTIAL_ANALYSIS, PERSISTENCE_ANALYSIS, ATTACK_CHAIN
    }

    /**
     * Entity types
     */
    public enum EntityType {
        HOST, USER, SERVICE, APPLICATION, DOMAIN, SHARE, CREDENTIAL,
        CERTIFICATE, API_ENDPOINT, DATABASE, LDAP_OBJECT, EMAIL, IP_ADDRESS
    }

    /**
     * Risk levels
     */
    public enum RiskLevel {
        CRITICAL(9-10), HIGH(7-8), MEDIUM(5-6), LOW(3-4), INFO(1-2);
        
        private final String range;
        RiskLevel(int range) {
            this.range = "Score: " + range;
        }
    }

    /**
     * Export formats
     */
    public enum ExportFormat {
        HTML, PDF, JSON, XML, CSV, MARKDOWN, PLAINTEXT, DOCX
    }

    /**
     * Entity Profile - Comprehensive entity information
     */
    public static class EntityProfile {
        public String entityId;
        public EntityType type;
        public String name;
        public String description;
        public long discoveredTime;
        public long lastSeenTime;
        public String ipAddress;
        public String hostname;
        public String osInfo;
        public String systemInfo;
        public List<String> services = new ArrayList<>();
        public List<String> applications = new ArrayList<>();
        public List<String> openPorts = new ArrayList<>();
        public List<String> identifiedCredentials = new ArrayList<>();
        public List<String> vulnerabilities = new ArrayList<>();
        public List<String> inboundConnections = new ArrayList<>();
        public List<String> outboundConnections = new ArrayList<>();
        public String accountStatus;
        public String privilegeLevel;
        public float riskScore;
        public RiskLevel riskLevel;
        public Map<String, String> metadata = new HashMap<>();
        public List<String> tags = new ArrayList<>();
        public String notes;
    }

    /**
     * Attack Chain Entry
     */
    public static class AttackChainEntry {
        public int sequence;
        public long timestamp;
        public String phase;
        public String action;
        public String source;
        public String target;
        public Entity impactedEntity;
        public String result;
        public RiskLevel riskLevel;
        public List<String> evidence = new ArrayList<>();
    }

    /**
     * Entity reference
     */
    public static class Entity {
        public String id;
        public EntityType type;
        public String name;
        
        public Entity(String id, EntityType type, String name) {
            this.id = id;
            this.type = type;
            this.name = name;
        }
    }

    /**
     * Finding/Vulnerability
     */
    public static class Finding {
        public String id;
        public String title;
        public String description;
        public RiskLevel severity;
        public Entity affectedEntity;
        public String category;
        public String remediation;
        public List<String> evidence = new ArrayList<>();
        public boolean exploitable;
        public String exploitDetails;
        public long discoveredTime;
    }

    /**
     * Report Container
     */
    public static class Report {
        public String reportId;
        public ReportType type;
        public String title;
        public String description;
        public long generatedTime;
        public String generatedBy;
        public List<EntityProfile> entityProfiles = new ArrayList<>();
        public List<Finding> findings = new ArrayList<>();
        public List<AttackChainEntry> attackChain = new ArrayList<>();
        public Map<String, Object> statistics = new HashMap<>();
        public Map<String, Integer> riskDistribution = new HashMap<>();
        public String executiveSummary;
        public List<String> recommendedActions = new ArrayList<>();
        public Map<String, String> metadata = new HashMap<>();
    }

    private ConcurrentHashMap<String, EntityProfile> entityProfiles;
    private ConcurrentHashMap<String, Finding> findings;
    private List<AttackChainEntry> attackChain;
    private ConcurrentHashMap<String, Report> generatedReports;
    private ScheduledExecutorService executor;
    private DateTimeFormatter dateFormatter;

    public ReportsModule() {
        this.entityProfiles = new ConcurrentHashMap<>();
        this.findings = new ConcurrentHashMap<>();
        this.attackChain = Collections.synchronizedList(new ArrayList<>());
        this.generatedReports = new ConcurrentHashMap<>();
        this.executor = Executors.newScheduledThreadPool(4);
        this.dateFormatter = DateTimeFormatter.ISO_DATE_TIME;
    }

    // ===== ENTITY PROFILING =====

    /**
     * Create entity profile
     */
    public EntityProfile createEntityProfile(String entityId, EntityType type, String name) {
        EntityProfile profile = new EntityProfile();
        profile.entityId = entityId;
        profile.type = type;
        profile.name = name;
        profile.discoveredTime = System.currentTimeMillis();
        profile.lastSeenTime = System.currentTimeMillis();
        profile.riskScore = 0.0f;
        profile.riskLevel = RiskLevel.INFO;
        entityProfiles.put(entityId, profile);
        return profile;
    }

    /**
     * Update entity profile with detailed information
     */
    public void updateEntityProfile(String entityId, String fieldName, Object value) {
        EntityProfile profile = entityProfiles.get(entityId);
        if (profile == null) return;

        switch(fieldName.toLowerCase()) {
            case "ipaddress" -> profile.ipAddress = (String) value;
            case "hostname" -> profile.hostname = (String) value;
            case "osinfo" -> profile.osInfo = (String) value;
            case "systeminfo" -> profile.systemInfo = (String) value;
            case "accountstatus" -> profile.accountStatus = (String) value;
            case "privilegelevel" -> profile.privilegeLevel = (String) value;
            case "description" -> profile.description = (String) value;
            case "notes" -> profile.notes = (String) value;
        }
        profile.lastSeenTime = System.currentTimeMillis();
    }

    /**
     * Add service to entity
     */
    public void addService(String entityId, String service) {
        EntityProfile profile = entityProfiles.get(entityId);
        if (profile != null && !profile.services.contains(service)) {
            profile.services.add(service);
        }
    }

    /**
     * Add vulnerability to entity
     */
    public void addVulnerability(String entityId, String vulnerability) {
        EntityProfile profile = entityProfiles.get(entityId);
        if (profile != null && !profile.vulnerabilities.contains(vulnerability)) {
            profile.vulnerabilities.add(vulnerability);
        }
    }

    /**
     * Add identified credential to entity
     */
    public void addIdentifiedCredential(String entityId, String credentialInfo) {
        EntityProfile profile = entityProfiles.get(entityId);
        if (profile != null && !profile.identifiedCredentials.contains(credentialInfo)) {
            profile.identifiedCredentials.add(credentialInfo);
        }
    }

    /**
     * Calculate risk score for entity
     */
    public float calculateRiskScore(String entityId) {
        EntityProfile profile = entityProfiles.get(entityId);
        if (profile == null) return 0.0f;

        float score = 0.0f;

        // Vulnerability count multiplier
        score += profile.vulnerabilities.size() * 1.5f;

        // Credential exposure
        score += profile.identifiedCredentials.size() * 2.0f;

        // Service exposure (each open port)
        score += profile.openPorts.size() * 0.8f;

        // Privilege level
        if ("ADMIN".equals(profile.privilegeLevel)) score += 3.0f;
        else if ("USER".equals(profile.privilegeLevel)) score += 1.5f;

        // Account status
        if ("ACTIVE".equals(profile.accountStatus)) score += 1.0f;

        // Cap at 10.0
        score = Math.min(score, 10.0f);

        profile.riskScore = score;

        // Set risk level
        if (score >= 9) profile.riskLevel = RiskLevel.CRITICAL;
        else if (score >= 7) profile.riskLevel = RiskLevel.HIGH;
        else if (score >= 5) profile.riskLevel = RiskLevel.MEDIUM;
        else if (score >= 3) profile.riskLevel = RiskLevel.LOW;
        else profile.riskLevel = RiskLevel.INFO;

        return score;
    }

    /**
     * Get high-risk entities
     */
    public List<EntityProfile> getHighRiskEntities() {
        return entityProfiles.values().stream()
                .filter(p -> p.riskLevel == RiskLevel.CRITICAL || p.riskLevel == RiskLevel.HIGH)
                .sorted((a, b) -> Float.compare(b.riskScore, a.riskScore))
                .collect(Collectors.toList());
    }

    /**
     * Profile entity by hostname
     */
    public EntityProfile profileByHostname(String hostname) {
        return entityProfiles.values().stream()
                .filter(p -> hostname.equalsIgnoreCase(p.hostname))
                .findFirst()
                .orElse(null);
    }

    /**
     * Profile entity by IP
     */
    public EntityProfile profileByIP(String ipAddress) {
        return entityProfiles.values().stream()
                .filter(p -> ipAddress.equals(p.ipAddress))
                .findFirst()
                .orElse(null);
    }

    // ===== FINDINGS & VULNERABILITIES =====

    /**
     * Add finding
     */
    public Finding addFinding(String title, String description, RiskLevel severity, String affectedEntity) {
        Finding finding = new Finding();
        finding.id = "F_" + System.currentTimeMillis();
        finding.title = title;
        finding.description = description;
        finding.severity = severity;
        finding.affectedEntity = new Entity("ent_" + affectedEntity, EntityType.HOST, affectedEntity);
        finding.discoveredTime = System.currentTimeMillis();

        findings.put(finding.id, finding);
        return finding;
    }

    /**
     * Get findings by severity
     */
    public List<Finding> getFindingsBySeverity(RiskLevel severity) {
        return findings.values().stream()
                .filter(f -> f.severity == severity)
                .collect(Collectors.toList());
    }

    /**
     * Get all critical findings
     */
    public List<Finding> getCriticalFindings() {
        return getFindingsBySeverity(RiskLevel.CRITICAL);
    }

    // ===== ATTACK CHAIN =====

    /**
     * Record attack chain entry
     */
    public void recordAttackChainEntry(int sequence, String phase, String action, String source, String target) {
        AttackChainEntry entry = new AttackChainEntry();
        entry.sequence = sequence;
        entry.timestamp = System.currentTimeMillis();
        entry.phase = phase;
        entry.action = action;
        entry.source = source;
        entry.target = target;
        entry.impactedEntity = new Entity("ent_" + target, EntityType.HOST, target);

        attackChain.add(entry);
    }

    /**
     * Get attack chain
     */
    public List<AttackChainEntry> getAttackChain() {
        return new ArrayList<>(attackChain);
    }

    /**
     * Get attack chain by phase
     */
    public List<AttackChainEntry> getAttackChainByPhase(String phase) {
        return attackChain.stream()
                .filter(e -> e.phase.equalsIgnoreCase(phase))
                .collect(Collectors.toList());
    }

    // ===== REPORT GENERATION =====

    /**
     * Generate executive summary report
     */
    public Report generateExecutiveSummary() {
        Report report = new Report();
        report.reportId = "REP_" + System.currentTimeMillis();
        report.type = ReportType.EXECUTIVE_SUMMARY;
        report.title = "Executive Summary Report";
        report.generatedTime = System.currentTimeMillis();
        report.generatedBy = "JABBER Framework";

        // Add high-risk entities
        List<EntityProfile> highRisk = getHighRiskEntities();
        report.entityProfiles.addAll(highRisk);

        // Add critical findings
        report.findings.addAll(getCriticalFindings());

        // Generate statistics
        report.statistics.put("totalEntities", entityProfiles.size());
        report.statistics.put("criticalEntities", highRisk.size());
        report.statistics.put("totalFindings", findings.size());
        report.statistics.put("criticalFindings", getCriticalFindings().size());
        report.statistics.put("averageRiskScore", 
            entityProfiles.values().stream()
                .mapToDouble(p -> p.riskScore)
                .average()
                .orElse(0.0));

        // Risk distribution
        report.riskDistribution.put("CRITICAL", 
            (int) findings.values().stream().filter(f -> f.severity == RiskLevel.CRITICAL).count());
        report.riskDistribution.put("HIGH", 
            (int) findings.values().stream().filter(f -> f.severity == RiskLevel.HIGH).count());
        report.riskDistribution.put("MEDIUM", 
            (int) findings.values().stream().filter(f -> f.severity == RiskLevel.MEDIUM).count());
        report.riskDistribution.put("LOW", 
            (int) findings.values().stream().filter(f -> f.severity == RiskLevel.LOW).count());

        // Executive summary
        report.executiveSummary = String.format(
            "Assessment identified %d entities with an average risk score of %.2f. " +
            "%d critical findings require immediate attention. " +
            "%d high-risk entities pose significant exposure.",
            entityProfiles.size(),
            (double) report.statistics.get("averageRiskScore"),
            report.riskDistribution.getOrDefault("CRITICAL", 0),
            highRisk.size()
        );

        // Recommended actions
        report.recommendedActions.add("Remediate all critical vulnerabilities within 24 hours");
        report.recommendedActions.add("Implement network segmentation to isolate high-risk assets");
        report.recommendedActions.add("Force password reset on compromised accounts");
        report.recommendedActions.add("Enable MFA on all administrative accounts");
        report.recommendedActions.add("Deploy EDR solution on critical hosts");

        generatedReports.put(report.reportId, report);
        return report;
    }

    /**
     * Generate entity profile report
     */
    public Report generateEntityProfileReport() {
        Report report = new Report();
        report.reportId = "REP_" + System.currentTimeMillis();
        report.type = ReportType.ENTITY_PROFILE;
        report.title = "Entity Profiling Report";
        report.generatedTime = System.currentTimeMillis();

        report.entityProfiles.addAll(entityProfiles.values());

        report.statistics.put("totalEntities", entityProfiles.size());
        report.statistics.put("hostCount", 
            entityProfiles.values().stream().filter(p -> p.type == EntityType.HOST).count());
        report.statistics.put("userCount", 
            entityProfiles.values().stream().filter(p -> p.type == EntityType.USER).count());
        report.statistics.put("serviceCount", 
            entityProfiles.values().stream().mapToInt(p -> p.services.size()).sum());
        report.statistics.put("vulnerabilityCount", 
            entityProfiles.values().stream().mapToInt(p -> p.vulnerabilities.size()).sum());

        generatedReports.put(report.reportId, report);
        return report;
    }

    /**
     * Generate attack chain report
     */
    public Report generateAttackChainReport() {
        Report report = new Report();
        report.reportId = "REP_" + System.currentTimeMillis();
        report.type = ReportType.ATTACK_CHAIN;
        report.title = "Attack Chain Analysis";
        report.generatedTime = System.currentTimeMillis();

        report.attackChain.addAll(getAttackChain());

        report.statistics.put("chainLength", attackChain.size());
        report.statistics.put("phases", attackChain.stream()
                .map(e -> e.phase)
                .distinct()
                .count());
        report.statistics.put("affectedEntities", attackChain.stream()
                .map(e -> e.target)
                .distinct()
                .count());

        // Phases identified
        Set<String> phases = attackChain.stream()
                .map(e -> e.phase)
                .collect(Collectors.toSet());
        report.executiveSummary = "Attack chain identified with " + 
            attackChain.size() + " steps across phases: " + 
            String.join(", ", phases);

        generatedReports.put(report.reportId, report);
        return report;
    }

    /**
     * Generate vulnerability assessment report
     */
    public Report generateVulnerabilityAssessment() {
        Report report = new Report();
        report.reportId = "REP_" + System.currentTimeMillis();
        report.type = ReportType.VULNERABILITY_ASSESSMENT;
        report.title = "Vulnerability Assessment Report";
        report.generatedTime = System.currentTimeMillis();

        report.findings.addAll(findings.values());

        report.statistics.put("totalVulnerabilities", findings.size());
        report.statistics.put("exploitable", 
            findings.values().stream().filter(f -> f.exploitable).count());

        generatedReports.put(report.reportId, report);
        return report;
    }

    // ===== REPORT EXPORT =====

    /**
     * Export report to JSON
     */
    public String exportReportJSON(Report report) {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"reportId\": \"").append(report.reportId).append("\",\n");
        json.append("  \"type\": \"").append(report.type).append("\",\n");
        json.append("  \"title\": \"").append(report.title).append("\",\n");
        json.append("  \"generatedTime\": ").append(report.generatedTime).append(",\n");
        json.append("  \"generatedBy\": \"").append(report.generatedBy).append("\",\n");
        
        // Entity profiles
        json.append("  \"entityProfiles\": [\n");
        for (int i = 0; i < report.entityProfiles.size(); i++) {
            EntityProfile ep = report.entityProfiles.get(i);
            json.append("    {\n");
            json.append("      \"entityId\": \"").append(ep.entityId).append("\",\n");
            json.append("      \"name\": \"").append(ep.name).append("\",\n");
            json.append("      \"type\": \"").append(ep.type).append("\",\n");
            json.append("      \"ipAddress\": \"").append(ep.ipAddress != null ? ep.ipAddress : "").append("\",\n");
            json.append("      \"hostname\": \"").append(ep.hostname != null ? ep.hostname : "").append("\",\n");
            json.append("      \"riskScore\": ").append(ep.riskScore).append(",\n");
            json.append("      \"riskLevel\": \"").append(ep.riskLevel).append("\",\n");
            json.append("      \"vulnerabilities\": [");
            for (int j = 0; j < ep.vulnerabilities.size(); j++) {
                json.append("\"").append(ep.vulnerabilities.get(j)).append("\"");
                if (j < ep.vulnerabilities.size() - 1) json.append(", ");
            }
            json.append("]\n");
            json.append("    }");
            if (i < report.entityProfiles.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("  ],\n");

        // Findings
        json.append("  \"findings\": [\n");
        for (int i = 0; i < report.findings.size(); i++) {
            Finding f = report.findings.get(i);
            json.append("    {\n");
            json.append("      \"id\": \"").append(f.id).append("\",\n");
            json.append("      \"title\": \"").append(f.title).append("\",\n");
            json.append("      \"severity\": \"").append(f.severity).append("\",\n");
            json.append("      \"exploitable\": ").append(f.exploitable).append("\n");
            json.append("    }");
            if (i < report.findings.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("  ],\n");

        // Statistics
        json.append("  \"statistics\": {\n");
        int statIndex = 0;
        for (Map.Entry<String, Object> stat : report.statistics.entrySet()) {
            json.append("    \"").append(stat.getKey()).append("\": ");
            if (stat.getValue() instanceof String) {
                json.append("\"").append(stat.getValue()).append("\"");
            } else {
                json.append(stat.getValue());
            }
            if (statIndex < report.statistics.size() - 1) json.append(",");
            json.append("\n");
            statIndex++;
        }
        json.append("  }\n");
        json.append("}");
        return json.toString();
    }

    /**
     * Export report to CSV
     */
    public String exportReportCSV(Report report) {
        StringBuilder csv = new StringBuilder();
        csv.append("Report ID,Type,Title,Generated Time,Entity Count,Finding Count\n");
        csv.append(String.format("\"%s\",\"%s\",\"%s\",%d,%d,%d\n",
            report.reportId, report.type, report.title,
            report.generatedTime, report.entityProfiles.size(), report.findings.size()
        ));

        csv.append("\nEntity Profiles:\n");
        csv.append("Entity ID,Name,Type,IP Address,Hostname,Risk Score,Risk Level,Vulnerabilities\n");
        for (EntityProfile ep : report.entityProfiles) {
            csv.append(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%f,\"%s\",%d\n",
                ep.entityId, ep.name, ep.type,
                ep.ipAddress != null ? ep.ipAddress : "",
                ep.hostname != null ? ep.hostname : "",
                ep.riskScore, ep.riskLevel, ep.vulnerabilities.size()
            ));
        }

        csv.append("\nFindings:\n");
        csv.append("Finding ID,Title,Severity,Exploitable\n");
        for (Finding f : report.findings) {
            csv.append(String.format("\"%s\",\"%s\",\"%s\",%b\n",
                f.id, f.title, f.severity, f.exploitable
            ));
        }

        return csv.toString();
    }

    /**
     * Export report to HTML
     */
    public String exportReportHTML(Report report) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n");
        html.append("<html>\n");
        html.append("<head>\n");
        html.append("<meta charset=\"UTF-8\">\n");
        html.append("<title>").append(report.title).append("</title>\n");
        html.append("<style>\n");
        html.append("body { font-family: Arial, sans-serif; margin: 20px; }\n");
        html.append("h1 { color: #333; }\n");
        html.append("h2 { color: #666; border-bottom: 2px solid #ccc; }\n");
        html.append("table { border-collapse: collapse; width: 100%; margin: 20px 0; }\n");
        html.append("th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }\n");
        html.append("th { background-color: #4CAF50; color: white; }\n");
        html.append(".critical { color: #d32f2f; font-weight: bold; }\n");
        html.append(".high { color: #f57c00; font-weight: bold; }\n");
        html.append(".medium { color: #fbc02d; }\n");
        html.append(".low { color: #689f38; }\n");
        html.append("</style>\n");
        html.append("</head>\n");
        html.append("<body>\n");

        html.append("<h1>").append(report.title).append("</h1>\n");
        html.append("<p><strong>Report ID:</strong> ").append(report.reportId).append("</p>\n");
        html.append("<p><strong>Generated:</strong> ").append(new Date(report.generatedTime)).append("</p>\n");

        if (report.executiveSummary != null) {
            html.append("<h2>Executive Summary</h2>\n");
            html.append("<p>").append(report.executiveSummary).append("</p>\n");
        }

        // Entities
        if (!report.entityProfiles.isEmpty()) {
            html.append("<h2>Entities</h2>\n");
            html.append("<table>\n");
            html.append("<tr><th>Name</th><th>Type</th><th>IP Address</th><th>Risk Score</th><th>Risk Level</th></tr>\n");
            for (EntityProfile ep : report.entityProfiles) {
                String riskClass = ep.riskLevel.toString().toLowerCase();
                html.append("<tr>\n");
                html.append("<td>").append(ep.name).append("</td>\n");
                html.append("<td>").append(ep.type).append("</td>\n");
                html.append("<td>").append(ep.ipAddress != null ? ep.ipAddress : "-").append("</td>\n");
                html.append("<td>").append(String.format("%.2f", ep.riskScore)).append("</td>\n");
                html.append("<td class=\"").append(riskClass).append("\">").append(ep.riskLevel).append("</td>\n");
                html.append("</tr>\n");
            }
            html.append("</table>\n");
        }

        // Findings
        if (!report.findings.isEmpty()) {
            html.append("<h2>Findings</h2>\n");
            html.append("<table>\n");
            html.append("<tr><th>Title</th><th>Severity</th><th>Exploitable</th></tr>\n");
            for (Finding f : report.findings) {
                String sevClass = f.severity.toString().toLowerCase();
                html.append("<tr>\n");
                html.append("<td>").append(f.title).append("</td>\n");
                html.append("<td class=\"").append(sevClass).append("\">").append(f.severity).append("</td>\n");
                html.append("<td>").append(f.exploitable ? "Yes" : "No").append("</td>\n");
                html.append("</tr>\n");
            }
            html.append("</table>\n");
        }

        html.append("</body>\n");
        html.append("</html>\n");
        return html.toString();
    }

    /**
     * Export report to Markdown
     */
    public String exportReportMarkdown(Report report) {
        StringBuilder md = new StringBuilder();
        md.append("# ").append(report.title).append("\n\n");
        md.append("**Report ID:** ").append(report.reportId).append("\n");
        md.append("**Generated:** ").append(new Date(report.generatedTime)).append("\n");
        md.append("**Type:** ").append(report.type).append("\n\n");

        if (report.executiveSummary != null) {
            md.append("## Executive Summary\n\n");
            md.append(report.executiveSummary).append("\n\n");
        }

        // Statistics
        if (!report.statistics.isEmpty()) {
            md.append("## Statistics\n\n");
            md.append("| Metric | Value |\n");
            md.append("|--------|-------|\n");
            for (Map.Entry<String, Object> stat : report.statistics.entrySet()) {
                md.append("| ").append(stat.getKey()).append(" | ").append(stat.getValue()).append(" |\n");
            }
            md.append("\n");
        }

        // Entities
        if (!report.entityProfiles.isEmpty()) {
            md.append("## Entities\n\n");
            for (EntityProfile ep : report.entityProfiles) {
                md.append("### ").append(ep.name).append(" (").append(ep.type).append(")\n");
                md.append("- **Entity ID:** ").append(ep.entityId).append("\n");
                md.append("- **IP Address:** ").append(ep.ipAddress != null ? ep.ipAddress : "-").append("\n");
                md.append("- **Risk Score:** ").append(String.format("%.2f", ep.riskScore)).append("\n");
                md.append("- **Risk Level:** ").append(ep.riskLevel).append("\n");
                md.append("- **Vulnerabilities:** ").append(ep.vulnerabilities.size()).append("\n");
                md.append("\n");
            }
        }

        // Findings
        if (!report.findings.isEmpty()) {
            md.append("## Findings\n\n");
            for (Finding f : report.findings) {
                md.append("### ").append(f.title).append(" (").append(f.severity).append(")\n");
                md.append(f.description).append("\n\n");
            }
        }

        return md.toString();
    }

    /**
     * Generic export method
     */
    public String exportReport(Report report, ExportFormat format) {
        return switch(format) {
            case JSON -> exportReportJSON(report);
            case CSV -> exportReportCSV(report);
            case HTML -> exportReportHTML(report);
            case MARKDOWN -> exportReportMarkdown(report);
            case PLAINTEXT -> exportReportPlaintext(report);
            default -> exportReportJSON(report);
        };
    }

    /**
     * Export report to plaintext
     */
    public String exportReportPlaintext(Report report) {
        StringBuilder text = new StringBuilder();
        text.append("=====================================\n");
        text.append(report.title).append("\n");
        text.append("=====================================\n\n");
        text.append("Report ID: ").append(report.reportId).append("\n");
        text.append("Generated: ").append(new Date(report.generatedTime)).append("\n");
        text.append("Type: ").append(report.type).append("\n\n");

        if (report.executiveSummary != null) {
            text.append("EXECUTIVE SUMMARY\n");
            text.append("-----\n");
            text.append(report.executiveSummary).append("\n\n");
        }

        text.append("ENTITIES (").append(report.entityProfiles.size()).append(")\n");
        text.append("-----\n");
        for (EntityProfile ep : report.entityProfiles) {
            text.append(ep.name).append(" [").append(ep.type).append("]\n");
            text.append("  IP: ").append(ep.ipAddress != null ? ep.ipAddress : "-").append("\n");
            text.append("  Risk Score: ").append(String.format("%.2f", ep.riskScore)).append(" (").append(ep.riskLevel).append(")\n");
            text.append("  Vulnerabilities: ").append(ep.vulnerabilities.size()).append("\n\n");
        }

        text.append("FINDINGS (").append(report.findings.size()).append(")\n");
        text.append("-----\n");
        for (Finding f : report.findings) {
            text.append("[").append(f.severity).append("] ").append(f.title).append("\n");
            text.append(f.description).append("\n\n");
        }

        return text.toString();
    }

    /**
     * Save report to file
     */
    public boolean saveReport(Report report, String filePath, ExportFormat format) throws Exception {
        try {
            String content = exportReport(report, format);
            Files.write(Paths.get(filePath), content.getBytes(StandardCharsets.UTF_8));
            return true;
        } catch (Exception e) {
            System.err.println("Error saving report: " + e.getMessage());
            return false;
        }
    }

    /**
     * Get entity profile
     */
    public EntityProfile getEntityProfile(String entityId) {
        return entityProfiles.get(entityId);
    }

    /**
     * Get all entity profiles
     */
    public List<EntityProfile> getAllEntityProfiles() {
        return new ArrayList<>(entityProfiles.values());
    }

    /**
     * Get generated report
     */
    public Report getGeneratedReport(String reportId) {
        return generatedReports.get(reportId);
    }

    /**
     * Get all generated reports
     */
    public List<Report> getAllGeneratedReports() {
        return new ArrayList<>(generatedReports.values());
    }

    /**
     * Get statistics summary
     */
    public Map<String, Object> getStatisticsSummary() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalEntities", entityProfiles.size());
        stats.put("totalFindings", findings.size());
        stats.put("attackChainLength", attackChain.size());
        stats.put("generatedReports", generatedReports.size());
        stats.put("averageRiskScore", 
            entityProfiles.values().stream()
                .mapToDouble(p -> p.riskScore)
                .average()
                .orElse(0.0));
        stats.put("criticalEntities", 
            entityProfiles.values().stream()
                .filter(p -> p.riskLevel == RiskLevel.CRITICAL)
                .count());
        return stats;
    }

    /**
     * Clear all data
     */
    public void clearAllData() {
        entityProfiles.clear();
        findings.clear();
        attackChain.clear();
        generatedReports.clear();
    }

    /**
     * Shutdown
     */
    public void shutdown() {
        clearAllData();
        executor.shutdown();
    }
}
