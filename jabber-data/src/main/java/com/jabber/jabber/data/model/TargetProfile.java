package com.jabber.jabber.data.model;

import java.time.Instant;
import java.util.*;

/**
 * V5.5: Structured target profile produced by the Target Profiling Engine.
 * Aggregates data from multiple reports with confidence scoring.
 */
public class TargetProfile {
    private String profileId;
    private Instant generatedAt;
    private List<String> sourceReports;   // report IDs used to build this profile

    // Identifiers
    private Set<String> ipAddresses;
    private Set<String> hostnames;
    private Set<String> domains;
    private Set<String> macAddresses;
    private Set<String> emails;
    private Set<String> urls;

    // Services
    private List<ServiceEntry> services;

    // Technologies
    private List<TechEntry> technologies;

    // Vulnerabilities
    private List<VulnEntry> vulnerabilities;

    // Behavioral insights
    private Map<String, Object> behavioralInsights;

    // Risk scoring
    private int overallRiskScore;       // 0-100
    private String confidenceLevel;     // LOW, MEDIUM, HIGH

    public TargetProfile() {
        this.profileId = UUID.randomUUID().toString().substring(0, 12);
        this.generatedAt = Instant.now();
        this.sourceReports = new ArrayList<>();
        this.ipAddresses = new LinkedHashSet<>();
        this.hostnames = new LinkedHashSet<>();
        this.domains = new LinkedHashSet<>();
        this.macAddresses = new LinkedHashSet<>();
        this.emails = new LinkedHashSet<>();
        this.urls = new LinkedHashSet<>();
        this.services = new ArrayList<>();
        this.technologies = new ArrayList<>();
        this.vulnerabilities = new ArrayList<>();
        this.behavioralInsights = new LinkedHashMap<>();
        this.overallRiskScore = 0;
        this.confidenceLevel = "LOW";
    }

    /**
     * Service discovered on a target.
     */
    public static class ServiceEntry {
        private int port;
        private String protocol;    // tcp, udp
        private String product;     // e.g. "Apache httpd"
        private String version;     // e.g. "2.4.49"
        private String state;       // open, filtered, closed
        private String banner;
        private String confidence;  // LOW, MEDIUM, HIGH
        private int sourceCount;    // how many reports confirmed this

        public ServiceEntry() {}
        public ServiceEntry(int port, String protocol, String product, String version, String state, String confidence) {
            this.port = port; this.protocol = protocol; this.product = product;
            this.version = version; this.state = state; this.confidence = confidence;
            this.sourceCount = 1;
        }

        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }
        public String getProtocol() { return protocol; }
        public void setProtocol(String protocol) { this.protocol = protocol; }
        public String getProduct() { return product; }
        public void setProduct(String product) { this.product = product; }
        public String getVersion() { return version; }
        public void setVersion(String version) { this.version = version; }
        public String getState() { return state; }
        public void setState(String state) { this.state = state; }
        public String getBanner() { return banner; }
        public void setBanner(String banner) { this.banner = banner; }
        public String getConfidence() { return confidence; }
        public void setConfidence(String confidence) { this.confidence = confidence; }
        public int getSourceCount() { return sourceCount; }
        public void setSourceCount(int sourceCount) { this.sourceCount = sourceCount; }
    }

    /**
     * Technology/software detected.
     */
    public static class TechEntry {
        private String name;
        private String version;
        private String category;    // web-server, cms, framework, os, database, etc.
        private String confidence;
        private int sourceCount;

        public TechEntry() {}
        public TechEntry(String name, String version, String category, String confidence) {
            this.name = name; this.version = version; this.category = category;
            this.confidence = confidence; this.sourceCount = 1;
        }

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getVersion() { return version; }
        public void setVersion(String version) { this.version = version; }
        public String getCategory() { return category; }
        public void setCategory(String category) { this.category = category; }
        public String getConfidence() { return confidence; }
        public void setConfidence(String confidence) { this.confidence = confidence; }
        public int getSourceCount() { return sourceCount; }
        public void setSourceCount(int sourceCount) { this.sourceCount = sourceCount; }
    }

    /**
     * Vulnerability identified.
     */
    public static class VulnEntry {
        private String cveId;
        private String title;
        private String severity;    // CRITICAL, HIGH, MEDIUM, LOW
        private String evidence;
        private String details;
        private String confidence;
        private String status;      // CONFIRMED, POTENTIAL, INFORMATIONAL
        private List<String> remediation;
        private int sourceCount;

        public VulnEntry() { this.remediation = new ArrayList<>(); }
        public VulnEntry(String cveId, String title, String severity, String evidence, String confidence) {
            this.cveId = cveId; this.title = title; this.severity = severity;
            this.evidence = evidence; this.confidence = confidence;
            this.status = "POTENTIAL"; this.remediation = new ArrayList<>(); this.sourceCount = 1;
        }

        public String getCveId() { return cveId; }
        public void setCveId(String cveId) { this.cveId = cveId; }
        public String getTitle() { return title; }
        public void setTitle(String title) { this.title = title; }
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
        public String getEvidence() { return evidence; }
        public void setEvidence(String evidence) { this.evidence = evidence; }
        public String getDetails() { return details; }
        public void setDetails(String details) { this.details = details; }
        public String getConfidence() { return confidence; }
        public void setConfidence(String confidence) { this.confidence = confidence; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public List<String> getRemediation() { return remediation; }
        public void setRemediation(List<String> remediation) { this.remediation = remediation; }
        public int getSourceCount() { return sourceCount; }
        public void setSourceCount(int sourceCount) { this.sourceCount = sourceCount; }
    }

    // Getters and setters
    public String getProfileId() { return profileId; }
    public void setProfileId(String profileId) { this.profileId = profileId; }
    public Instant getGeneratedAt() { return generatedAt; }
    public void setGeneratedAt(Instant generatedAt) { this.generatedAt = generatedAt; }
    public List<String> getSourceReports() { return sourceReports; }
    public void setSourceReports(List<String> sourceReports) { this.sourceReports = sourceReports; }
    public Set<String> getIpAddresses() { return ipAddresses; }
    public void setIpAddresses(Set<String> ipAddresses) { this.ipAddresses = ipAddresses; }
    public Set<String> getHostnames() { return hostnames; }
    public void setHostnames(Set<String> hostnames) { this.hostnames = hostnames; }
    public Set<String> getDomains() { return domains; }
    public void setDomains(Set<String> domains) { this.domains = domains; }
    public Set<String> getMacAddresses() { return macAddresses; }
    public void setMacAddresses(Set<String> macAddresses) { this.macAddresses = macAddresses; }
    public Set<String> getEmails() { return emails; }
    public void setEmails(Set<String> emails) { this.emails = emails; }
    public Set<String> getUrls() { return urls; }
    public void setUrls(Set<String> urls) { this.urls = urls; }
    public List<ServiceEntry> getServices() { return services; }
    public void setServices(List<ServiceEntry> services) { this.services = services; }
    public List<TechEntry> getTechnologies() { return technologies; }
    public void setTechnologies(List<TechEntry> technologies) { this.technologies = technologies; }
    public List<VulnEntry> getVulnerabilities() { return vulnerabilities; }
    public void setVulnerabilities(List<VulnEntry> vulnerabilities) { this.vulnerabilities = vulnerabilities; }
    public Map<String, Object> getBehavioralInsights() { return behavioralInsights; }
    public void setBehavioralInsights(Map<String, Object> behavioralInsights) { this.behavioralInsights = behavioralInsights; }
    public int getOverallRiskScore() { return overallRiskScore; }
    public void setOverallRiskScore(int overallRiskScore) { this.overallRiskScore = overallRiskScore; }
    public String getConfidenceLevel() { return confidenceLevel; }
    public void setConfidenceLevel(String confidenceLevel) { this.confidenceLevel = confidenceLevel; }
}
