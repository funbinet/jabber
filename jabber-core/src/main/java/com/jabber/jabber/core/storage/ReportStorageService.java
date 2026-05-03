package com.jabber.jabber.core.storage;

import com.jabber.jabber.core.report.ReportEngine;
import com.jabber.jabber.data.model.*;
import com.google.gson.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.*;

/**
 * V5.5: Filesystem-based persistence for all module outputs, payloads, and analysis profiles.
 * Manages /reports/outputs/, /reports/payloads/, /reports/analysis/ hierarchy.
 * Each artifact has a .meta.json sidecar for indexing.
 */
@Service
public class ReportStorageService {

    private static final Logger log = LoggerFactory.getLogger(ReportStorageService.class);
    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
    private final Gson gson = new GsonBuilder().setPrettyPrinting().serializeNulls()
            .registerTypeAdapter(Instant.class, (JsonSerializer<Instant>) (src, t, ctx) -> new JsonPrimitive(src.toString()))
            .registerTypeAdapter(Instant.class, (JsonDeserializer<Instant>) (json, t, ctx) -> Instant.parse(json.getAsString()))
            .create();
    private final ReportEngine reportEngine;

    @Value("${jabber.reports.base-dir:./reports}")
    private String baseDir;

    private Path outputsDir;
    private Path payloadsDir;
    private Path analysisDir;
    private Path artifactsDir;
    private Path logsDir;

    public ReportStorageService(ReportEngine reportEngine) {
        this.reportEngine = reportEngine;
    }

    @PostConstruct
    public void init() throws IOException {
        Path base = Path.of(baseDir).toAbsolutePath();
        outputsDir = base.resolve("outputs");
        payloadsDir = base.resolve("payloads");
        analysisDir = base.resolve("analysis");
        artifactsDir = base.resolve("artifacts");
        logsDir = base.resolve("logs");
        Files.createDirectories(outputsDir);
        Files.createDirectories(payloadsDir);
        Files.createDirectories(analysisDir);
        Files.createDirectories(artifactsDir);
        Files.createDirectories(logsDir);
        log.info("V5.5 Report storage initialized: {}", base);
        log.info("  Outputs:    {}", outputsDir);
        log.info("  Payloads:   {}", payloadsDir);
        log.info("  Analysis:   {}", analysisDir);
        log.info("  Artifacts:  {}", artifactsDir);
        log.info("  Logs:       {}", logsDir);
    }

    // ===== Save Operations =====

    /**
     * Save a module execution result to /reports/outputs/.
     * Returns the ReportMetadata with the file path populated.
     */
    public ReportMetadata saveOutput(ModuleResult result, String format) throws IOException {
        String normalizedFormat = format == null ? "json" : format.toLowerCase(Locale.ROOT);
        String content = reportEngine.generate(result, normalizedFormat);
        String ext = formatToExtension(normalizedFormat);
        String fileName = buildFileName(result.getCategory(), result.getModuleId(),
                result.getTarget(), ext);
        Path filePath = outputsDir.resolve(fileName);
        Files.writeString(filePath, content, StandardCharsets.UTF_8);

        // Track generated output path on the in-memory result.
        if (result.getExportedFiles() != null) {
            result.getExportedFiles().put(normalizedFormat, filePath.toString());
        }
        addArtifactIfAbsent(result, filePath.toString());

        // Persist command/event execution logs as sidecar attachments.
        Map<String, String> attachments = saveExecutionLogAttachments(result, filePath, normalizedFormat);

        ReportMetadata meta = ReportMetadata.forOutput(result, normalizedFormat, filePath.toString());
        meta.setAttachments(attachments);
        if (!attachments.isEmpty()) {
            meta.getTags().add("execution-log-attached");
        }
        meta.setFileSize(Files.size(filePath));
        saveMetadata(meta, filePath);

        log.info("Saved output: {} ({})", fileName, normalizedFormat);
        return meta;
    }

    /**
     * Save a payload artifact to /reports/payloads/.
     */
    public ReportMetadata savePayload(byte[] data, String moduleName, String moduleId,
                                       String category, String target, String ext) throws IOException {
        String fileName = buildFileName(category, moduleId, target, ext);
        Path filePath = payloadsDir.resolve(fileName);
        Files.write(filePath, data);

        ReportMetadata meta = ReportMetadata.forPayload(moduleName, moduleId, category, target, filePath.toString());
        meta.setFileSize(data.length);
        saveMetadata(meta, filePath);

        log.info("Saved payload: {} ({} bytes)", fileName, data.length);
        return meta;
    }

    /**
     * Save a target profile to /reports/analysis/.
     * V5.5: HTML is the PRIMARY format. Always generates HTML, plus optional extras.
     */
    public ReportMetadata saveProfile(TargetProfile profile, String format) throws IOException {
        String ts = TS_FMT.format(LocalDateTime.now());
        String targetStr = String.join(",", profile.getIpAddresses());

        // Always save HTML as primary
        String htmlContent = profileToHtml(profile);
        String htmlFileName = "profile_" + profile.getProfileId() + "_" + ts + ".html";
        Path htmlPath = analysisDir.resolve(htmlFileName);
        Files.writeString(htmlPath, htmlContent, StandardCharsets.UTF_8);
        ReportMetadata htmlMeta = ReportMetadata.forProfile(htmlPath.toString(), "html");
        htmlMeta.setTarget(targetStr);
        htmlMeta.setFileSize(Files.size(htmlPath));
        htmlMeta.setSha256(computeSHA256(htmlPath));
        saveMetadata(htmlMeta, htmlPath);
        log.info("Saved HTML profile: {}", htmlFileName);

        // If user requested a different format, save that too
        if (!"html".equals(format)) {
            String extraContent;
            String ext;
            if ("json".equals(format)) {
                extraContent = gson.toJson(profile);
                ext = "json";
            } else {
                extraContent = profileToMarkdown(profile);
                ext = "md";
            }
            String extraFileName = "profile_" + profile.getProfileId() + "_" + ts + "." + ext;
            Path extraPath = analysisDir.resolve(extraFileName);
            Files.writeString(extraPath, extraContent, StandardCharsets.UTF_8);
            ReportMetadata extraMeta = ReportMetadata.forProfile(extraPath.toString(), format);
            extraMeta.setTarget(targetStr);
            extraMeta.setFileSize(Files.size(extraPath));
            extraMeta.setSha256(computeSHA256(extraPath));
            saveMetadata(extraMeta, extraPath);
            log.info("Saved {} profile: {}", format, extraFileName);
        }

        return htmlMeta;
    }

    /**
     * Save a forensic artifact (pcap, image, certificate, graph data, etc.) to /reports/artifacts/.
     */
    public ReportMetadata saveArtifact(byte[] data, String moduleName, String moduleId,
                                        String category, String target, String fileName) throws IOException {
        Path filePath = artifactsDir.resolve(fileName);
        Files.write(filePath, data);

        ReportMetadata meta = ReportMetadata.forArtifact(moduleName, moduleId, category, target, filePath.toString());
        meta.setFileSize(data.length);
        meta.setSha256(computeSHA256(filePath));
        saveMetadata(meta, filePath);

        log.info("Saved artifact: {} ({} bytes)", fileName, data.length);
        return meta;
    }

    /**
     * Save a raw tool execution log to /reports/logs/.
     */
    public ReportMetadata saveToolLog(String content, String moduleName, String moduleId,
                                       String category, String target, String toolName) throws IOException {
        String ts = TS_FMT.format(LocalDateTime.now());
        String fileName = toolName + "_" + ts + ".log";
        Path filePath = logsDir.resolve(fileName);
        Files.writeString(filePath, content, StandardCharsets.UTF_8);

        ReportMetadata meta = ReportMetadata.forLog(moduleName, moduleId, category, target, filePath.toString());
        meta.setFileSize(Files.size(filePath));
        meta.setSha256(computeSHA256(filePath));
        saveMetadata(meta, filePath);

        log.info("Saved tool log: {}", fileName);
        return meta;
    }

    /**
     * Compute SHA256 hash for integrity verification.
     */
    private String computeSHA256(Path file) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(Files.readAllBytes(file));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            log.warn("Failed to compute SHA256 for {}: {}", file, e.getMessage());
            return "error";
        }
    }

    // ===== Read Operations =====

    /**
     * List all reports, optionally filtered.
     */
    public List<Map<String, Object>> listReports(String category, String module,
                                                   String target, String type,
                                                   String fromDate, String toDate) {
        List<Map<String, Object>> results = new ArrayList<>();
        try {
            collectMetadata(outputsDir, results);
            collectMetadata(payloadsDir, results);
            collectMetadata(analysisDir, results);
            collectMetadata(artifactsDir, results);
            collectMetadata(logsDir, results);
        } catch (IOException e) {
            log.error("Error listing reports", e);
        }

        // Apply filters
        Stream<Map<String, Object>> stream = results.stream();
        if (category != null && !category.isEmpty()) {
            stream = stream.filter(m -> category.equalsIgnoreCase((String) m.get("category")));
        }
        if (module != null && !module.isEmpty()) {
            stream = stream.filter(m -> module.equalsIgnoreCase((String) m.get("moduleId")));
        }
        if (target != null && !target.isEmpty()) {
            String t = target.toLowerCase();
            stream = stream.filter(m -> {
                String mt = (String) m.get("target");
                return mt != null && mt.toLowerCase().contains(t);
            });
        }
        if (type != null && !type.isEmpty()) {
            stream = stream.filter(m -> type.equalsIgnoreCase((String) m.get("type")));
        }

        return stream
                .sorted((a, b) -> {
                    String ta = (String) a.getOrDefault("timestamp", "");
                    String tb = (String) b.getOrDefault("timestamp", "");
                    return tb.compareTo(ta); // newest first
                })
                .collect(Collectors.toList());
    }

    /**
     * Get report content by ID.
     */
    public String getReportContent(String reportId) throws IOException {
        Path filePath = findFileById(reportId);
        if (filePath == null) return null;
        return Files.readString(filePath, StandardCharsets.UTF_8);
    }

    /**
     * Get report content as bytes (for binary payloads).
     */
    public byte[] getReportBytes(String reportId) throws IOException {
        Path filePath = findFileById(reportId);
        if (filePath == null) return null;
        return Files.readAllBytes(filePath);
    }

    /**
     * Get metadata for a report.
     */
    public Map<String, Object> getReportMeta(String reportId) {
        return listReports(null, null, null, null, null, null)
                .stream()
                .filter(m -> reportId.equals(m.get("id")))
                .findFirst()
                .orElse(null);
    }

    // ===== Update Operations =====

    /**
     * Edit report content (text-based formats only).
     */
    public boolean editReport(String reportId, String newContent) throws IOException {
        Path filePath = findFileById(reportId);
        if (filePath == null) return false;
        String name = filePath.getFileName().toString();
        // Block binary editing
        if (name.endsWith(".bin") || name.endsWith(".exe") || name.endsWith(".elf")) {
            return false;
        }
        Files.writeString(filePath, newContent, StandardCharsets.UTF_8);
        // Update file size in metadata
        Path metaPath = Path.of(filePath + ".meta.json");
        if (Files.exists(metaPath)) {
            String metaJson = Files.readString(metaPath);
            @SuppressWarnings("unchecked")
            Map<String, Object> meta = (Map<String, Object>) gson.fromJson(metaJson, Map.class);
            meta.put("fileSize", Files.size(filePath));
            Files.writeString(metaPath, gson.toJson(meta));
        }
        return true;
    }

    /**
     * Rename a report file.
     */
    public boolean renameReport(String reportId, String newName) throws IOException {
        Path filePath = findFileById(reportId);
        if (filePath == null) return false;
        Path metaPath = Path.of(filePath + ".meta.json");
        Path newFilePath = filePath.getParent().resolve(newName);
        Path newMetaPath = Path.of(newFilePath + ".meta.json");

        Files.move(filePath, newFilePath, StandardCopyOption.REPLACE_EXISTING);
        if (Files.exists(metaPath)) {
            String metaJson = Files.readString(metaPath);
            @SuppressWarnings("unchecked")
            Map<String, Object> meta = (Map<String, Object>) gson.fromJson(metaJson, Map.class);
            meta.put("filePath", newFilePath.toString());
            Files.writeString(newMetaPath, gson.toJson(meta));
            Files.deleteIfExists(metaPath);
        }
        return true;
    }

    // ===== Delete Operations =====

    public boolean deleteReport(String reportId) throws IOException {
        Path filePath = findFileById(reportId);
        if (filePath == null) return false;
        Path metaPath = Path.of(filePath + ".meta.json");
        Files.deleteIfExists(filePath);
        Files.deleteIfExists(metaPath);
        log.info("Deleted report: {}", reportId);
        return true;
    }

    // ===== Stats =====

    public Map<String, Object> getStats() {
        List<Map<String, Object>> all = listReports(null, null, null, null, null, null);
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalReports", all.size());
        stats.put("outputs", all.stream().filter(m -> "OUTPUT".equals(m.get("type"))).count());
        stats.put("payloads", all.stream().filter(m -> "PAYLOAD".equals(m.get("type"))).count());
        stats.put("analyses", all.stream().filter(m -> "ANALYSIS".equals(m.get("type")) || "PROFILE".equals(m.get("type"))).count());
        stats.put("artifacts", all.stream().filter(m -> "ARTIFACT".equals(m.get("type"))).count());
        stats.put("logs", all.stream().filter(m -> "LOG".equals(m.get("type"))).count());
        long totalSize = all.stream()
                .mapToLong(m -> ((Number) m.getOrDefault("fileSize", 0)).longValue())
                .sum();
        stats.put("totalSizeBytes", totalSize);
        stats.put("totalSizeHuman", humanReadableSize(totalSize));

        // By category
        Map<String, Long> byCategory = all.stream()
                .collect(Collectors.groupingBy(
                        m -> (String) m.getOrDefault("category", "unknown"),
                        Collectors.counting()));
        stats.put("byCategory", byCategory);

        // By type
        Map<String, Long> byType = all.stream()
                .collect(Collectors.groupingBy(
                        m -> (String) m.getOrDefault("type", "unknown"),
                        Collectors.counting()));
        stats.put("byType", byType);
        return stats;
    }

    // ===== Helpers =====

    private String buildFileName(String category, String moduleId, String target, String ext) {
        String safeCat = sanitize(category != null ? category : "unknown");
        String safeMod = sanitize(moduleId != null ? moduleId : "unknown");
        String safeTarget = sanitize(target != null ? target : "unknown");
        String ts = TS_FMT.format(LocalDateTime.now());
        String uid = UUID.randomUUID().toString().substring(0, 8);
        return String.format("%s_%s_%s_%s_%s.%s", safeCat, safeMod, safeTarget, ts, uid, ext);
    }

    private String sanitize(String s) {
        return s.replaceAll("[^a-zA-Z0-9._-]", "_").toLowerCase();
    }

    private String formatToExtension(String format) {
        return switch (format.toLowerCase()) {
            case "json" -> "json";
            case "html" -> "html";
            case "markdown", "md" -> "md";
            case "xml" -> "xml";
            case "csv" -> "csv";
            case "txt" -> "txt";
            default -> "json";
        };
    }

    private Map<String, String> saveExecutionLogAttachments(ModuleResult result, Path outputPath, String reportFormat) throws IOException {
        Map<String, Object> executionLog = reportEngine.buildExecutionLog(result);
        @SuppressWarnings("unchecked")
        List<String> events = executionLog.get("events") instanceof List<?> list
            ? (List<String>) list
            : List.of();
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> commands = executionLog.get("commands") instanceof List<?> list
            ? (List<Map<String, Object>>) list
            : List.of();

        boolean hasData = (events != null && !events.isEmpty()) || (commands != null && !commands.isEmpty());
        if (!hasData) {
            return Map.of();
        }

        String fileName = outputPath.getFileName().toString();
        String baseName = stripExtension(fileName);
        Path jsonLogPath = outputPath.getParent().resolve(baseName + ".execution.json");
        Path textLogPath = outputPath.getParent().resolve(baseName + ".execution.log");

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("generator", "JABBER V 5.5.0");
        payload.put("timestamp", Instant.now().toString());
        payload.put("taskId", result.getTaskId());
        payload.put("moduleId", result.getModuleId());
        payload.put("reportFile", outputPath.toString());
        payload.put("reportFormat", reportFormat);
        payload.put("execution_log", executionLog);

        Files.writeString(jsonLogPath, gson.toJson(payload), StandardCharsets.UTF_8);
        Files.writeString(textLogPath, reportEngine.generateExecutionLogText(result), StandardCharsets.UTF_8);

        addArtifactIfAbsent(result, jsonLogPath.toString());
        addArtifactIfAbsent(result, textLogPath.toString());
        if (result.getExportedFiles() != null) {
            result.getExportedFiles().put("execution_json", jsonLogPath.toString());
            result.getExportedFiles().put("execution_log", textLogPath.toString());
        }

        Map<String, String> attachments = new LinkedHashMap<>();
        attachments.put("execution_json", jsonLogPath.toString());
        attachments.put("execution_log", textLogPath.toString());
        return attachments;
    }

    private void addArtifactIfAbsent(ModuleResult result, String path) {
        if (result == null || path == null || path.isBlank()) {
            return;
        }

        if (result.getArtifacts() == null) {
            result.setArtifacts(new ArrayList<>());
        }
        if (!result.getArtifacts().contains(path)) {
            result.getArtifacts().add(path);
        }
    }

    private String stripExtension(String fileName) {
        if (fileName == null || fileName.isBlank()) {
            return "output";
        }
        int dotIndex = fileName.lastIndexOf('.');
        if (dotIndex <= 0) {
            return fileName;
        }
        return fileName.substring(0, dotIndex);
    }

    private void saveMetadata(ReportMetadata meta, Path artifactPath) throws IOException {
        Path metaPath = Path.of(artifactPath + ".meta.json");
        Files.writeString(metaPath, gson.toJson(meta), StandardCharsets.UTF_8);
    }

    private void collectMetadata(Path dir, List<Map<String, Object>> results) throws IOException {
        if (!Files.exists(dir)) return;
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*.meta.json")) {
            for (Path metaFile : stream) {
                try {
                    String json = Files.readString(metaFile);
                    @SuppressWarnings("unchecked")
                    Map<String, Object> meta = gson.fromJson(json, Map.class);
                    // Verify the actual file still exists
                    String filePath = (String) meta.get("filePath");
                    if (filePath != null && Files.exists(Path.of(filePath))) {
                        results.add(meta);
                    } else {
                        // Orphaned metadata - delete it
                        Files.deleteIfExists(metaFile);
                    }
                } catch (Exception e) {
                    log.warn("Corrupt metadata file: {}", metaFile, e);
                }
            }
        }
    }

    private Path findFileById(String reportId) {
        Map<String, Object> meta = getReportMeta(reportId);
        if (meta == null) return null;
        String filePath = (String) meta.get("filePath");
        if (filePath == null) return null;
        Path p = Path.of(filePath);
        return Files.exists(p) ? p : null;
    }

    private String humanReadableSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
    }

    private String profileToMarkdown(TargetProfile profile) {
        StringBuilder md = new StringBuilder();
        md.append("# Target Profile Report\n\n");
        md.append("**Profile ID**: ").append(profile.getProfileId()).append("\n");
        md.append("**Generated**: ").append(profile.getGeneratedAt()).append("\n");
        md.append("**Risk Score**: ").append(profile.getOverallRiskScore()).append("/100\n");
        md.append("**Confidence**: ").append(profile.getConfidenceLevel()).append("\n\n");

        md.append("## Identifiers\n\n");
        if (!profile.getIpAddresses().isEmpty())
            md.append("- **IPs**: ").append(String.join(", ", profile.getIpAddresses())).append("\n");
        if (!profile.getHostnames().isEmpty())
            md.append("- **Hostnames**: ").append(String.join(", ", profile.getHostnames())).append("\n");
        if (!profile.getDomains().isEmpty())
            md.append("- **Domains**: ").append(String.join(", ", profile.getDomains())).append("\n");

        if (!profile.getServices().isEmpty()) {
            md.append("\n## Services\n\n");
            md.append("| Port | Protocol | Product | Version | State | Confidence |\n");
            md.append("|---|---|---|---|---|---|\n");
            for (TargetProfile.ServiceEntry s : profile.getServices()) {
                md.append("| ").append(s.getPort()).append(" | ").append(s.getProtocol())
                  .append(" | ").append(s.getProduct()).append(" | ").append(s.getVersion())
                  .append(" | ").append(s.getState()).append(" | ").append(s.getConfidence())
                  .append(" |\n");
            }
        }

        if (!profile.getVulnerabilities().isEmpty()) {
            md.append("\n## Vulnerabilities\n\n");
            for (TargetProfile.VulnEntry v : profile.getVulnerabilities()) {
                md.append("### ").append(v.getCveId() != null ? v.getCveId() : "N/A")
                  .append(" — ").append(v.getTitle()).append("\n");
                md.append("- **Severity**: ").append(v.getSeverity()).append("\n");
                md.append("- **Status**: ").append(v.getStatus()).append("\n");
                md.append("- **Confidence**: ").append(v.getConfidence()).append("\n");
                md.append("- **Evidence**: ").append(v.getEvidence()).append("\n\n");
            }
        }

        if (!profile.getTechnologies().isEmpty()) {
            md.append("\n## Technologies\n\n");
            md.append("| Name | Version | Category | Confidence |\n");
            md.append("|---|---|---|---|\n");
            for (TargetProfile.TechEntry t : profile.getTechnologies()) {
                md.append("| ").append(t.getName()).append(" | ").append(t.getVersion())
                  .append(" | ").append(t.getCategory()).append(" | ").append(t.getConfidence())
                  .append(" |\n");
            }
        }

        return md.toString();
    }

    /**
     * V5.5: Professional HTML profile with dark theme, charts, tables, analytics.
     * ZERO JSON pollution — all data is rendered as visual components.
     */
    private String profileToHtml(TargetProfile profile) {
        StringBuilder h = new StringBuilder();
        h.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        h.append("<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        h.append("<title>JABBER — Target Profile: ").append(escHtml(profile.getProfileId())).append("</title>\n");
        h.append(getProfileStyles());
        h.append("</head>\n<body>\n<div class=\"wrap\">\n");

        // Header
        h.append("<header class=\"prf-header\">\n");
        h.append("  <div><h1>Target Intelligence Profile</h1>\n");
        h.append("  <p class=\"prf-sub\">JABBER V 5.5.0 &middot; Generated ").append(profile.getGeneratedAt()).append("</p></div>\n");
        h.append("  <div class=\"prf-id\"><code>").append(escHtml(profile.getProfileId())).append("</code></div>\n");
        h.append("</header>\n\n");

        // Risk + Confidence Row
        int risk = profile.getOverallRiskScore();
        String riskColor = risk > 70 ? "#f85149" : risk > 40 ? "#f0883e" : "#3fb950";
        h.append("<div class=\"score-row\">\n");
        h.append("  <div class=\"risk-gauge\">\n");
        h.append("    <div class=\"risk-ring\" style=\"background:conic-gradient(").append(riskColor)
         .append(" ").append(risk * 3.6).append("deg, #1b2638 0deg)\">\n");
        h.append("      <span>").append(risk).append("</span>\n");
        h.append("    </div>\n    <div class=\"risk-label\">Risk Score</div>\n  </div>\n");
        String confColor = "HIGH".equals(profile.getConfidenceLevel()) ? "#3fb950" : "MEDIUM".equals(profile.getConfidenceLevel()) ? "#d29922" : "#f85149";
        h.append("  <div class=\"conf-badge\" style=\"border-color:").append(confColor).append(";color:").append(confColor).append("\">\n");
        h.append("    &#x1F6E1; Confidence: ").append(escHtml(profile.getConfidenceLevel())).append("\n  </div>\n");
        h.append("  <div class=\"score-stats\">\n");
        h.append("    <div class=\"stat\"><span class=\"stat-val\">").append(profile.getIpAddresses().size()).append("</span><span class=\"stat-lbl\">IPs</span></div>\n");
        h.append("    <div class=\"stat\"><span class=\"stat-val\">").append(profile.getServices().size()).append("</span><span class=\"stat-lbl\">Services</span></div>\n");
        h.append("    <div class=\"stat\"><span class=\"stat-val\">").append(profile.getVulnerabilities().size()).append("</span><span class=\"stat-lbl\">Vulns</span></div>\n");
        h.append("    <div class=\"stat\"><span class=\"stat-val\">").append(profile.getTechnologies().size()).append("</span><span class=\"stat-lbl\">Tech</span></div>\n");
        h.append("  </div>\n</div>\n\n");

        // Identifiers
        h.append("<section class=\"prf-section\">\n<h2>Identifiers</h2>\n<div class=\"tag-cloud\">\n");
        for (String ip : profile.getIpAddresses()) h.append("<span class=\"tag tag--ip\">").append(escHtml(ip)).append("</span>\n");
        for (String hn : profile.getHostnames()) h.append("<span class=\"tag tag--host\">").append(escHtml(hn)).append("</span>\n");
        for (String d : profile.getDomains()) h.append("<span class=\"tag tag--domain\">").append(escHtml(d)).append("</span>\n");
        for (String e : profile.getEmails()) h.append("<span class=\"tag tag--email\">").append(escHtml(e)).append("</span>\n");
        for (String mac : profile.getMacAddresses()) h.append("<span class=\"tag tag--mac\">").append(escHtml(mac)).append("</span>\n");
        h.append("</div>\n</section>\n\n");

        // Services Table
        if (!profile.getServices().isEmpty()) {
            h.append("<section class=\"prf-section\">\n<h2>Discovered Services (").append(profile.getServices().size()).append(")</h2>\n");
            h.append("<div class=\"tbl-wrap\"><table class=\"dt\">\n<thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>State</th><th>Confidence</th></tr></thead>\n<tbody>\n");
            for (TargetProfile.ServiceEntry s : profile.getServices()) {
                String sc = "HIGH".equals(s.getConfidence()) ? "#3fb950" : "MEDIUM".equals(s.getConfidence()) ? "#d29922" : "#8b949e";
                h.append("<tr><td class=\"mono\">").append(s.getPort()).append("</td><td>").append(escHtml(s.getProtocol()))
                 .append("</td><td><strong>").append(escHtml(s.getProduct())).append("</strong></td><td>").append(escHtml(s.getVersion()))
                 .append("</td><td><span class=\"state-ok\">").append(escHtml(s.getState()))
                 .append("</span></td><td style=\"color:").append(sc).append("\">").append(escHtml(s.getConfidence())).append("</td></tr>\n");
            }
            h.append("</tbody>\n</table></div>\n</section>\n\n");
        }

        // Vulnerabilities
        if (!profile.getVulnerabilities().isEmpty()) {
            h.append("<section class=\"prf-section\">\n<h2>Vulnerabilities (").append(profile.getVulnerabilities().size()).append(")</h2>\n");
            for (TargetProfile.VulnEntry v : profile.getVulnerabilities()) {
                String sevCls = v.getSeverity().toLowerCase();
                h.append("<div class=\"vuln-card vuln--").append(sevCls).append("\">\n");
                h.append("  <div class=\"vuln-top\"><span class=\"vuln-cve\">").append(escHtml(v.getCveId() != null ? v.getCveId() : "N/A")).append("</span>");
                h.append("<span class=\"sev sev--").append(sevCls).append("\">").append(escHtml(v.getSeverity())).append("</span>");
                h.append("<span class=\"vuln-status\">").append(escHtml(v.getStatus())).append("</span></div>\n");
                h.append("  <div class=\"vuln-title\">").append(escHtml(v.getTitle())).append("</div>\n");
                if (v.getEvidence() != null && !v.getEvidence().isBlank())
                    h.append("  <div class=\"vuln-evidence\">").append(escHtml(v.getEvidence())).append("</div>\n");
                h.append("</div>\n");
            }
            h.append("</section>\n\n");
        }

        // Technologies
        if (!profile.getTechnologies().isEmpty()) {
            h.append("<section class=\"prf-section\">\n<h2>Technology Stack (").append(profile.getTechnologies().size()).append(")</h2>\n<div class=\"tag-cloud\">\n");
            for (TargetProfile.TechEntry t : profile.getTechnologies()) {
                h.append("<span class=\"tag tag--tech\">").append(escHtml(t.getName()));
                if (t.getVersion() != null && !t.getVersion().isBlank()) h.append(" <small>v").append(escHtml(t.getVersion())).append("</small>");
                h.append(" <span class=\"tag-cat\">").append(escHtml(t.getCategory())).append("</span></span>\n");
            }
            h.append("</div>\n</section>\n\n");
        }

        // Behavioral Insights
        if (profile.getBehavioralInsights() != null && !profile.getBehavioralInsights().isEmpty()) {
            h.append("<section class=\"prf-section\">\n<h2>Behavioral Insights</h2>\n<div class=\"insights-grid\">\n");
            for (Map.Entry<String, Object> e : profile.getBehavioralInsights().entrySet()) {
                h.append("<div class=\"insight\"><span class=\"insight-key\">").append(escHtml(e.getKey().replace("_", " ")))
                 .append("</span><span class=\"insight-val\">").append(escHtml(String.valueOf(e.getValue()))).append("</span></div>\n");
            }
            h.append("</div>\n</section>\n\n");
        }

        // Footer
        h.append("<footer class=\"prf-footer\">JABBER V 5.5.0 &middot; Funbinet (dancan.tech) &middot; ").append(java.time.Instant.now()).append("</footer>\n");
        h.append("</div>\n</body>\n</html>");
        return h.toString();
    }

    private String getProfileStyles() {
        return """
                <style>
                  :root{color-scheme:dark;--bg:#0d1117;--panel:#141b27;--ink:#e6edf7;--muted:#8b949e;--line:#2b3648;--accent:#4bb3fd}
                  *{box-sizing:border-box;margin:0;padding:0}
                  body{font-family:'Segoe UI',-apple-system,system-ui,sans-serif;background:var(--bg);color:var(--ink);line-height:1.6}
                  .wrap{max-width:1200px;margin:0 auto;padding:2rem}
                  code{font-family:'JetBrains Mono',Consolas,monospace;font-size:.85em;background:rgba(255,255,255,.06);padding:.15em .4em;border-radius:4px}
                  .mono{font-family:'JetBrains Mono',Consolas,monospace}
                  .prf-header{display:flex;justify-content:space-between;align-items:center;padding:1.5rem 0;border-bottom:1px solid var(--line);margin-bottom:1.5rem}
                  .prf-header h1{font-size:1.5rem;font-weight:800;color:#fff}
                  .prf-sub{font-size:.82rem;color:var(--muted)}
                  .prf-id{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.5rem 1rem}
                  .score-row{display:flex;align-items:center;gap:2rem;padding:1.5rem;background:var(--panel);border:1px solid var(--line);border-radius:16px;margin-bottom:1.5rem}
                  .risk-gauge{text-align:center}
                  .risk-ring{width:100px;height:100px;border-radius:50%;display:flex;align-items:center;justify-content:center;position:relative}
                  .risk-ring span{font-size:1.8rem;font-weight:800;color:#fff;background:var(--bg);width:70px;height:70px;border-radius:50%;display:flex;align-items:center;justify-content:center}
                  .risk-label{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-top:.4rem}
                  .conf-badge{border:2px solid;border-radius:12px;padding:.6rem 1.2rem;font-weight:700;font-size:.88rem}
                  .score-stats{display:flex;gap:1.5rem;margin-left:auto}
                  .stat{text-align:center}.stat-val{display:block;font-size:1.5rem;font-weight:800;color:var(--accent)}.stat-lbl{font-size:.68rem;color:var(--muted);text-transform:uppercase}
                  .prf-section{margin-bottom:1.5rem}
                  .prf-section h2{font-size:1rem;font-weight:700;color:var(--accent);margin-bottom:.75rem;padding-bottom:.4rem;border-bottom:1px solid var(--line)}
                  .tag-cloud{display:flex;flex-wrap:wrap;gap:.4rem}
                  .tag{padding:.25rem .65rem;border-radius:6px;font-size:.78rem;font-weight:600}
                  .tag--ip{background:rgba(75,179,253,.12);color:#4bb3fd;border:1px solid rgba(75,179,253,.25)}
                  .tag--host{background:rgba(63,185,80,.12);color:#3fb950;border:1px solid rgba(63,185,80,.25)}
                  .tag--domain{background:rgba(188,140,255,.12);color:#bc8cff;border:1px solid rgba(188,140,255,.25)}
                  .tag--email{background:rgba(248,81,73,.12);color:#f85149;border:1px solid rgba(248,81,73,.25)}
                  .tag--mac{background:rgba(210,153,34,.12);color:#d29922;border:1px solid rgba(210,153,34,.25)}
                  .tag--tech{background:rgba(75,179,253,.08);color:#e6edf7;border:1px solid var(--line)}
                  .tag-cat{font-size:.65rem;opacity:.6;margin-left:.3rem}
                  .tbl-wrap{overflow-x:auto}
                  .dt{width:100%;border-collapse:collapse;font-size:.82rem}
                  .dt th{padding:.6rem .75rem;text-align:left;background:rgba(27,38,55,.8);color:#dbe7ff;font-weight:700;font-size:.72rem;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid var(--line)}
                  .dt td{padding:.55rem .75rem;border-bottom:1px solid rgba(43,54,72,.4);vertical-align:top}
                  .dt tbody tr:hover{background:rgba(88,166,255,.04)}
                  .state-ok{background:rgba(63,185,80,.15);color:#3fb950;padding:.12rem .5rem;border-radius:4px;font-size:.72rem;font-weight:600}
                  .vuln-card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:1rem;margin-bottom:.6rem}
                  .vuln--critical{border-left:3px solid #f85149}.vuln--high{border-left:3px solid #f0883e}.vuln--medium{border-left:3px solid #d29922}.vuln--low{border-left:3px solid #3fb950}
                  .vuln-top{display:flex;align-items:center;gap:.6rem;margin-bottom:.4rem}
                  .vuln-cve{font-family:'JetBrains Mono',monospace;font-weight:700;color:var(--accent)}
                  .sev{padding:.1rem .5rem;border-radius:4px;font-size:.68rem;font-weight:700;text-transform:uppercase}
                  .sev--critical{background:rgba(248,81,73,.2);color:#f85149}.sev--high{background:rgba(240,136,62,.2);color:#f0883e}
                  .sev--medium{background:rgba(210,153,34,.2);color:#d29922}.sev--low{background:rgba(63,185,80,.2);color:#3fb950}
                  .sev--unknown{background:rgba(139,148,158,.2);color:#8b949e}
                  .vuln-status{font-size:.7rem;color:var(--muted);margin-left:auto}
                  .vuln-title{font-weight:500;margin-bottom:.3rem}
                  .vuln-evidence{font-size:.82rem;color:var(--muted);background:rgba(0,0,0,.2);padding:.5rem;border-radius:6px;margin-top:.3rem}
                  .insights-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:.5rem}
                  .insight{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.6rem .8rem;display:flex;flex-direction:column;gap:.2rem}
                  .insight-key{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
                  .insight-val{font-weight:600;color:var(--accent);font-size:.88rem}
                  .prf-footer{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--line);text-align:center;font-size:.72rem;color:rgba(139,148,158,.6)}
                  @media(max-width:768px){.score-row{flex-direction:column;text-align:center}.score-stats{margin-left:0;justify-content:center}}
                </style>
                """;
    }

    private String escHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                   .replace("\"", "&quot;").replace("'", "&#39;");
    }

    public Path getOutputsDir() { return outputsDir; }
    public Path getPayloadsDir() { return payloadsDir; }
    public Path getAnalysisDir() { return analysisDir; }
    public Path getArtifactsDir() { return artifactsDir; }
    public Path getLogsDir() { return logsDir; }
}
