package com.jabber.jrts.core.storage;

import com.jabber.jrts.core.report.ReportEngine;
import com.jabber.jrts.data.model.*;
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
 * V3: Filesystem-based persistence for all module outputs, payloads, and analysis profiles.
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

    @Value("${jrts.reports.base-dir:./reports}")
    private String baseDir;

    private Path outputsDir;
    private Path payloadsDir;
    private Path analysisDir;

    public ReportStorageService(ReportEngine reportEngine) {
        this.reportEngine = reportEngine;
    }

    @PostConstruct
    public void init() throws IOException {
        Path base = Path.of(baseDir).toAbsolutePath();
        outputsDir = base.resolve("outputs");
        payloadsDir = base.resolve("payloads");
        analysisDir = base.resolve("analysis");
        Files.createDirectories(outputsDir);
        Files.createDirectories(payloadsDir);
        Files.createDirectories(analysisDir);
        log.info("V3 Report storage initialized: {}", base);
        log.info("  Outputs:  {}", outputsDir);
        log.info("  Payloads: {}", payloadsDir);
        log.info("  Analysis: {}", analysisDir);
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
     */
    public ReportMetadata saveProfile(TargetProfile profile, String format) throws IOException {
        String content;
        String ext = formatToExtension(format);
        if ("json".equals(format)) {
            content = gson.toJson(profile);
        } else {
            content = profileToMarkdown(profile);
            ext = "md";
        }
        String fileName = "profile_" + profile.getProfileId() + "_" +
                TS_FMT.format(LocalDateTime.now()) + "." + ext;
        Path filePath = analysisDir.resolve(fileName);
        Files.writeString(filePath, content, StandardCharsets.UTF_8);

        ReportMetadata meta = ReportMetadata.forAnalysis(filePath.toString(), format);
        meta.setTarget(String.join(",", profile.getIpAddresses()));
        meta.setFileSize(Files.size(filePath));
        saveMetadata(meta, filePath);

        log.info("Saved profile: {}", fileName);
        return meta;
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
        stats.put("analyses", all.stream().filter(m -> "ANALYSIS".equals(m.get("type"))).count());
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
        payload.put("generator", "JABBER Red Teaming Suite v1.0.0");
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

    public Path getOutputsDir() { return outputsDir; }
    public Path getPayloadsDir() { return payloadsDir; }
    public Path getAnalysisDir() { return analysisDir; }
}
