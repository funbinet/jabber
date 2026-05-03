package com.jabber.jabber.data.model;

import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/**
 * V5.5: Metadata sidecar for persisted report/output/payload files.
 * Serialized as .meta.json alongside the actual artifact.
 */
public class ReportMetadata {
    private String id;
    private String moduleName;
    private String moduleId;
    private String category;
    private String target;
    private Instant timestamp;
    private String format;       // json, html, md, txt, xml, csv, bin, png, pdf, mp4, pcap, etc.
    private String filePath;     // absolute path to the artifact
    private long fileSize;
    private String type;         // OUTPUT, PAYLOAD, ANALYSIS, ARTIFACT, LOG, PROFILE
    private String mimeType;     // e.g. text/html, image/png, video/mp4, application/pdf
    private String sha256;       // SHA256 integrity hash
    private List<String> tags;
    private Map<String, String> attachments;
    private String taskId;

    public ReportMetadata() {
        this.id = UUID.randomUUID().toString().substring(0, 8);
        this.timestamp = Instant.now();
        this.tags = new ArrayList<>();
        this.attachments = new LinkedHashMap<>();
    }

    public static ReportMetadata forOutput(ModuleResult result, String format, String filePath) {
        ReportMetadata m = new ReportMetadata();
        m.moduleId = result.getModuleId();
        m.moduleName = result.getModuleName() != null ? result.getModuleName() : result.getModuleId();
        m.category = result.getCategory() != null ? result.getCategory() : "unknown";
        m.target = result.getTarget() != null ? result.getTarget() : "unknown";
        m.taskId = result.getTaskId();
        m.format = format;
        m.filePath = filePath;
        m.type = "OUTPUT";
        return m;
    }

    public static ReportMetadata forPayload(String moduleName, String moduleId, String category, String target, String filePath) {
        ReportMetadata m = new ReportMetadata();
        m.moduleName = moduleName;
        m.moduleId = moduleId;
        m.category = category;
        m.target = target;
        m.filePath = filePath;
        m.format = "bin";
        m.type = "PAYLOAD";
        return m;
    }

    public static ReportMetadata forAnalysis(String filePath, String format) {
        ReportMetadata m = new ReportMetadata();
        m.moduleName = "target-profiler";
        m.moduleId = "target-profiler";
        m.category = "REPORTS";
        m.filePath = filePath;
        m.format = format;
        m.type = "ANALYSIS";
        m.mimeType = guessMimeType(filePath, format);
        return m;
    }

    public static ReportMetadata forArtifact(String moduleName, String moduleId, String category,
                                              String target, String filePath) {
        ReportMetadata m = new ReportMetadata();
        m.moduleName = moduleName;
        m.moduleId = moduleId;
        m.category = category;
        m.target = target;
        m.filePath = filePath;
        m.format = extensionFromPath(filePath);
        m.type = "ARTIFACT";
        m.mimeType = guessMimeType(filePath, m.format);
        m.tags.add("artifact");
        return m;
    }

    public static ReportMetadata forLog(String moduleName, String moduleId, String category,
                                         String target, String filePath) {
        ReportMetadata m = new ReportMetadata();
        m.moduleName = moduleName;
        m.moduleId = moduleId;
        m.category = category;
        m.target = target;
        m.filePath = filePath;
        m.format = "log";
        m.type = "LOG";
        m.mimeType = "text/plain";
        m.tags.add("log");
        return m;
    }

    public static ReportMetadata forProfile(String filePath, String format) {
        ReportMetadata m = new ReportMetadata();
        m.moduleName = "target-profiler";
        m.moduleId = "target-profiler";
        m.category = "REPORTS";
        m.filePath = filePath;
        m.format = format;
        m.type = "PROFILE";
        m.mimeType = guessMimeType(filePath, format);
        m.tags.add("profile");
        return m;
    }

    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getModuleName() { return moduleName; }
    public void setModuleName(String moduleName) { this.moduleName = moduleName; }
    public String getModuleId() { return moduleId; }
    public void setModuleId(String moduleId) { this.moduleId = moduleId; }
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    public String getTarget() { return target; }
    public void setTarget(String target) { this.target = target; }
    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }
    public String getFormat() { return format; }
    public void setFormat(String format) { this.format = format; }
    public String getFilePath() { return filePath; }
    public void setFilePath(String filePath) { this.filePath = filePath; }
    public long getFileSize() { return fileSize; }
    public void setFileSize(long fileSize) { this.fileSize = fileSize; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getMimeType() { return mimeType; }
    public void setMimeType(String mimeType) { this.mimeType = mimeType; }
    public String getSha256() { return sha256; }
    public void setSha256(String sha256) { this.sha256 = sha256; }
    public List<String> getTags() { return tags; }
    public void setTags(List<String> tags) { this.tags = tags; }
    public Map<String, String> getAttachments() { return attachments; }
    public void setAttachments(Map<String, String> attachments) { this.attachments = attachments; }
    public String getTaskId() { return taskId; }
    public void setTaskId(String taskId) { this.taskId = taskId; }

    // ===== Utility =====

    private static String extensionFromPath(String path) {
        if (path == null) return "bin";
        int dot = path.lastIndexOf('.');
        return dot > 0 ? path.substring(dot + 1).toLowerCase() : "bin";
    }

    /**
     * Guess MIME type from file path and format hint.
     * Supports all artifact types: images, videos, PDFs, scripts, captures, binaries.
     */
    public static String guessMimeType(String filePath, String format) {
        String ext = (format != null && !format.isBlank()) ? format.toLowerCase()
                     : extensionFromPath(filePath);
        return switch (ext) {
            // Text & Reports
            case "json" -> "application/json";
            case "html", "htm" -> "text/html";
            case "md", "markdown" -> "text/markdown";
            case "txt", "log", "raw" -> "text/plain";
            case "xml" -> "application/xml";
            case "csv" -> "text/csv";
            case "yaml", "yml" -> "text/yaml";
            // Images
            case "png" -> "image/png";
            case "jpg", "jpeg" -> "image/jpeg";
            case "gif" -> "image/gif";
            case "svg" -> "image/svg+xml";
            case "webp" -> "image/webp";
            case "bmp" -> "image/bmp";
            case "ico" -> "image/x-icon";
            // Video
            case "mp4" -> "video/mp4";
            case "webm" -> "video/webm";
            case "avi" -> "video/x-msvideo";
            case "mkv" -> "video/x-matroska";
            case "mov" -> "video/quicktime";
            // Audio
            case "mp3" -> "audio/mpeg";
            case "wav" -> "audio/wav";
            case "ogg" -> "audio/ogg";
            // Documents
            case "pdf" -> "application/pdf";
            case "doc", "docx" -> "application/msword";
            case "xls", "xlsx" -> "application/vnd.ms-excel";
            // Archives
            case "zip" -> "application/zip";
            case "tar" -> "application/x-tar";
            case "gz", "gzip" -> "application/gzip";
            // Captures & Forensics
            case "pcap", "cap" -> "application/vnd.tcpdump.pcap";
            case "pcapng" -> "application/x-pcapng";
            case "evtx" -> "application/x-ms-evtx";
            // Scripts
            case "py" -> "text/x-python";
            case "sh", "bash" -> "text/x-shellscript";
            case "ps1" -> "text/x-powershell";
            case "js" -> "text/javascript";
            case "rb" -> "text/x-ruby";
            case "pl" -> "text/x-perl";
            case "java" -> "text/x-java";
            case "c", "cpp", "h" -> "text/x-c";
            // Kerberos
            case "kirbi" -> "application/x-kirbi";
            case "ccache" -> "application/x-ccache";
            // Binaries
            case "exe" -> "application/x-dosexec";
            case "elf" -> "application/x-elf";
            case "msi" -> "application/x-msi";
            case "apk" -> "application/vnd.android.package-archive";
            case "dll" -> "application/x-msdownload";
            case "so" -> "application/x-sharedlib";
            case "bin", "dat" -> "application/octet-stream";
            default -> "application/octet-stream";
        };
    }
}
