package com.jabber.jrts.data.model;

import java.time.Instant;
import java.util.*;

/**
 * V3: Metadata sidecar for persisted report/output/payload files.
 * Serialized as .meta.json alongside the actual artifact.
 */
public class ReportMetadata {
    private String id;
    private String moduleName;
    private String moduleId;
    private String category;
    private String target;
    private Instant timestamp;
    private String format;       // json, html, md, txt, xml, csv, bin
    private String filePath;     // absolute path to the artifact
    private long fileSize;
    private String type;         // OUTPUT, PAYLOAD, ANALYSIS
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
    public List<String> getTags() { return tags; }
    public void setTags(List<String> tags) { this.tags = tags; }
    public Map<String, String> getAttachments() { return attachments; }
    public void setAttachments(Map<String, String> attachments) { this.attachments = attachments; }
    public String getTaskId() { return taskId; }
    public void setTaskId(String taskId) { this.taskId = taskId; }
}
