package com.jabber.jrts.data.model;

import java.time.Instant;
import java.util.*;

/**
 * Represents the result of a module execution.
 */
public class ModuleResult {
    private String taskId;
    private String moduleId;
    private String moduleName;
    private String category;
    private String target;
    private TaskStatus status;
    private Instant startTime;
    private Instant endTime;
    private Map<String, Object> output;
    private Map<String, Object> normalizedOutput; // V3: raw_output, parsed_output{vulnerable,evidence,details,status}, metadata
    private List<String> logLines;
    private String errorMessage;
    private List<Map<String, Object>> findings;
    private Map<String, String> exportedFiles; // format -> filePath
    private List<String> artifacts; // V3: paths to generated files (payloads, etc)

    public ModuleResult() {
        this.output = new LinkedHashMap<>();
        this.normalizedOutput = new LinkedHashMap<>();
        this.logLines = new ArrayList<>();
        this.findings = new ArrayList<>();
        this.exportedFiles = new LinkedHashMap<>();
        this.artifacts = new ArrayList<>();
    }

    public ModuleResult(String taskId, String moduleId) {
        this();
        this.taskId = taskId;
        this.moduleId = moduleId;
        this.status = TaskStatus.RUNNING;
        this.startTime = Instant.now();
    }

    public void complete(Map<String, Object> output) {
        this.status = TaskStatus.COMPLETED;
        this.endTime = Instant.now();
        this.output = output;
    }

    public void fail(String errorMessage) {
        this.status = TaskStatus.FAILED;
        this.endTime = Instant.now();
        this.errorMessage = errorMessage;
    }

    public void addLogLine(String line) { this.logLines.add(line); }
    public void addFinding(Map<String, Object> finding) { this.findings.add(finding); }
    public void addArtifact(String path) { this.artifacts.add(path); }

    // Getters and setters
    public String getTaskId() { return taskId; }
    public void setTaskId(String taskId) { this.taskId = taskId; }
    public String getModuleId() { return moduleId; }
    public void setModuleId(String moduleId) { this.moduleId = moduleId; }
    public String getModuleName() { return moduleName; }
    public void setModuleName(String moduleName) { this.moduleName = moduleName; }
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    public String getTarget() { return target; }
    public void setTarget(String target) { this.target = target; }
    public TaskStatus getStatus() { return status; }
    public void setStatus(TaskStatus status) { this.status = status; }
    public Instant getStartTime() { return startTime; }
    public void setStartTime(Instant startTime) { this.startTime = startTime; }
    public Instant getEndTime() { return endTime; }
    public void setEndTime(Instant endTime) { this.endTime = endTime; }
    public Map<String, Object> getOutput() { return output; }
    public void setOutput(Map<String, Object> output) { this.output = output; }
    public Map<String, Object> getNormalizedOutput() { return normalizedOutput; }
    public void setNormalizedOutput(Map<String, Object> normalizedOutput) { this.normalizedOutput = normalizedOutput; }
    public List<String> getLogLines() { return logLines; }
    public void setLogLines(List<String> logLines) { this.logLines = logLines; }
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    public List<Map<String, Object>> getFindings() { return findings; }
    public void setFindings(List<Map<String, Object>> findings) { this.findings = findings; }
    public Map<String, String> getExportedFiles() { return exportedFiles; }
    public void setExportedFiles(Map<String, String> exportedFiles) { this.exportedFiles = exportedFiles; }
    public List<String> getArtifacts() { return artifacts; }
    public void setArtifacts(List<String> artifacts) { this.artifacts = artifacts; }
}
