package com.jabber.jrts.core.api;

import com.jabber.jrts.data.model.*;
import com.jabber.jrts.core.engine.TaskEngine;
import com.jabber.jrts.core.plugin.PluginRegistry;
import com.jabber.jrts.core.report.ReportEngine;
import com.jabber.jrts.core.storage.ReportStorageService;
import com.jabber.jrts.core.profiling.TargetProfileEngine;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;
import java.nio.file.*;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class JRTSApiController {

    private final PluginRegistry registry;
    private final TaskEngine taskEngine;
    private final ReportEngine reportEngine;
    private final ReportStorageService storage;
    private final TargetProfileEngine profiler;

    public JRTSApiController(PluginRegistry registry, TaskEngine taskEngine,
                              ReportEngine reportEngine, ReportStorageService storage,
                              TargetProfileEngine profiler) {
        this.registry = registry;
        this.taskEngine = taskEngine;
        this.reportEngine = reportEngine;
        this.storage = storage;
        this.profiler = profiler;
    }

    // ===== System Info =====
    @GetMapping("/info")
    public Map<String, Object> getSystemInfo() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("name", "JABBER Red Teaming Suite V3");
        info.put("version", "V3");
        info.put("creator", "Funbinet");
        info.put("website", "dancan.tech");
        info.put("modules_loaded", registry.getModuleCount());
        info.put("categories_active", registry.getCategories().size());
        info.put("runtime", "dual-mode");
        // V3: report stats
        Map<String, Object> reportStats = storage.getStats();
        info.put("total_reports", reportStats.get("totalReports"));
        return info;
    }

    // ===== Categories =====
    @GetMapping("/categories")
    public List<Map<String, Object>> getCategories() {
        return Arrays.stream(Category.values())
                .sorted(Comparator.comparingInt(Category::getSortOrder))
                .map(cat -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", cat.name());
                    m.put("name", cat.getDisplayName());
                    m.put("slug", cat.getSlug());
                    m.put("group", cat.getGroup());
                    m.put("order", cat.getSortOrder());
                    m.put("moduleCount", registry.getByCategory(cat).size());
                    return m;
                })
                .collect(Collectors.toList());
    }

    // ===== All Modules =====
    @GetMapping("/modules")
    public List<Map<String, Object>> getAllModules() {
        return registry.getAllDescriptors().stream()
                .map(this::descriptorToMap)
                .collect(Collectors.toList());
    }

    // ===== Modules by Category =====
    @GetMapping("/modules/category/{category}")
    public List<Map<String, Object>> getModulesByCategory(@PathVariable String category) {
        try {
            Category cat = Category.valueOf(category);
            return registry.getByCategory(cat).stream()
                    .map(this::descriptorToMap)
                    .collect(Collectors.toList());
        } catch (IllegalArgumentException e) {
            return List.of();
        }
    }

    // ===== Single Module =====
    @GetMapping("/modules/{id}")
    public ResponseEntity<Map<String, Object>> getModule(@PathVariable String id) {
        ModuleDescriptor desc = registry.getDescriptor(id);
        if (desc == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(descriptorToMap(desc));
    }

    // ===== Module Input Schema =====
    @GetMapping("/modules/{id}/schema")
    public ResponseEntity<List<Map<String, Object>>> getModuleSchema(@PathVariable String id) {
        JRTSModuleInterface module = registry.getModule(id);
        if (module == null) return ResponseEntity.notFound().build();
        List<Map<String, Object>> schema = module.getInputSchema().stream()
                .map(this::fieldToMap)
                .collect(Collectors.toList());
        return ResponseEntity.ok(schema);
    }

    // ===== Execute Module =====
    @PostMapping("/tasks/execute/{moduleId}")
    public Map<String, Object> executeModule(@PathVariable String moduleId, @RequestBody Map<String, String> input) {
        String taskId = taskEngine.executeModule(moduleId, input);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("taskId", taskId);
        result.put("moduleId", moduleId);
        result.put("status", "RUNNING");
        return result;
    }

    // ===== Task Info =====
    @GetMapping("/tasks/{taskId}")
    public Map<String, Object> getTaskInfo(@PathVariable String taskId) {
        return taskEngine.getTaskInfo(taskId);
    }

    // ===== Task Logs =====
    @GetMapping("/tasks/{taskId}/logs")
    public List<String> getTaskLogs(@PathVariable String taskId) {
        return taskEngine.getLogs(taskId);
    }

    // ===== Task Result =====
    @GetMapping("/tasks/{taskId}/result")
    public ResponseEntity<?> getTaskResult(@PathVariable String taskId) {
        ModuleResult result = taskEngine.getResult(taskId);
        if (result == null) return ResponseEntity.notFound().build();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("taskId", result.getTaskId());
        out.put("moduleId", result.getModuleId());
        out.put("moduleName", result.getModuleName());
        out.put("category", result.getCategory());
        out.put("target", result.getTarget());
        out.put("status", result.getStatus());
        out.put("output", result.getOutput());
        out.put("normalizedOutput", result.getNormalizedOutput());
        out.put("findings", result.getFindings());
        out.put("logLines", result.getLogLines());
        out.put("exportedFiles", result.getExportedFiles());
        out.put("artifacts", result.getArtifacts());
        return ResponseEntity.ok(out);
    }

    // ===== Task Progress =====
    @GetMapping("/tasks/{taskId}/progress")
    public Map<String, Object> getTaskProgress(@PathVariable String taskId) {
        Map<String, Object> progress = new LinkedHashMap<>();
        progress.put("taskId", taskId);
        progress.put("progress", taskEngine.getProgress(taskId));
        progress.put("status", taskEngine.getStatus(taskId));
        return progress;
    }

    // ===== V3.1: Cancel Task (Kill Switch) =====
    @PostMapping("/tasks/{taskId}/cancel")
    public Map<String, Object> cancelTask(@PathVariable String taskId) {
        return taskEngine.cancelTask(taskId);
    }

    // ===== Generate Report (legacy) =====
    @PostMapping("/reports/generate/{taskId}")
    public Map<String, Object> generateReport(@PathVariable String taskId, @RequestBody Map<String, String> body) {
        String format = body.getOrDefault("format", "json");
        ModuleResult result = taskEngine.getResult(taskId);
        Map<String, Object> response = new LinkedHashMap<>();
        if (result == null) {
            response.put("error", "No result found for task " + taskId);
            return response;
        }
        String content = reportEngine.generate(result, format);
        response.put("taskId", taskId);
        response.put("format", format);
        response.put("content", content);
        return response;
    }

    // =============== V3: REPORTS MANAGEMENT ===============

    /**
     * List all saved reports with optional filters.
     */
    @GetMapping("/reports")
    public List<Map<String, Object>> listReports(
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String module,
            @RequestParam(required = false) String target,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to) {
        return storage.listReports(category, module, target, type, from, to);
    }

    /**
     * Get report content by ID.
     */
    @GetMapping("/reports/{id}/content")
    public ResponseEntity<String> getReportContent(@PathVariable String id) {
        try {
            String content = storage.getReportContent(id);
            if (content == null) return ResponseEntity.notFound().build();
            return ResponseEntity.ok(content);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Error: " + e.getMessage());
        }
    }

    /**
     * Get report metadata by ID.
     */
    @GetMapping("/reports/{id}/meta")
    public ResponseEntity<Map<String, Object>> getReportMeta(@PathVariable String id) {
        Map<String, Object> meta = storage.getReportMeta(id);
        if (meta == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(meta);
    }

    /**
     * Download arbitrary artifact from reports directory.
     */
    @GetMapping("/reports/download")
    public ResponseEntity<Resource> downloadArtifact(@RequestParam String path) {
        try {
            // Safety measure: sanitize path to prevent directory traversal outside of reports
            if (path.contains("..")) return ResponseEntity.badRequest().build();
            
            Path baseDir = Paths.get(System.getProperty("user.home"), ".gemini", "antigravity", "reports");
            // If path is absolute, it might already have the prefix, so we check carefully
            Path file;
            if (path.startsWith("/")) {
                file = Paths.get(path);
            } else {
                file = baseDir.resolve(path);
            }
            
            Resource resource = new UrlResource(file.toUri());
            if (resource.exists() || resource.isReadable()) {
                String mimeType = Files.probeContentType(file);
                if (mimeType == null) {
                    mimeType = MediaType.APPLICATION_OCTET_STREAM_VALUE;
                }
                return ResponseEntity.ok()
                        .contentType(MediaType.parseMediaType(mimeType))
                        .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"" + resource.getFilename() + "\"")
                        .body(resource);
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Save current task result as a report in specified format.
     */
    @PostMapping("/reports/save")
    public ResponseEntity<Map<String, Object>> saveReport(@RequestBody Map<String, String> body) {
        String taskId = body.get("taskId");
        String format = body.getOrDefault("format", "json");

        ModuleResult result = taskEngine.getResult(taskId);
        if (result == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Task not found: " + taskId));
        }

        try {
            ReportMetadata meta = storage.saveOutput(result, format);
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success", true);
            response.put("id", meta.getId());
            response.put("filePath", meta.getFilePath());
            response.put("format", format);
            response.put("fileSize", meta.getFileSize());
            response.put("attachments", meta.getAttachments());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Edit report content (text-based formats only).
     */
    @PutMapping("/reports/{id}")
    public ResponseEntity<Map<String, Object>> editReport(@PathVariable String id, @RequestBody Map<String, String> body) {
        try {
            String content = body.get("content");
            if (content == null) return ResponseEntity.badRequest().body(Map.of("error", "Content required"));
            boolean success = storage.editReport(id, content);
            return ResponseEntity.ok(Map.of("success", success));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Rename a report.
     */
    @PutMapping("/reports/{id}/rename")
    public ResponseEntity<Map<String, Object>> renameReport(@PathVariable String id, @RequestBody Map<String, String> body) {
        try {
            String newName = body.get("name");
            if (newName == null) return ResponseEntity.badRequest().body(Map.of("error", "Name required"));
            boolean success = storage.renameReport(id, newName);
            return ResponseEntity.ok(Map.of("success", success));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Delete a report.
     */
    @DeleteMapping("/reports/{id}")
    public ResponseEntity<Map<String, Object>> deleteReport(@PathVariable String id) {
        try {
            boolean success = storage.deleteReport(id);
            return ResponseEntity.ok(Map.of("success", success));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Download report in specified format.
     */
    @GetMapping("/reports/{id}/download")
    public ResponseEntity<byte[]> downloadReport(@PathVariable String id,
                                                  @RequestParam(defaultValue = "json") String format) {
        try {
            byte[] content = storage.getReportBytes(id);
            if (content == null) return ResponseEntity.notFound().build();

            Map<String, Object> meta = storage.getReportMeta(id);
            String fileName = meta != null ? (String) meta.get("filePath") : "report." + format;
            // Extract just the filename
            fileName = fileName.substring(fileName.lastIndexOf('/') + 1);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.setContentDisposition(ContentDisposition.builder("attachment")
                    .filename(fileName).build());
            return new ResponseEntity<>(content, headers, HttpStatus.OK);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Get report statistics.
     */
    @GetMapping("/reports/stats")
    public Map<String, Object> getReportStats() {
        return storage.getStats();
    }

    // =============== V3: TARGET PROFILING ===============

    /**
     * Generate a target profile from selected report IDs.
     */
    @PostMapping("/profiling/generate")
    public ResponseEntity<Map<String, Object>> generateProfile(@RequestBody Map<String, Object> body) {
        @SuppressWarnings("unchecked")
        List<String> reportIds = (List<String>) body.get("reportIds");
        if (reportIds == null || reportIds.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "reportIds required"));
        }

        boolean save = Boolean.TRUE.equals(body.get("save"));
        String format = (String) body.getOrDefault("format", "json");

        TargetProfile profile = profiler.generateProfile(reportIds);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("profileId", profile.getProfileId());
        response.put("generatedAt", profile.getGeneratedAt().toString());
        response.put("sourceReports", profile.getSourceReports());
        response.put("ipAddresses", profile.getIpAddresses());
        response.put("hostnames", profile.getHostnames());
        response.put("domains", profile.getDomains());
        response.put("macAddresses", profile.getMacAddresses());
        response.put("emails", profile.getEmails());
        response.put("urls", profile.getUrls());
        response.put("services", profile.getServices());
        response.put("technologies", profile.getTechnologies());
        response.put("vulnerabilities", profile.getVulnerabilities());
        response.put("behavioralInsights", profile.getBehavioralInsights());
        response.put("overallRiskScore", profile.getOverallRiskScore());
        response.put("confidenceLevel", profile.getConfidenceLevel());

        // Auto-save if requested
        if (save) {
            try {
                ReportMetadata meta = storage.saveProfile(profile, format);
                response.put("savedAs", meta.getFilePath());
                response.put("savedId", meta.getId());
            } catch (Exception e) {
                response.put("saveError", e.getMessage());
            }
        }

        return ResponseEntity.ok(response);
    }

    // ===== Helpers =====
    private Map<String, Object> descriptorToMap(ModuleDescriptor d) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", d.getId());
        m.put("name", d.getName());
        m.put("description", d.getDescription());
        m.put("category", d.getCategory().name());
        m.put("categoryGroup", d.getCategory().getGroup());
        m.put("riskLevel", d.getRiskLevel().name());
        m.put("version", d.getVersion());
        m.put("sourceRef", d.getSourceRef());
        // Include full input schema so UI can render module-specific forms
        if (d.getInputSchema() != null && !d.getInputSchema().isEmpty()) {
            m.put("inputSchema", d.getInputSchema().stream()
                .map(this::fieldToMap)
                .collect(Collectors.toList()));
        }
        return m;
    }

    private Map<String, Object> fieldToMap(ModuleInputField f) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", f.getName());
        m.put("label", f.getLabel());
        m.put("type", f.getType());
        m.put("required", f.isRequired());
        m.put("placeholder", f.getPlaceholder());
        m.put("defaultValue", f.getDefaultValue());
        m.put("helpText", f.getHelpText());
        m.put("group", f.getGroup());
        m.put("options", f.getOptions());
        m.put("modes", f.getModes());
        return m;
    }
}
