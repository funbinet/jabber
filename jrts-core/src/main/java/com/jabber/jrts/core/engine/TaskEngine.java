package com.jabber.jrts.core.engine;

import com.jabber.jrts.core.plugin.PluginRegistry;
import com.jabber.jrts.core.storage.ReportStorageService;
import com.jabber.jrts.data.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.*;

/**
 * Task Engine - manages async execution of JRTS modules.
 * V3: Auto-persists results to filesystem, populates metadata fields.
 */
@Service
public class TaskEngine {

    private static final Logger log = LoggerFactory.getLogger(TaskEngine.class);
    private final PluginRegistry registry;
    private final ReportStorageService storage;
    private final Map<String, ModuleResult> taskResults = new ConcurrentHashMap<>();
    private final Map<String, List<String>> taskLogs = new ConcurrentHashMap<>();
    private final Map<String, Integer> taskProgress = new ConcurrentHashMap<>();
    private final Map<String, Map<String, String>> taskInputs = new ConcurrentHashMap<>();
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    public TaskEngine(PluginRegistry registry, ReportStorageService storage) {
        this.registry = registry;
        this.storage = storage;
    }

    /**
     * Execute a module asynchronously.
     */
    public String executeModule(String moduleId, Map<String, String> input) {
        String taskId = UUID.randomUUID().toString();
        String sessionId = "session-" + System.currentTimeMillis();

        JRTSModuleInterface module = registry.getModule(moduleId);
        if (module == null) {
            throw new IllegalArgumentException("Module not found: " + moduleId);
        }

        // Get descriptor for metadata
        ModuleDescriptor desc = module.getDescriptor();

        taskLogs.put(taskId, Collections.synchronizedList(new ArrayList<>()));
        taskProgress.put(taskId, 0);
        taskInputs.put(taskId, input);

        TaskContext ctx = new TaskContext(taskId, sessionId);
        ctx.setLogCallback(line -> {
            taskLogs.get(taskId).add(line);
            log.debug("[{}] {}", taskId, line);
        });
        ctx.setProgressCallback(pct -> taskProgress.put(taskId, pct));

        log.info("Starting task {} for module {}", taskId, moduleId);

        CompletableFuture<ModuleResult> future = module.execute(input, ctx);
        future.whenComplete((result, throwable) -> {
            ModuleResult finalResult;
            if (throwable != null) {
                finalResult = new ModuleResult(taskId, moduleId);
                finalResult.fail(throwable.getMessage());
            } else {
                finalResult = result;
            }

            // V3: Populate metadata fields
            if (desc != null) {
                finalResult.setModuleName(desc.getName());
                finalResult.setCategory(desc.getCategory() != null ? desc.getCategory().name() : "UNKNOWN");
            }
            // Extract target from input
            String target = extractTarget(input);
            finalResult.setTarget(target);

            taskResults.put(taskId, finalResult);

            // V3: Auto-persist to filesystem
            try {
                storage.saveOutput(finalResult, "json");
                log.info("Auto-persisted result for task {} to filesystem", taskId);
            } catch (Exception e) {
                log.warn("Failed to auto-persist result for task {}: {}", taskId, e.getMessage());
            }

            try { module.cleanup(); } catch (Exception ignored) {}
            log.info("Task {} completed with status: {}",
                taskId, finalResult.getStatus());
        });

        return taskId;
    }

    /**
     * Extract target identifier from input parameters.
     */
    private String extractTarget(Map<String, String> input) {
        // Try common target field names in priority order
        String[] targetKeys = {"target", "target_url", "rhost", "target_host", "domain",
                "base_url", "target_ip", "host", "url", "bind_address"};
        for (String key : targetKeys) {
            String val = input.get(key);
            if (val != null && !val.isBlank()) {
                // Truncate long URLs for filename safety
                return val.length() > 60 ? val.substring(0, 60) : val;
            }
        }
        return "unknown";
    }

    public ModuleResult getResult(String taskId) {
        return taskResults.get(taskId);
    }

    public List<String> getLogs(String taskId) {
        return taskLogs.getOrDefault(taskId, List.of());
    }

    public int getProgress(String taskId) {
        return taskProgress.getOrDefault(taskId, 0);
    }

    public TaskStatus getStatus(String taskId) {
        ModuleResult result = taskResults.get(taskId);
        if (result != null) return result.getStatus();
        if (taskLogs.containsKey(taskId)) return TaskStatus.RUNNING;
        return TaskStatus.QUEUED;
    }

    public Map<String, String> getTaskInput(String taskId) {
        return taskInputs.getOrDefault(taskId, Map.of());
    }

    public Map<String, Object> getTaskInfo(String taskId) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("taskId", taskId);
        info.put("status", getStatus(taskId));
        info.put("progress", getProgress(taskId));
        info.put("logCount", getLogs(taskId).size());
        ModuleResult result = getResult(taskId);
        if (result != null) {
            info.put("startTime", result.getStartTime());
            info.put("endTime", result.getEndTime());
            info.put("findingsCount", result.getFindings().size());
            info.put("moduleName", result.getModuleName());
            info.put("category", result.getCategory());
            info.put("target", result.getTarget());
        }
        return info;
    }
}
