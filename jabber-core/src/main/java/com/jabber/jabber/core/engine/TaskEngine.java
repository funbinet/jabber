package com.jabber.jabber.core.engine;

import com.jabber.jabber.core.plugin.PluginRegistry;
import com.jabber.jabber.core.storage.ReportStorageService;
import com.jabber.jabber.data.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.*;
import java.util.concurrent.*;

/**
 * Task Engine - manages async execution of JABBER modules.
 * V5.5: Auto-persists results to filesystem, populates metadata fields.
 * V5.5: Kill switch support — stores futures, supports cancellation.
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
    private final Map<String, CompletableFuture<ModuleResult>> taskFutures = new ConcurrentHashMap<>();
    private final Map<String, String> taskModuleIds = new ConcurrentHashMap<>();

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

        JABBERModuleInterface module = registry.getModule(moduleId);
        if (module == null) {
            throw new IllegalArgumentException("Module not found: " + moduleId);
        }

        // Get descriptor for metadata
        ModuleDescriptor desc = module.getDescriptor();

        taskLogs.put(taskId, Collections.synchronizedList(new ArrayList<>()));
        taskProgress.put(taskId, 0);
        taskInputs.put(taskId, input);
        taskModuleIds.put(taskId, moduleId);

        TaskContext ctx = new TaskContext(taskId, sessionId);
        ctx.setLogCallback(line -> {
            taskLogs.get(taskId).add(line);
            log.debug("[{}] {}", taskId, line);
        });
        ctx.setProgressCallback(pct -> taskProgress.put(taskId, pct));

        log.info("Starting task {} for module {}", taskId, moduleId);

        CompletableFuture<ModuleResult> future = module.execute(input, ctx);
        taskFutures.put(taskId, future);

        future.whenComplete((result, throwable) -> {
            // Remove future reference (execution complete)
            taskFutures.remove(taskId);

            ModuleResult finalResult;
            if (throwable != null) {
                // Check if this was a cancellation
                if (throwable instanceof CancellationException || (throwable.getCause() instanceof CancellationException)) {
                    finalResult = new ModuleResult(taskId, moduleId);
                    finalResult.setStatus(TaskStatus.CANCELLED);
                    finalResult.setErrorMessage("Task cancelled by user");
                } else {
                    finalResult = new ModuleResult(taskId, moduleId);
                    finalResult.fail(throwable.getMessage());
                }
            } else {
                finalResult = result;
            }

            // Ensure task-context logs are persisted with the module result.
            List<String> capturedTaskLogs = new ArrayList<>(taskLogs.getOrDefault(taskId, List.of()));
            if (throwable != null && !(throwable instanceof CancellationException)) {
                capturedTaskLogs.add("[!] Task failed: " + throwable.getMessage());
            }
            List<String> existingLogs = finalResult.getLogLines() != null
                ? new ArrayList<>(finalResult.getLogLines())
                : new ArrayList<>();
            if (!capturedTaskLogs.isEmpty()) {
                existingLogs.addAll(capturedTaskLogs);
            }
            finalResult.setLogLines(existingLogs);

            // V5.5: Populate metadata fields
            if (desc != null) {
                finalResult.setModuleName(desc.getName());
                finalResult.setCategory(desc.getCategory() != null ? desc.getCategory().name() : "UNKNOWN");
            }
            // Extract target from input
            String target = extractTarget(input);
            finalResult.setTarget(target);

            taskResults.put(taskId, finalResult);

            // V5.5: Auto-persist to filesystem
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
     * V5.5: Cancel a running task.
     * Interrupts the executing thread and sets status to CANCELLED.
     */
    public Map<String, Object> cancelTask(String taskId) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("taskId", taskId);

        CompletableFuture<ModuleResult> future = taskFutures.get(taskId);
        if (future == null) {
            // Check if already completed
            ModuleResult existingResult = taskResults.get(taskId);
            if (existingResult != null) {
                response.put("cancelled", false);
                response.put("reason", "Task already completed with status: " + existingResult.getStatus());
                return response;
            }
            response.put("cancelled", false);
            response.put("reason", "Task not found or not running");
            return response;
        }

        // Add cancellation log
        List<String> logs = taskLogs.get(taskId);
        if (logs != null) {
            logs.add("[!] Task cancellation requested by user");
        }

        // Cancel the future — interrupt if running
        boolean cancelled = future.cancel(true);

        // Attempt to cleanup the module
        String moduleId = taskModuleIds.get(taskId);
        if (moduleId != null) {
            try {
                JABBERModuleInterface module = registry.getModule(moduleId);
                if (module != null) {
                    module.cleanup();
                }
            } catch (Exception e) {
                log.warn("Error during module cleanup for cancelled task {}: {}", taskId, e.getMessage());
            }
        }

        // If future.cancel didn't trigger whenComplete (already), handle manually
        if (cancelled && !taskResults.containsKey(taskId)) {
            ModuleResult cancelledResult = new ModuleResult(taskId, moduleId != null ? moduleId : "unknown");
            cancelledResult.setStatus(TaskStatus.CANCELLED);
            cancelledResult.setErrorMessage("Task cancelled by user");

            List<String> capturedLogs = new ArrayList<>(taskLogs.getOrDefault(taskId, List.of()));
            capturedLogs.add("[!] Task cancelled by user");
            cancelledResult.setLogLines(capturedLogs);

            // Populate metadata
            if (moduleId != null) {
                JABBERModuleInterface module = registry.getModule(moduleId);
                if (module != null) {
                    ModuleDescriptor desc = module.getDescriptor();
                    if (desc != null) {
                        cancelledResult.setModuleName(desc.getName());
                        cancelledResult.setCategory(desc.getCategory() != null ? desc.getCategory().name() : "UNKNOWN");
                    }
                }
            }
            Map<String, String> input = taskInputs.getOrDefault(taskId, Map.of());
            cancelledResult.setTarget(extractTarget(input));

            taskResults.put(taskId, cancelledResult);
            taskFutures.remove(taskId);

            // Auto-persist cancelled result
            try {
                storage.saveOutput(cancelledResult, "json");
                log.info("Auto-persisted cancelled result for task {}", taskId);
            } catch (Exception e) {
                log.warn("Failed to persist cancelled result for task {}: {}", taskId, e.getMessage());
            }
        }

        response.put("cancelled", true);
        response.put("status", "CANCELLED");
        log.info("Task {} cancelled by user", taskId);
        return response;
    }

    /**
     * V5.5: Get list of currently running task IDs.
     */
    public List<String> getActiveTaskIds() {
        return new ArrayList<>(taskFutures.keySet());
    }

    /**
     * Extract target identifier from input parameters.
     */
    private String extractTarget(Map<String, String> input) {
        // Try common target field names in priority order
        String[] targetKeys = {"target", "target_url", "rhost", "target_host", "domain",
                "base_url", "target_ip", "host", "url", "bind_address", "target_ips"};
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
