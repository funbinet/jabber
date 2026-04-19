package com.jabber.jrts.data.model;

import java.util.Map;
import java.util.function.Consumer;

/**
 * Execution context provided to modules during execution.
 * Enables logging, progress reporting, and finding submission.
 */
public class TaskContext {
    private final String taskId;
    private final String sessionId;
    private Consumer<String> logCallback;
    private Consumer<Integer> progressCallback;

    public TaskContext(String taskId, String sessionId) {
        this.taskId = taskId;
        this.sessionId = sessionId;
    }

    public String getTaskId() { return taskId; }
    public String getSessionId() { return sessionId; }

    public void log(String message) {
        if (logCallback != null) logCallback.accept(message);
    }

    public void reportProgress(int percent) {
        if (progressCallback != null) progressCallback.accept(percent);
    }

    public void setLogCallback(Consumer<String> cb) { this.logCallback = cb; }
    public void setProgressCallback(Consumer<Integer> cb) { this.progressCallback = cb; }
}
