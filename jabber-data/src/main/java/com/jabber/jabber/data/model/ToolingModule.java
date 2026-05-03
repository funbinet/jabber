package com.jabber.jabber.data.model;

import java.util.List;
import java.util.Map;

/**
 * Optional contract for modules that expose tool readiness and download actions to the UI.
 */
public interface ToolingModule {

    /**
     * Return tool readiness status objects for UI rendering.
     */
    List<Map<String, Object>> getToolStatuses();

    /**
     * Return tool readiness status objects filtered by execution mode.
     */
    default List<Map<String, Object>> getToolStatusesForMode(String mode) {
        return getToolStatuses();
    }

    /**
     * Trigger a tool download and return the initial download status payload.
     */
    Map<String, Object> downloadTool(String toolId);

    /**
     * Return current download status payload for a tool.
     */
    Map<String, Object> getToolDownloadStatus(String toolId);

    /**
     * Safely delete a tool's binary from the system.
     */
    Map<String, Object> deleteTool(String toolId);
}