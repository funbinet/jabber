package com.jabber.jabber.modules.reconnaissance.bannergrab;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class CommandRecord {
    public String tool;
    public String command;
    public List<String> args = new ArrayList<>();
    public String workingDir;
    public String status = "unknown";
    public int exitCode = -1;
    public boolean timedOut = false;
    public long durationMs = 0L;
    public String stdout = "";
    public String stderr = "";
    public String stdoutPreview = "";
    public String stderrPreview = "";

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tool", tool);
        map.put("command", command);
        map.put("args", args);
        map.put("working_dir", workingDir);
        map.put("status", status);
        map.put("timed_out", timedOut);
        map.put("duration_ms", durationMs);
        map.put("stdout_preview", truncate(stdoutPreview, 1200));
        map.put("stderr_preview", truncate(stderrPreview, 1200));
        return map;
    }

    private String truncate(String value, int max) {
        if (value == null) {
            return "";
        }
        if (value.length() <= max) {
            return value;
        }
        return value.substring(0, max) + "...";
    }
}
