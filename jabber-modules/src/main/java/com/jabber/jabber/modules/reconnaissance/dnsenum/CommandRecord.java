package com.jabber.jabber.modules.reconnaissance.dnsenum;

import java.util.*;

public record CommandRecord(
    String toolId,
    List<String> command,
    int exitCode,
    String stdout,
    String stderr,
    long durationMs
) {
    public static CommandRecord timeout(String toolId, List<String> cmd, long ms) {
        return new CommandRecord(toolId, cmd, -1, "", "Execution timed out", ms);
    }
    public static CommandRecord error(String toolId, List<String> cmd, String err, long ms) {
        return new CommandRecord(toolId, cmd, -1, "", err, ms);
    }
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("toolId", toolId);
        m.put("command", String.join(" ", command));
        m.put("exitCode", exitCode);
        m.put("durationMs", durationMs);
        m.put("stdout_len", stdout.length());
        m.put("stderr_len", stderr.length());
        return m;
    }
}
