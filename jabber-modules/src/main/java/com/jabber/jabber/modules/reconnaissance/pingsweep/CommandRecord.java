package com.jabber.jabber.modules.reconnaissance.pingsweep;

import java.util.List;

/**
 * CommandRecord — Telemetry record for tool executions.
 */
public record CommandRecord(
    String toolId,
    List<String> command,
    int exitCode,
    String stdout,
    String stderr,
    long durationMs
) {}
