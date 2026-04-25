package com.jabber.jrts.core.terminal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/terminal")
public class TerminalController {

    private final PtyProcessManager ptyProcessManager;

    @Autowired
    public TerminalController(PtyProcessManager ptyProcessManager) {
        this.ptyProcessManager = ptyProcessManager;
    }

    @PostMapping("/kill")
    public ResponseEntity<?> killTerminal(@RequestParam(value = "sessionId", required = false) String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            ptyProcessManager.destroyProcess();
            return ResponseEntity.ok(Map.of(
                "status", "destroyed",
                "processRunning", ptyProcessManager.isProcessRunning(),
                "workingDirectory", ptyProcessManager.getCurrentWorkingDirectory(),
                "historyCount", ptyProcessManager.getCommandHistorySnapshot().size()
            ));
        }
        ptyProcessManager.destroyProcess(sessionId);
        return ResponseEntity.ok(Map.of(
            "status", "destroyed",
            "processRunning", ptyProcessManager.isProcessRunning(sessionId),
            "workingDirectory", ptyProcessManager.getCurrentWorkingDirectory(sessionId),
            "historyCount", ptyProcessManager.getCommandHistorySnapshot(sessionId).size()
        ));
    }

    @PostMapping("/clear")
    public ResponseEntity<?> clearTerminal(@RequestParam(value = "sessionId", required = false) String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            ptyProcessManager.clearScrollback();
            return ResponseEntity.ok(Map.of(
                "status", "cleared",
                "processRunning", ptyProcessManager.isProcessRunning(),
                "workingDirectory", ptyProcessManager.getCurrentWorkingDirectory(),
                "historyCount", ptyProcessManager.getCommandHistorySnapshot().size()
            ));
        }
        ptyProcessManager.clearScrollback(sessionId);
        return ResponseEntity.ok(Map.of(
            "status", "cleared",
            "processRunning", ptyProcessManager.isProcessRunning(sessionId),
            "workingDirectory", ptyProcessManager.getCurrentWorkingDirectory(sessionId),
            "historyCount", ptyProcessManager.getCommandHistorySnapshot(sessionId).size()
        ));
    }

    @PostMapping("/export")
    public ResponseEntity<?> exportTerminal(@RequestParam(value = "sessionId", required = false) String sessionId) {
        String scrollback;
        List<String> commandHistory;
        String workingDir;

        if (sessionId == null || sessionId.isBlank()) {
            scrollback = ptyProcessManager.getScrollback();
            commandHistory = ptyProcessManager.getCommandHistorySnapshot();
            workingDir = ptyProcessManager.getCurrentWorkingDirectory();
        } else {
            scrollback = ptyProcessManager.getScrollback(sessionId);
            commandHistory = ptyProcessManager.getCommandHistorySnapshot(sessionId);
            workingDir = ptyProcessManager.getCurrentWorkingDirectory(sessionId);
        }

        if ((scrollback == null || scrollback.isBlank()) && commandHistory.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Buffer is empty"));
        }

        try {
            Path dir = Paths.get(System.getProperty("user.dir"), "reports", "terminal_sessions");
            Files.createDirectories(dir);

            ZonedDateTime exportedAt = ZonedDateTime.now(ZoneOffset.UTC);
            String timestampForFilename = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss_SSS").format(exportedAt);
            String filename = "terminal_session_" + timestampForFilename + ".log";
            Path file = dir.resolve(filename);

            String formattedSession = buildStructuredSessionLog(exportedAt, commandHistory, scrollback, workingDir);
            Files.writeString(file, formattedSession);

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("status", "success");
            payload.put("file", file.toString());
            payload.put("exportedAtUtc", exportedAt.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
            payload.put("workingDirectory", workingDir);
            payload.put("historyCount", commandHistory.size());
            return ResponseEntity.ok(payload);
        } catch (IOException e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/state")
    public ResponseEntity<?> terminalState(@RequestParam(value = "sessionId", required = false) String sessionId) {
        List<String> commandHistory;
        String workingDir;
        boolean running;

        if (sessionId == null || sessionId.isBlank()) {
            commandHistory = ptyProcessManager.getCommandHistorySnapshot();
            workingDir = ptyProcessManager.getCurrentWorkingDirectory();
            running = ptyProcessManager.isProcessRunning();
        } else {
            commandHistory = ptyProcessManager.getCommandHistorySnapshot(sessionId);
            workingDir = ptyProcessManager.getCurrentWorkingDirectory(sessionId);
            running = ptyProcessManager.isProcessRunning(sessionId);
        }

        return ResponseEntity.ok(Map.of(
            "workingDirectory", workingDir,
            "historyCount", commandHistory.size(),
            "processRunning", running
        ));
    }

    private String buildStructuredSessionLog(ZonedDateTime exportedAt, List<String> commandHistory, String scrollback, String workingDir) {
        StringBuilder builder = new StringBuilder();
        builder.append("# JRTS Terminal Session").append('\n');
        builder.append("exported_at_utc: ")
            .append(exportedAt.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME))
            .append('\n');
        builder.append("working_directory: ")
            .append(workingDir)
            .append('\n');
        builder.append("process_running: ")
            .append(ptyProcessManager.isProcessRunning())
            .append('\n');
        builder.append("command_count: ")
            .append(commandHistory.size())
            .append('\n');
        builder.append('\n');

        builder.append("[commands]").append('\n');
        for (int index = 0; index < commandHistory.size(); index++) {
            builder.append(index + 1)
                .append(": ")
                .append(commandHistory.get(index))
                .append('\n');
        }
        builder.append('\n');

        builder.append("[output]").append('\n');
        if (scrollback != null) {
            builder.append(scrollback);
            if (!scrollback.endsWith("\n")) {
                builder.append('\n');
            }
        }

        return builder.toString();
    }
}
