package com.jabber.jabber.core.terminal;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class PtyProcessManager {

    private static class SessionState {
        final String sessionId;
        Process process;
        final StringBuilder scrollbackBuffer = new StringBuilder();
        final StringBuilder commandLineBuffer = new StringBuilder();
        final Deque<String> commandHistory = new ArrayDeque<>();
        Path currentWorkingDirectory = Paths.get(System.getProperty("user.home")).toAbsolutePath().normalize();
        Path previousWorkingDirectory = currentWorkingDirectory;
        volatile boolean isRunning = false;
        long createdAtMs = System.currentTimeMillis();

        SessionState(String sessionId) {
            this.sessionId = sessionId;
        }
    }

    private final Map<String, SessionState> sessions = new HashMap<>();
    private final Object sessionsLock = new Object();

    public String createNewSession() {
        String sessionId = UUID.randomUUID().toString();
        SessionState state = new SessionState(sessionId);
        synchronized (sessionsLock) {
            sessions.put(sessionId, state);
        }
        return sessionId;
    }

    public void destroySession(String sessionId) {
        SessionState state;
        synchronized (sessionsLock) {
            state = sessions.remove(sessionId);
        }
        if (state != null) {
            destroyProcessInternal(state);
        }
    }

    private SessionState getSessionOrDefault(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            sessionId = "default";
        }
        final String finalSessionId = sessionId;
        synchronized (sessionsLock) {
            return sessions.computeIfAbsent(finalSessionId, k -> new SessionState(k));
        }
    }

    public synchronized void startProcess() throws IOException {
        startProcess("default");
    }

    public synchronized void startProcess(String sessionId) throws IOException {
        SessionState state = getSessionOrDefault(sessionId);
        synchronized (sessionsLock) {
            if (state.isRunning && state.process != null && state.process.isAlive()) {
                return;
            }

            if (!Files.isDirectory(state.currentWorkingDirectory)) {
                state.currentWorkingDirectory = Paths.get(System.getProperty("user.home")).toAbsolutePath().normalize();
                state.previousWorkingDirectory = state.currentWorkingDirectory;
            }

            // Spawn bash inside 'script' to emulate a real PTY
            ProcessBuilder builder = new ProcessBuilder("script", "-q", "-c", "/bin/bash", "/dev/null");
            Map<String, String> envs = builder.environment();
            envs.put("TERM", "xterm-256color");
            builder.directory(state.currentWorkingDirectory.toFile());
            builder.redirectErrorStream(true);

            state.process = builder.start();
            state.isRunning = true;
        }
    }

    public synchronized void writeToProcess(String input) throws IOException {
        writeToProcess("default", input);
    }

    public synchronized void writeToProcess(String sessionId, String input) throws IOException {
        SessionState state = getSessionOrDefault(sessionId);
        synchronized (sessionsLock) {
            if (state.process != null && state.process.getOutputStream() != null) {
                captureCommandInput(state, input);
                OutputStream os = state.process.getOutputStream();
                os.write(input.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }
        }
    }

    public InputStream getInputStream() {
        return getInputStream("default");
    }

    public InputStream getInputStream(String sessionId) {
        SessionState state = getSessionOrDefault(sessionId);
        synchronized (sessionsLock) {
            if (state.process != null) {
                return state.process.getInputStream();
            }
        }
        return null;
    }

    public synchronized void appendScrollback(String data) {
        appendScrollback("default", data);
    }

    public synchronized void appendScrollback(String sessionId, String data) {
        SessionState state = getSessionOrDefault(sessionId);
        synchronized (sessionsLock) {
            state.scrollbackBuffer.append(data);
            if (state.scrollbackBuffer.length() > 500000) {
                state.scrollbackBuffer.delete(0, 100000);
            }
        }
    }

    public synchronized String getScrollback() {
        return getScrollback("default");
    }

    public synchronized String getScrollback(String sessionId) {
        SessionState state = getSessionOrDefault(sessionId);
        synchronized (sessionsLock) {
            return state.scrollbackBuffer.toString();
        }
    }

    public synchronized List<String> getCommandHistorySnapshot() {
        return getCommandHistorySnapshot("default");
    }

    public synchronized List<String> getCommandHistorySnapshot(String sessionId) {
        SessionState state = getSessionOrDefault(sessionId);
        synchronized (sessionsLock) {
            return new ArrayList<>(state.commandHistory);
        }
    }

    public synchronized String getCurrentWorkingDirectory() {
        return getCurrentWorkingDirectory("default");
    }

    public synchronized String getCurrentWorkingDirectory(String sessionId) {
        SessionState state = getSessionOrDefault(sessionId);
        synchronized (sessionsLock) {
            return state.currentWorkingDirectory.toString();
        }
    }

    public synchronized boolean isProcessRunning() {
        return isProcessRunning("default");
    }

    public synchronized boolean isProcessRunning(String sessionId) {
        SessionState state = getSessionOrDefault(sessionId);
        synchronized (sessionsLock) {
            return state.process != null && state.process.isAlive();
        }
    }

    public synchronized void clearScrollback() {
        clearScrollback("default");
    }

    public synchronized void clearScrollback(String sessionId) {
        SessionState state = getSessionOrDefault(sessionId);
        synchronized (sessionsLock) {
            state.scrollbackBuffer.setLength(0);
        }
    }

    public void resizeWindow(int cols, int rows) {
        resizeWindow("default", cols, rows);
    }

    public void resizeWindow(String sessionId, int cols, int rows) {
        SessionState state = getSessionOrDefault(sessionId);
        synchronized (sessionsLock) {
            if (state.process != null && state.process.isAlive()) {
                try {
                    String sttyCmd = String.format("stty cols %d rows %d\r", cols, rows);
                    writeToProcess(sessionId, sttyCmd);
                } catch (IOException e) {
                    // Ignore
                }
            }
        }
    }

    public synchronized void destroyProcess() {
        destroyProcess("default");
    }

    public synchronized void destroyProcess(String sessionId) {
        SessionState state = getSessionOrDefault(sessionId);
        synchronized (sessionsLock) {
            destroyProcessInternal(state);
        }
    }

    private void destroyProcessInternal(SessionState state) {
        if (state.process != null) {
            state.process.destroy();
            state.process = null;
        }
        state.isRunning = false;
        state.scrollbackBuffer.setLength(0);
        state.commandLineBuffer.setLength(0);
        state.commandHistory.clear();
        state.currentWorkingDirectory = Paths.get(System.getProperty("user.home")).toAbsolutePath().normalize();
        state.previousWorkingDirectory = state.currentWorkingDirectory;
    }

    private void captureCommandInput(SessionState state, String input) {
        if (input == null || input.isEmpty()) {
            return;
        }

        // Ignore control-sequence payloads such as arrow-key terminal escape sequences.
        if (input.indexOf('\u001b') >= 0) {
            return;
        }

        for (int index = 0; index < input.length(); index++) {
            char character = input.charAt(index);

            if (character == '\r' || character == '\n') {
                flushCommandBuffer(state);
                continue;
            }

            if (character == '\b' || character == 127) {
                if (state.commandLineBuffer.length() > 0) {
                    state.commandLineBuffer.deleteCharAt(state.commandLineBuffer.length() - 1);
                }
                continue;
            }

            if (!Character.isISOControl(character)) {
                state.commandLineBuffer.append(character);
            }
        }
    }

    private void flushCommandBuffer(SessionState state) {
        String command = state.commandLineBuffer.toString().trim();
        state.commandLineBuffer.setLength(0);

        if (command.isEmpty()) {
            return;
        }

        if (state.commandHistory.size() >= 200) {
            state.commandHistory.removeFirst();
        }
        state.commandHistory.addLast(command);

        updateWorkingDirectoryFromCommand(state, command);
    }

    private void updateWorkingDirectoryFromCommand(SessionState state, String command) {
        String normalized = command.trim();
        if (!(normalized.equals("cd") || normalized.startsWith("cd ") || normalized.startsWith("cd\t"))) {
            return;
        }

        if (normalized.contains("&&") || normalized.contains(";") || normalized.contains("|")) {
            return;
        }

        String argument = normalized.length() > 2 ? normalized.substring(2).trim() : "";
        Path nextPath;

        if (argument.isEmpty() || "~".equals(argument)) {
            nextPath = Paths.get(System.getProperty("user.home")).toAbsolutePath().normalize();
        } else if ("-".equals(argument)) {
            nextPath = state.previousWorkingDirectory;
        } else {
            String unquoted = argument;
            if ((unquoted.startsWith("\"") && unquoted.endsWith("\""))
                || (unquoted.startsWith("'") && unquoted.endsWith("'"))) {
                unquoted = unquoted.substring(1, unquoted.length() - 1);
            }

            if (unquoted.startsWith("~/")) {
                Path home = Paths.get(System.getProperty("user.home")).toAbsolutePath().normalize();
                nextPath = home.resolve(unquoted.substring(2));
            } else {
                Path maybeRelative = Paths.get(unquoted);
                nextPath = maybeRelative.isAbsolute()
                    ? maybeRelative
                    : state.currentWorkingDirectory.resolve(maybeRelative);
            }
        }

        if (nextPath != null && Files.isDirectory(nextPath)) {
            state.previousWorkingDirectory = state.currentWorkingDirectory;
            state.currentWorkingDirectory = nextPath;
        }
    }
}
