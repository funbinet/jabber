package com.jabber.jabber.core.terminal;

import com.google.gson.Gson;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

@Component
public class TerminalWebsocketHandler extends TextWebSocketHandler {

    private final PtyProcessManager ptyProcessManager;
    private final Gson gson = new Gson();

    // Per-session tracking
    private static class SessionGroup {
        String terminalSessionId;
        CopyOnWriteArrayList<WebSocketSession> webSessions = new CopyOnWriteArrayList<>();
        Thread outputReaderThread;
    }

    private final Map<String, SessionGroup> sessionGroups = new HashMap<>();
    private final Object sessionGroupsLock = new Object();

    @Autowired
    public TerminalWebsocketHandler(PtyProcessManager ptyProcessManager) {
        this.ptyProcessManager = ptyProcessManager;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        // Extract terminal session ID from query params (or create one)
        String terminalSessionId = getTerminalSessionIdFromQuery(session);
        if (terminalSessionId == null) {
            System.err.println("[TERMINAL] ERROR: No sessionId in query params, creating new session (session will not persist)");
            terminalSessionId = ptyProcessManager.createNewSession();
        }

        SessionGroup group;
        synchronized (sessionGroupsLock) {
            group = sessionGroups.computeIfAbsent(terminalSessionId, k -> {
                SessionGroup sg = new SessionGroup();
                sg.terminalSessionId = k;
                return sg;
            });
            group.webSessions.add(session);
        }

        // Start the PTY process for this session if not already running
        if (!ptyProcessManager.isProcessRunning(terminalSessionId)) {
            ptyProcessManager.startProcess(terminalSessionId);
        }

        // Send historical scrollback to the new web session
        String scrollback = ptyProcessManager.getScrollback(terminalSessionId);
        if (scrollback != null && !scrollback.isEmpty()) {
            session.sendMessage(new TextMessage(scrollback));
        }

        // Start output reader if not already running for this session
        if (group.outputReaderThread == null || !group.outputReaderThread.isAlive()) {
            startOutputReaderForSession(terminalSessionId, group);
        }

        // Store the terminal session ID in the web session attributes for later lookup
        session.getAttributes().put("terminalSessionId", terminalSessionId);
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        String terminalSessionId = (String) session.getAttributes().get("terminalSessionId");
        if (terminalSessionId == null) {
            return; // Invalid session state
        }

        String payload = message.getPayload();

        // Check if it's a resize command
        int resizeIdx = payload.indexOf("\"type\":\"resize\"");
        if (resizeIdx >= 0) {
            try {
                Map<String, Object> resizeData = gson.fromJson(payload, Map.class);
                if (resizeData.containsKey("cols") && resizeData.containsKey("rows")) {
                    int cols = ((Double) resizeData.get("cols")).intValue();
                    int rows = ((Double) resizeData.get("rows")).intValue();
                    ptyProcessManager.resizeWindow(terminalSessionId, cols, rows);
                }
            } catch (Exception e) {
                // Ignore JSON parse errors
            }
            return;
        }

        // Otherwise write to PTY for this session
        ptyProcessManager.writeToProcess(terminalSessionId, payload);
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
        String terminalSessionId = (String) session.getAttributes().get("terminalSessionId");
        if (terminalSessionId == null) {
            return;
        }

        synchronized (sessionGroupsLock) {
            SessionGroup group = sessionGroups.get(terminalSessionId);
            if (group != null) {
                group.webSessions.remove(session);
                // If no more web sessions for this terminal session, optionally clean up
                // (For now we keep the PTY alive for potential reconnect)
            }
        }
    }

    private String getTerminalSessionIdFromQuery(WebSocketSession session) {
        String uri = session.getUri() != null ? session.getUri().toString() : "";
        int idx = uri.indexOf("sessionId=");
        if (idx >= 0) {
            int endIdx = uri.indexOf("&", idx);
            if (endIdx < 0) endIdx = uri.length();
            String sessionId = uri.substring(idx + 10, endIdx);
            System.out.println("[TERMINAL] Session ID extracted from query: " + sessionId);
            return sessionId;
        }
        System.err.println("[TERMINAL] WARNING: No sessionId parameter found in URI: " + uri);
        return null;
    }

    private void startOutputReaderForSession(String terminalSessionId, SessionGroup group) {
        group.outputReaderThread = new Thread(() -> {
            try {
                InputStream is = ptyProcessManager.getInputStream(terminalSessionId);
                if (is == null) return;

                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    if (bytesRead > 0) {
                        String text = new String(buffer, 0, bytesRead, "UTF-8");
                        ptyProcessManager.appendScrollback(terminalSessionId, text);

                        TextMessage tm = new TextMessage(text);
                        for (WebSocketSession s : group.webSessions) {
                            if (s.isOpen()) {
                                synchronized (s) {
                                    s.sendMessage(tm);
                                }
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // Session or stream closed
            }
        });
        group.outputReaderThread.setDaemon(true);
        group.outputReaderThread.start();
    }
}
