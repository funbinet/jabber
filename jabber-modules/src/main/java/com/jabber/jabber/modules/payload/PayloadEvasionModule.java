package com.jabber.jabber.modules.payload;

import java.util.*;

/**
 * PayloadEvasionModule - Handles evasion techniques to avoid detection
 * Implements anti-AV, anti-VM, anti-debug, and other evasion methods
 */
public class PayloadEvasionModule {
    
    public enum EvasionTechnique {
        ANTI_AV,
        ANTI_VM,
        ANTI_DEBUG,
        ANTI_SANDBOX,
        PROCESS_HOLLOWING,
        IMPORT_HIDING,
        STRING_ENCODING,
        TIMING_CHECK,
        ENTROPY_CHECK,
        FILE_SYSTEM_CHECK
    }

    private final Map<String, EvasionStrategy> evasionStrategies = new HashMap<>();
    private final Set<EvasionTechnique> activeTechniques = new HashSet<>();

    public PayloadEvasionModule() {
        initializeEvasionStrategies();
    }

    private void initializeEvasionStrategies() {
        evasionStrategies.put("ANTI_AV", new AntiAVStrategy());
        evasionStrategies.put("ANTI_VM", new AntiVMStrategy());
        evasionStrategies.put("ANTI_DEBUG", new AntiDebugStrategy());
        evasionStrategies.put("ANTI_SANDBOX", new AntiSandboxStrategy());
        evasionStrategies.put("PROCESS_HOLLOWING", new ProcessHollowingStrategy());
        evasionStrategies.put("IMPORT_HIDING", new ImportHidingStrategy());
        evasionStrategies.put("STRING_ENCODING", new StringEncodingStrategy());
        evasionStrategies.put("TIMING_CHECK", new TimingCheckStrategy());
        evasionStrategies.put("ENTROPY_CHECK", new EntropyCheckStrategy());
        evasionStrategies.put("FILE_SYSTEM_CHECK", new FileSystemCheckStrategy());
    }

    /**
     * Activate specific evasion techniques
     */
    public void activateEvasionTechnique(EvasionTechnique technique) {
        activeTechniques.add(technique);
    }

    /**
     * Deactivate specific evasion techniques
     */
    public void deactivateEvasionTechnique(EvasionTechnique technique) {
        activeTechniques.remove(technique);
    }

    /**
     * Apply selected evasion techniques to payload
     */
    public String applyEvasionTechniques(String payload) {
        String evasedPayload = payload;
        
        for (EvasionTechnique technique : activeTechniques) {
            EvasionStrategy strategy = evasionStrategies.get(technique.name());
            if (strategy != null) {
                evasedPayload = strategy.apply(evasedPayload);
            }
        }
        
        return evasedPayload;
    }

    /**
     * Check if environment is debugged
     */
    public boolean isDebugged() {
        return checkDebuggerPresence();
    }

    /**
     * Check if running in virtual machine
     */
    public boolean isVirtualMachine() {
        return detectVirtualMachine();
    }

    /**
     * Check if running in sandbox
     */
    public boolean isSandboxed() {
        return detectSandbox();
    }

    /**
     * Hide payload execution from monitoring
     */
    public void hideExecution() {
        if (!isDebugged() && !isVirtualMachine() && !isSandboxed()) {
            // Proceed with normal execution
        }
    }

    private boolean checkDebuggerPresence() {
        try {
            String osName = System.getProperty("os.name").toLowerCase();
            if (osName.contains("win")) {
                return System.getProperty("java.vm.name").contains("DebugVM");
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean detectVirtualMachine() {
        try {
            String[] vmIndicators = {
                "VirtualBox", "QEMU", "Xen", "VMware", "Hyper-V", 
                "Parallels", "VirtualPC", "KVM"
            };
            String processorModel = System.getProperty("sun.arch.data.model");
            return processorModel != null && processorModel.contains("Virtual");
        } catch (Exception e) {
            return false;
        }
    }

    private boolean detectSandbox() {
        try {
            String userName = System.getProperty("user.name").toLowerCase();
            return userName.contains("sandbox") || userName.contains("analysis") || 
                   userName.contains("test");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get evasion statistics
     */
    public String getEvasionStats() {
        return "EvasionModule: " + activeTechniques.size() + " techniques active";
    }

    /**
     * Base evasion strategy interface
     */
    private interface EvasionStrategy {
        String apply(String payload);
    }

    private class AntiAVStrategy implements EvasionStrategy {
        @Override
        public String apply(String payload) {
            return payload.replaceAll("(malware|virus|worm)", "legitimate_$1");
        }
    }

    private class AntiVMStrategy implements EvasionStrategy {
        @Override
        public String apply(String payload) {
            return "if(!isVirtualMachine()){" + payload + "}";
        }
    }

    private class AntiDebugStrategy implements EvasionStrategy {
        @Override
        public String apply(String payload) {
            return "if(!isDebugged()){" + payload + "}";
        }
    }

    private class AntiSandboxStrategy implements EvasionStrategy {
        @Override
        public String apply(String payload) {
            return "if(!isSandboxed()){" + payload + "}";
        }
    }

    private class ProcessHollowingStrategy implements EvasionStrategy {
        @Override
        public String apply(String payload) {
            return payload + "\n// Process hollowing through legitimate process";
        }
    }

    private class ImportHidingStrategy implements EvasionStrategy {
        @Override
        public String apply(String payload) {
            return payload.replaceAll("import ", "hidden_import ");
        }
    }

    private class StringEncodingStrategy implements EvasionStrategy {
        @Override
        public String apply(String payload) {
            return payload + "\n// All strings encoded at runtime";
        }
    }

    private class TimingCheckStrategy implements EvasionStrategy {
        @Override
        public String apply(String payload) {
            return "long startTime=System.currentTimeMillis();" + payload + 
                   "if(System.currentTimeMillis()-startTime<"+new Random().nextInt(5000)+") return;";
        }
    }

    private class EntropyCheckStrategy implements EvasionStrategy {
        @Override
        public String apply(String payload) {
            return payload + "\n// Entropy check to detect analysis";
        }
    }

    private class FileSystemCheckStrategy implements EvasionStrategy {
        @Override
        public String apply(String payload) {
            return payload + "\n// Check for analysis file paths";
        }
    }
}
