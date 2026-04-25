package com.jabber.jrts.modules.phoneenum;

import com.jabber.jrts.data.model.Category;
import com.jabber.jrts.data.model.JRTSModuleInterface;
import com.jabber.jrts.data.model.ModuleInputField;
import com.jabber.jrts.data.model.ModuleResult;
import com.jabber.jrts.data.model.TaskContext;
import com.jabber.jrts.data.model.JRTSModule;
import com.jabber.jrts.data.model.RiskLevel;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@JRTSModule(
    id = "phone-enum-android",
    name = "Android Device Enumeration",
    description = "Operational ADB-based enumeration and extraction for Android devices.",
    category = Category.PHONE_ENUMERATION,
    riskLevel = RiskLevel.HIGH,
    sourceRef = "Android Debug Bridge (ADB)",
    author = "JRTS"
)
public class AndroidEnumerationModule implements JRTSModuleInterface {

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.text("action", "Action"),
            ModuleInputField.text("device_id", "Target Device ID"),
            ModuleInputField.text("param", "Parameter")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> inputs, TaskContext context) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(context.getTaskId(), "phone-enum-android");
            String action = inputs.getOrDefault("action", "discover");
            String deviceId = inputs.getOrDefault("device_id", "");
            String param = inputs.getOrDefault("param", "");

            context.log("[*] Executing Android Action: " + action);

            try {
                if ("discover".equals(action)) {
                    executeDeviceDiscovery(result, context);
                } else {
                    if (deviceId.isBlank()) {
                        throw new IllegalArgumentException("Target Device ID is required for operational actions.");
                    }
                    executeAction(action, deviceId, param, result, context);
                }
            } catch (Exception e) {
                context.log("[!] Execution failed: " + e.getMessage());
                result.fail(e.getMessage());
            }

            return result;
        });
    }

    private void executeDeviceDiscovery(ModuleResult result, TaskContext ctx) throws Exception {
        Map<String, Object> cmdResult = runCommand(new String[]{"adb", "devices", "-l"}, ctx);
        String output = (String) cmdResult.get("stdout");
        
        List<Map<String, String>> devices = new ArrayList<>();
        String[] lines = output.split("\n");
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("List of devices") || line.startsWith("* daemon")) continue;
            
            // Format: `serial device product:model model:device device:hardware transport_id:1`
            String[] parts = line.split("\\s+", 2);
            if (parts.length >= 2) {
                String id = parts[0];
                String details = parts[1];
                String state = details.split("\\s+")[0]; // "device", "unauthorized", "offline"

                Map<String, String> dev = new LinkedHashMap<>();
                dev.put("id", id);
                dev.put("state", state);
                dev.put("model", extractDetail(details, "model:"));
                dev.put("product", extractDetail(details, "product:"));
                dev.put("transport", extractDetail(details, "transport_id:"));
                devices.add(dev);
            }
        }
        
        Map<String, Object> outMap = new LinkedHashMap<>();
        outMap.put("action", "discover");
        outMap.put("devices", devices);
        result.complete(outMap);
        ctx.log("[+] Discovered " + devices.size() + " connected ADB devices");
    }

    private String extractDetail(String line, String key) {
        int idx = line.indexOf(key);
        if (idx == -1) return "Unknown";
        int start = idx + key.length();
        int end = line.indexOf(" ", start);
        if (end == -1) end = line.length();
        return line.substring(start, end).trim();
    }

    private void executeAction(String action, String devId, String param, ModuleResult result, TaskContext ctx) throws Exception {
        String artifactDir = System.getProperty("user.dir") + "/reports/artifacts/" + ctx.getTaskId();
        new File(artifactDir).mkdirs();

        String[] cmd = null;
        boolean isPull = false;
        String pullDest = "";

        switch (action) {
            // A) Device Control
            case "shell_whoami": cmd = new String[]{"adb", "-s", devId, "shell", "whoami"}; break;

            // B) Screenshots & Interaction
            case "screenshot":
                runCommand(new String[]{"adb", "-s", devId, "shell", "screencap", "-p", "/sdcard/screen.png"}, ctx);
                cmd = new String[]{"adb", "-s", devId, "pull", "/sdcard/screen.png", artifactDir + "/screen.png"};
                isPull = true; pullDest = artifactDir + "/screen.png";
                break;
            case "record_screen":
                // Normally blocking, we will just record for 5 seconds for demonstration then pull.
                ctx.log("[~] Recording screen for 5 seconds...");
                runCommand(new String[]{"/bin/sh", "-c", "timeout 5 adb -s " + devId + " shell screenrecord --time-limit 5 /sdcard/record.mp4 || true"}, ctx);
                cmd = new String[]{"adb", "-s", devId, "pull", "/sdcard/record.mp4", artifactDir + "/record.mp4"};
                isPull = true; pullDest = artifactDir + "/record.mp4";
                break;

            // C) File Extraction
            case "pull_sdcard":
                cmd = new String[]{"adb", "-s", devId, "pull", "/sdcard/", artifactDir + "/"};
                isPull = true; pullDest = artifactDir + "/sdcard";
                break;
            case "pull_downloads":
                cmd = new String[]{"adb", "-s", devId, "pull", "/sdcard/Download/", artifactDir + "/"};
                isPull = true; pullDest = artifactDir + "/Download";
                break;
            case "pull_app_data":
                cmd = new String[]{"adb", "-s", devId, "pull", "/data/data/", artifactDir + "/"};
                isPull = true; pullDest = artifactDir + "/data";
                break;
            case "pull_file":
                if (param.isBlank()) throw new IllegalArgumentException("Remote file path parameter required.");
                String fName = param.substring(param.lastIndexOf('/') + 1);
                cmd = new String[]{"adb", "-s", devId, "pull", param, artifactDir + "/" + fName};
                isPull = true; pullDest = artifactDir + "/" + fName;
                break;

            // D) Logs
            case "logcat_dump": cmd = new String[]{"adb", "-s", devId, "logcat", "-d"}; break;
            case "logcat_filter":
                if (param.isBlank()) throw new IllegalArgumentException("Keyword parameter required.");
                cmd = new String[]{"/bin/sh", "-c", "adb -s " + devId + " logcat -d | grep -i '" + param.replace("'", "") + "'"}; break;
            case "crash_logs":
                cmd = new String[]{"/bin/sh", "-c", "adb -s " + devId + " logcat -d | grep -i 'fatal'"}; break;
            case "dumpsys": cmd = new String[]{"adb", "-s", devId, "shell", "dumpsys"}; break;
            case "running_activities": cmd = new String[]{"adb", "-s", devId, "shell", "dumpsys", "activity"}; break;

            // E) Accounts
            case "dump_accounts": cmd = new String[]{"adb", "-s", devId, "shell", "dumpsys", "account"}; break;
            case "extract_emails":
                cmd = new String[]{"/bin/sh", "-c", "adb -s " + devId + " shell dumpsys account | grep -aE -o '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b' | sort -u"}; break;

            // F) Content Providers
            case "contacts": cmd = new String[]{"adb", "-s", devId, "shell", "content", "query", "--uri", "content://contacts/phones/"}; break;
            case "call_logs": cmd = new String[]{"adb", "-s", devId, "shell", "content", "query", "--uri", "content://call_log/calls"}; break;
            case "sms": cmd = new String[]{"adb", "-s", devId, "shell", "content", "query", "--uri", "content://sms/"}; break;

            // G) App Recon
            case "list_apps": cmd = new String[]{"adb", "-s", devId, "shell", "pm", "list", "packages"}; break;
            case "list_third_party": cmd = new String[]{"adb", "-s", devId, "shell", "pm", "list", "packages", "-3"}; break;
            case "app_path":
                if (param.isBlank()) throw new IllegalArgumentException("Package name parameter required.");
                cmd = new String[]{"adb", "-s", devId, "shell", "pm", "path", param}; break;
            case "pull_apk":
                if (param.isBlank()) throw new IllegalArgumentException("Package name parameter required.");
                // We must query path first to get the actual remote base.apk path
                Map<String, Object> pResult = runCommand(new String[]{"adb", "-s", devId, "shell", "pm", "path", param}, ctx);
                String apkPath = ((String) pResult.get("stdout")).replace("package:", "").trim();
                if (apkPath.isEmpty()) throw new IllegalArgumentException("App not found.");
                cmd = new String[]{"adb", "-s", devId, "pull", apkPath, artifactDir + "/" + param + ".apk"};
                isPull = true; pullDest = artifactDir + "/" + param + ".apk";
                break;
            case "dump_app_info":
                if (param.isBlank()) throw new IllegalArgumentException("Package name parameter required.");
                cmd = new String[]{"adb", "-s", devId, "shell", "dumpsys", "package", param}; break;

            // H) Secrets
            case "search_config_files":
                cmd = new String[]{"adb", "-s", devId, "shell", "find", "/sdcard/", "-type", "f", "\\(", "-name", "\"*.env\"", "-o", "-name", "\"*.json\"", "-o", "-name", "\"*.xml\"", "\\)"}; break;
            case "grep_secrets":
                cmd = new String[]{"adb", "-s", devId, "shell", "grep", "-r", "\"token\\|api_key\\|password\"", "/sdcard/"}; break;

            // I) Network
            case "ip_addr": cmd = new String[]{"adb", "-s", devId, "shell", "ip", "addr"}; break;
            case "netstat": cmd = new String[]{"adb", "-s", devId, "shell", "netstat", "-tuln"}; break;
            case "wifi_info": cmd = new String[]{"adb", "-s", devId, "shell", "dumpsys", "wifi"}; break;
            
            default:
                throw new IllegalArgumentException("Unknown operational action: " + action);
        }

        Map<String, Object> cmdResult = runCommand(cmd, ctx);
        String stdout = (String) cmdResult.get("stdout");
        String stderr = (String) cmdResult.get("stderr");

        Map<String, Object> outMap = new LinkedHashMap<>();
        outMap.put("action", action);
        outMap.put("device_id", devId);
        
        if (isPull) {
            outMap.put("status", "Artifact extracted successfully");
            outMap.put("artifact_path", pullDest);
            ctx.log("[+] Extraction saved to: " + pullDest);
            // Append finding artifact
            Map<String, Object> finding = new LinkedHashMap<>();
            finding.put("type", "extracted_artifact");
            finding.put("title", action.replace("_", " ").toUpperCase() + " Artifact");
            finding.put("description", "File extraction workflow completed successfully.");
            finding.put("evidence", pullDest);
            finding.put("severity", "medium");
            result.getFindings().add(finding);
        } else {
            outMap.put("stdout_length", stdout.length());
            outMap.put("output_sample", stdout.length() > 2000 ? stdout.substring(0, 2000) + "... [truncated]" : stdout);
            
            Map<String, Object> finding = new LinkedHashMap<>();
            finding.put("type", "enumerated_data");
            finding.put("title", action.replace("_", " ").toUpperCase() + " Output");
            finding.put("description", "Command executed and data returned.");
            finding.put("evidence", stdout.length() > 5000 ? stdout.substring(0, 5000) + "... [truncated]" : stdout);
            finding.put("severity", "low");
            result.getFindings().add(finding);
        }

        if (!stderr.isBlank()) {
            outMap.put("errors", stderr);
            ctx.log("[!] Stderr during execution: " + stderr);
        }

        result.complete(outMap);
    }

    private Map<String, Object> runCommand(String[] cmd, TaskContext ctx) throws Exception {
        ctx.log("[*] Executing: " + String.join(" ", cmd));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        long start = System.currentTimeMillis();
        Process p = pb.start();

        StringBuilder outStr = new StringBuilder();
        StringBuilder errStr = new StringBuilder();
        
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                outStr.append(line).append("\n");
            }
        }
        
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getErrorStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                errStr.append(line).append("\n");
            }
        }

        int exitCode = p.waitFor();
        long duration = System.currentTimeMillis() - start;

        Map<String, Object> res = new LinkedHashMap<>();
        res.put("stdout", outStr.toString().trim());
        res.put("stderr", errStr.toString().trim());
        res.put("exit_code", exitCode);
        res.put("duration_ms", duration);
        res.put("tool", "adb");
        res.put("command", String.join(" ", cmd));
        
        return res;
    }

    @Override
    public void cleanup() {
        // No heavy allocations
    }
}
