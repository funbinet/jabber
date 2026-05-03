package com.jabber.jabber.modules.phoneenum;

import com.jabber.jabber.data.model.Category;
import com.jabber.jabber.data.model.JABBERModuleInterface;
import com.jabber.jabber.data.model.ModuleInputField;
import com.jabber.jabber.data.model.ModuleResult;
import com.jabber.jabber.data.model.TaskContext;
import com.jabber.jabber.data.model.JABBERModule;
import com.jabber.jabber.data.model.RiskLevel;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@JABBERModule(
    id = "phone-enum-ios",
    name = "iOS Device Enumeration",
    description = "Extract iOS device info, apps, logs, files, and runtime data via trusted tools and backups.",
    category = Category.PHONE_ENUMERATION,
    riskLevel = RiskLevel.HIGH,
    sourceRef = "libimobiledevice / idevicebackup2",
    author = "JABBER"
)
public class iOSEnumerationModule implements JABBERModuleInterface {

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
            ModuleResult result = new ModuleResult(context.getTaskId(), "phone-enum-ios");
            String action = inputs.getOrDefault("action", "discover");
            String deviceId = inputs.getOrDefault("device_id", "");
            String param = inputs.getOrDefault("param", "");

            context.log("[*] Executing iOS Action: " + action);

            try {
                if ("discover".equals(action)) {
                    executeDeviceDiscovery(result, context);
                } else {
                    if (deviceId.isBlank()) {
                        throw new IllegalArgumentException("Target Device UDID is required for operational actions.");
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
        Map<String, Object> cmdResult = runCommand(new String[]{"idevice_id", "-l"}, ctx);
        String output = (String) cmdResult.get("stdout");
        
        List<Map<String, String>> devices = new ArrayList<>();
        String[] lines = output.split("\n");
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("Error")) continue;
            
            // Map basic UDID out. Since libimobiledevice usually dumps raw UDIDs with `-l`
            Map<String, String> dev = new LinkedHashMap<>();
            dev.put("id", line);
            
            // Optional: run ideviceinfo rapidly to query name & model, fail open if unauthorized
            try {
                Map<String, Object> infoCmd = runCommand(new String[]{"ideviceinfo", "-u", line}, ctx);
                String infoStr = (String) infoCmd.get("stdout");
                dev.put("state", infoStr.contains("ERROR") ? "unauthorized" : "authorized");
                dev.put("model", extractDetail(infoStr, "ProductType:"));
                dev.put("name", extractDetail(infoStr, "DeviceName:"));
                dev.put("os_version", extractDetail(infoStr, "ProductVersion:"));
            } catch (Exception e) {
                dev.put("state", "unauthorized");
            }
            
            devices.add(dev);
        }
        
        Map<String, Object> outMap = new LinkedHashMap<>();
        outMap.put("action", "discover");
        outMap.put("devices", devices);
        result.complete(outMap);
        ctx.log("[+] Discovered " + devices.size() + " connected iOS devices via usbmuxd");
    }

    private String extractDetail(String text, String key) {
        String[] lines = text.split("\n");
        for (String l : lines) {
            if (l.trim().startsWith(key)) {
                return l.substring(l.indexOf(":") + 1).trim();
            }
        }
        return "Unknown";
    }

    private void executeAction(String action, String devId, String param, ModuleResult result, TaskContext ctx) throws Exception {
        String artifactDir = System.getProperty("user.dir") + "/reports/artifacts/" + ctx.getTaskId();
        new File(artifactDir).mkdirs();

        String[] cmd = null;
        boolean extractsData = false;
        String outputPath = "";
        
        // Define backup dir statically mapped per task context isolating executions
        String backupDir = artifactDir + "/backup";

        switch (action) {
            // A) Device Discovery & Control
            case "device_info": cmd = new String[]{"ideviceinfo", "-u", devId}; break;
            case "device_name": cmd = new String[]{"ideviceinfo", "-u", devId, "-k", "DeviceName"}; break;
            case "ios_version": cmd = new String[]{"ideviceinfo", "-u", devId, "-k", "ProductVersion"}; break;
            case "device_model": cmd = new String[]{"ideviceinfo", "-u", devId, "-k", "ProductType"}; break;

            // B) System Logs & Runtime
            case "live_logs": 
                // idevicesyslog streams indefinitely, restrict via timeout
                ctx.log("[~] Capturing 5 seconds of syslog...");
                cmd = new String[]{"/bin/sh", "-c", "timeout 5 idevicesyslog -u " + devId + " || true"}; 
                break;
            case "log_secret_filter":
                ctx.log("[~] Capturing 5 seconds of syslog filtering for secrets...");
                cmd = new String[]{"/bin/sh", "-c", "timeout 5 idevicesyslog -u " + devId + " | grep -i 'token\\|auth\\|password' || true"}; 
                break;
            case "crash_logs": 
                // Assumes local macOS mount point or prior backup sync
                cmd = new String[]{"/bin/sh", "-c", "ls ~/Library/Logs/CrashReporter/MobileDevice/ || echo 'No local crash logs found.'"}; 
                break;

            // C) Backup-Based Enumeration
            case "create_backup":
                cmd = new String[]{"idevicebackup2", "-u", devId, "backup", backupDir}; 
                extractsData = true; outputPath = backupDir;
                break;
            case "encrypted_backup":
                cmd = new String[]{"idevicebackup2", "-u", devId, "backup", "--full", backupDir}; 
                extractsData = true; outputPath = backupDir;
                break;
            case "extract_backup_contents":
                cmd = new String[]{"/bin/sh", "-c", "ls " + backupDir + " || echo 'No backup found. Create one first.'"}; 
                break;
            case "parse_sms_db":
                cmd = new String[]{"/bin/sh", "-c", "sqlite3 " + backupDir + "/*/Library/SMS/sms.db \".tables\" || echo 'Could not read SMS DB'"}; 
                break;
            case "parse_contacts":
                cmd = new String[]{"/bin/sh", "-c", "sqlite3 " + backupDir + "/*/Library/AddressBook/AddressBook.sqlitedb \".tables\" || echo 'Could not read Contacts'"}; 
                break;
            case "extract_call_history":
                cmd = new String[]{"/bin/sh", "-c", "sqlite3 " + backupDir + "/*/Library/CallHistoryDB/CallHistory.storedata \".tables\" || echo 'Could not read CallHistory'"}; 
                break;

            // D) File System Mount
            case "mount_filesystem":
                new File(artifactDir + "/mount").mkdirs();
                cmd = new String[]{"ifuse", artifactDir + "/mount/", "-u", devId}; 
                ctx.log("[+] Mounted into: " + artifactDir + "/mount/");
                break;
            case "browse_media":
                cmd = new String[]{"ls", artifactDir + "/mount/DCIM/"}; 
                break;
            case "extract_photos":
                cmd = new String[]{"cp", "-r", artifactDir + "/mount/DCIM/", artifactDir + "/photos/"}; 
                extractsData = true; outputPath = artifactDir + "/photos/";
                break;

            // E) Application Enumeration
            case "list_backup_apps":
                cmd = new String[]{"/bin/sh", "-c", "grep -r 'CFBundleIdentifier' " + backupDir + " || echo 'No backup apps found'"}; 
                break;
            case "extract_app_containers":
                cmd = new String[]{"/bin/sh", "-c", "ls " + backupDir + "/*/Applications/ || echo 'No app containers extracted'"}; 
                break;
            case "sensitive_app_files":
                cmd = new String[]{"/bin/sh", "-c", "grep -r 'token\\|api_key\\|password' " + backupDir + " || true"}; 
                break;

            // F) Network & Services (Requires Jailbreak/usbmux setup natively handled)
            case "port_forward_ssh":
                ctx.log("[!] Initiating port forward on 2222 -> 22...");
                cmd = new String[]{"/bin/sh", "-c", "nohup iproxy 2222 22 -u " + devId + " > /dev/null 2>&1 & echo 'Port 2222 forwarded.'"}; 
                break;
            case "ssh_access_check":
                // Standard ping/auth check against the forwarded jailbroken port
                cmd = new String[]{"/bin/sh", "-c", "ssh -o BatchMode=yes -o ConnectTimeout=3 root@127.0.0.1 -p 2222 'whoami' || echo 'SSH failed or device not jailbroken'"}; 
                break;
            case "jailbreak_network_config":
                cmd = new String[]{"/bin/sh", "-c", "ssh -o BatchMode=yes root@127.0.0.1 -p 2222 'ifconfig' || echo 'Requires active SSH relay'"}; 
                break;

            // G) Screenshots
            case "take_screenshot":
                cmd = new String[]{"idevicescreenshot", "-u", devId, artifactDir + "/screen.png"}; 
                extractsData = true; outputPath = artifactDir + "/screen.png";
                break;
            case "screen_record_info":
                cmd = new String[]{"echo", "[!] macOS QuickTime handles native iPhone recording. Execute locally via: QuickTime Player -> New Movie Recording -> Select iPhone."}; 
                break;

            // H) Keychain & Secrets
            case "dump_keychain":
                cmd = new String[]{"/bin/sh", "-c", "ssh -o BatchMode=yes root@127.0.0.1 -p 2222 'keychain_dumper' || echo 'Requires jailbroken SSH & keychain_dumper binary natively'"}; 
                break;
            case "extract_cookies":
                cmd = new String[]{"/bin/sh", "-c", "find " + backupDir + " -name '*Cookies.binarycookies' || echo 'No cookies found'"}; 
                break;
            case "extract_plists":
                cmd = new String[]{"/bin/sh", "-c", "find " + backupDir + " -name '*.plist' || echo 'No plists dumped'"}; 
                break;

            // I) Runtime App Instrumentation
            case "frida_attach":
                if (param.isBlank()) throw new IllegalArgumentException("Target App Bundle ID parameter required.");
                cmd = new String[]{"frida", "-U", devId, "-n", param, "--eval", "console.log('[+] Frida Attached Successfully');"}; 
                break;
            case "objection_explore":
                if (param.isBlank()) throw new IllegalArgumentException("Target App Bundle ID parameter required.");
                // We'll run a quick invocation of objection, as exploration is highly interactive.
                cmd = new String[]{"objection", "--device", devId, "-g", param, "explore", "--startup-command", "env; exit"}; 
                break;
            
            default:
                throw new IllegalArgumentException("Unknown operational action: " + action);
        }

        Map<String, Object> cmdResult = runCommand(cmd, ctx);
        String stdout = (String) cmdResult.get("stdout");
        String stderr = (String) cmdResult.get("stderr");

        Map<String, Object> outMap = new LinkedHashMap<>();
        outMap.put("action", action);
        outMap.put("device_id", devId);
        
        if (extractsData) {
            outMap.put("status", "Artifact extracted successfully");
            outMap.put("artifact_path", outputPath);
            ctx.log("[+] Extraction saved to: " + outputPath);
            
            Map<String, Object> finding = new LinkedHashMap<>();
            finding.put("type", "extracted_artifact");
            finding.put("title", action.replace("_", " ").toUpperCase() + " Artifact");
            finding.put("description", "File extraction workflow completed successfully.");
            finding.put("evidence", outputPath);
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
        
        StringBuilder outStr = new StringBuilder();
        StringBuilder errStr = new StringBuilder();
        int exitCode = -1;
        long duration = 0;

        try {
            Process p = pb.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) outStr.append(line).append("\n");
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getErrorStream()))) {
                String line;
                while ((line = reader.readLine()) != null) errStr.append(line).append("\n");
            }
            exitCode = p.waitFor();
        } catch (Exception e) {
            errStr.append(e.getMessage());
        } finally {
            duration = System.currentTimeMillis() - start;
        }

        Map<String, Object> res = new LinkedHashMap<>();
        res.put("stdout", outStr.toString().trim());
        res.put("stderr", errStr.toString().trim());
        res.put("exit_code", exitCode);
        res.put("duration_ms", duration);
        res.put("tool", cmd[0]);
        res.put("command", String.join(" ", cmd));
        
        return res;
    }

    @Override
    public void cleanup() {
        // No heavy allocations
    }
}
