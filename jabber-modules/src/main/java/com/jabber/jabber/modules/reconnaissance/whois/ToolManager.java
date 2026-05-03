package com.jabber.jabber.modules.reconnaissance.whois;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * ToolManager — Registry for Whois module tools.
 * Manages: whois, dig, nmap, subfinder, dnsx, amass, bgpq4, httpx, sherlock, maigret, shodan
 */
public class ToolManager {

    public static final List<ToolDefinition> DEFAULT_TOOLS = List.of(
        ToolDefinition.managed("whois", "whois", "Standard domain and IP registration lookup.",
            List.of("--version"), "https://github.com/rfc1036/whois", "sudo apt-get install -y whois"),
        ToolDefinition.managed("dig", "dig", "DNS query utility for mapping infrastructure.",
            List.of("-v"), "https://linux.die.net/man/1/dig", "sudo apt-get install -y dnsutils"),
        ToolDefinition.managed("nmap", "Nmap", "Network mapper for range sweeps and liveness.",
            List.of("--version"), "https://nmap.org/", "sudo apt-get install -y nmap"),
        ToolDefinition.downloaded("subfinder", "Subfinder", "Fast passive subdomain discovery.",
            "subfinder", List.of("-version"), "https://github.com/projectdiscovery/subfinder", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        ToolDefinition.downloaded("dnsx", "dnsx", "Fast multi-purpose DNS toolkit.",
            "dnsx", List.of("-version"), "https://github.com/projectdiscovery/dnsx", "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
        ToolDefinition.downloaded("amass", "Amass", "In-depth Attack Surface Mapping.",
            "amass", List.of("-version"), "https://github.com/owasp-amass/amass", "go install -v github.com/owasp-amass/amass/v4/...@latest"),
        ToolDefinition.managed("bgpq4", "bgpq4", "BGP routing prefix generator.",
            List.of("-v"), "https://github.com/bgp/bgpq4", "sudo apt-get install -y bgpq4"),
        ToolDefinition.downloaded("httpx", "httpx", "Fast and multi-purpose HTTP toolkit.",
            "httpx", List.of("-version"), "https://github.com/projectdiscovery/httpx", "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        ToolDefinition.managed("sherlock", "Sherlock", "Hunt down social media accounts by username.",
            List.of("--version"), "https://github.com/sherlock-project/sherlock", "python3 -m pip install sherlock-project --break-system-packages"),
        ToolDefinition.managed("maigret", "Maigret", "Collect a dossier on a person by username.",
            List.of("--version"), "https://github.com/soxoj/maigret", "python3 -m pip install maigret --break-system-packages"),
        ToolDefinition.managed("shodan", "Shodan CLI", "Access the Shodan IoT search engine.",
            List.of("version"), "https://cli.shodan.io/", "python3 -m pip install shodan --break-system-packages"),
        ToolDefinition.managed("holehe", "Holehe", "Check if an email is attached to an account on 120+ sites.",
            List.of("--version"), "https://github.com/megadose/holehe", "python3 -m pip install holehe --break-system-packages"),
        ToolDefinition.managed("h8mail", "h8mail", "Email OSINT and password breach hunting.",
            List.of("-h"), "https://github.com/khast3x/h8mail", "python3 -m pip install h8mail --break-system-packages"),
        ToolDefinition.managed("ignorant", "Ignorant", "Check if a phone/email is used on Snapchat/IG.",
            List.of("-h"), "https://github.com/megadose/ignorant", "python3 -m pip install ignorant --break-system-packages")
    );

    private final Path toolsDir;
    private final Map<String, ToolDefinition> tools;

    public ToolManager() {
        this(defaultToolsDir(), DEFAULT_TOOLS);
    }

    public ToolManager(Path toolsDir, List<ToolDefinition> definitions) {
        this.toolsDir = toolsDir.toAbsolutePath();
        this.tools = new LinkedHashMap<>();
        for (ToolDefinition def : definitions) this.tools.put(def.id, def);
        try { Files.createDirectories(this.toolsDir); } catch (IOException e) {
            throw new IllegalStateException("Cannot init tools dir: " + this.toolsDir, e);
        }
    }

    public List<ToolDefinition> getRequiredTools() { return new ArrayList<>(tools.values()); }

    public List<Map<String, Object>> getToolStatuses() {
        List<Map<String, Object>> statuses = new ArrayList<>();
        for (ToolDefinition def : tools.values()) statuses.add(getToolStatus(def.id).toMap());
        return statuses;
    }

    public List<Map<String, Object>> getToolStatusesForMode(String mode) {
        List<String> activeTools = switch (mode.toUpperCase()) {
            case "REC" -> List.of("whois", "shodan", "dig", "dnsx", "subfinder");
            case "AST" -> List.of("whois", "nmap", "dnsx", "dig", "shodan");
            case "BGP" -> List.of("whois", "bgpq4", "nmap", "dnsx");
            case "CRP" -> List.of("amass", "subfinder", "dnsx", "httpx");
            case "PER" -> List.of("sherlock", "maigret");
            case "BRC" -> List.of("holehe", "h8mail", "ignorant");
            default -> List.of();
        };
        List<Map<String, Object>> statuses = new ArrayList<>();
        for (String id : activeTools) {
            if (tools.containsKey(id)) statuses.add(getToolStatus(id).toMap());
        }
        return statuses;
    }

    public ToolStatus getToolStatus(String toolId) {
        ToolDefinition def = tools.get(toolId);
        if (def == null) return ToolStatus.missing(toolId, toolId, "Unknown tool");
        Path resolved = resolveToolPath(def);
        boolean installed = resolved != null && Files.exists(resolved);
        String version = installed ? resolveVersion(def, resolved) : "";
        String source = installed ? (resolved.startsWith(toolsDir) ? "tools_dir" : "path") : "missing";
        return new ToolStatus(def, installed, resolved == null ? "" : resolved.toString(), version, source);
    }

    private final Map<String, DownloadState> downloads = new ConcurrentHashMap<>();

    public Map<String, Object> downloadTool(String toolId) {
        ToolDefinition def = tools.get(toolId);
        if (def == null) {
            return Map.of("toolId", toolId, "status", "failed", "error", "Tool definition not found");
        }

        if (getToolStatus(toolId).installed) {
            return Map.of("toolId", toolId, "status", "completed", "message", "Tool already installed");
        }

        DownloadState state = downloads.computeIfAbsent(toolId, id -> new DownloadState());
        if (state.inProgress) return getToolDownloadStatus(toolId);

        state.inProgress = true;
        state.progress = 10;
        state.message = "Starting installation...";

        Thread.ofVirtual().start(() -> {
            try {
                String cmd = def.installCommand;
                if (cmd == null || cmd.isBlank()) {
                    state.error = "No install command defined for " + toolId;
                    state.inProgress = false;
                    return;
                }

                state.message = "Executing: " + cmd;
                String[] parts = cmd.split("\\s+");
                CommandResult res = runCmd(List.of(parts), 300000); // 5 min timeout

                if (res.exitCode == 0) {
                    state.progress = 100;
                    state.message = "Installation successful";
                    state.completed = true;
                } else {
                    state.error = "Installation failed (exit " + res.exitCode + "): " + res.stderr;
                }
            } catch (Exception e) {
                state.error = "Error: " + e.getMessage();
            } finally {
                state.inProgress = false;
            }
        });

        return getToolDownloadStatus(toolId);
    }

    public Map<String, Object> getToolDownloadStatus(String toolId) {
        DownloadState state = downloads.get(toolId);
        if (state == null) {
            ToolStatus current = getToolStatus(toolId);
            return Map.of(
                "toolId", toolId,
                "status", current.installed ? "completed" : "idle",
                "progress", current.installed ? 100 : 0,
                "message", current.installed ? "Tool is ready" : "Not installed"
            );
        }
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("toolId", toolId);
        map.put("status", state.inProgress ? "downloading" : (state.error != null ? "failed" : "completed"));
        map.put("progress", state.progress);
        map.put("message", state.error != null ? state.error : state.message);
        if (state.error != null) map.put("error", state.error);
        return map;
    }

    private static class DownloadState {
        boolean inProgress = false;
        int progress = 0;
        String message = "";
        String error = null;
        boolean completed = false;
    }

    public Map<String, Object> deleteTool(String toolId) {
        return Map.of("success", false, "error", "Cannot delete system tool");
    }

    // ── Internals ──

    private Path resolveToolPath(ToolDefinition def) { 
        if (!def.isSystemCommand) {
            Path local = toolsDir.resolve(def.binaryFileName());
            if (Files.exists(local)) return local;
        }
        String r = findOnPath(def.binaryFileName()); 
        return r != null ? Path.of(r) : null; 
    }

    private String resolveVersion(ToolDefinition def, Path bin) { 
        if (def.versionArgs == null || def.versionArgs.isEmpty()) return ""; 
        for (String arg : def.versionArgs) { 
            CommandResult r = runCmd(List.of(bin.toString(), arg), 2000); 
            if (!r.stdout.isBlank()) return firstLine(r.stdout); 
            if (!r.stderr.isBlank()) return firstLine(r.stderr);
        } 
        return ""; 
    }

    private CommandResult runCmd(List<String> cmd, long timeout) { 
        try { 
            ProcessBuilder pb = new ProcessBuilder(cmd); 
            Process p = pb.start(); 
            StringBuilder out = new StringBuilder(), err = new StringBuilder(); 
            Thread t1 = Thread.ofVirtual().start(() -> readStream(p.getInputStream(), out)); 
            Thread t2 = Thread.ofVirtual().start(() -> readStream(p.getErrorStream(), err)); 
            boolean done = p.waitFor(timeout, TimeUnit.MILLISECONDS); 
            if (!done) { p.destroyForcibly(); joinQ(t1); joinQ(t2); return new CommandResult(-1, out.toString(), err.toString()); } 
            joinQ(t1); joinQ(t2); 
            return new CommandResult(p.exitValue(), out.toString(), err.toString()); 
        } catch (Exception e) { return new CommandResult(-1, "", ""); } 
    }

    private void readStream(InputStream s, StringBuilder sb) { 
        try (BufferedReader r = new BufferedReader(new InputStreamReader(s, java.nio.charset.StandardCharsets.UTF_8))) { 
            String l; while ((l = r.readLine()) != null) sb.append(l).append('\n'); 
        } catch (IOException ignored) {} 
    }

    private void joinQ(Thread t) { try { t.join(200); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } }

    private String findOnPath(String cmd) { 
        List<String> c = isWindows() ? List.of("where", cmd) : List.of("which", cmd); 
        CommandResult r = runCmd(c, 2000); 
        if (r.exitCode == 0 && !r.stdout.isBlank()) { 
            String l = firstLine(r.stdout); 
            if (!l.isBlank()) return l.trim(); 
        } 
        // Fallback for Python tools in ~/.local/bin
        if (!isWindows()) {
            List<String> paths = List.of(
                Path.of(System.getProperty("user.home"), ".local", "bin", cmd).toString(),
                "/usr/local/bin/" + cmd,
                "/usr/bin/" + cmd,
                "/bin/" + cmd
            );
            for (String p : paths) {
                if (Files.exists(Path.of(p))) return p;
            }
        }
        return null;
    }

    private String firstLine(String s) { int i = s.indexOf('\n'); return (i >= 0 ? s.substring(0, i) : s).trim(); }

    private static Path defaultToolsDir() { return Path.of(System.getProperty("user.dir", "."), "jabber-tools", "recon"); }

    private static boolean isWindows() { return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win"); }

    // ── Inner classes ──

    public static final class ToolDefinition {
        final String id, name, description, binaryName, homepage, installCommand;
        final List<String> versionArgs; 
        final boolean isSystemCommand;
        private ToolDefinition(String id, String name, String desc, String bin, List<String> verArgs, String home, boolean isSystem, String installCmd) {
            this.id = id; this.name = name; this.description = desc; this.binaryName = bin; this.versionArgs = verArgs; this.homepage = home; this.isSystemCommand = isSystem;
            this.installCommand = installCmd;
        }
        public static ToolDefinition system(String id, String name, String desc, List<String> ver, String home) { 
            return new ToolDefinition(id, name, desc, id, ver, home, true, null); 
        }
        public static ToolDefinition managed(String id, String name, String desc, List<String> ver, String home, String installCmd) { 
            return new ToolDefinition(id, name, desc, id, ver, home, false, installCmd); 
        }
        public static ToolDefinition downloaded(String id, String name, String desc, String bin, List<String> ver, String home, String installCmd) { 
            return new ToolDefinition(id, name, desc, bin, ver, home, false, installCmd); 
        }
        public String binaryFileName() { return isWindows() ? binaryName + ".exe" : binaryName; }
    }

    public static final class ToolStatus {
        private final String id, name, description, homepage, path, version, source;
        private final boolean installed;
        private ToolStatus(ToolDefinition def, boolean installed, String path, String version, String source) {
            this.id = def.id; this.name = def.name; this.description = def.description; this.homepage = def.homepage;
            this.installed = installed; this.path = path; this.version = version; this.source = source;
        }
        public static ToolStatus missing(String id, String name, String desc) { 
            return new ToolStatus(ToolDefinition.system(id, name, desc, List.of(), ""), false, "", "", "missing"); 
        }
        public Map<String, Object> toMap() { 
            Map<String, Object> m = new LinkedHashMap<>(); 
            m.put("id", id); m.put("name", name); m.put("description", description); m.put("homepage", homepage); 
            m.put("installed", installed); m.put("path", path); m.put("version", version); m.put("source", source); 
            return m; 
        }
        public boolean isInstalled() { return installed; }
        public String getPath() { return path; }
    }

    private static final class CommandResult { 
        final int exitCode; final String stdout; final String stderr;
        CommandResult(int c, String out, String err) { this.exitCode = c; this.stdout = out == null ? "" : out; this.stderr = err == null ? "" : err;} 
    }
}
