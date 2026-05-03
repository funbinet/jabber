package com.jabber.jabber.modules.reconnaissance.adlaps;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * ToolManager — Registry for ADLAPS tools.
 * Manages: rpcclient, nmap, dig, crackmapexec
 */
public class ToolManager {

    public static final List<ToolDefinition> DEFAULT_TOOLS = List.of(
        ToolDefinition.system("rpcclient", "rpcclient", "MS-RPC client for account mapping and cred checks.",
            List.of("-V"), "https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html"),
        ToolDefinition.system("nmap", "Nmap", "Network mapper for OS and liveness discovery.",
            List.of("--version"), "https://nmap.org/"),
        ToolDefinition.system("dig", "dig", "DNS query utility for host mapping and PTR verification.",
            List.of("-v"), "https://linux.die.net/man/1/dig"),
        ToolDefinition.system("crackmapexec", "CrackMapExec", "Swiss army knife for pentesting networks (SMB validation).",
            List.of("--version"), "https://github.com/Porchetta-Industries/CrackMapExec")
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

    public ToolStatus getToolStatus(String toolId) {
        ToolDefinition def = tools.get(toolId);
        if (def == null) return ToolStatus.missing(toolId, toolId, "Unknown tool");
        Path resolved = resolveToolPath(def);
        boolean installed = resolved != null && Files.exists(resolved);
        String version = installed ? resolveVersion(def, resolved) : "";
        String source = installed ? (resolved.startsWith(toolsDir) ? "tools_dir" : "path") : "missing";
        return new ToolStatus(def, installed, resolved == null ? "" : resolved.toString(), version, source);
    }

    public Map<String, Object> downloadTool(String toolId) {
        return Map.of("toolId", toolId, "status", "failed", "error", "Cannot auto-download system tool");
    }

    public Map<String, Object> getToolDownloadStatus(String toolId) {
        ToolStatus current = getToolStatus(toolId);
        return Map.of(
            "toolId", toolId,
            "status", current.installed ? "completed" : "idle",
            "progress", current.installed ? 100 : 0,
            "message", current.installed ? "Installed in system" : "System tool missing"
        );
    }

    public Map<String, Object> deleteTool(String toolId) {
        return Map.of("success", false, "error", "Cannot delete system tool");
    }

    // ── Internals ──

    private Path resolveToolPath(ToolDefinition def) { 
        String r = findOnPath(def.binaryFileName()); 
        if (r == null && "crackmapexec".equals(def.id)) {
            r = findOnPath("cme");
            if (r == null) r = findOnPath("netexec");
            if (r == null) r = findOnPath("nxc");
        }
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
            return l.isBlank() ? null : l.trim(); 
        } 
        return null; 
    }

    private String firstLine(String s) { int i = s.indexOf('\n'); return (i >= 0 ? s.substring(0, i) : s).trim(); }

    private static Path defaultToolsDir() { return Path.of(System.getProperty("user.dir", "."), "jabber-tools", "recon"); }

    private static boolean isWindows() { return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win"); }

    // ── Inner classes ──

    public static final class ToolDefinition {
        final String id, name, description, binaryName, homepage;
        final List<String> versionArgs; 
        private ToolDefinition(String id, String name, String desc, String bin, List<String> verArgs, String home) {
            this.id = id; this.name = name; this.description = desc; this.binaryName = bin; this.versionArgs = verArgs; this.homepage = home; 
        }
        public static ToolDefinition system(String id, String name, String desc, List<String> ver, String home) { 
            return new ToolDefinition(id, name, desc, id, ver, home); 
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
            return new ToolStatus(new ToolDefinition(id, name, desc, id, List.of(), ""), false, "", "", "missing"); 
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
