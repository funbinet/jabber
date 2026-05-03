package com.jabber.jabber.modules.reconnaissance.portscan;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.*;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.*;

/**
 * ToolManager — Self-contained registry for the Port Scanner module's tools.
 * Manages: nmap, masscan, arp-scan, dnsx, httpx
 * Supports sudo flag per tool for elevated privilege identification.
 */
public class ToolManager {

    private static final int DEFAULT_VERSION_TIMEOUT_MS = 2000;
    private static final int DEFAULT_DOWNLOAD_TIMEOUT_SEC = 300;
    private static final int DOWNLOAD_BUFFER_BYTES = 8192;

    public static final List<ToolDefinition> DEFAULT_TOOLS = List.of(
        ToolDefinition.system("nmap", "Nmap", "Network mapper and port scanner.",
            List.of("--version"), "https://nmap.org/", false),
        ToolDefinition.system("masscan", "Masscan", "High-speed TCP port scanner (requires root).",
            List.of("--version"), "https://github.com/robertdavidgraham/masscan", true),
        ToolDefinition.system("arp-scan", "arp-scan", "Layer-2 network discovery (requires root).",
            List.of("--version"), "https://github.com/royhills/arp-scan", true),
        ToolDefinition.github("dnsx", "dnsx", "Advanced DNS toolkit.",
            "projectdiscovery", "dnsx", "dnsx", List.of("-version"),
            "https://github.com/projectdiscovery/dnsx", false),
        ToolDefinition.github("httpx", "httpx", "Advanced HTTP toolkit.",
            "projectdiscovery", "httpx", "httpx", List.of("-version"),
            "https://github.com/projectdiscovery/httpx", false));

    private final Path toolsDir;
    private final Map<String, ToolDefinition> tools;
    private final Map<String, DownloadStatus> downloadStates = new ConcurrentHashMap<>();
    private final HttpClient httpClient;
    private final ExecutorService downloadExecutor;

    public ToolManager() {
        this(defaultToolsDir(), DEFAULT_TOOLS, HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.ALWAYS)
            .connectTimeout(java.time.Duration.ofSeconds(20))
            .build());
    }

    public ToolManager(Path toolsDir, List<ToolDefinition> definitions, HttpClient httpClient) {
        this.toolsDir = toolsDir.toAbsolutePath();
        this.tools = new LinkedHashMap<>();
        for (ToolDefinition def : definitions) {
            this.tools.put(def.id, def);
        }
        this.httpClient = httpClient;
        this.downloadExecutor = Executors.newCachedThreadPool();
        try { Files.createDirectories(this.toolsDir); } catch (IOException e) {
            throw new IllegalStateException("Unable to initialize tools directory: " + this.toolsDir, e);
        }
    }

    public List<ToolDefinition> getRequiredTools() { return new ArrayList<>(tools.values()); }
    public Path getToolsDir() { return toolsDir; }

    /**
     * Check if any of the given tool IDs require sudo.
     */
    public boolean anyToolRequiresSudo(List<String> toolIds) {
        return toolIds.stream()
            .map(tools::get)
            .filter(Objects::nonNull)
            .anyMatch(def -> def.requiresSudo);
    }

    /**
     * Get tool IDs that require sudo from a given list.
     */
    public List<String> getSudoTools(List<String> toolIds) {
        return toolIds.stream()
            .map(tools::get)
            .filter(Objects::nonNull)
            .filter(def -> def.requiresSudo)
            .map(def -> def.id)
            .toList();
    }

    public List<Map<String, Object>> getToolStatuses() {
        List<Map<String, Object>> statuses = new ArrayList<>();
        for (ToolDefinition def : tools.values()) {
            statuses.add(getToolStatus(def.id).toMap());
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

    public Map<String, Object> downloadTool(String toolId) {
        return downloadToolInternal(toolId, false).toMap();
    }

    public Map<String, Object> getToolDownloadStatus(String toolId) {
        DownloadStatus status = downloadStates.get(toolId);
        if (status == null) {
            ToolStatus toolStatus = getToolStatus(toolId);
            return DownloadStatus.fromToolStatus(toolStatus).toMap();
        }
        return status.toMap();
    }

    public Map<String, Object> deleteTool(String toolId) {
        ToolStatus status = getToolStatus(toolId);
        if (!status.installed) return Map.of("success", false, "error", "Tool not installed");
        if (!"tools_dir".equals(status.source))
            return Map.of("success", false, "error", "Cannot delete system tool on PATH.");
        try {
            Files.deleteIfExists(Path.of(status.path));
            downloadStates.remove(toolId);
            return Map.of("success", true, "message", "Tool binary deleted: " + toolId);
        } catch (IOException e) {
            return Map.of("success", false, "error", "Failed to delete: " + e.getMessage());
        }
    }

    // ── Download internals (identical pattern to bannergrab ToolManager) ──

    private DownloadStatus downloadToolInternal(String toolId, boolean block) {
        ToolDefinition def = tools.get(toolId);
        if (def == null) {
            DownloadStatus s = DownloadStatus.error(toolId, "unknown", "Unknown tool");
            downloadStates.put(toolId, s); return s;
        }
        ToolStatus current = getToolStatus(toolId);
        if (current.installed) {
            DownloadStatus s = DownloadStatus.completed(toolId, 100, "Already installed");
            downloadStates.put(toolId, s); return s;
        }
        DownloadStatus existing = downloadStates.get(toolId);
        if (existing != null && "downloading".equals(existing.status)) return existing;

        DownloadStatus status = DownloadStatus.downloading(toolId);
        downloadStates.put(toolId, status);

        Runnable task = () -> {
            try {
                downloadToolBlocking(def, status);
                status.status = "completed"; status.progress = 100;
                status.finishedAt = Instant.now(); status.message = "Download complete";
            } catch (Exception e) {
                status.status = "failed"; status.error = e.getMessage();
                status.finishedAt = Instant.now(); status.message = "Download failed";
            }
        };
        if (block) task.run(); else downloadExecutor.submit(task);
        return status;
    }

    private void downloadToolBlocking(ToolDefinition def, DownloadStatus status) throws Exception {
        ToolPlatform platform = ToolPlatform.detect();
        ReleaseAsset asset = resolveReleaseAsset(def, platform);
        if (asset == null) throw new IOException("No release asset for " + def.id + " on " + platform.os + "/" + platform.arch);
        status.message = "Downloading " + asset.name;
        Path downloadPath = toolsDir.resolve(def.id + "_" + asset.name);
        Files.createDirectories(toolsDir);
        downloadFile(asset.downloadUrl, downloadPath, status);
        Path extractedBinary = extractOrMoveBinary(def, asset, downloadPath);
        if (extractedBinary == null || !Files.exists(extractedBinary))
            throw new IOException("Failed to locate binary for " + def.id);
        makeExecutable(extractedBinary);
        try { Files.deleteIfExists(downloadPath); } catch (IOException ignored) {}
    }

    private ReleaseAsset resolveReleaseAsset(ToolDefinition def, ToolPlatform platform) throws Exception {
        String apiUrl = String.format("https://api.github.com/repos/%s/%s/releases/latest", def.repoOwner, def.repoName);
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(apiUrl)).timeout(java.time.Duration.ofSeconds(20)).GET().build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() >= 400) throw new IOException("GitHub API error: " + response.statusCode());
        JsonObject root = JsonParser.parseString(response.body()).getAsJsonObject();
        JsonArray assets = root.getAsJsonArray("assets");
        if (assets == null) return null;
        List<ReleaseAsset> candidates = new ArrayList<>();
        for (JsonElement el : assets) {
            if (!el.isJsonObject()) continue;
            JsonObject a = el.getAsJsonObject();
            String name = asString(a, "name"), url = asString(a, "browser_download_url");
            if (name == null || url == null) continue;
            String lower = name.toLowerCase(Locale.ROOT);
            if (lower.contains("sbom") || lower.endsWith(".sig") || lower.endsWith(".asc") || lower.endsWith(".txt")) continue;
            candidates.add(new ReleaseAsset(name, url));
        }
        if (candidates.isEmpty()) return null;
        String osToken = platform.osToken();
        List<String> archTokens = platform.archTokens();
        for (ReleaseAsset c : candidates) {
            String lower = c.name.toLowerCase(Locale.ROOT);
            if (!lower.contains(osToken)) continue;
            boolean archMatch = archTokens.isEmpty() || archTokens.stream().anyMatch(lower::contains);
            if (archMatch) return c;
        }
        for (ReleaseAsset c : candidates) { if (c.name.toLowerCase(Locale.ROOT).contains(osToken)) return c; }
        return null;
    }

    private void downloadFile(String url, Path dest, DownloadStatus status) throws Exception {
        HttpRequest req = HttpRequest.newBuilder().uri(URI.create(url)).timeout(java.time.Duration.ofSeconds(DEFAULT_DOWNLOAD_TIMEOUT_SEC)).GET().build();
        HttpResponse<InputStream> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofInputStream());
        if (resp.statusCode() >= 400) throw new IOException("Download failed: HTTP " + resp.statusCode());
        long contentLength = resp.headers().firstValueAsLong("Content-Length").orElse(-1L);
        long totalRead = 0L;
        try (InputStream in = new BufferedInputStream(resp.body());
             OutputStream out = Files.newOutputStream(dest, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            byte[] buf = new byte[DOWNLOAD_BUFFER_BYTES]; int read;
            while ((read = in.read(buf)) != -1) {
                out.write(buf, 0, read); totalRead += read;
                if (contentLength > 0) status.progress = (int)((totalRead * 100) / contentLength);
            }
        }
        status.progress = 100;
    }

    private Path extractOrMoveBinary(ToolDefinition def, ReleaseAsset asset, Path downloaded) throws Exception {
        String lower = asset.name.toLowerCase(Locale.ROOT);
        Path target = toolsDir.resolve(def.binaryFileName());
        if (lower.endsWith(".zip")) {
            Path tmp = Files.createTempDirectory("jabber_zip_");
            try { extractZip(downloaded, tmp); return moveBinary(def, tmp, target); } finally { deleteQuietly(tmp); }
        }
        if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) {
            Path tmp = Files.createTempDirectory("jabber_tgz_");
            try { extractTarGz(downloaded, tmp); return moveBinary(def, tmp, target); } finally { deleteQuietly(tmp); }
        }
        Files.move(downloaded, target, StandardCopyOption.REPLACE_EXISTING);
        return target;
    }

    private Path moveBinary(ToolDefinition def, Path src, Path target) throws IOException {
        Path bin = findBinary(src, def);
        if (bin == null) return null;
        Files.createDirectories(target.getParent());
        Files.move(bin, target, StandardCopyOption.REPLACE_EXISTING);
        return target;
    }

    private Path findBinary(Path base, ToolDefinition def) throws IOException {
        String expected = def.binaryFileName();
        try (var s = Files.walk(base)) {
            return s.filter(Files::isRegularFile).filter(p -> p.getFileName().toString().equalsIgnoreCase(expected)).findFirst().orElse(null);
        }
    }

    private void extractZip(Path zip, Path dest) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(zip))) {
            ZipEntry e; while ((e = zis.getNextEntry()) != null) {
                if (e.isDirectory()) continue;
                Path out = dest.resolve(e.getName()).normalize();
                Files.createDirectories(out.getParent());
                try (OutputStream os = Files.newOutputStream(out)) { zis.transferTo(os); }
            }
        }
    }

    private void extractTarGz(Path tarGz, Path dest) throws IOException {
        try (InputStream fis = Files.newInputStream(tarGz); GZIPInputStream gis = new GZIPInputStream(fis)) {
            byte[] header = new byte[512];
            while (true) {
                int read = gis.readNBytes(header, 0, 512); if (read < 512) break;
                String name = extractTarString(header, 0, 100); if (name.isBlank()) break;
                long size = parseTarSize(header, 124, 12); int type = header[156];
                boolean isFile = type == 0 || type == '0';
                if (isFile) {
                    Path out = dest.resolve(name).normalize(); Files.createDirectories(out.getParent());
                    try (OutputStream os = Files.newOutputStream(out)) { copyFixed(gis, os, size); }
                } else { gis.skipNBytes(size); }
                long pad = (512 - (size % 512)) % 512; if (pad > 0) gis.skipNBytes(pad);
            }
        }
    }

    private String extractTarString(byte[] buf, int off, int len) {
        int i = off; while (i < off + len && buf[i] != 0) i++;
        return new String(buf, off, i - off, StandardCharsets.US_ASCII).trim();
    }
    private long parseTarSize(byte[] buf, int off, int len) {
        String raw = new String(buf, off, len, StandardCharsets.US_ASCII).trim();
        if (raw.isEmpty()) return 0L;
        try { return Long.parseLong(raw.replaceAll("[^0-7]", ""), 8); } catch (NumberFormatException e) { return 0L; }
    }
    private void copyFixed(InputStream in, OutputStream out, long size) throws IOException {
        byte[] buf = new byte[DOWNLOAD_BUFFER_BYTES]; long rem = size;
        while (rem > 0) { int r = in.read(buf, 0, (int)Math.min(buf.length, rem)); if (r == -1) break; out.write(buf, 0, r); rem -= r; }
    }
    private Path resolveToolPath(ToolDefinition def) {
        Path localPath = toolsDir.resolve(def.binaryFileName());
        if (Files.exists(localPath)) return localPath;
        String systemPath = findOnPath(def.binaryFileName());
        if (systemPath != null) return Path.of(systemPath);
        return null;
    }

    private boolean verifyChecksum(String checksumUrl, Path downloadPath, Path extractedBinary) {
        return true;
    }

    private void makeExecutable(Path file) {
        if (!isWindows()) {
            try {
                Set<PosixFilePermission> perms = Files.getPosixFilePermissions(file);
                perms.add(PosixFilePermission.OWNER_EXECUTE);
                perms.add(PosixFilePermission.GROUP_EXECUTE);
                perms.add(PosixFilePermission.OTHERS_EXECUTE);
                Files.setPosixFilePermissions(file, perms);
            } catch (IOException ignored) {}
        }
    }

    private String resolveVersion(ToolDefinition def, Path binaryPath) {
        if (def.versionArgs == null || def.versionArgs.isEmpty()) {
            return "";
        }
        for (String arg : def.versionArgs) {
            CommandResult result = runCommand(List.of(binaryPath.toString(), arg), DEFAULT_VERSION_TIMEOUT_MS);
            if (!result.stdout.isBlank()) {
                return firstLine(result.stdout);
            }
        }
        return "";
    }

    private CommandResult runCommand(List<String> command, long timeoutMs) {
        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            Process runningProcess = builder.start();
            final Process proc = runningProcess;

            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();

            Thread outThread = Thread.ofVirtual().start(() -> readStream(proc.getInputStream(), stdout));
            Thread errThread = Thread.ofVirtual().start(() -> readStream(proc.getErrorStream(), stderr));

            boolean finished = proc.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            if (!finished) {
                proc.destroyForcibly();
                joinQuietly(outThread, 200);
                joinQuietly(errThread, 200);
                return new CommandResult(-1, stdout.toString());
            }

            joinQuietly(outThread, 200);
            joinQuietly(errThread, 200);

            return new CommandResult(proc.exitValue(), stdout.toString());
        } catch (Exception e) {
            return new CommandResult(-1, "");
        }
    }

    private void readStream(InputStream stream, StringBuilder sb) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
        } catch (IOException ignored) {
        }
    }

    private void joinQuietly(Thread thread, long timeoutMs) {
        try {
            thread.join(timeoutMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private String findOnPath(String command) {
        List<String> check = isWindows() ? List.of("where", command) : List.of("which", command);
        CommandResult result = runCommand(check, 2000);
        if (result.exitCode == 0 && !result.stdout.isBlank()) {
            String line = firstLine(result.stdout);
            return line.isBlank() ? null : line.trim();
        }
        return null;
    }

    private String firstLine(String s) { int i = s.indexOf('\n'); return (i >= 0 ? s.substring(0, i) : s).trim(); }
    private static Path defaultToolsDir() { return Path.of(System.getProperty("user.dir", "."), "jabber-tools", "recon"); }
    private static boolean isWindows() { return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win"); }
    private static String asString(JsonObject o, String k) { return o.has(k) && o.get(k).isJsonPrimitive() ? o.get(k).getAsString() : null; }
    private void deleteQuietly(Path dir) { if (dir == null) return; try (var s = Files.walk(dir)) { s.sorted((a, b) -> b.compareTo(a)).forEach(p -> { try { Files.deleteIfExists(p); } catch (IOException ignored) {} }); } catch (IOException ignored) {} }

    // ── Inner classes ──

    public static final class ToolDefinition {
        final String id, name, description, repoOwner, repoName, binaryName, homepage;
        final List<String> versionArgs;
        final boolean requiresSudo;

        private ToolDefinition(String id, String name, String desc, String owner, String repo, String bin, List<String> verArgs, String home, boolean sudo) {
            this.id = id; this.name = name; this.description = desc; this.repoOwner = owner; this.repoName = repo;
            this.binaryName = bin; this.versionArgs = verArgs; this.homepage = home; this.requiresSudo = sudo;
        }
        public static ToolDefinition github(String id, String name, String desc, String owner, String repo, String bin, List<String> ver, String home, boolean sudo) {
            return new ToolDefinition(id, name, desc, owner, repo, bin, ver, home, sudo);
        }
        public static ToolDefinition system(String id, String name, String desc, List<String> ver, String home, boolean sudo) {
            return new ToolDefinition(id, name, desc, "", "", id, ver, home, sudo);
        }
        public String binaryFileName() { return isWindows() ? binaryName + ".exe" : binaryName; }
        public String getId() { return id; }
        public String getName() { return name; }
        public boolean requiresSudo() { return requiresSudo; }
    }

    public static final class ToolStatus {
        private final String id, name, description, homepage, path, version, source;
        private final boolean installed, requiresSudo;

        private ToolStatus(ToolDefinition def, boolean installed, String path, String version, String source) {
            this.id = def.id; this.name = def.name; this.description = def.description;
            this.homepage = def.homepage; this.installed = installed; this.path = path;
            this.version = version; this.source = source; this.requiresSudo = def.requiresSudo;
        }
        public static ToolStatus missing(String id, String name, String desc) {
            return new ToolStatus(new ToolDefinition(id, name, desc, "", "", id, List.of(), "", false), false, "", "", "missing");
        }
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id); m.put("name", name); m.put("description", description);
            m.put("homepage", homepage); m.put("installed", installed); m.put("path", path);
            m.put("version", version); m.put("source", source); m.put("requiresSudo", requiresSudo);
            return m;
        }
        public boolean isInstalled() { return installed; }
        public String getPath() { return path; }
        public String getId() { return id; }
    }

    private static final class CommandResult {
        final int exitCode; final String stdout;
        CommandResult(int c, String s) { this.exitCode = c; this.stdout = s == null ? "" : s; }
    }
    private static final class ReleaseAsset {
        final String name, downloadUrl;
        ReleaseAsset(String n, String u) { this.name = n; this.downloadUrl = u; }
    }
    private static final class ToolPlatform {
        final String os, arch;
        ToolPlatform(String os, String arch) { this.os = os; this.arch = arch; }
        static ToolPlatform detect() {
            String osN = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
            String archN = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
            if (osN.contains("android") || System.getenv("ANDROID_ROOT") != null || System.getenv("TERMUX_VERSION") != null) osN = "android";
            String os = osN.contains("win") ? "windows" : osN.contains("mac") || osN.contains("darwin") ? "darwin" : "linux";
            String arch = archN.contains("aarch64") || archN.contains("arm64") ? "arm64" : archN.contains("arm") ? "arm" : "amd64";
            return new ToolPlatform(os, arch);
        }
        String osToken() { return switch (os) { case "windows" -> "windows"; case "darwin" -> "darwin"; default -> "linux"; }; }
        List<String> archTokens() { return switch (arch) { case "arm64" -> List.of("arm64", "aarch64"); case "arm" -> List.of("armv7", "armv6", "arm"); default -> List.of("amd64", "x86_64", "x64"); }; }
    }

    public static final class DownloadStatus {
        private final String toolId;
        String status; int progress; String message, error;
        Instant startedAt, finishedAt;
        private DownloadStatus(String id) { this.toolId = id; this.status = "idle"; this.progress = 0; this.message = ""; this.error = ""; }
        static DownloadStatus downloading(String id) { DownloadStatus s = new DownloadStatus(id); s.status = "downloading"; s.startedAt = Instant.now(); s.message = "Download started"; return s; }
        static DownloadStatus completed(String id, int p, String msg) { DownloadStatus s = new DownloadStatus(id); s.status = "completed"; s.progress = p; s.message = msg; s.finishedAt = Instant.now(); return s; }
        static DownloadStatus error(String id, String st, String msg) { DownloadStatus s = new DownloadStatus(id); s.status = st; s.message = msg; s.error = msg; s.finishedAt = Instant.now(); return s; }
        static DownloadStatus fromToolStatus(ToolStatus ts) { DownloadStatus s = new DownloadStatus(ts.id); s.status = ts.installed ? "completed" : "idle"; s.progress = ts.installed ? 100 : 0; s.message = ts.installed ? "Installed" : "Not installed"; return s; }
        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>(); m.put("toolId", toolId); m.put("status", status); m.put("progress", progress);
            m.put("message", message); m.put("error", error); if (startedAt != null) m.put("started_at", startedAt.toString());
            if (finishedAt != null) m.put("finished_at", finishedAt.toString()); return m;
        }
    }
}
