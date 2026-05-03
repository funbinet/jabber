package com.jabber.jabber.modules.reconnaissance.crawler;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ToolManager {

    private static final int DEFAULT_VERSION_TIMEOUT_MS = 2000;
    private static final int DEFAULT_DOWNLOAD_TIMEOUT_SEC = 300;
    private static final int DOWNLOAD_BUFFER_BYTES = 8192;

    public static final List<ToolDefinition> DEFAULT_TOOLS = List.of(
        ToolDefinition.github("gospider", "GoSpider", "Fast web crawler and spidering toolkit.",
            "jaeles-project", "gospider", "gospider", List.of("-version"), "https://github.com/jaeles-project/gospider"),
        ToolDefinition.github("katana", "Katana", "ProjectDiscovery web crawling framework.",
            "projectdiscovery", "katana", "katana", List.of("-version"), "https://github.com/projectdiscovery/katana"),
        ToolDefinition.github("httpx", "Httpx", "HTTP probing and technology detection toolkit.",
            "projectdiscovery", "httpx", "httpx", List.of("-version"), "https://github.com/projectdiscovery/httpx"),
        ToolDefinition.github("waybackurls", "Waybackurls", "Fetch URLs from Wayback Machine for a domain.",
            "tomnomnom", "waybackurls", "waybackurls", List.of("-version"), "https://github.com/tomnomnom/waybackurls"),
        ToolDefinition.github("gau", "GAU", "GetAllUrls - query URL discovery sources.",
            "lc", "gau", "gau", List.of("-version"), "https://github.com/lc/gau"),
        ToolDefinition.github("subfinder", "Subfinder", "Subdomain discovery tool.",
            "projectdiscovery", "subfinder", "subfinder", List.of("-version"), "https://github.com/projectdiscovery/subfinder"),
        ToolDefinition.github("dnsx", "dnsx", "Advanced DNS toolkit.",
            "projectdiscovery", "dnsx", "dnsx", List.of("-version"), "https://github.com/projectdiscovery/dnsx"),
        ToolDefinition.system("whois", "Whois", "WHOIS lookup client.",
            List.of("--version"), "https://linux.die.net/man/1/whois")
    );

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
        try {
            Files.createDirectories(this.toolsDir);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to initialize tools directory: " + this.toolsDir, e);
        }
    }

    public static ToolManager createForTesting(Path toolsDir, List<ToolDefinition> definitions) {
        return new ToolManager(toolsDir, definitions, HttpClient.newHttpClient());
    }

    public List<ToolDefinition> getRequiredTools() {
        return new ArrayList<>(tools.values());
    }

    public Path getToolsDir() {
        return toolsDir;
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
        if (def == null) {
            return ToolStatus.missing(toolId, toolId, "Unknown tool");
        }

        Path resolved = resolveToolPath(def);
        boolean installed = resolved != null && Files.exists(resolved);
        String version = installed ? resolveVersion(def, resolved) : "";
        String source = installed ? (resolved.startsWith(toolsDir) ? "tools_dir" : "path") : "missing";
        return new ToolStatus(def, installed, resolved == null ? "" : resolved.toString(), version, source);
    }

    public ToolStatus ensureToolAvailable(String toolId, boolean allowDownload) {
        ToolStatus status = getToolStatus(toolId);
        if (status.installed || !allowDownload) {
            return status;
        }
        DownloadStatus download = downloadToolInternal(toolId, true);
        if ("failed".equals(download.status)) {
            return status;
        }
        return getToolStatus(toolId);
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
        if (!status.installed) {
            return Map.of("success", false, "error", "Tool not installed");
        }
        if (!"tools_dir".equals(status.source)) {
            return Map.of("success", false, "error", "Cannot delete system tool on PATH. Only locally installed tools can be removed.");
        }

        try {
            Path binPath = Path.of(status.path);
            Files.deleteIfExists(binPath);
            downloadStates.remove(toolId);
            return Map.of("success", true, "message", "Tool binary deleted: " + toolId);
        } catch (IOException e) {
            return Map.of("success", false, "error", "Failed to delete binary: " + e.getMessage());
        }
    }

    private DownloadStatus downloadToolInternal(String toolId, boolean blockUntilComplete) {
        ToolDefinition def = tools.get(toolId);
        if (def == null) {
            DownloadStatus missing = DownloadStatus.error(toolId, "unknown", "Unknown tool definition");
            downloadStates.put(toolId, missing);
            return missing;
        }

        ToolStatus current = getToolStatus(toolId);
        if (current.installed) {
            DownloadStatus ready = DownloadStatus.completed(toolId, 100, "Already installed");
            downloadStates.put(toolId, ready);
            return ready;
        }

        DownloadStatus existing = downloadStates.get(toolId);
        if (existing != null && "downloading".equals(existing.status)) {
            return existing;
        }

        DownloadStatus status = DownloadStatus.downloading(toolId);
        downloadStates.put(toolId, status);

        Runnable task = () -> {
            try {
                downloadToolBlocking(def, status);
                status.status = "completed";
                status.progress = 100;
                status.finishedAt = Instant.now();
                status.message = "Download complete";
            } catch (Exception e) {
                status.status = "failed";
                status.error = e.getMessage();
                status.finishedAt = Instant.now();
                status.message = "Download failed";
            }
        };

        if (blockUntilComplete) {
            task.run();
        } else {
            downloadExecutor.submit(task);
        }
        return status;
    }

    private void downloadToolBlocking(ToolDefinition def, DownloadStatus status) throws Exception {
        ToolPlatform platform = ToolPlatform.detect();
        ReleaseAsset asset = resolveReleaseAsset(def, platform);
        if (asset == null) {
            throw new IOException("No release asset found for " + def.id + " on " + platform.os + "/" + platform.arch);
        }

        status.message = "Downloading " + asset.name;

        Path downloadPath = toolsDir.resolve(def.id + "_" + asset.name);
        Files.createDirectories(toolsDir);

        downloadFile(asset.downloadUrl, downloadPath, status);

        Path extractedBinary = extractOrMoveBinary(def, asset, downloadPath, status);
        if (extractedBinary == null || !Files.exists(extractedBinary)) {
            throw new IOException("Failed to locate binary for " + def.id + " after extraction");
        }

        makeExecutable(extractedBinary);

        try {
            Files.deleteIfExists(downloadPath);
        } catch (IOException ignored) {
        }

        if (asset.checksumUrl != null) {
            boolean verified = verifyChecksum(asset.checksumUrl, downloadPath, extractedBinary);
            status.checksumVerified = verified;
            if (!verified) {
                status.message = "Checksum verification failed";
            }
        }
    }

    private ReleaseAsset resolveReleaseAsset(ToolDefinition def, ToolPlatform platform) throws Exception {
        String apiUrl = String.format("https://api.github.com/repos/%s/%s/releases/latest", def.repoOwner, def.repoName);
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(apiUrl)).timeout(java.time.Duration.ofSeconds(20)).GET().build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() >= 400) {
            throw new IOException("GitHub API error for " + def.id + ": " + response.statusCode());
        }

        JsonObject root = JsonParser.parseString(response.body()).getAsJsonObject();
        JsonArray assets = root.getAsJsonArray("assets");
        if (assets == null) {
            return null;
        }

        List<ReleaseAsset> candidates = new ArrayList<>();
        for (JsonElement element : assets) {
            if (!element.isJsonObject()) {
                continue;
            }
            JsonObject asset = element.getAsJsonObject();
            String name = asString(asset, "name");
            String url = asString(asset, "browser_download_url");
            if (name == null || url == null) {
                continue;
            }
            String lower = name.toLowerCase(Locale.ROOT);
            if (lower.contains("sbom") || lower.endsWith(".sig") || lower.endsWith(".asc") || lower.endsWith(".txt")) {
                continue;
            }
            candidates.add(new ReleaseAsset(name, url));
        }

        if (candidates.isEmpty()) {
            return null;
        }

        String osToken = platform.osToken();
        List<String> archTokens = platform.archTokens();

        ReleaseAsset best = null;
        for (ReleaseAsset asset : candidates) {
            String lower = asset.name.toLowerCase(Locale.ROOT);
            if (!lower.contains(osToken)) {
                continue;
            }
            if (!archTokens.isEmpty()) {
                boolean matchArch = false;
                for (String token : archTokens) {
                    if (lower.contains(token)) {
                        matchArch = true;
                        break;
                    }
                }
                if (!matchArch) {
                    continue;
                }
            }
            best = asset;
            break;
        }

        if (best == null) {
            for (ReleaseAsset asset : candidates) {
                String lower = asset.name.toLowerCase(Locale.ROOT);
                if (lower.contains(osToken)) {
                    best = asset;
                    break;
                }
            }
        }

        if (best != null) {
            best.checksumUrl = findChecksumAsset(candidates, best.name);
        }
        return best;
    }

    private String findChecksumAsset(List<ReleaseAsset> assets, String targetName) {
        String base = targetName;
        for (String suffix : List.of(".zip", ".tar.gz", ".tgz", ".gz")) {
            if (base.toLowerCase(Locale.ROOT).endsWith(suffix)) {
                base = base.substring(0, base.length() - suffix.length());
                break;
            }
        }

        for (ReleaseAsset asset : assets) {
            String lower = asset.name.toLowerCase(Locale.ROOT);
            if (lower.endsWith(".sha256") || lower.endsWith(".sha256sum")) {
                if (lower.contains(base.toLowerCase(Locale.ROOT))) {
                    return asset.downloadUrl;
                }
            }
        }
        return null;
    }

    private void downloadFile(String url, Path dest, DownloadStatus status) throws Exception {
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url))
            .timeout(java.time.Duration.ofSeconds(DEFAULT_DOWNLOAD_TIMEOUT_SEC))
            .GET().build();
        HttpResponse<InputStream> response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() >= 400) {
            throw new IOException("Download failed with HTTP " + response.statusCode());
        }

        long contentLength = response.headers().firstValueAsLong("Content-Length").orElse(-1L);
        long totalRead = 0L;
        int lastPercent = 0;

        try (InputStream in = new BufferedInputStream(response.body());
             OutputStream out = Files.newOutputStream(dest, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            byte[] buffer = new byte[DOWNLOAD_BUFFER_BYTES];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
                totalRead += read;
                if (contentLength > 0) {
                    int pct = (int) ((totalRead * 100) / contentLength);
                    if (pct != lastPercent) {
                        status.progress = pct;
                        lastPercent = pct;
                    }
                }
            }
        }
        status.progress = 100;
    }

    private Path extractOrMoveBinary(ToolDefinition def, ReleaseAsset asset, Path downloaded, DownloadStatus status) throws Exception {
        String nameLower = asset.name.toLowerCase(Locale.ROOT);
        Path targetBinary = toolsDir.resolve(def.binaryFileName());

        if (nameLower.endsWith(".zip")) {
            Path tempDir = Files.createTempDirectory("jabber_tool_zip_");
            try {
                extractZip(downloaded, tempDir);
                return moveBinaryFromDirectory(def, tempDir, targetBinary);
            } finally {
                deleteQuietly(tempDir);
            }
        }

        if (nameLower.endsWith(".tar.gz") || nameLower.endsWith(".tgz")) {
            Path tempDir = Files.createTempDirectory("jabber_tool_tgz_");
            try {
                extractTarGz(downloaded, tempDir);
                return moveBinaryFromDirectory(def, tempDir, targetBinary);
            } finally {
                deleteQuietly(tempDir);
            }
        }

        Files.move(downloaded, targetBinary, StandardCopyOption.REPLACE_EXISTING);
        return targetBinary;
    }

    private Path moveBinaryFromDirectory(ToolDefinition def, Path sourceDir, Path targetBinary) throws IOException {
        Path binary = findBinary(sourceDir, def);
        if (binary == null) {
            return null;
        }
        Files.createDirectories(targetBinary.getParent());
        Files.move(binary, targetBinary, StandardCopyOption.REPLACE_EXISTING);
        return targetBinary;
    }

    private Path findBinary(Path baseDir, ToolDefinition def) throws IOException {
        String expected = def.binaryFileName();
        try (var stream = Files.walk(baseDir)) {
            return stream
                .filter(Files::isRegularFile)
                .filter(path -> path.getFileName().toString().equalsIgnoreCase(expected))
                .findFirst()
                .orElse(null);
        }
    }

    private void extractZip(Path zipFile, Path destDir) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(zipFile))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                Path out = destDir.resolve(entry.getName()).normalize();
                Files.createDirectories(out.getParent());
                try (OutputStream os = Files.newOutputStream(out, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                    zis.transferTo(os);
                }
            }
        }
    }

    private void extractTarGz(Path tarGz, Path destDir) throws IOException {
        try (InputStream fis = Files.newInputStream(tarGz);
             GZIPInputStream gis = new GZIPInputStream(fis)) {
            byte[] header = new byte[512];
            while (true) {
                int read = gis.readNBytes(header, 0, 512);
                if (read < 512) {
                    break;
                }
                String name = extractTarString(header, 0, 100);
                if (name.isBlank()) {
                    break;
                }
                long size = parseTarSize(header, 124, 12);
                int type = header[156];
                boolean isFile = type == 0 || type == '0';
                if (isFile) {
                    Path out = destDir.resolve(name).normalize();
                    Files.createDirectories(out.getParent());
                    try (OutputStream os = Files.newOutputStream(out, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                        copyFixedBytes(gis, os, size);
                    }
                } else {
                    gis.skipNBytes(size);
                }

                long padding = (512 - (size % 512)) % 512;
                if (padding > 0) {
                    gis.skipNBytes(padding);
                }
            }
        }
    }

    private String extractTarString(byte[] buffer, int offset, int length) {
        int end = offset + length;
        int i = offset;
        while (i < end && buffer[i] != 0) {
            i++;
        }
        return new String(buffer, offset, i - offset, StandardCharsets.US_ASCII).trim();
    }

    private long parseTarSize(byte[] buffer, int offset, int length) {
        String raw = new String(buffer, offset, length, StandardCharsets.US_ASCII).trim();
        if (raw.isEmpty()) {
            return 0L;
        }
        try {
            return Long.parseLong(raw.replaceAll("[^0-7]", ""), 8);
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    private void copyFixedBytes(InputStream in, OutputStream out, long size) throws IOException {
        byte[] buffer = new byte[DOWNLOAD_BUFFER_BYTES];
        long remaining = size;
        while (remaining > 0) {
            int toRead = (int) Math.min(buffer.length, remaining);
            int read = in.read(buffer, 0, toRead);
            if (read == -1) {
                break;
            }
            out.write(buffer, 0, read);
            remaining -= read;
        }
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

    private String firstLine(String input) {
        int idx = input.indexOf('\n');
        String line = idx >= 0 ? input.substring(0, idx) : input;
        return line.trim();
    }

    private static Path defaultToolsDir() {
        String base = System.getProperty("user.dir", ".");
        return Path.of(base, "jabber-tools", "recon");
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    private static String asString(JsonObject object, String key) {
        if (object.has(key) && object.get(key).isJsonPrimitive()) {
            return object.get(key).getAsString();
        }
        return null;
    }

    private void deleteQuietly(Path dir) {
        if (dir == null) {
            return;
        }
        try (var stream = Files.walk(dir)) {
            stream.sorted((a, b) -> b.compareTo(a)).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                }
            });
        } catch (IOException ignored) {
        }
    }

    public static final class ToolDefinition {
        private final String id;
        private final String name;
        private final String description;
        private final String repoOwner;
        private final String repoName;
        private final String binaryName;
        private final List<String> versionArgs;
        private final String homepage;

        private ToolDefinition(String id, String name, String description, String repoOwner,
                               String repoName, String binaryName, List<String> versionArgs, String homepage) {
            this.id = id;
            this.name = name;
            this.description = description;
            this.repoOwner = repoOwner;
            this.repoName = repoName;
            this.binaryName = binaryName;
            this.versionArgs = versionArgs;
            this.homepage = homepage;
        }

        public static ToolDefinition github(String id, String name, String description,
                                            String owner, String repo, String binaryName,
                                            List<String> versionArgs, String homepage) {
            return new ToolDefinition(id, name, description, owner, repo, binaryName, versionArgs, homepage);
        }

        public static ToolDefinition system(String id, String name, String description,
                                            List<String> versionArgs, String homepage) {
            return new ToolDefinition(id, name, description, "", "", id, versionArgs, homepage);
        }

        public String binaryFileName() {
            return isWindows() ? binaryName + ".exe" : binaryName;
        }

        public String getId() {
            return id;
        }

        public String getName() {
            return name;
        }
    }

    public static final class ToolStatus {
        private final String id;
        private final String name;
        private final String description;
        private final String homepage;
        private final boolean installed;
        private final String path;
        private final String version;
        private final String source;

        private ToolStatus(ToolDefinition def, boolean installed, String path, String version, String source) {
            this.id = def.id;
            this.name = def.name;
            this.description = def.description;
            this.homepage = def.homepage;
            this.installed = installed;
            this.path = path;
            this.version = version;
            this.source = source;
        }

        public static ToolStatus missing(String id, String name, String description) {
            return new ToolStatus(new ToolDefinition(id, name, description, "", "", id, List.of(), ""), false, "", "", "missing");
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("id", id);
            map.put("name", name);
            map.put("description", description);
            map.put("homepage", homepage);
            map.put("installed", installed);
            map.put("path", path);
            map.put("version", version);
            map.put("source", source);
            return map;
        }

        public boolean isInstalled() {
            return installed;
        }

        public String getPath() {
            return path;
        }

        public String getId() {
            return id;
        }
    }

    private static final class CommandResult {
        private final int exitCode;
        private final String stdout;

        private CommandResult(int exitCode, String stdout) {
            this.exitCode = exitCode;
            this.stdout = stdout == null ? "" : stdout;
        }
    }

    private static final class ReleaseAsset {
        private final String name;
        private final String downloadUrl;
        private String checksumUrl;

        private ReleaseAsset(String name, String downloadUrl) {
            this.name = name;
            this.downloadUrl = downloadUrl;
        }
    }

    private static final class ToolPlatform {
        private final String os;
        private final String arch;

        private ToolPlatform(String os, String arch) {
            this.os = os;
            this.arch = arch;
        }

        static ToolPlatform detect() {
            String osName = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
            String archName = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);

            if (osName.contains("android") || System.getenv("ANDROID_ROOT") != null || System.getenv("TERMUX_VERSION") != null) {
                osName = "android";
            }

            String os;
            if (osName.contains("win")) {
                os = "windows";
            } else if (osName.contains("mac") || osName.contains("darwin")) {
                os = "darwin";
            } else if (osName.contains("android")) {
                os = "linux";
            } else {
                os = "linux";
            }

            String arch;
            if (archName.contains("aarch64") || archName.contains("arm64")) {
                arch = "arm64";
            } else if (archName.contains("arm")) {
                arch = "arm";
            } else if (archName.contains("86")) {
                arch = "amd64";
            } else {
                arch = "amd64";
            }

            return new ToolPlatform(os, arch);
        }

        String osToken() {
            return switch (os) {
                case "windows" -> "windows";
                case "darwin" -> "darwin";
                default -> "linux";
            };
        }

        List<String> archTokens() {
            return switch (arch) {
                case "arm64" -> List.of("arm64", "aarch64");
                case "arm" -> List.of("armv7", "armv6", "arm");
                default -> List.of("amd64", "x86_64", "x64");
            };
        }
    }

    public static final class DownloadStatus {
        private final String toolId;
        private String status;
        private int progress;
        private String message;
        private String error;
        private Instant startedAt;
        private Instant finishedAt;
        private boolean checksumVerified;

        private DownloadStatus(String toolId) {
            this.toolId = toolId;
            this.status = "idle";
            this.progress = 0;
            this.message = "";
            this.error = "";
        }

        static DownloadStatus downloading(String toolId) {
            DownloadStatus status = new DownloadStatus(toolId);
            status.status = "downloading";
            status.startedAt = Instant.now();
            status.message = "Download started";
            return status;
        }

        static DownloadStatus completed(String toolId, int progress, String message) {
            DownloadStatus status = new DownloadStatus(toolId);
            status.status = "completed";
            status.progress = progress;
            status.message = message;
            status.finishedAt = Instant.now();
            return status;
        }

        static DownloadStatus error(String toolId, String statusValue, String message) {
            DownloadStatus status = new DownloadStatus(toolId);
            status.status = statusValue;
            status.message = message;
            status.error = message;
            status.finishedAt = Instant.now();
            return status;
        }

        static DownloadStatus fromToolStatus(ToolStatus toolStatus) {
            DownloadStatus status = new DownloadStatus(toolStatus.id);
            status.status = toolStatus.installed ? "completed" : "idle";
            status.progress = toolStatus.installed ? 100 : 0;
            status.message = toolStatus.installed ? "Installed" : "Not installed";
            return status;
        }

        Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("toolId", toolId);
            map.put("status", status);
            map.put("progress", progress);
            map.put("message", message);
            map.put("error", error);
            map.put("checksum_verified", checksumVerified);
            if (startedAt != null) {
                map.put("started_at", startedAt.toString());
            }
            if (finishedAt != null) {
                map.put("finished_at", finishedAt.toString());
            }
            return map;
        }
    }
}
