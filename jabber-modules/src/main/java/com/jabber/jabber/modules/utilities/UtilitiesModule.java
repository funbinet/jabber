package com.jabber.jabber.modules.utilities;

import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.net.*;
import java.security.*;
import java.util.regex.*;
import java.lang.management.*;

/**
 * UtilitiesModule - Common utilities for JABBER framework
 * File operations, process execution, system info, network utilities, encoding utilities
 */
public class UtilitiesModule {

    /**
     * OS type enumeration
     */
    public enum OSType {
        WINDOWS, LINUX, MACOS, UNKNOWN
    }

    /**
     * Execute command and return output
     */
    public static class CommandResult {
        public int exitCode;
        public String output;
        public String error;
        public long executionTime;

        public CommandResult(int exitCode, String output, String error, long executionTime) {
            this.exitCode = exitCode;
            this.output = output;
            this.error = error;
            this.executionTime = executionTime;
        }

        @Override
        public String toString() {
            return "CommandResult{" +
                    "exitCode=" + exitCode +
                    ", executionTime=" + executionTime + "ms" +
                    ", outputSize=" + (output != null ? output.length() : 0) +
                    ", errorSize=" + (error != null ? error.length() : 0) +
                    '}';
        }
    }

    // ===== FILE OPERATIONS =====

    /**
     * Read file as string
     */
    public static String readFile(String filePath) throws Exception {
        return new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
    }

    /**
     * Write string to file
     */
    public static boolean writeFile(String filePath, String content) {
        try {
            Files.write(Paths.get(filePath), content.getBytes(StandardCharsets.UTF_8));
            return true;
        } catch (Exception e) {
            System.err.println("Error writing file: " + e.getMessage());
            return false;
        }
    }

    /**
     * Write bytes to file
     */
    public static boolean writeFile(String filePath, byte[] data) {
        try {
            Files.write(Paths.get(filePath), data);
            return true;
        } catch (Exception e) {
            System.err.println("Error writing file: " + e.getMessage());
            return false;
        }
    }

    /**
     * Read file as bytes
     */
    public static byte[] readFileBytes(String filePath) throws Exception {
        return Files.readAllBytes(Paths.get(filePath));
    }

    /**
     * Read file as lines
     */
    public static List<String> readFileLines(String filePath) throws Exception {
        return Files.readAllLines(Paths.get(filePath));
    }

    /**
     * Append to file
     */
    public static boolean appendFile(String filePath, String content) {
        try {
            Files.write(Paths.get(filePath), content.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            return true;
        } catch (Exception e) {
            System.err.println("Error appending to file: " + e.getMessage());
            return false;
        }
    }

    /**
     * Delete file
     */
    public static boolean deleteFile(String filePath) {
        try {
            return Files.deleteIfExists(Paths.get(filePath));
        } catch (Exception e) {
            System.err.println("Error deleting file: " + e.getMessage());
            return false;
        }
    }

    /**
     * Copy file
     */
    public static boolean copyFile(String source, String destination) {
        try {
            Files.copy(Paths.get(source), Paths.get(destination),
                    StandardCopyOption.REPLACE_EXISTING);
            return true;
        } catch (Exception e) {
            System.err.println("Error copying file: " + e.getMessage());
            return false;
        }
    }

    /**
     * Move file
     */
    public static boolean moveFile(String source, String destination) {
        try {
            Files.move(Paths.get(source), Paths.get(destination),
                    StandardCopyOption.REPLACE_EXISTING);
            return true;
        } catch (Exception e) {
            System.err.println("Error moving file: " + e.getMessage());
            return false;
        }
    }

    /**
     * Check if file exists
     */
    public static boolean fileExists(String filePath) {
        return Files.exists(Paths.get(filePath));
    }

    /**
     * Get file size
     */
    public static long getFileSize(String filePath) throws Exception {
        return Files.size(Paths.get(filePath));
    }

    /**
     * Get file size in human-readable format
     */
    public static String getFileSizeFormatted(String filePath) throws Exception {
        long bytes = Files.size(Paths.get(filePath));
        if (bytes <= 0) return "0 B";
        final String[] units = new String[]{"B", "KB", "MB", "GB", "TB"};
        int digitGroups = (int) (Math.log10(bytes) / Math.log10(1024));
        return String.format("%.1f %s", bytes / Math.pow(1024, digitGroups), units[digitGroups]);
    }

    /**
     * List directory contents
     */
    public static List<String> listDirectory(String dirPath) throws Exception {
        return Files.list(Paths.get(dirPath))
                .map(Path::toString)
                .collect(Collectors.toList());
    }

    /**
     * List files recursively
     */
    public static List<String> listFilesRecursive(String dirPath) throws Exception {
        return Files.walk(Paths.get(dirPath))
                .filter(Files::isRegularFile)
                .map(Path::toString)
                .collect(Collectors.toList());
    }

    /**
     * Find files by pattern
     */
    public static List<String> findFiles(String dirPath, String pattern) throws Exception {
        return Files.walk(Paths.get(dirPath))
                .filter(Files::isRegularFile)
                .filter(p -> p.getFileName().toString().matches(pattern))
                .map(Path::toString)
                .collect(Collectors.toList());
    }

    /**
     * Create directory
     */
    public static boolean createDirectory(String dirPath) {
        try {
            Files.createDirectories(Paths.get(dirPath));
            return true;
        } catch (Exception e) {
            System.err.println("Error creating directory: " + e.getMessage());
            return false;
        }
    }

    /**
     * Delete directory recursively
     */
    public static boolean deleteDirectoryRecursive(String dirPath) {
        try {
            Files.walk(Paths.get(dirPath))
                    .sorted(Comparator.reverseOrder())
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            System.err.println("Error deleting: " + path);
                        }
                    });
            return true;
        } catch (Exception e) {
            System.err.println("Error deleting directory: " + e.getMessage());
            return false;
        }
    }

    /**
     * Get file extension
     */
    public static String getFileExtension(String filePath) {
        String fileName = new File(filePath).getName();
        int lastDot = fileName.lastIndexOf('.');
        return lastDot > 0 ? fileName.substring(lastDot + 1) : "";
    }

    /**
     * Get file name without extension
     */
    public static String getFileNameWithoutExtension(String filePath) {
        String fileName = new File(filePath).getName();
        int lastDot = fileName.lastIndexOf('.');
        return lastDot > 0 ? fileName.substring(0, lastDot) : fileName;
    }

    // ===== PROCESS EXECUTION =====

    /**
     * Execute command and return result
     */
    public static CommandResult executeCommand(String command) {
        return executeCommand(command, null);
    }

    /**
     * Execute command in directory
     */
    public static CommandResult executeCommand(String command, String workDirectory) {
        long startTime = System.currentTimeMillis();
        StringBuilder output = new StringBuilder();
        StringBuilder error = new StringBuilder();
        int exitCode = -1;

        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);

            if (workDirectory != null) {
                pb.directory(new File(workDirectory));
            }

            pb.redirectErrorStream(false);
            Process process = pb.start();

            // Read output
            BufferedReader outputReader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = outputReader.readLine()) != null) {
                output.append(line).append("\n");
            }

            // Read error
            BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()));
            while ((line = errorReader.readLine()) != null) {
                error.append(line).append("\n");
            }

            exitCode = process.waitFor();

        } catch (Exception e) {
            error.append("Exception: ").append(e.getMessage());
            exitCode = -1;
        }

        long executionTime = System.currentTimeMillis() - startTime;
        return new CommandResult(exitCode, output.toString(), error.toString(), executionTime);
    }

    /**
     * Execute PowerShell command (Windows)
     */
    public static CommandResult executePowerShell(String command) {
        long startTime = System.currentTimeMillis();
        StringBuilder output = new StringBuilder();
        StringBuilder error = new StringBuilder();
        int exitCode = -1;

        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "powershell", "-NoProfile", "-Command", command);

            Process process = pb.start();

            BufferedReader outputReader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = outputReader.readLine()) != null) {
                output.append(line).append("\n");
            }

            BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()));
            while ((line = errorReader.readLine()) != null) {
                error.append(line).append("\n");
            }

            exitCode = process.waitFor();

        } catch (Exception e) {
            error.append("Exception: ").append(e.getMessage());
            exitCode = -1;
        }

        long executionTime = System.currentTimeMillis() - startTime;
        return new CommandResult(exitCode, output.toString(), error.toString(), executionTime);
    }

    /**
     * Execute with timeout
     */
    public static CommandResult executeCommandWithTimeout(String command, long timeoutSeconds) {
        long startTime = System.currentTimeMillis();
        StringBuilder output = new StringBuilder();
        StringBuilder error = new StringBuilder();
        int exitCode = -1;

        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
            Process process = pb.start();

            // Wait with timeout
            boolean finished = process.waitFor(timeoutSeconds, java.util.concurrent.TimeUnit.SECONDS);

            if (!finished) {
                process.destroyForcibly();
                return new CommandResult(-1, output.toString(), "Command timed out", 
                    System.currentTimeMillis() - startTime);
            }

            // Read output
            BufferedReader outputReader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = outputReader.readLine()) != null) {
                output.append(line).append("\n");
            }

            exitCode = process.exitValue();

        } catch (Exception e) {
            error.append("Exception: ").append(e.getMessage());
            exitCode = -1;
        }

        long executionTime = System.currentTimeMillis() - startTime;
        return new CommandResult(exitCode, output.toString(), error.toString(), executionTime);
    }

    // ===== SYSTEM INFORMATION =====

    /**
     * Get OS type
     */
    public static OSType getOSType() {
        String osName = System.getProperty("os.name").toLowerCase();
        if (osName.contains("win")) return OSType.WINDOWS;
        if (osName.contains("linux")) return OSType.LINUX;
        if (osName.contains("mac")) return OSType.MACOS;
        return OSType.UNKNOWN;
    }

    /**
     * Get OS name
     */
    public static String getOSName() {
        return System.getProperty("os.name");
    }

    /**
     * Get OS version
     */
    public static String getOSVersion() {
        return System.getProperty("os.version");
    }

    /**
     * Get OS architecture
     */
    public static String getOSArch() {
        return System.getProperty("os.arch");
    }

    /**
     * Get Java version
     */
    public static String getJavaVersion() {
        return System.getProperty("java.version");
    }

    /**
     * Get current user
     */
    public static String getCurrentUser() {
        return System.getProperty("user.name");
    }

    /**
     * Get home directory
     */
    public static String getHomeDirectory() {
        return System.getProperty("user.home");
    }

    /**
     * Get current working directory
     */
    public static String getCurrentDirectory() {
        return System.getProperty("user.dir");
    }

    /**
     * Get system memory info
     */
    public static Map<String, Long> getMemoryInfo() {
        Map<String, Long> info = new HashMap<>();
        Runtime runtime = Runtime.getRuntime();

        long totalMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();
        long usedMemory = totalMemory - freeMemory;
        long maxMemory = runtime.maxMemory();

        info.put("total", totalMemory);
        info.put("free", freeMemory);
        info.put("used", usedMemory);
        info.put("max", maxMemory);

        return info;
    }

    /**
     * Get CPU count
     */
    public static int getCPUCount() {
        return Runtime.getRuntime().availableProcessors();
    }

    /**
     * Get system uptime
     */
    public static long getSystemUptime() {
        return ManagementFactory.getRuntimeMXBean().getUptime();
    }

    /**
     * Get uptime formatted
     */
    public static String getSystemUptimeFormatted() {
        long uptime = getSystemUptime();
        long days = uptime / (1000 * 60 * 60 * 24);
        long hours = (uptime % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60);
        long minutes = (uptime % (1000 * 60 * 60)) / (1000 * 60);
        long seconds = (uptime % (1000 * 60)) / 1000;

        return String.format("%d days, %d hours, %d minutes, %d seconds", 
            days, hours, minutes, seconds);
    }

    // ===== STRING/ENCODING UTILITIES =====

    /**
     * Convert bytes to hex string
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Convert hex string to bytes
     */
    public static byte[] hexToBytes(String hex) {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return result;
    }

    /**
     * Base64 encode
     */
    public static String base64Encode(String input) {
        return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Base64 decode
     */
    public static String base64Decode(String input) {
        return new String(Base64.getDecoder().decode(input), StandardCharsets.UTF_8);
    }

    /**
     * Base64 encode bytes
     */
    public static String base64EncodeBytes(byte[] input) {
        return Base64.getEncoder().encodeToString(input);
    }

    /**
     * Base64 decode to bytes
     */
    public static byte[] base64DecodeBytes(String input) {
        return Base64.getDecoder().decode(input);
    }

    /**
     * MD5 hash
     */
    public static String md5Hash(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return bytesToHex(md.digest(input.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * SHA256 hash
     */
    public static String sha256Hash(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return bytesToHex(md.digest(input.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * SHA256 hash file
     */
    public static String sha256HashFile(String filePath) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));
        return bytesToHex(md.digest(fileBytes));
    }

    /**
     * Random string generation
     */
    public static String randomString(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    /**
     * Random hex string
     */
    public static String randomHex(int length) {
        String chars = "0123456789abcdef";
        StringBuilder sb = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    // ===== NETWORK UTILITIES =====

    /**
     * Get local IP address
     */
    public static String getLocalIP() {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress("8.8.8.8", 53));
            String ip = socket.getLocalAddress().getHostAddress();
            socket.close();
            return ip;
        } catch (Exception e) {
            return "127.0.0.1";
        }
    }

    /**
     * Get hostname
     */
    public static String getHostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return "unknown";
        }
    }

    /**
     * Check if port is open
     */
    public static boolean isPortOpen(String host, int port, int timeoutMs) {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Scan ports in range
     */
    public static List<Integer> scanOpenPorts(String host, int startPort, int endPort) {
        List<Integer> openPorts = Collections.synchronizedList(new ArrayList<>());

        for (int port = startPort; port <= endPort; port++) {
            if (isPortOpen(host, port, 1000)) {
                openPorts.add(port);
            }
        }

        return openPorts;
    }

    /**
     * Get DNS info
     */
    public static String resolveDomain(String domain) {
        try {
            return InetAddress.getByName(domain).getHostAddress();
        } catch (Exception e) {
            return "Unknown";
        }
    }

    /**
     * Get machine MAC address
     */
    public static String getMACAddress() {
        try {
            InetAddress ip = InetAddress.getLocalHost();
            byte[] mac = java.net.NetworkInterface.getByInetAddress(ip).getHardwareAddress();

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < mac.length; i++) {
                sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
            }
            return sb.toString();
        } catch (Exception e) {
            return "Unknown";
        }
    }

    // ===== DATE/TIME UTILITIES =====

    /**
     * Get current timestamp
     */
    public static long getCurrentTimestamp() {
        return System.currentTimeMillis();
    }

    /**
     * Get current timestamp (seconds)
     */
    public static long getCurrentTimestampSeconds() {
        return System.currentTimeMillis() / 1000;
    }

    /**
     * Format timestamp
     */
    public static String formatTimestamp(long timestamp) {
        return Instant.ofEpochMilli(timestamp)
                .atZone(java.time.ZoneId.systemDefault())
                .format(DateTimeFormatter.ISO_DATE_TIME);
    }

    /**
     * Get current date/time
     */
    public static String getCurrentDateTime() {
        return LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME);
    }

    /**
     * Get current date
     */
    public static String getCurrentDate() {
        return LocalDate.now().toString();
    }

    /**
     * Get difference in seconds
     */
    public static long getTimeDifferenceSeconds(long timestamp1, long timestamp2) {
        return Math.abs(timestamp1 - timestamp2) / 1000;
    }

    // ===== REGEX & PATTERN MATCHING =====

    /**
     * Check if text matches pattern
     */
    public static boolean matches(String text, String pattern) {
        return Pattern.matches(pattern, text);
    }

    /**
     * Find all matches
     */
    public static List<String> findMatches(String text, String pattern) {
        List<String> matches = new ArrayList<>();
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(text);
        while (m.find()) {
            matches.add(m.group());
        }
        return matches;
    }

    /**
     * Check if valid email
     */
    public static boolean isValidEmail(String email) {
        String emailPattern = "^[A-Za-z0-9+_.-]+@(.+)$";
        return matches(email, emailPattern);
    }

    /**
     * Check if valid IP (IPv4)
     */
    public static boolean isValidIPv4(String ip) {
        String ipPattern = "^(\\d{1,3}\\.){3}\\d{1,3}$";
        if (!matches(ip, ipPattern)) return false;

        String[] parts = ip.split("\\.");
        for (String part : parts) {
            int num = Integer.parseInt(part);
            if (num < 0 || num > 255) return false;
        }
        return true;
    }

    /**
     * Check if valid URL
     */
    public static boolean isValidURL(String url) {
        try {
            new URL(url);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // ===== COLLECTION UTILITIES =====

    /**
     * Join list with delimiter
     */
    public static String join(List<String> list, String delimiter) {
        return String.join(delimiter, list);
    }

    /**
     * Split string with limit
     */
    public static List<String> split(String text, String delimiter) {
        return Arrays.asList(text.split(delimiter));
    }

    /**
     * Unique elements from list
     */
    public static List<String> unique(List<String> list) {
        return list.stream().distinct().collect(Collectors.toList());
    }

    /**
     * Filter list by pattern
     */
    public static List<String> filterByPattern(List<String> list, String pattern) {
        return list.stream()
                .filter(s -> matches(s, pattern))
                .collect(Collectors.toList());
    }

    /**
     * Remove duplicates from list
     */
    public static List<String> removeDuplicates(List<String> list) {
        return new ArrayList<>(new LinkedHashSet<>(list));
    }

    /**
     * Reverse list
     */
    public static List<String> reverse(List<String> list) {
        List<String> reversed = new ArrayList<>(list);
        Collections.reverse(reversed);
        return reversed;
    }

    /**
     * Sort list
     */
    public static List<String> sort(List<String> list) {
        List<String> sorted = new ArrayList<>(list);
        Collections.sort(sorted);
        return sorted;
    }

    // ===== VALIDATION UTILITIES =====

    /**
     * Check if null or empty
     */
    public static boolean isEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }

    /**
     * Check if not empty
     */
    public static boolean isNotEmpty(String str) {
        return !isEmpty(str);
    }

    /**
     * Null-safe string length
     */
    public static int length(String str) {
        return str != null ? str.length() : 0;
    }

    /**
     * Safe string comparison
     */
    public static boolean equals(String str1, String str2) {
        return str1 != null && str1.equals(str2);
    }

    /**
     * Case-insensitive comparison
     */
    public static boolean equalsIgnoreCase(String str1, String str2) {
        return str1 != null && str1.equalsIgnoreCase(str2);
    }

    /**
     * Null-safe contains
     */
    public static boolean contains(String str, String substring) {
        return str != null && str.contains(substring);
    }

    // ===== PAUSE/DELAY UTILITIES =====

    /**
     * Sleep for milliseconds
     */
    public static void sleepMs(long milliseconds) {
        try {
            Thread.sleep(milliseconds);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Sleep for seconds
     */
    public static void sleepSeconds(long seconds) {
        sleepMs(seconds * 1000);
    }

    /**
     * Get system info summary
     */
    public static Map<String, String> getSystemInfoSummary() {
        Map<String, String> info = new LinkedHashMap<>();
        info.put("OS", getOSName() + " " + getOSVersion());
        info.put("Architecture", getOSArch());
        info.put("Java Version", getJavaVersion());
        info.put("Current User", getCurrentUser());
        info.put("Hostname", getHostname());
        info.put("Local IP", getLocalIP());
        info.put("CPU Cores", String.valueOf(getCPUCount()));
        info.put("System Uptime", getSystemUptimeFormatted());

        Map<String, Long> memory = getMemoryInfo();
        info.put("Memory Used", memory.get("used") / (1024 * 1024) + " MB");
        info.put("Memory Free", memory.get("free") / (1024 * 1024) + " MB");
        info.put("Memory Max", memory.get("max") / (1024 * 1024) + " MB");

        return info;
    }
}
