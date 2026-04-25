package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.Category;
import com.jabber.jrts.data.model.JRTSModule;
import com.jabber.jrts.data.model.JRTSModuleInterface;
import com.jabber.jrts.data.model.ModuleInputField;
import com.jabber.jrts.data.model.ModuleResult;
import com.jabber.jrts.data.model.RiskLevel;
import com.jabber.jrts.data.model.TaskContext;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@JRTSModule(
    id = "gen-arpsniffer",
    name = "ARP Sniffer",
    description = "Read and analyze local ARP/neighbor cache entries to enumerate IP-to-MAC mappings, interface relationships, and vendor-derived pivot hints.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.LOW,
    sourceRef = "ip neigh / arp -a / arp-scan",
    author = "JRTS"
)
public class ARPSnifferModule implements JRTSModuleInterface {

    private static final String MODULE_ID = "gen-arpsniffer";

    private static final int DEFAULT_COMMAND_TIMEOUT_MS = 4_000;
    private static final int DEFAULT_MAX_ACTIVE_HOSTS = 128;
    private static final int MAX_ACTIVE_HOSTS_LIMIT = 4_096;

    private static final Pattern IPV4_PATTERN = Pattern.compile("^(?:\\d{1,3}\\.){3}\\d{1,3}$");
    private static final Pattern MAC_PATTERN = Pattern.compile("(?i)^[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}$");
    private static final Pattern WINDOWS_INTERFACE_PATTERN = Pattern.compile(
        "^Interface:\\s*((?:\\d{1,3}\\.){3}\\d{1,3}).*$",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern WINDOWS_ARP_ENTRY_PATTERN = Pattern.compile(
        "^((?:\\d{1,3}\\.){3}\\d{1,3})\\s+([0-9a-fA-F:-]{11,17})\\s+(dynamic|static|invalid)\\b.*$",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern LEGACY_UNIX_ARP_PATTERN = Pattern.compile(
        "^((?:\\d{1,3}\\.){3}\\d{1,3})\\s+\\S+\\s+([0-9a-fA-F:-]{11,17})\\s+\\S+\\s+\\S*\\s*(\\S+)$"
    );
    private static final Pattern ARP_SCAN_INTERFACE_PATTERN = Pattern.compile(
        "^Interface:\\s*(\\S+).*$",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern ARP_SCAN_ENTRY_PATTERN = Pattern.compile(
        "^((?:\\d{1,3}\\.){3}\\d{1,3})\\s+([0-9a-fA-F:-]{11,17})\\s*(.*)$"
    );
    private static final Pattern WINDOWS_DEFAULT_ROUTE_PATTERN = Pattern.compile(
        "^0\\.0\\.0\\.0\\s+0\\.0\\.0\\.0\\s+((?:\\d{1,3}\\.){3}\\d{1,3})\\s+.*$"
    );
    private static final Pattern CIDR_PATTERN = Pattern.compile("^((?:\\d{1,3}\\.){3}\\d{1,3})/(\\d|[12]\\d|3[0-2])$");

    private static final Set<String> NEIGHBOR_STATES = Set.of(
        "REACHABLE",
        "STALE",
        "DELAY",
        "PROBE",
        "FAILED",
        "INCOMPLETE",
        "PERMANENT",
        "NOARP",
        "DYNAMIC",
        "STATIC",
        "INVALID",
        "ACTIVE_DISCOVERED",
        "UNKNOWN"
    );

    private static final List<String> VIRTUALIZATION_HINTS = List.of(
        "vmware",
        "virtualbox",
        "xen",
        "qemu",
        "hyper-v"
    );

    private static final List<String> NETWORK_INFRA_HINTS = List.of(
        "cisco",
        "juniper",
        "arista",
        "ubiquiti",
        "mikrotik",
        "aruba",
        "huawei",
        "fortinet",
        "palo alto"
    );

    private static final Map<String, String> OUI_VENDOR_MAP = buildOuiVendorMap();

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of(
                    "arp_cache_snapshot",
                    "vendor_intelligence",
                    "pivot_map",
                    "host_confirmation"
                ))
                .required()
                .defaultValue("arp_cache_snapshot")
                .group("Mode")
                .helpText("Passive ARP cache inventory, MAC vendor intelligence, pivot mapping, or focused host confirmation."),
            ModuleInputField.text("focus_host", "Focus Host (IP/MAC)")
                .placeholder("192.168.1.25 or 00:50:56:aa:bb:cc")
                .group("Mode")
                .modes("host_confirmation")
                .helpText("Required when mode=host_confirmation."),

            ModuleInputField.text("target_subnet", "Target Subnet (Optional)")
                .placeholder("192.168.1.0/24")
                .group("Target")
                .helpText("Optional CIDR/IP used for active_refresh ping warmup and arp-scan scope. Legacy aliases target/cidr are accepted."),
            ModuleInputField.text("interface", "Network Interface")
                .placeholder("eth0")
                .group("Target")
                .helpText("Optional interface filter and arp-scan interface override."),
            ModuleInputField.text("platform_hint", "Platform Hint")
                .placeholder("linux | windows | macos")
                .group("Target")
                .helpText("Optional OS hint. Defaults to automatic detection from runtime OS."),

            ModuleInputField.checkbox("active_refresh", "Enable Active Refresh")
                .defaultValue("false")
                .group("Execution")
                .helpText("If enabled, attempts active discovery (arp-scan first, then optional ping warmup) to populate additional ARP entries."),
            ModuleInputField.checkbox("use_arp_scan", "Use arp-scan When Available")
                .defaultValue("true")
                .group("Execution"),
            ModuleInputField.text("max_active_hosts", "Maximum Active Warmup Hosts")
                .placeholder(String.valueOf(DEFAULT_MAX_ACTIVE_HOSTS))
                .group("Execution")
                .helpText("Caps ping warmup host count when target_subnet is CIDR."),
            ModuleInputField.text("command_timeout_ms", "Command Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_COMMAND_TIMEOUT_MS))
                .group("Execution"),

            ModuleInputField.checkbox("include_incomplete", "Include Incomplete Entries")
                .defaultValue("true")
                .group("Output"),
            ModuleInputField.checkbox("include_ipv6", "Include IPv6 Neighbors")
                .defaultValue("false")
                .group("Output"),
            ModuleInputField.checkbox("resolve_hostnames", "Reverse Resolve Hostnames")
                .defaultValue("false")
                .group("Output")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), MODULE_ID);

            try {
                long startedAt = System.currentTimeMillis();
                ctx.log("[*] Starting ARP Sniffer module");
                ctx.reportProgress(5);

                ModuleConfig config = parseConfig(input);
                List<String> validationErrors = validateConfig(config);
                if (!validationErrors.isEmpty()) {
                    String message = String.join("; ", validationErrors);
                    result.fail("Validation failed: " + message);
                    ctx.log("[!] Validation failed: " + message);
                    return result;
                }

                String osFamily = detectOsFamily(config);
                ctx.log("[*] Mode: " + config.mode.value);
                ctx.log("[*] Platform: " + osFamily);
                ctx.reportProgress(20);

                String defaultGateway = resolveDefaultGateway(osFamily, config);
                List<ArpEntry> allEntries = readArpCache(osFamily, config, ctx);
                ctx.log("[*] Passive ARP entries observed: " + allEntries.size());
                ctx.reportProgress(45);

                int activeAdded = 0;
                int warmupProbes = 0;
                if (config.activeRefresh) {
                    List<ArpEntry> activeEntries = performActiveDiscovery(osFamily, config, ctx);
                    activeAdded += mergeEntries(allEntries, activeEntries);

                    if (activeAdded == 0 && !config.targetSubnet.isBlank()) {
                        warmupProbes = performPingWarmup(osFamily, config, ctx);
                        List<ArpEntry> refreshed = readArpCache(osFamily, config, ctx);
                        activeAdded += mergeEntries(allEntries, refreshed);
                    }
                    ctx.log("[*] Active refresh added " + activeAdded + " additional ARP record(s)");
                }
                ctx.reportProgress(65);

                List<ArpEntry> filteredEntries = new ArrayList<>();
                for (ArpEntry entry : allEntries) {
                    applyDynamicAttributes(entry, defaultGateway, config);
                    if (matchesFilters(entry, config)) {
                        filteredEntries.add(entry);
                    }
                }
                filteredEntries.sort(this::compareEntries);
                ctx.reportProgress(78);

                List<Map<String, Object>> findings = new ArrayList<>();
                for (ArpEntry entry : filteredEntries) {
                    Map<String, Object> finding = toFinding(entry);
                    findings.add(finding);
                    result.addFinding(finding);
                }

                Map<String, Object> summary = buildSummary(
                    allEntries,
                    filteredEntries,
                    config,
                    defaultGateway,
                    activeAdded,
                    warmupProbes
                );
                Map<String, Object> modeResult = buildModeResult(filteredEntries, config, defaultGateway);

                Map<String, Object> executionMetadata = new LinkedHashMap<>();
                executionMetadata.put("os_family", osFamily);
                executionMetadata.put("platform_hint", config.platformHint);
                executionMetadata.put("interface_filter", config.interfaceName);
                executionMetadata.put("target_subnet", config.targetSubnet);
                executionMetadata.put("active_refresh_enabled", config.activeRefresh);
                executionMetadata.put("use_arp_scan", config.useArpScan);
                executionMetadata.put("command_timeout_ms", config.commandTimeoutMs);
                executionMetadata.put("elapsed_ms", System.currentTimeMillis() - startedAt);

                Map<String, Object> output = new LinkedHashMap<>();
                output.put("pipeline", List.of(
                    "mode_selection",
                    "input_validation",
                    "processing_engine",
                    "execution_steps",
                    "result_normalization",
                    "structured_output"
                ));
                output.put("mode", config.mode.value);
                output.put("os_family", osFamily);
                output.put("default_gateway", defaultGateway);
                output.put("summary", summary);
                output.put("arp_entries", findings);
                output.put("operational_stack", buildOperationalStack());
                output.put(config.mode.resultKey, modeResult);
                output.put("execution_metadata", executionMetadata);

                result.setNormalizedOutput(buildNormalizedOutput(summary, findings, config));
                result.complete(output);

                ctx.log("[+] ARP Sniffer completed with " + findings.size() + " mapped entry(ies)");
                ctx.reportProgress(100);
            } catch (Exception e) {
                result.fail("ARP Sniffer execution failed: " + e.getMessage());
                ctx.log("[!] ERROR: " + e.getMessage());
            }

            return result;
        });
    }

    protected String detectOsFamily(ModuleConfig config) {
        String hint = trim(config.platformHint).toLowerCase(Locale.ROOT);
        if (!hint.isBlank()) {
            if (hint.contains("win")) {
                return "windows";
            }
            if (hint.contains("mac") || hint.contains("darwin")) {
                return "macos";
            }
            if (hint.contains("linux")) {
                return "linux";
            }
        }

        String os = trim(System.getProperty("os.name")).toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            return "windows";
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return "macos";
        }
        if (os.contains("linux")) {
            return "linux";
        }
        return "other";
    }

    protected boolean isCommandAvailable(String command) {
        List<String> check = detectOsFamily(new ModuleConfig()).equals("windows")
            ? List.of("where", command)
            : List.of("which", command);

        CommandExecutionResult result = runCommand(check, 2_000L);
        return !result.timedOut && result.exitCode == 0;
    }

    protected CommandExecutionResult runCommand(List<String> command, long timeoutMs) {
        long startedAt = System.currentTimeMillis();
        Process process = null;

        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            Process running = pb.start();
            process = running;

            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();

            Thread stdoutThread = Thread.ofVirtual().start(() -> copyStream(running.getInputStream(), stdout));
            Thread stderrThread = Thread.ofVirtual().start(() -> copyStream(running.getErrorStream(), stderr));

            boolean finished = running.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            if (!finished) {
                running.destroyForcibly();
                joinQuietly(stdoutThread, 200);
                joinQuietly(stderrThread, 200);
                return new CommandExecutionResult(-1, stdout.toString(), stderr.toString(), true,
                    System.currentTimeMillis() - startedAt);
            }

            joinQuietly(stdoutThread, 500);
            joinQuietly(stderrThread, 500);

            return new CommandExecutionResult(
                running.exitValue(),
                stdout.toString(),
                stderr.toString(),
                false,
                System.currentTimeMillis() - startedAt
            );
        } catch (Exception e) {
            return new CommandExecutionResult(
                -1,
                "",
                e.getMessage(),
                false,
                System.currentTimeMillis() - startedAt
            );
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    protected String resolveReverseDns(String ipAddress) {
        try {
            String resolved = InetAddress.getByName(ipAddress).getCanonicalHostName();
            return resolved.equals(ipAddress) ? "" : resolved;
        } catch (Exception ignored) {
            return "";
        }
    }

    protected List<ArpEntry> readArpCache(String osFamily, ModuleConfig config, TaskContext ctx) {
        List<ArpEntry> entries = new ArrayList<>();

        if ("linux".equals(osFamily) || "other".equals(osFamily)) {
            CommandExecutionResult ipNeigh = runCommand(List.of("ip", "neigh", "show"), config.commandTimeoutMs);
            if (!ipNeigh.stdout.isBlank()) {
                entries.addAll(parseIpNeighOutput(ipNeigh.stdout, "passive_cache", config.interfaceName));
                ctx.log("[*] Parsed ARP neighbors from ip neigh");
            }
        }

        if (entries.isEmpty()) {
            CommandExecutionResult arpA = runCommand(List.of("arp", "-a"), config.commandTimeoutMs);
            if (!arpA.stdout.isBlank()) {
                entries.addAll(parseArpOutput(arpA.stdout, osFamily, "passive_cache", config.interfaceName));
                ctx.log("[*] Parsed ARP neighbors from arp -a");
            }
        }

        if (entries.isEmpty() && !"linux".equals(osFamily)) {
            CommandExecutionResult ipNeigh = runCommand(List.of("ip", "neigh", "show"), config.commandTimeoutMs);
            if (!ipNeigh.stdout.isBlank()) {
                entries.addAll(parseIpNeighOutput(ipNeigh.stdout, "passive_cache", config.interfaceName));
                ctx.log("[*] Parsed ARP neighbors from ip neigh fallback");
            }
        }

        return dedupeEntries(entries);
    }

    protected List<ArpEntry> performActiveDiscovery(String osFamily, ModuleConfig config, TaskContext ctx) {
        List<ArpEntry> discovered = new ArrayList<>();
        if (!config.activeRefresh) {
            return discovered;
        }

        if (!"linux".equals(osFamily) && !"other".equals(osFamily)) {
            ctx.log("[*] Active refresh limited on this platform; relying on passive cache and optional ping warmup");
            return discovered;
        }

        if (config.useArpScan && isCommandAvailable("arp-scan")) {
            List<String> command = new ArrayList<>();
            command.add("arp-scan");
            if (!config.interfaceName.isBlank()) {
                command.add("-I");
                command.add(config.interfaceName);
            }
            if (config.targetSubnet.isBlank()) {
                command.add("-l");
            } else {
                command.add(config.targetSubnet);
            }

            CommandExecutionResult scanResult = runCommand(command, Math.max(10_000L, config.commandTimeoutMs * 4L));
            if (!scanResult.stdout.isBlank()) {
                discovered.addAll(parseArpScanOutput(scanResult.stdout, config.interfaceName));
                ctx.log("[*] Active arp-scan completed with " + discovered.size() + " discovered host(s)");
            }
        }

        return dedupeEntries(discovered);
    }

    protected int performPingWarmup(String osFamily, ModuleConfig config, TaskContext ctx) {
        if (config.targetSubnet.isBlank()) {
            return 0;
        }

        List<String> targets = expandTargets(config.targetSubnet, config.maxActiveHosts);
        if (targets.isEmpty()) {
            return 0;
        }

        int attempted = 0;
        for (String target : targets) {
            List<String> command;
            if ("windows".equals(osFamily)) {
                command = List.of("ping", "-n", "1", "-w", "800", target);
            } else {
                command = List.of("ping", "-c", "1", "-W", "1", target);
            }
            runCommand(command, Math.max(1_500L, config.commandTimeoutMs));
            attempted++;
        }

        ctx.log("[*] Active warmup probes sent: " + attempted);
        return attempted;
    }

    protected String resolveDefaultGateway(String osFamily, ModuleConfig config) {
        if ("windows".equals(osFamily)) {
            CommandExecutionResult routePrint = runCommand(List.of("route", "print", "-4"), config.commandTimeoutMs);
            return parseWindowsDefaultGateway(routePrint.stdout);
        }

        if ("macos".equals(osFamily)) {
            CommandExecutionResult routeGet = runCommand(List.of("route", "-n", "get", "default"), config.commandTimeoutMs);
            String gateway = parseMacDefaultGateway(routeGet.stdout);
            if (!gateway.isBlank()) {
                return gateway;
            }
        }

        CommandExecutionResult ipRoute = runCommand(List.of("ip", "route", "show", "default"), config.commandTimeoutMs);
        String gateway = parseLinuxDefaultGateway(ipRoute.stdout);
        if (!gateway.isBlank()) {
            return gateway;
        }

        CommandExecutionResult routeN = runCommand(List.of("route", "-n"), config.commandTimeoutMs);
        return parseRouteNDefaultGateway(routeN.stdout);
    }

    private List<ArpEntry> parseIpNeighOutput(String output, String source, String interfaceOverride) {
        List<ArpEntry> entries = new ArrayList<>();
        for (String rawLine : output.split("\\R")) {
            String line = trim(rawLine);
            if (line.isBlank()) {
                continue;
            }

            String[] tokens = line.split("\\s+");
            if (tokens.length == 0) {
                continue;
            }

            ArpEntry entry = new ArpEntry();
            entry.ipAddress = tokens[0];
            entry.interfaceName = normalizeInterfaceName(firstNonBlank(interfaceOverride, extractTokenAfter(tokens, "dev")));
            entry.macAddress = normalizeMac(extractTokenAfter(tokens, "lladdr"));
            entry.state = normalizeState(extractNeighborState(tokens));
            entry.source = source;

            if (entry.macAddress.isBlank() && "INCOMPLETE".equals(entry.state)) {
                entry.incomplete = true;
            }

            entries.add(entry);
        }
        return entries;
    }

    private List<ArpEntry> parseArpOutput(
            String output,
            String osFamily,
            String source,
            String interfaceOverride) {

        if ("windows".equals(osFamily)) {
            return parseWindowsArpOutput(output, source);
        }

        List<ArpEntry> entries = parseUnixArpOutput(output, source, interfaceOverride);
        if (!entries.isEmpty()) {
            return entries;
        }
        return parseWindowsArpOutput(output, source);
    }

    private List<ArpEntry> parseWindowsArpOutput(String output, String source) {
        List<ArpEntry> entries = new ArrayList<>();
        String currentInterface = "";

        for (String rawLine : output.split("\\R")) {
            String line = trim(rawLine);
            if (line.isBlank()) {
                continue;
            }

            Matcher interfaceMatcher = WINDOWS_INTERFACE_PATTERN.matcher(line);
            if (interfaceMatcher.matches()) {
                currentInterface = trim(interfaceMatcher.group(1));
                continue;
            }

            Matcher entryMatcher = WINDOWS_ARP_ENTRY_PATTERN.matcher(line);
            if (!entryMatcher.matches()) {
                continue;
            }

            ArpEntry entry = new ArpEntry();
            entry.ipAddress = trim(entryMatcher.group(1));
            entry.macAddress = normalizeMac(entryMatcher.group(2));
            entry.interfaceName = normalizeInterfaceName(currentInterface);
            entry.state = normalizeState(entryMatcher.group(3));
            entry.source = source;
            entries.add(entry);
        }

        return entries;
    }

    private List<ArpEntry> parseUnixArpOutput(String output, String source, String interfaceOverride) {
        List<ArpEntry> entries = new ArrayList<>();
        for (String rawLine : output.split("\\R")) {
            String line = trim(rawLine);
            if (line.isBlank()) {
                continue;
            }

            if (line.contains("(") && line.contains(")") && line.contains(" at ")) {
                int open = line.indexOf('(');
                int close = line.indexOf(')', open + 1);
                int at = line.indexOf(" at ");
                if (open >= 0 && close > open && at > close) {
                    String ip = trim(line.substring(open + 1, close));
                    String right = trim(line.substring(at + 4));
                    String[] rightTokens = right.split("\\s+");
                    String mac = rightTokens.length > 0 ? normalizeMac(rightTokens[0]) : "";
                    String iface = interfaceOverride;
                    int onIndex = line.indexOf(" on ");
                    if (onIndex > 0) {
                        String afterOn = trim(line.substring(onIndex + 4));
                        iface = firstNonBlank(interfaceOverride, firstToken(afterOn));
                    }

                    ArpEntry entry = new ArpEntry();
                    entry.ipAddress = ip;
                    entry.macAddress = "<incomplete>".equalsIgnoreCase(firstToken(right)) ? "" : mac;
                    entry.interfaceName = normalizeInterfaceName(iface);
                    entry.state = entry.macAddress.isBlank() ? "INCOMPLETE" : "DYNAMIC";
                    entry.incomplete = entry.macAddress.isBlank();
                    entry.source = source;
                    entries.add(entry);
                    continue;
                }
            }

            Matcher legacy = LEGACY_UNIX_ARP_PATTERN.matcher(line);
            if (legacy.matches()) {
                ArpEntry entry = new ArpEntry();
                entry.ipAddress = trim(legacy.group(1));
                entry.macAddress = normalizeMac(legacy.group(2));
                entry.interfaceName = normalizeInterfaceName(firstNonBlank(interfaceOverride, trim(legacy.group(3))));
                entry.state = "DYNAMIC";
                entry.source = source;
                entries.add(entry);
            }
        }
        return entries;
    }

    private List<ArpEntry> parseArpScanOutput(String output, String interfaceOverride) {
        List<ArpEntry> entries = new ArrayList<>();
        String scanInterface = "";

        for (String rawLine : output.split("\\R")) {
            String line = trim(rawLine);
            if (line.isBlank()) {
                continue;
            }

            Matcher iface = ARP_SCAN_INTERFACE_PATTERN.matcher(line);
            if (iface.matches()) {
                scanInterface = normalizeInterfaceName(trim(iface.group(1)));
                continue;
            }

            Matcher row = ARP_SCAN_ENTRY_PATTERN.matcher(line);
            if (!row.matches()) {
                continue;
            }

            ArpEntry entry = new ArpEntry();
            entry.ipAddress = trim(row.group(1));
            entry.macAddress = normalizeMac(row.group(2));
            entry.vendorHint = trim(row.group(3));
            entry.interfaceName = normalizeInterfaceName(firstNonBlank(interfaceOverride, scanInterface));
            entry.state = "ACTIVE_DISCOVERED";
            entry.source = "active_arp_scan";
            entries.add(entry);
        }
        return entries;
    }

    private void applyDynamicAttributes(ArpEntry entry, String defaultGateway, ModuleConfig config) {
        entry.ipAddress = trim(entry.ipAddress);
        entry.interfaceName = normalizeInterfaceName(firstNonBlank(entry.interfaceName, "unknown"));
        entry.macAddress = normalizeMac(entry.macAddress);
        entry.state = normalizeState(entry.state);
        entry.addressFamily = classifyAddressFamily(entry.ipAddress);

        if (entry.state.equals("INCOMPLETE") || entry.state.equals("FAILED") || entry.macAddress.isBlank()) {
            entry.incomplete = true;
        }

        entry.isGateway = !defaultGateway.isBlank() && defaultGateway.equalsIgnoreCase(entry.ipAddress);
        entry.vendor = resolveVendor(entry.macAddress, entry.vendorHint);
        entry.vendorKnown = !"Unknown".equals(entry.vendor);

        if (config.resolveHostnames && !entry.ipAddress.isBlank()) {
            entry.hostname = resolveReverseDns(entry.ipAddress);
        }

        entry.deviceHint = inferDeviceHint(entry);
    }

    private String resolveVendor(String macAddress, String vendorHint) {
        String hint = trim(vendorHint);
        if (!hint.isBlank() && !"unknown".equalsIgnoreCase(hint)) {
            return hint;
        }

        String oui = normalizeOui(macAddress);
        if (oui.isBlank()) {
            return "Unknown";
        }
        return OUI_VENDOR_MAP.getOrDefault(oui, "Unknown");
    }

    private String inferDeviceHint(ArpEntry entry) {
        if (entry.isGateway) {
            return "gateway";
        }
        if (entry.incomplete) {
            return "incomplete_neighbor";
        }

        String vendor = trim(entry.vendor).toLowerCase(Locale.ROOT);
        for (String hint : VIRTUALIZATION_HINTS) {
            if (vendor.contains(hint)) {
                return "virtualized_host";
            }
        }
        for (String hint : NETWORK_INFRA_HINTS) {
            if (vendor.contains(hint)) {
                return "network_infrastructure";
            }
        }
        if (entry.vendorKnown) {
            return "host";
        }
        return "unknown_device";
    }

    private boolean matchesFilters(ArpEntry entry, ModuleConfig config) {
        if (!config.includeIpv6 && "ipv6".equals(entry.addressFamily)) {
            return false;
        }

        if (!config.includeIncomplete && entry.incomplete) {
            return false;
        }

        if (!config.interfaceName.isBlank() && !entry.interfaceName.equalsIgnoreCase(config.interfaceName)) {
            return false;
        }

        if (config.mode == ModuleMode.HOST_CONFIRMATION) {
            return matchesFocus(entry, config.focusHost);
        }

        return true;
    }

    private boolean matchesFocus(ArpEntry entry, String focusHost) {
        String focus = trim(focusHost).toLowerCase(Locale.ROOT);
        if (focus.isBlank()) {
            return false;
        }

        String normalizedFocusMac = normalizeMac(focus);
        String entryMac = normalizeMac(entry.macAddress);

        return entry.ipAddress.equalsIgnoreCase(focus)
            || (!normalizedFocusMac.isBlank() && normalizedFocusMac.equals(entryMac))
            || trim(entry.hostname).toLowerCase(Locale.ROOT).contains(focus)
            || trim(entry.interfaceName).toLowerCase(Locale.ROOT).contains(focus);
    }

    private int compareEntries(ArpEntry left, ArpEntry right) {
        int family = Integer.compare(addressFamilyRank(left.addressFamily), addressFamilyRank(right.addressFamily));
        if (family != 0) {
            return family;
        }

        if ("ipv4".equals(left.addressFamily) && "ipv4".equals(right.addressFamily)) {
            int ipCompare = Long.compare(ipToLong(left.ipAddress), ipToLong(right.ipAddress));
            if (ipCompare != 0) {
                return ipCompare;
            }
        } else {
            int lexical = left.ipAddress.compareToIgnoreCase(right.ipAddress);
            if (lexical != 0) {
                return lexical;
            }
        }

        int iface = left.interfaceName.compareToIgnoreCase(right.interfaceName);
        if (iface != 0) {
            return iface;
        }

        return left.macAddress.compareToIgnoreCase(right.macAddress);
    }

    private int addressFamilyRank(String family) {
        return switch (family) {
            case "ipv4" -> 0;
            case "ipv6" -> 1;
            default -> 2;
        };
    }

    private int mergeEntries(List<ArpEntry> baseEntries, List<ArpEntry> incomingEntries) {
        Map<String, ArpEntry> keyed = new LinkedHashMap<>();
        for (ArpEntry entry : baseEntries) {
            keyed.put(entry.primaryKey(), entry);
        }

        int added = 0;
        for (ArpEntry incoming : incomingEntries) {
            String key = incoming.primaryKey();
            ArpEntry existing = keyed.get(key);
            if (existing == null) {
                baseEntries.add(incoming);
                keyed.put(key, incoming);
                added++;
            } else {
                existing.mergeFrom(incoming);
            }
        }

        return added;
    }

    private List<ArpEntry> dedupeEntries(List<ArpEntry> entries) {
        List<ArpEntry> deduped = new ArrayList<>();
        mergeEntries(deduped, entries);
        return deduped;
    }

    private Map<String, Object> toFinding(ArpEntry entry) {
        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("ip_address", entry.ipAddress);
        finding.put("mac_address", entry.macAddress);
        finding.put("interface", entry.interfaceName);
        finding.put("state", entry.state);
        finding.put("address_family", entry.addressFamily);
        finding.put("vendor", entry.vendor);
        finding.put("vendor_known", entry.vendorKnown);
        finding.put("device_hint", entry.deviceHint);
        finding.put("hostname", entry.hostname);
        finding.put("is_gateway", entry.isGateway);
        finding.put("incomplete", entry.incomplete);
        finding.put("source", entry.source);
        return finding;
    }

    private Map<String, Object> buildSummary(
            List<ArpEntry> allEntries,
            List<ArpEntry> filteredEntries,
            ModuleConfig config,
            String defaultGateway,
            int activeAdded,
            int warmupProbes) {

        long ipv4 = filteredEntries.stream().filter(e -> "ipv4".equals(e.addressFamily)).count();
        long ipv6 = filteredEntries.stream().filter(e -> "ipv6".equals(e.addressFamily)).count();
        long incomplete = filteredEntries.stream().filter(e -> e.incomplete).count();
        long knownVendors = filteredEntries.stream().filter(e -> e.vendorKnown).count();
        long networkHints = filteredEntries.stream()
            .filter(e -> e.isGateway || "network_infrastructure".equals(e.deviceHint))
            .count();
        long virtualizedHints = filteredEntries.stream()
            .filter(e -> "virtualized_host".equals(e.deviceHint))
            .count();

        Set<String> uniqueMacs = new HashSet<>();
        Set<String> interfaces = new HashSet<>();
        for (ArpEntry entry : filteredEntries) {
            if (!entry.macAddress.isBlank()) {
                uniqueMacs.add(entry.macAddress);
            }
            if (!entry.interfaceName.isBlank()) {
                interfaces.add(entry.interfaceName);
            }
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", config.mode.value);
        summary.put("total_observed_entries", allEntries.size());
        summary.put("total_entries", filteredEntries.size());
        summary.put("ipv4_entries", ipv4);
        summary.put("ipv6_entries", ipv6);
        summary.put("unique_mac_count", uniqueMacs.size());
        summary.put("incomplete_entries", incomplete);
        summary.put("known_vendor_entries", knownVendors);
        summary.put("unknown_vendor_entries", Math.max(0L, filteredEntries.size() - knownVendors));
        summary.put("network_infrastructure_hints", networkHints);
        summary.put("virtualized_host_hints", virtualizedHints);
        summary.put("gateway_present", filteredEntries.stream().anyMatch(e -> e.isGateway));
        summary.put("default_gateway", defaultGateway);
        summary.put("interface_count", interfaces.size());
        summary.put("active_refresh_enabled", config.activeRefresh);
        summary.put("active_refresh_entries_added", activeAdded);
        summary.put("warmup_probe_count", warmupProbes);
        return summary;
    }

    private Map<String, Object> buildModeResult(
            List<ArpEntry> entries,
            ModuleConfig config,
            String defaultGateway) {

        return switch (config.mode) {
            case ARP_CACHE_SNAPSHOT -> buildSnapshotResult(entries);
            case VENDOR_INTELLIGENCE -> buildVendorResult(entries);
            case PIVOT_MAP -> buildPivotResult(entries, defaultGateway);
            case HOST_CONFIRMATION -> buildHostConfirmationResult(entries, config.focusHost);
        };
    }

    private Map<String, Object> buildSnapshotResult(List<ArpEntry> entries) {
        Map<String, Integer> stateCounts = new LinkedHashMap<>();
        Map<String, Integer> interfaceCounts = new LinkedHashMap<>();

        for (ArpEntry entry : entries) {
            stateCounts.put(entry.state, stateCounts.getOrDefault(entry.state, 0) + 1);
            interfaceCounts.put(entry.interfaceName, interfaceCounts.getOrDefault(entry.interfaceName, 0) + 1);
        }

        List<Map<String, Object>> inventory = entries.stream()
            .map(this::inventoryView)
            .toList();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("inventory_size", entries.size());
        result.put("state_counts", stateCounts);
        result.put("interface_counts", interfaceCounts);
        result.put("mappings", inventory);
        return result;
    }

    private Map<String, Object> buildVendorResult(List<ArpEntry> entries) {
        Map<String, List<ArpEntry>> grouped = new LinkedHashMap<>();
        for (ArpEntry entry : entries) {
            grouped.computeIfAbsent(entry.vendor, ignored -> new ArrayList<>()).add(entry);
        }

        List<Map<String, Object>> vendorGroups = new ArrayList<>();
        for (Map.Entry<String, List<ArpEntry>> row : grouped.entrySet()) {
            List<String> ips = row.getValue().stream().map(e -> e.ipAddress).sorted().toList();
            List<String> macs = row.getValue().stream()
                .map(e -> e.macAddress)
                .filter(mac -> !mac.isBlank())
                .distinct()
                .sorted()
                .toList();

            Map<String, Object> group = new LinkedHashMap<>();
            group.put("vendor", row.getKey());
            group.put("host_count", row.getValue().size());
            group.put("ip_addresses", ips);
            group.put("mac_addresses", macs);
            vendorGroups.add(group);
        }
        vendorGroups.sort(Comparator.comparingInt(group -> -((Number) group.get("host_count")).intValue()));

        List<Map<String, Object>> unknownVendorEntries = entries.stream()
            .filter(entry -> !entry.vendorKnown)
            .map(this::inventoryView)
            .toList();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("vendor_group_count", vendorGroups.size());
        result.put("vendor_groups", vendorGroups);
        result.put("unknown_vendor_entries", unknownVendorEntries);
        return result;
    }

    private Map<String, Object> buildPivotResult(List<ArpEntry> entries, String defaultGateway) {
        ArpEntry gateway = entries.stream().filter(e -> e.isGateway).findFirst().orElse(null);

        List<Map<String, Object>> infrastructure = entries.stream()
            .filter(e -> e.isGateway || "network_infrastructure".equals(e.deviceHint))
            .map(this::inventoryView)
            .toList();

        List<Map<String, Object>> duplicateMacGroups = buildDuplicateMacGroups(entries);

        List<Map<String, Object>> pivotCandidates = entries.stream()
            .filter(e -> !e.incomplete)
            .filter(e -> !e.isGateway)
            .map(this::inventoryView)
            .toList();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("default_gateway", defaultGateway);
        result.put("gateway_entry", gateway == null ? Map.of() : inventoryView(gateway));
        result.put("infrastructure_candidates", infrastructure);
        result.put("duplicate_mac_groups", duplicateMacGroups);
        result.put("pivot_candidates", pivotCandidates);
        return result;
    }

    private Map<String, Object> buildHostConfirmationResult(List<ArpEntry> entries, String focusHost) {
        List<Map<String, Object>> matches = entries.stream().map(this::inventoryView).toList();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("focus_host", focusHost);
        result.put("confirmed", !matches.isEmpty());
        result.put("match_count", matches.size());
        result.put("matches", matches);
        return result;
    }

    private List<Map<String, Object>> buildDuplicateMacGroups(List<ArpEntry> entries) {
        Map<String, List<String>> grouped = new LinkedHashMap<>();
        for (ArpEntry entry : entries) {
            if (entry.macAddress.isBlank()) {
                continue;
            }
            grouped.computeIfAbsent(entry.macAddress, ignored -> new ArrayList<>()).add(entry.ipAddress);
        }

        List<Map<String, Object>> groups = new ArrayList<>();
        for (Map.Entry<String, List<String>> row : grouped.entrySet()) {
            List<String> ips = row.getValue().stream().distinct().sorted().toList();
            if (ips.size() < 2) {
                continue;
            }

            Map<String, Object> group = new LinkedHashMap<>();
            group.put("mac_address", row.getKey());
            group.put("ip_count", ips.size());
            group.put("ip_addresses", ips);
            groups.add(group);
        }

        groups.sort(Comparator.comparingInt(group -> -((Number) group.get("ip_count")).intValue()));
        return groups;
    }

    private Map<String, Object> inventoryView(ArpEntry entry) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ip_address", entry.ipAddress);
        row.put("mac_address", entry.macAddress);
        row.put("interface", entry.interfaceName);
        row.put("state", entry.state);
        row.put("vendor", entry.vendor);
        row.put("device_hint", entry.deviceHint);
        row.put("hostname", entry.hostname);
        row.put("is_gateway", entry.isGateway);
        row.put("source", entry.source);
        return row;
    }

    private Map<String, Object> buildNormalizedOutput(
            Map<String, Object> summary,
            List<Map<String, Object>> findings,
            ModuleConfig config) {

        long total = ((Number) summary.getOrDefault("total_entries", 0)).longValue();

        Map<String, Object> rawOutput = new LinkedHashMap<>();
        rawOutput.put("summary", summary);
        rawOutput.put("entry_count", findings.size());

        Map<String, Object> parsedOutput = new LinkedHashMap<>();
        parsedOutput.put("status", total > 0
            ? "ARP_NEIGHBOR_RELATIONSHIPS_IDENTIFIED"
            : "NO_ARP_NEIGHBORS_OBSERVED");
        parsedOutput.put("vulnerable", false);
        parsedOutput.put("details", summary);
        parsedOutput.put("evidence", findings);

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("module", MODULE_ID);
        metadata.put("mode", config.mode.value);

        Map<String, Object> normalized = new LinkedHashMap<>();
        normalized.put("raw_output", rawOutput);
        normalized.put("parsed_output", parsedOutput);
        normalized.put("metadata", metadata);
        return normalized;
    }

    private List<Map<String, Object>> buildOperationalStack() {
        List<Map<String, Object>> stack = new ArrayList<>();
        stack.add(tool("ip neigh", "Linux neighbor table inspection for passive ARP cache mapping", "https://man7.org/linux/man-pages/man8/ip-neighbour.8.html"));
        stack.add(tool("arp -a", "Cross-platform ARP table inspection (Linux/macOS/Windows)", "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/arp"));
        stack.add(tool("arp-scan", "Active local segment ARP discovery and OUI mapping", "https://github.com/royhills/arp-scan"));
        stack.add(tool("netdiscover", "Active ARP-based host discovery across local ranges", "https://tools.kali.org/information-gathering/netdiscover"));
        stack.add(tool("Wireshark", "Passive ARP frame analysis for traffic-level verification", "https://www.wireshark.org/"));
        stack.add(tool("RFC 826", "ARP protocol reference and expected behavior baseline", "https://www.rfc-editor.org/rfc/rfc826"));
        return stack;
    }

    private Map<String, Object> tool(String name, String purpose, String reference) {
        Map<String, Object> tool = new LinkedHashMap<>();
        tool.put("name", name);
        tool.put("purpose", purpose);
        tool.put("reference", reference);
        return tool;
    }

    private ModuleConfig parseConfig(Map<String, String> input) {
        ModuleConfig config = new ModuleConfig();
        config.mode = ModuleMode.fromInput(firstNonBlank(input.get("mode"), "arp_cache_snapshot"));
        config.focusHost = firstNonBlank(input.get("focus_host"), input.get("identify_target"), input.get("target_host"));
        config.targetSubnet = firstNonBlank(input.get("target_subnet"), input.get("target"), input.get("cidr"));
        config.interfaceName = firstNonBlank(input.get("interface"), input.get("network_interface"), input.get("iface"));
        config.platformHint = trim(input.get("platform_hint"));

        config.activeRefresh = parseBoolean(input.get("active_refresh"), false);
        config.useArpScan = parseBoolean(input.get("use_arp_scan"), true);
        config.maxActiveHosts = parseInteger(input.get("max_active_hosts"), DEFAULT_MAX_ACTIVE_HOSTS);
        config.commandTimeoutMs = parseInteger(input.get("command_timeout_ms"), DEFAULT_COMMAND_TIMEOUT_MS);

        config.includeIncomplete = parseBoolean(input.get("include_incomplete"), true);
        config.includeIpv6 = parseBoolean(input.get("include_ipv6"), false);
        config.resolveHostnames = parseBoolean(input.get("resolve_hostnames"), false);
        return config;
    }

    private List<String> validateConfig(ModuleConfig config) {
        List<String> errors = new ArrayList<>();

        if (config.mode == ModuleMode.HOST_CONFIRMATION && config.focusHost.isBlank()) {
            errors.add("focus_host is required when mode=host_confirmation");
        }

        if (config.commandTimeoutMs < 500 || config.commandTimeoutMs > 120_000) {
            errors.add("command_timeout_ms must be between 500 and 120000");
        }

        if (config.maxActiveHosts < 1 || config.maxActiveHosts > MAX_ACTIVE_HOSTS_LIMIT) {
            errors.add("max_active_hosts must be between 1 and " + MAX_ACTIVE_HOSTS_LIMIT);
        }

        if (!config.targetSubnet.isBlank() && !isIpv4(config.targetSubnet) && !isIpv4Cidr(config.targetSubnet)) {
            errors.add("target_subnet must be an IPv4 address or CIDR (for example 192.168.1.0/24)");
        }

        return errors;
    }

    private String parseLinuxDefaultGateway(String output) {
        for (String rawLine : output.split("\\R")) {
            String line = trim(rawLine);
            if (!line.startsWith("default")) {
                continue;
            }
            String[] tokens = line.split("\\s+");
            for (int i = 0; i < tokens.length - 1; i++) {
                if ("via".equals(tokens[i]) && isIpv4(tokens[i + 1])) {
                    return tokens[i + 1];
                }
            }
        }
        return "";
    }

    private String parseRouteNDefaultGateway(String output) {
        for (String rawLine : output.split("\\R")) {
            String line = trim(rawLine);
            if (line.startsWith("0.0.0.0")) {
                String[] tokens = line.split("\\s+");
                if (tokens.length > 1 && isIpv4(tokens[1])) {
                    return tokens[1];
                }
            }
        }
        return "";
    }

    private String parseWindowsDefaultGateway(String output) {
        for (String rawLine : output.split("\\R")) {
            String line = trim(rawLine);
            Matcher matcher = WINDOWS_DEFAULT_ROUTE_PATTERN.matcher(line);
            if (matcher.matches()) {
                String gateway = trim(matcher.group(1));
                if (isIpv4(gateway)) {
                    return gateway;
                }
            }
        }
        return "";
    }

    private String parseMacDefaultGateway(String output) {
        for (String rawLine : output.split("\\R")) {
            String line = trim(rawLine);
            if (line.toLowerCase(Locale.ROOT).startsWith("gateway:")) {
                String gateway = trim(line.substring(line.indexOf(':') + 1));
                return isIpv4(gateway) ? gateway : "";
            }
        }
        return "";
    }

    private List<String> expandTargets(String subnetOrIp, int maxHosts) {
        String target = trim(subnetOrIp);
        if (target.isBlank()) {
            return List.of();
        }
        if (isIpv4(target)) {
            return List.of(target);
        }

        Matcher cidr = CIDR_PATTERN.matcher(target);
        if (!cidr.matches()) {
            return List.of();
        }

        String baseIp = cidr.group(1);
        int prefix = Integer.parseInt(cidr.group(2));
        long base = ipToLong(baseIp);
        long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        long network = base & mask;
        long broadcast = network | (~mask & 0xFFFFFFFFL);

        long start = prefix >= 31 ? network : network + 1;
        long end = prefix >= 31 ? broadcast : broadcast - 1;

        List<String> hosts = new ArrayList<>();
        for (long current = start; current <= end; current++) {
            hosts.add(longToIp(current));
            if (hosts.size() >= maxHosts) {
                break;
            }
        }
        return hosts;
    }

    private String classifyAddressFamily(String ipAddress) {
        String ip = trim(ipAddress);
        if (ip.contains(":")) {
            return "ipv6";
        }
        if (isIpv4(ip)) {
            return "ipv4";
        }
        return "unknown";
    }

    private String normalizeState(String rawState) {
        String state = trim(rawState).toUpperCase(Locale.ROOT);
        if (state.isBlank()) {
            return "UNKNOWN";
        }
        return NEIGHBOR_STATES.contains(state) ? state : "UNKNOWN";
    }

    private String extractNeighborState(String[] tokens) {
        for (int i = tokens.length - 1; i >= 0; i--) {
            String token = trim(tokens[i]).toUpperCase(Locale.ROOT);
            if (NEIGHBOR_STATES.contains(token)) {
                return token;
            }
        }
        for (String token : tokens) {
            String upper = trim(token).toUpperCase(Locale.ROOT);
            if ("INCOMPLETE".equals(upper) || "FAILED".equals(upper)) {
                return upper;
            }
        }
        return "UNKNOWN";
    }

    private String extractTokenAfter(String[] tokens, String marker) {
        for (int i = 0; i < tokens.length - 1; i++) {
            if (marker.equalsIgnoreCase(tokens[i])) {
                return tokens[i + 1];
            }
        }
        return "";
    }

    private long ipToLong(String ipAddress) {
        if (!isIpv4(ipAddress)) {
            return Long.MAX_VALUE;
        }
        String[] octets = ipAddress.split("\\.");
        long value = 0;
        for (int i = 0; i < 4; i++) {
            value = (value << 8) | Integer.parseInt(octets[i]);
        }
        return value & 0xFFFFFFFFL;
    }

    private String longToIp(long ip) {
        return ((ip >>> 24) & 0xFF) + "."
            + ((ip >>> 16) & 0xFF) + "."
            + ((ip >>> 8) & 0xFF) + "."
            + (ip & 0xFF);
    }

    private boolean isIpv4(String value) {
        if (!IPV4_PATTERN.matcher(trim(value)).matches()) {
            return false;
        }
        String[] octets = trim(value).split("\\.");
        for (String octet : octets) {
            int parsed = Integer.parseInt(octet);
            if (parsed < 0 || parsed > 255) {
                return false;
            }
        }
        return true;
    }

    private boolean isIpv4Cidr(String value) {
        Matcher matcher = CIDR_PATTERN.matcher(trim(value));
        if (!matcher.matches()) {
            return false;
        }
        return isIpv4(matcher.group(1));
    }

    private String normalizeMac(String rawMac) {
        String value = trim(rawMac);
        if (value.isBlank() || "<incomplete>".equalsIgnoreCase(value) || "(incomplete)".equalsIgnoreCase(value)) {
            return "";
        }

        String normalized = value.replace('-', ':').toLowerCase(Locale.ROOT);
        if (!MAC_PATTERN.matcher(normalized).matches()) {
            return "";
        }
        return normalized;
    }

    private String normalizeInterfaceName(String rawInterface) {
        String iface = trim(rawInterface);
        while (iface.endsWith(",") || iface.endsWith(";")) {
            iface = iface.substring(0, iface.length() - 1).trim();
        }
        return iface;
    }

    private String normalizeOui(String macAddress) {
        String mac = normalizeMac(macAddress);
        if (mac.isBlank()) {
            return "";
        }
        String hex = mac.replace(":", "").toUpperCase(Locale.ROOT);
        return hex.length() >= 6 ? hex.substring(0, 6) : "";
    }

    private String firstToken(String value) {
        String trimmed = trim(value);
        if (trimmed.isBlank()) {
            return "";
        }
        String[] parts = trimmed.split("\\s+");
        return parts.length == 0 ? "" : parts[0];
    }

    private int parseInteger(String value, int defaultValue) {
        String token = trim(value);
        if (token.isBlank()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(token);
        } catch (NumberFormatException ignored) {
            return defaultValue;
        }
    }

    private boolean parseBoolean(String value, boolean defaultValue) {
        String token = trim(value);
        if (token.isBlank()) {
            return defaultValue;
        }
        return Boolean.parseBoolean(token);
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.trim().isBlank()) {
                return value.trim();
            }
        }
        return "";
    }

    private String trim(String value) {
        return value == null ? "" : value.trim();
    }

    private static Map<String, String> buildOuiVendorMap() {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("005056", "VMware");
        map.put("000C29", "VMware");
        map.put("001C14", "VMware");
        map.put("080027", "VirtualBox");
        map.put("00155D", "Microsoft Hyper-V");
        map.put("F01898", "Cisco");
        map.put("001B54", "Cisco");
        map.put("3C5282", "Dell");
        map.put("F0D1A9", "Dell");
        map.put("3C970E", "Hewlett Packard Enterprise");
        map.put("00163E", "Apple");
        map.put("B827EB", "Raspberry Pi Foundation");
        map.put("D850E6", "Ubiquiti Networks");
        map.put("44D9E7", "Juniper Networks");
        return map;
    }

    private void copyStream(InputStream stream, StringBuilder sink) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sink.append(line).append('\n');
            }
        } catch (IOException ignored) {
            // no-op
        }
    }

    private void joinQuietly(Thread thread, long timeoutMs) {
        try {
            thread.join(timeoutMs);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    protected static class CommandExecutionResult {
        protected final int exitCode;
        protected final String stdout;
        protected final String stderr;
        protected final boolean timedOut;
        protected final long elapsedMs;

        protected CommandExecutionResult(
                int exitCode,
                String stdout,
                String stderr,
                boolean timedOut,
                long elapsedMs) {

            this.exitCode = exitCode;
            this.stdout = stdout == null ? "" : stdout;
            this.stderr = stderr == null ? "" : stderr;
            this.timedOut = timedOut;
            this.elapsedMs = elapsedMs;
        }
    }

    protected enum ModuleMode {
        ARP_CACHE_SNAPSHOT("arp_cache_snapshot", "arp_cache_snapshot_result"),
        VENDOR_INTELLIGENCE("vendor_intelligence", "vendor_intelligence_result"),
        PIVOT_MAP("pivot_map", "pivot_map_result"),
        HOST_CONFIRMATION("host_confirmation", "host_confirmation_result");

        private final String value;
        private final String resultKey;

        ModuleMode(String value, String resultKey) {
            this.value = value;
            this.resultKey = resultKey;
        }

        private static ModuleMode fromInput(String raw) {
            String normalized = raw == null
                ? ""
                : raw.trim().toLowerCase(Locale.ROOT).replace('-', '_').replace(' ', '_');

            return switch (normalized) {
                case "vendor", "vendor_intel", "vendor_intelligence" -> VENDOR_INTELLIGENCE;
                case "pivot", "pivot_map", "pivot_mapping" -> PIVOT_MAP;
                case "host_confirmation", "identify", "confirmation" -> HOST_CONFIRMATION;
                default -> ARP_CACHE_SNAPSHOT;
            };
        }
    }

    protected static class ModuleConfig {
        protected ModuleMode mode = ModuleMode.ARP_CACHE_SNAPSHOT;
        protected String focusHost = "";
        protected String targetSubnet = "";
        protected String interfaceName = "";
        protected String platformHint = "";

        protected boolean activeRefresh;
        protected boolean useArpScan = true;
        protected int maxActiveHosts = DEFAULT_MAX_ACTIVE_HOSTS;
        protected int commandTimeoutMs = DEFAULT_COMMAND_TIMEOUT_MS;

        protected boolean includeIncomplete = true;
        protected boolean includeIpv6;
        protected boolean resolveHostnames;
    }

    protected static class ArpEntry {
        protected String ipAddress = "";
        protected String macAddress = "";
        protected String interfaceName = "";
        protected String state = "UNKNOWN";
        protected String addressFamily = "unknown";
        protected String vendor = "Unknown";
        protected String vendorHint = "";
        protected boolean vendorKnown;
        protected String deviceHint = "unknown_device";
        protected String hostname = "";
        protected boolean isGateway;
        protected boolean incomplete;
        protected String source = "passive_cache";

        protected String primaryKey() {
            String ip = ipAddress == null ? "" : ipAddress.toLowerCase(Locale.ROOT);
            String iface = interfaceName == null ? "" : interfaceName.toLowerCase(Locale.ROOT);
            String mac = macAddress == null ? "" : macAddress.toLowerCase(Locale.ROOT);
            if (!mac.isBlank()) {
                return ip + "|" + mac + "|" + iface;
            }
            return ip + "||" + iface;
        }

        protected void mergeFrom(ArpEntry other) {
            if (other == null) {
                return;
            }
            if (macAddress.isBlank() && !other.macAddress.isBlank()) {
                macAddress = other.macAddress;
            }
            if (interfaceName.isBlank() && !other.interfaceName.isBlank()) {
                interfaceName = other.interfaceName;
            }
            if (("UNKNOWN".equals(state) || state.isBlank()) && !other.state.isBlank()) {
                state = other.state;
            }
            if (vendorHint.isBlank() && !other.vendorHint.isBlank()) {
                vendorHint = other.vendorHint;
            }
            if (hostname.isBlank() && !other.hostname.isBlank()) {
                hostname = other.hostname;
            }
            if (!source.contains(other.source)) {
                source = source + "," + other.source;
            }
            incomplete = incomplete || other.incomplete;
        }
    }

}
