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
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Network Ping Sweep (Enhanced Host Discovery).
 *
 * Reality model:
 * - Core sweep identifies host reachability.
 * - Latency/loss add response quality.
 * - Service/throughput views are optional enrichment layers.
 *
 * Pipeline:
 * mode selection -> input validation -> multi-protocol discovery -> optional enrichment -> structured output.
 */
@JRTSModule(
    id = "recon-ping-sweep",
    name = "Network Ping Sweep (Enhanced Host Discovery)",
    description = "Scan IPv4 ranges for live hosts with ICMP and auxiliary probes, then optionally enrich results with latency, packet-loss, basic service exposure, and performance indicators.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.MEDIUM,
    sourceRef = "nmap/fping/arp-scan/hping3",
    author = "JRTS"
)
public class NetworkPingSweepModule implements JRTSModuleInterface {

    private static final String MODULE_ID = "recon-ping-sweep";

    private static final int DEFAULT_TIMEOUT_MS = 1200;
    private static final int DEFAULT_PROBE_COUNT = 2;
    private static final int DEFAULT_CONFIRMATION_ATTEMPTS = 3;
    private static final int DEFAULT_CONCURRENCY = 32;
    private static final int DEFAULT_MAX_HOSTS = 1024;
    private static final int MAX_HOSTS_LIMIT = 65534;
    private static final int MAX_CONCURRENCY_LIMIT = 512;

    private static final String DEFAULT_TCP_FALLBACK_PORTS = "80,443";
    private static final String DEFAULT_SERVICE_PORTS = "22,80,443,445,3389";

    private static final Pattern NMAP_HOST_PATTERN = Pattern.compile(
        "Nmap\\s+scan\\s+report\\s+for\\s+(?:.+?\\()?((?:\\d{1,3}\\.){3}\\d{1,3})\\)?",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern IPV4_PATTERN = Pattern.compile("((?:\\d{1,3}\\.){3}\\d{1,3})");
    private static final Pattern RTT_PATTERN = Pattern.compile(
        "time[=<]\\s*([0-9]+(?:\\.[0-9]+)?)\\s*ms",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern WINDOWS_AVERAGE_PATTERN = Pattern.compile(
        "Average\\s*=\\s*([0-9]+)ms",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern NMAP_OPEN_PORT_PATTERN = Pattern.compile(
        "^(\\d{1,5})/tcp\\s+open\\s+(\\S+).*$",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern MASSCAN_HOST_PATTERN = Pattern.compile(
        "Discovered\\s+open\\s+port\\s+\\d+/tcp\\s+on\\s+((?:\\d{1,3}\\.){3}\\d{1,3})",
        Pattern.CASE_INSENSITIVE
    );

    private final Map<String, Boolean> commandAvailabilityCache = new ConcurrentHashMap<>();

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of(
                    "host_discovery",
                    "latency_profile",
                    "enhanced_discovery",
                    "host_confirmation"
                ))
                .required()
                .defaultValue("host_discovery")
                .group("Mode")
                .helpText("Host discovery only, ICMP profile, enhanced discovery with optional enrichment, or focused host confirmation."),

            ModuleInputField.text("target_subnet", "Target Subnet (CIDR)")
                .placeholder("192.168.1.0/24 or 10.0.0.0/16")
                .group("Target")
                .modes("host_discovery", "latency_profile", "enhanced_discovery")
                .helpText("CIDR or single IPv4 target for sweep modes."),
            ModuleInputField.text("confirmation_target", "Confirmation Target")
                .placeholder("192.168.1.25")
                .group("Mode")
                .modes("host_confirmation")
                .helpText("Required when mode=host_confirmation."),

            ModuleInputField.text("timeout_ms", "Probe Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_TIMEOUT_MS))
                .group("Execution"),
            ModuleInputField.text("probe_count", "Probe Count")
                .placeholder(String.valueOf(DEFAULT_PROBE_COUNT))
                .group("Execution")
                .modes("latency_profile", "enhanced_discovery")
                .helpText("ICMP attempts per host used for packet loss and latency profiling."),
            ModuleInputField.text("confirmation_attempts", "Confirmation Attempts")
                .placeholder(String.valueOf(DEFAULT_CONFIRMATION_ATTEMPTS))
                .group("Execution")
                .modes("host_confirmation"),
            ModuleInputField.text("concurrency", "Concurrency")
                .placeholder(String.valueOf(DEFAULT_CONCURRENCY))
                .group("Execution"),
            ModuleInputField.text("max_hosts", "Maximum Hosts")
                .placeholder(String.valueOf(DEFAULT_MAX_HOSTS))
                .group("Execution")
                .modes("host_discovery", "latency_profile", "enhanced_discovery"),
            ModuleInputField.text("inter_probe_delay_ms", "Inter-Probe Delay (ms)")
                .placeholder("0")
                .group("Execution"),

            ModuleInputField.checkbox("resolve_dns", "Resolve DNS")
                .defaultValue("false")
                .group("Output"),
            ModuleInputField.checkbox("include_nonresponsive", "Include Non-Responsive Hosts")
                .defaultValue("true")
                .group("Output"),

            ModuleInputField.checkbox("use_nmap", "Use nmap")
                .defaultValue("true")
                .group("Discovery Tools"),
            ModuleInputField.checkbox("use_fping", "Use fping")
                .defaultValue("true")
                .group("Discovery Tools"),
            ModuleInputField.checkbox("use_arp_scan", "Use arp-scan (Local Segment)")
                .defaultValue("false")
                .group("Discovery Tools"),
            ModuleInputField.text("arp_interface", "arp-scan Interface")
                .placeholder("eth0")
                .group("Discovery Tools"),
            ModuleInputField.checkbox("use_hping3", "Use hping3 TCP Fallback")
                .defaultValue("false")
                .group("Discovery Tools"),
            ModuleInputField.checkbox("use_masscan", "Use masscan Auxiliary Discovery")
                .defaultValue("false")
                .group("Discovery Tools")
                .helpText("Disabled by default. Requires elevated privileges in most environments."),
            ModuleInputField.checkbox("enable_tcp_fallback", "Enable TCP Ping Fallback")
                .defaultValue("true")
                .group("Discovery Tools"),
            ModuleInputField.text("tcp_fallback_ports", "TCP Fallback Ports")
                .placeholder(DEFAULT_TCP_FALLBACK_PORTS)
                .group("Discovery Tools"),

            ModuleInputField.checkbox("enable_service_probe", "Enable Basic Service Probe")
                .defaultValue("false")
                .group("Enrichment")
                .modes("enhanced_discovery", "host_confirmation")
                .helpText("Optional follow-up open-port checks (not part of baseline ping sweep)."),
            ModuleInputField.text("service_ports", "Service Ports")
                .placeholder(DEFAULT_SERVICE_PORTS)
                .group("Enrichment")
                .modes("enhanced_discovery", "host_confirmation"),
            ModuleInputField.checkbox("enable_throughput_estimate", "Enable Throughput Estimation")
                .defaultValue("false")
                .group("Enrichment")
                .modes("enhanced_discovery")
                .helpText("Estimates response-performance score from latency/loss; does not measure real bandwidth.")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), MODULE_ID);

            try {
                long startedAt = System.currentTimeMillis();
                ctx.log("[*] Starting Network Ping Sweep module");
                ctx.reportProgress(5);

                ScanConfig config = parseConfig(input);
                List<String> validationErrors = validateConfig(config);
                if (!validationErrors.isEmpty()) {
                    String message = String.join("; ", validationErrors);
                    result.fail("Validation failed: " + message);
                    ctx.log("[!] Validation failed: " + message);
                    return result;
                }

                List<String> targets = resolveTargets(config);
                if (targets.isEmpty()) {
                    result.fail("No targets resolved from provided input");
                    ctx.log("[!] No targets resolved from input");
                    return result;
                }

                ctx.log("[*] Mode: " + config.mode.value);
                ctx.log("[*] Target definition: " + firstNonBlank(config.targetSubnet, config.confirmationTarget));
                ctx.log("[*] Resolved targets: " + targets.size());
                ctx.reportProgress(20);

                Map<String, HostObservation> observations = initializeObservations(targets);
                ExecutionDiagnostics diagnostics = new ExecutionDiagnostics();

                switch (config.mode) {
                    case HOST_DISCOVERY -> executeHostDiscovery(config, targets, observations, diagnostics, ctx);
                    case LATENCY_PROFILE -> executeLatencyProfile(config, targets, observations, diagnostics, ctx);
                    case ENHANCED_DISCOVERY -> executeEnhancedDiscovery(config, targets, observations, diagnostics, ctx);
                    case HOST_CONFIRMATION -> executeHostConfirmation(config, targets, observations, diagnostics, ctx);
                }

                if (config.resolveDns) {
                    enrichDns(observations, ctx);
                }

                if ((config.mode == ModuleMode.ENHANCED_DISCOVERY || config.mode == ModuleMode.HOST_CONFIRMATION)
                        && config.enableServiceProbe) {
                    enrichServices(observations, config, diagnostics, ctx);
                }

                if (config.enableThroughputEstimate) {
                    applyPerformanceEstimates(observations);
                }

                List<Map<String, Object>> hostOutput = toHostOutput(observations, config.includeNonResponsive);
                for (Map<String, Object> host : hostOutput) {
                    if (config.includeNonResponsive || Boolean.TRUE.equals(host.get("alive"))) {
                        result.addFinding(host);
                    }
                }

                Map<String, Object> summary = buildSummary(observations, config, targets.size());

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
                output.put("target_definition", firstNonBlank(config.targetSubnet, config.confirmationTarget));
                output.put("resolved_target_count", targets.size());
                output.put("summary", summary);
                output.put("hosts", hostOutput);

                switch (config.mode) {
                    case HOST_DISCOVERY -> output.put("host_discovery_result", buildHostDiscoveryResult(observations));
                    case LATENCY_PROFILE -> output.put("latency_profile_result", buildLatencyProfileResult(hostOutput));
                    case ENHANCED_DISCOVERY -> output.put("enhanced_discovery_result", buildEnhancedResult(hostOutput));
                    case HOST_CONFIRMATION -> output.put("host_confirmation_result", buildConfirmationResult(hostOutput, config));
                }

                output.put("operational_stack", buildOperationalStack());
                output.put("execution_metadata", buildExecutionMetadata(config, diagnostics, startedAt));

                result.setNormalizedOutput(buildNormalizedOutput(summary, hostOutput, config));
                result.complete(output);

                ctx.log("[+] Network Ping Sweep completed with " + summary.get("responsive_hosts") + " responsive hosts");
                ctx.reportProgress(100);

            } catch (Exception e) {
                result.fail("Execution failed: " + e.getMessage());
                ctx.log("[!] ERROR: " + e.getMessage());
            }
            return result;
        });
    }

    private void executeHostDiscovery(
            ScanConfig config,
            List<String> targets,
            Map<String, HostObservation> observations,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx) {

        ctx.log("[*] Host discovery mode: ICMP sweep with optional auxiliary probes");
        boolean usedPrimaryTool = false;

        if (config.useNmap && isCommandAvailable("nmap") && supportsSubnetCommand(config.targetSubnet)) {
            Set<String> alive = discoverWithNmapIcmp(config.targetSubnet, config, diagnostics);
            applyAliveSet(observations, alive, "NMAP_ICMP", "nmap -sn");
            usedPrimaryTool = true;
            ctx.log("[*] nmap discovery identified " + alive.size() + " responsive hosts");
        }

        if (!usedPrimaryTool && config.useFping && isCommandAvailable("fping") && supportsSubnetCommand(config.targetSubnet)) {
            Set<String> alive = discoverWithFping(config.targetSubnet, config, diagnostics);
            applyAliveSet(observations, alive, "FPING_ICMP", "fping -a -g");
            usedPrimaryTool = true;
            ctx.log("[*] fping discovery identified " + alive.size() + " responsive hosts");
        }

        if (config.useArpScan && isCommandAvailable("arp-scan") && supportsSubnetCommand(config.targetSubnet)) {
            Set<String> alive = discoverWithArpScan(config.targetSubnet, config, diagnostics);
            applyAliveSet(observations, alive, "ARP_SCAN", "arp-scan");
            ctx.log("[*] arp-scan identified " + alive.size() + " local-segment hosts");
        }

        if (config.useMasscan && isCommandAvailable("masscan") && supportsSubnetCommand(config.targetSubnet)) {
            Set<String> alive = discoverWithMasscan(config.targetSubnet, config, diagnostics);
            applyAliveSet(observations, alive, "MASSCAN_AUX", "masscan auxiliary sweep");
            if (!alive.isEmpty()) {
                ctx.log("[*] masscan auxiliary discovery identified " + alive.size() + " hosts");
            }
        }

        if (!usedPrimaryTool && observations.values().stream().noneMatch(host -> host.alive)) {
            ctx.log("[*] Falling back to native ping probes");
            runIcmpProbeBatch(
                targets,
                config,
                1,
                "PING_ICMP",
                observations,
                diagnostics,
                ctx,
                25,
                55
            );
        }

        ctx.reportProgress(82);
    }

    private void executeLatencyProfile(
            ScanConfig config,
            List<String> targets,
            Map<String, HostObservation> observations,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx) {

        int attempts = Math.max(1, config.probeCount);
        ctx.log("[*] Latency profile mode: ICMP response quality measurement");

        runIcmpProbeBatch(
            targets,
            config,
            attempts,
            "PING_PROFILE",
            observations,
            diagnostics,
            ctx,
            25,
            55
        );

        ctx.reportProgress(82);
    }

    private void executeEnhancedDiscovery(
            ScanConfig config,
            List<String> targets,
            Map<String, HostObservation> observations,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx) {

        ctx.log("[*] Enhanced discovery mode: host discovery + latency/loss + optional TCP fallback");

        executeHostDiscovery(config, targets, observations, diagnostics, ctx);

        runIcmpProbeBatch(
            targets,
            config,
            Math.max(2, config.probeCount),
            "PING_ENHANCED",
            observations,
            diagnostics,
            ctx,
            35,
            30
        );

        if (config.enableTcpFallback && config.useNmap && isCommandAvailable("nmap")) {
            List<String> nonResponsive = collectNonResponsive(observations);
            if (!nonResponsive.isEmpty()) {
                Set<String> tcpRecovered = discoverWithNmapTcpFallback(config, nonResponsive, diagnostics);
                applyAliveSet(observations, tcpRecovered, "NMAP_TCP_FALLBACK", "nmap -PS/-PA fallback");
                if (!tcpRecovered.isEmpty()) {
                    ctx.log("[*] TCP fallback recovered " + tcpRecovered.size() + " hosts");
                }
            }
        }

        if (config.enableTcpFallback && config.useHping3 && isCommandAvailable("hping3")) {
            List<String> nonResponsive = collectNonResponsive(observations);
            if (!nonResponsive.isEmpty()) {
                Set<String> hpingRecovered = discoverWithHping3(config, nonResponsive, diagnostics);
                applyAliveSet(observations, hpingRecovered, "HPING3_TCP", "hping3 SYN fallback");
                if (!hpingRecovered.isEmpty()) {
                    ctx.log("[*] hping3 fallback recovered " + hpingRecovered.size() + " hosts");
                }
            }
        }

        ctx.reportProgress(82);
    }

    private void executeHostConfirmation(
            ScanConfig config,
            List<String> targets,
            Map<String, HostObservation> observations,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx) {

        String target = targets.get(0);
        ctx.log("[*] Host confirmation mode: focused verification for " + target);

        runIcmpProbeBatch(
            List.of(target),
            config,
            Math.max(1, config.confirmationAttempts),
            "PING_CONFIRMATION",
            observations,
            diagnostics,
            ctx,
            25,
            40
        );

        HostObservation host = observations.get(target);
        if (host != null && !host.alive && config.enableTcpFallback && config.useNmap && isCommandAvailable("nmap")) {
            Set<String> fallbackAlive = discoverWithNmapTcpFallback(config, List.of(target), diagnostics);
            applyAliveSet(observations, fallbackAlive, "NMAP_TCP_FALLBACK", "confirmation TCP fallback");
        }

        if (host != null && !host.alive && config.enableTcpFallback && config.useHping3 && isCommandAvailable("hping3")) {
            Set<String> hpingAlive = discoverWithHping3(config, List.of(target), diagnostics);
            applyAliveSet(observations, hpingAlive, "HPING3_TCP", "confirmation hping3 fallback");
        }

        ctx.reportProgress(82);
    }

    private void runIcmpProbeBatch(
            List<String> targets,
            ScanConfig config,
            int attempts,
            String method,
            Map<String, HostObservation> observations,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx,
            int progressStart,
            int progressSpan) {

        ThreadFactory threadFactory = Thread.ofVirtual().name("jrts-net-ping-worker-", 0).factory();
        ExecutorService executor = Executors.newThreadPerTaskExecutor(threadFactory);
        ExecutorCompletionService<ProbeOutcome> completion = new ExecutorCompletionService<>(executor);

        try {
            for (String target : targets) {
                completion.submit(() -> probeHost(target, config, attempts, diagnostics));
            }

            AtomicInteger processed = new AtomicInteger(0);
            for (int i = 0; i < targets.size(); i++) {
                Future<ProbeOutcome> future = completion.take();
                ProbeOutcome outcome = future.get();
                HostObservation host = observations.get(outcome.target);
                if (host != null) {
                    host.applyProbeOutcome(outcome, method);
                }

                int done = processed.incrementAndGet();
                int pct = progressStart + (int) ((done / (double) targets.size()) * progressSpan);
                ctx.reportProgress(Math.min(95, pct));
            }
        } catch (Exception e) {
            diagnostics.warnings.add("Probe batch error: " + e.getMessage());
        } finally {
            executor.shutdownNow();
        }
    }

    private ProbeOutcome probeHost(String target, ScanConfig config, int attempts, ExecutionDiagnostics diagnostics) {
        ProbeOutcome outcome = new ProbeOutcome(target);

        for (int i = 0; i < attempts; i++) {
            List<String> command = buildPingCommand(target, config.timeoutMs);
            CommandExecutionResult result = runCommand(command, config.timeoutMs + 1500L);

            diagnostics.commandExecutions++;
            diagnostics.toolUsage.add("ping");
            diagnostics.executedCommands.add(String.join(" ", command));

            outcome.sent++;
            outcome.evidenceCommands.add(String.join(" ", command));

            if (result.timedOut) {
                outcome.lastError = "timed_out";
            } else if (result.exitCode == 0) {
                outcome.received++;
                outcome.rttSamples.addAll(extractRttSamples(result.combinedOutput()));
            } else {
                String combined = result.combinedOutput();
                if (!combined.isBlank()) {
                    outcome.lastError = firstLine(combined);
                }
            }

            if (config.interProbeDelayMs > 0 && i < attempts - 1) {
                sleepQuietly(config.interProbeDelayMs);
            }
        }

        outcome.alive = outcome.received > 0;
        return outcome;
    }

    private Set<String> discoverWithNmapIcmp(String targetDefinition, ScanConfig config, ExecutionDiagnostics diagnostics) {
        List<String> command = List.of(
            "nmap",
            "-sn",
            "-n",
            "--max-retries",
            "1",
            "--host-timeout",
            Math.max(1000, config.timeoutMs) + "ms",
            targetDefinition
        );

        CommandExecutionResult result = runCommand(command, Math.max(8_000L, config.timeoutMs * 10L));
        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("nmap");
        diagnostics.executedCommands.add(String.join(" ", command));

        if (result.timedOut) {
            diagnostics.warnings.add("nmap ICMP discovery timed out");
            return Set.of();
        }
        if (result.exitCode != 0) {
            diagnostics.warnings.add("nmap ICMP discovery returned exit code " + result.exitCode);
        }

        return parseNmapHosts(result.combinedOutput());
    }

    private Set<String> discoverWithFping(String targetDefinition, ScanConfig config, ExecutionDiagnostics diagnostics) {
        List<String> command = List.of("fping", "-a", "-g", targetDefinition);
        CommandExecutionResult result = runCommand(command, Math.max(8_000L, config.timeoutMs * 8L));

        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("fping");
        diagnostics.executedCommands.add(String.join(" ", command));

        if (result.timedOut) {
            diagnostics.warnings.add("fping discovery timed out");
            return Set.of();
        }
        if (result.exitCode != 0 && result.stdout.isBlank()) {
            diagnostics.warnings.add("fping discovery returned exit code " + result.exitCode);
        }

        return parseIpLines(result.stdout + "\n" + result.stderr);
    }

    private Set<String> discoverWithArpScan(String targetDefinition, ScanConfig config, ExecutionDiagnostics diagnostics) {
        List<String> command = new ArrayList<>();
        command.add("arp-scan");
        if (!config.arpInterface.isBlank()) {
            command.add("-I");
            command.add(config.arpInterface);
        }
        command.add(targetDefinition);

        CommandExecutionResult result = runCommand(command, Math.max(10_000L, config.timeoutMs * 12L));
        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("arp-scan");
        diagnostics.executedCommands.add(String.join(" ", command));

        if (result.timedOut) {
            diagnostics.warnings.add("arp-scan timed out");
            return Set.of();
        }
        if (result.exitCode != 0 && result.stdout.isBlank()) {
            diagnostics.warnings.add("arp-scan returned exit code " + result.exitCode);
        }

        return parseArpScanHosts(result.combinedOutput());
    }

    private Set<String> discoverWithMasscan(String targetDefinition, ScanConfig config, ExecutionDiagnostics diagnostics) {
        String ports = config.tcpFallbackPorts.replace(",", ",");
        List<String> command = List.of(
            "masscan",
            "-p" + ports,
            targetDefinition,
            "--rate",
            "1000"
        );

        CommandExecutionResult result = runCommand(command, Math.max(10_000L, config.timeoutMs * 15L));
        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("masscan");
        diagnostics.executedCommands.add(String.join(" ", command));

        if (result.timedOut) {
            diagnostics.warnings.add("masscan timed out");
            return Set.of();
        }

        Set<String> hosts = new LinkedHashSet<>();
        Matcher matcher = MASSCAN_HOST_PATTERN.matcher(result.combinedOutput());
        while (matcher.find()) {
            String candidate = matcher.group(1);
            if (isIpv4(candidate)) {
                hosts.add(candidate);
            }
        }
        return hosts;
    }

    private Set<String> discoverWithNmapTcpFallback(
            ScanConfig config,
            List<String> nonResponsiveTargets,
            ExecutionDiagnostics diagnostics) {

        String targetExpression = supportsSubnetCommand(config.targetSubnet)
            ? config.targetSubnet
            : String.join(",", nonResponsiveTargets);

        List<String> command = List.of(
            "nmap",
            "-sn",
            "-n",
            "-PS" + config.tcpFallbackPorts,
            "-PA" + config.tcpFallbackPorts,
            "--max-retries",
            "1",
            "--host-timeout",
            Math.max(1000, config.timeoutMs) + "ms",
            targetExpression
        );

        CommandExecutionResult result = runCommand(command, Math.max(10_000L, config.timeoutMs * 12L));
        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("nmap");
        diagnostics.executedCommands.add(String.join(" ", command));

        if (result.timedOut) {
            diagnostics.warnings.add("nmap TCP fallback timed out");
            return Set.of();
        }
        if (result.exitCode != 0) {
            diagnostics.warnings.add("nmap TCP fallback returned exit code " + result.exitCode);
        }

        return parseNmapHosts(result.combinedOutput());
    }

    private Set<String> discoverWithHping3(
            ScanConfig config,
            List<String> targets,
            ExecutionDiagnostics diagnostics) {

        Set<String> responsive = new LinkedHashSet<>();
        int firstPort = parsePortList(config.tcpFallbackPorts).stream().findFirst().orElse(80);

        for (String target : targets) {
            List<String> command = List.of(
                "hping3",
                "-S",
                "-p",
                String.valueOf(firstPort),
                "-c",
                "1",
                "-n",
                target
            );

            CommandExecutionResult result = runCommand(command, Math.max(4_000L, config.timeoutMs * 4L));
            diagnostics.commandExecutions++;
            diagnostics.toolUsage.add("hping3");
            diagnostics.executedCommands.add(String.join(" ", command));

            String output = result.combinedOutput().toLowerCase(Locale.ROOT);
            if (output.contains("flags=") || output.contains("len=")) {
                responsive.add(target);
            }
        }

        return responsive;
    }

    private void applyAliveSet(
            Map<String, HostObservation> observations,
            Set<String> aliveHosts,
            String method,
            String note) {

        if (aliveHosts.isEmpty()) {
            return;
        }
        for (String host : aliveHosts) {
            HostObservation observation = observations.get(host);
            if (observation == null) {
                observation = new HostObservation(host);
                observations.put(host, observation);
            }
            observation.markAlive(method, note);
        }
    }

    private void enrichDns(Map<String, HostObservation> observations, TaskContext ctx) {
        int resolved = 0;
        for (HostObservation observation : observations.values()) {
            if (!observation.alive) {
                continue;
            }
            String dns = resolveDnsName(observation.target);
            if (!dns.isBlank() && !dns.equals(observation.target)) {
                observation.dnsName = dns;
                resolved++;
            }
        }
        ctx.log("[*] DNS enrichment resolved " + resolved + " hostnames");
    }

    private void enrichServices(
            Map<String, HostObservation> observations,
            ScanConfig config,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx) {

        List<Integer> servicePorts = parsePortList(config.servicePorts);
        int enriched = 0;
        for (HostObservation host : observations.values()) {
            if (!host.alive) {
                continue;
            }

            Map<Integer, String> open = probeServicesForHost(host.target, servicePorts, config, diagnostics);
            host.openPorts.putAll(open);
            if (!open.isEmpty()) {
                host.note = firstNonBlank(host.note, "service_exposure_identified");
                enriched++;
            }
        }

        ctx.log("[*] Service enrichment completed for " + enriched + " host(s) with open ports");
    }

    protected Map<Integer, String> probeServicesForHost(
            String target,
            List<Integer> servicePorts,
            ScanConfig config,
            ExecutionDiagnostics diagnostics) {

        if (servicePorts.isEmpty()) {
            return Map.of();
        }

        if (config.useNmap && isCommandAvailable("nmap")) {
            String ports = servicePorts.stream().map(String::valueOf).reduce((a, b) -> a + "," + b).orElse("");
            List<String> command = List.of("nmap", "-Pn", "-n", "--open", "-p", ports, target);

            CommandExecutionResult result = runCommand(command, Math.max(10_000L, config.timeoutMs * 12L));
            diagnostics.commandExecutions++;
            diagnostics.toolUsage.add("nmap");
            diagnostics.executedCommands.add(String.join(" ", command));

            Map<Integer, String> parsed = parseNmapOpenPorts(result.combinedOutput());
            if (!parsed.isEmpty()) {
                return parsed;
            }
        }

        Map<Integer, String> fallback = new LinkedHashMap<>();
        for (int port : servicePorts) {
            if (isTcpPortOpen(target, port, config.timeoutMs)) {
                fallback.put(port, serviceName(port));
            }
        }
        return fallback;
    }

    private boolean isTcpPortOpen(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), Math.max(200, timeoutMs));
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    private Map<Integer, String> parseNmapOpenPorts(String output) {
        Map<Integer, String> ports = new LinkedHashMap<>();
        if (output == null || output.isBlank()) {
            return ports;
        }

        for (String line : output.split("\\R")) {
            Matcher matcher = NMAP_OPEN_PORT_PATTERN.matcher(line.trim());
            if (!matcher.matches()) {
                continue;
            }

            int port = Integer.parseInt(matcher.group(1));
            String service = trim(matcher.group(2));
            ports.put(port, firstNonBlank(service, serviceName(port), "unknown"));
        }
        return ports;
    }

    private void applyPerformanceEstimates(Map<String, HostObservation> observations) {
        for (HostObservation host : observations.values()) {
            if (!host.alive) {
                host.performanceScore = 0.0;
                host.performanceBand = "unreachable";
                host.estimatedThroughputMbps = 0.0;
                continue;
            }

            double responseRate = Math.max(0.0, 100.0 - host.packetLossPercent);
            double avgRtt = host.rttSamples.isEmpty()
                ? 50.0
                : host.rttSamples.stream().mapToDouble(Double::doubleValue).average().orElse(50.0);

            double latencyPenalty = Math.min(45.0, avgRtt / 3.0);
            double score = Math.max(0.0, Math.min(100.0, responseRate - latencyPenalty));

            host.performanceScore = roundTwo(score);
            host.estimatedThroughputMbps = roundTwo(Math.max(0.0, score * 1.15));
            host.performanceBand = performanceBand(host.performanceScore);
        }
    }

    protected String resolveDnsName(String ip) {
        try {
            return InetAddress.getByName(ip).getCanonicalHostName();
        } catch (Exception ignored) {
            return "";
        }
    }

    protected boolean isCommandAvailable(String command) {
        return commandAvailabilityCache.computeIfAbsent(command, cmd -> {
            List<String> checkCommand = isWindows() ? List.of("where", cmd) : List.of("which", cmd);
            CommandExecutionResult result = runCommand(checkCommand, 2_000);
            return !result.timedOut && result.exitCode == 0;
        });
    }

    protected CommandExecutionResult runCommand(List<String> command, long timeoutMs) {
        long startedAt = System.currentTimeMillis();
        Process process = null;

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            Process runningProcess = processBuilder.start();
            process = runningProcess;

            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();

            Thread stdoutThread = Thread.ofVirtual().start(() -> copyStream(runningProcess.getInputStream(), stdout));
            Thread stderrThread = Thread.ofVirtual().start(() -> copyStream(runningProcess.getErrorStream(), stderr));

            boolean finished = runningProcess.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            if (!finished) {
                runningProcess.destroyForcibly();
                joinQuietly(stdoutThread, 200);
                joinQuietly(stderrThread, 200);
                return new CommandExecutionResult(-1, stdout.toString(), stderr.toString(), true,
                    System.currentTimeMillis() - startedAt);
            }

            joinQuietly(stdoutThread, 500);
            joinQuietly(stderrThread, 500);

            return new CommandExecutionResult(
                runningProcess.exitValue(),
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

    private Map<String, HostObservation> initializeObservations(List<String> targets) {
        Map<String, HostObservation> observations = new LinkedHashMap<>();
        targets.stream()
            .sorted(Comparator.comparingLong(this::ipSortKey))
            .forEach(target -> observations.put(target, new HostObservation(target)));
        return observations;
    }

    private List<String> resolveTargets(ScanConfig config) {
        if (config.mode == ModuleMode.HOST_CONFIRMATION) {
            String confirmationTarget = firstNonBlank(config.confirmationTarget, config.targetSubnet);
            if (confirmationTarget.isBlank()) {
                return List.of();
            }
            return List.of(normalizeTarget(confirmationTarget));
        }

        if (config.targetSubnet.contains("/")) {
            return expandCidr(config.targetSubnet, config.maxHosts);
        }
        return List.of(normalizeTarget(config.targetSubnet));
    }

    private String normalizeTarget(String target) {
        String value = trim(target);
        if (isIpv4(value)) {
            return value;
        }
        try {
            return InetAddress.getByName(value).getHostAddress();
        } catch (Exception ignored) {
            return value;
        }
    }

    private List<String> expandCidr(String cidr, int maxHosts) {
        String[] parts = cidr.split("/");
        String baseIp = parts[0].trim();
        int prefix = Integer.parseInt(parts[1].trim());

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

    private List<Map<String, Object>> toHostOutput(
            Map<String, HostObservation> observations,
            boolean includeNonResponsive) {

        List<Map<String, Object>> output = new ArrayList<>();
        for (HostObservation host : observations.values()) {
            if (!includeNonResponsive && !host.alive) {
                continue;
            }
            output.add(host.toMap());
        }

        output.sort(Comparator.comparingLong(h -> ipSortKey(String.valueOf(h.get("ip")))));
        return output;
    }

    private Map<String, Object> buildSummary(
            Map<String, HostObservation> observations,
            ScanConfig config,
            int totalTargets) {

        long responsive = observations.values().stream().filter(h -> h.alive).count();
        long nonResponsive = Math.max(0, totalTargets - responsive);

        Map<String, Integer> methods = new LinkedHashMap<>();
        for (HostObservation observation : observations.values()) {
            if (!observation.alive) {
                continue;
            }
            for (String method : observation.methods) {
                methods.put(method, methods.getOrDefault(method, 0) + 1);
            }
        }

        double avgRtt = observations.values().stream()
            .filter(h -> h.alive && !h.rttSamples.isEmpty())
            .mapToDouble(h -> h.rttSamples.stream().mapToDouble(Double::doubleValue).average().orElse(0.0))
            .average()
            .orElse(0.0);

        double avgLoss = observations.values().stream()
            .filter(h -> h.alive || h.probesSent > 0)
            .mapToDouble(h -> h.packetLossPercent)
            .average()
            .orElse(100.0);

        long serviceExposed = observations.values().stream().filter(h -> !h.openPorts.isEmpty()).count();
        long highPerformance = observations.values().stream().filter(h -> h.performanceScore >= 80.0).count();

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", config.mode.value);
        summary.put("total_targets", totalTargets);
        summary.put("responsive_hosts", responsive);
        summary.put("non_responsive_hosts", nonResponsive);
        summary.put("host_density_percent", roundTwo(totalTargets == 0 ? 0.0 : (responsive * 100.0) / totalTargets));
        summary.put("average_rtt_ms", roundTwo(avgRtt));
        summary.put("average_packet_loss_percent", roundTwo(avgLoss));
        summary.put("service_exposed_hosts", serviceExposed);
        summary.put("high_performance_hosts", highPerformance);
        summary.put("discovery_method_counts", methods);
        summary.put("tcp_fallback_enabled", config.enableTcpFallback);
        summary.put("service_probe_enabled", config.enableServiceProbe);
        summary.put("throughput_estimation_enabled", config.enableThroughputEstimate);

        if (config.mode == ModuleMode.HOST_CONFIRMATION) {
            summary.put("confirmation_target", config.confirmationTarget);
            summary.put("confirmation_status", responsive > 0 ? "responsive" : "non_responsive");
        }

        return summary;
    }

    private Map<String, Object> buildHostDiscoveryResult(Map<String, HostObservation> observations) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("alive_hosts", observations.values().stream().filter(host -> host.alive).count());
        result.put("silent_hosts", observations.values().stream().filter(host -> !host.alive).count());
        result.put("methods", observations.values().stream()
            .flatMap(host -> host.methods.stream())
            .distinct()
            .sorted()
            .toList());
        return result;
    }

    private Map<String, Object> buildLatencyProfileResult(List<Map<String, Object>> hostOutput) {
        List<Map<String, Object>> profiled = hostOutput.stream()
            .map(host -> {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("ip", host.get("ip"));
                row.put("alive", host.get("alive"));
                row.put("packet_loss_percent", host.get("packet_loss_percent"));
                row.put("rtt_avg_ms", host.getOrDefault("rtt_avg_ms", null));
                row.put("response_rate_percent", host.getOrDefault("response_rate_percent", 0.0));
                return row;
            })
            .toList();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("hosts_profiled", profiled.size());
        result.put("profiles", profiled);
        return result;
    }

    private Map<String, Object> buildEnhancedResult(List<Map<String, Object>> hostOutput) {
        List<Map<String, Object>> prioritized = hostOutput.stream()
            .filter(host -> Boolean.TRUE.equals(host.get("alive")))
            .sorted((a, b) -> Double.compare(
                ((Number) b.getOrDefault("performance_score", 0.0)).doubleValue(),
                ((Number) a.getOrDefault("performance_score", 0.0)).doubleValue()
            ))
            .toList();

        long tcpFallbackRecovered = hostOutput.stream().filter(host -> {
            Object methods = host.get("discovery_methods");
            if (methods instanceof List<?> list) {
                for (Object item : list) {
                    String value = item == null ? "" : String.valueOf(item);
                    if ("NMAP_TCP_FALLBACK".equals(value) || "HPING3_TCP".equals(value)) {
                        return true;
                    }
                }
            }
            return false;
        }).count();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("prioritized_targets", prioritized);
        result.put("tcp_fallback_recovered_hosts", tcpFallbackRecovered);
        result.put("hosts_with_service_exposure", hostOutput.stream()
            .filter(host -> {
                Object ports = host.get("open_ports");
                return (ports instanceof List<?> list) && !list.isEmpty();
            })
            .count());
        return result;
    }

    private Map<String, Object> buildConfirmationResult(List<Map<String, Object>> hostOutput, ScanConfig config) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("target", config.confirmationTarget);

        if (hostOutput.isEmpty()) {
            result.put("confirmed", false);
            result.put("reason", "target_not_in_output");
            return result;
        }

        Map<String, Object> host = hostOutput.get(0);
        result.put("confirmed", Boolean.TRUE.equals(host.get("alive")));
        result.put("host", host);
        return result;
    }

    private List<Map<String, Object>> buildOperationalStack() {
        List<Map<String, Object>> stack = new ArrayList<>();
        stack.add(tool("nmap", "Primary host discovery and optional service probing", "https://nmap.org/"));
        stack.add(tool("fping", "Fast ICMP sweep across CIDR ranges", "https://fping.org/"));
        stack.add(tool("arp-scan", "LAN-focused ARP-based host discovery", "https://github.com/royhills/arp-scan"));
        stack.add(tool("masscan", "Auxiliary high-speed host/port signal discovery", "https://github.com/robertdavidgraham/masscan"));
        stack.add(tool("hping3", "Custom TCP SYN probing fallback", "https://www.kali.org/tools/hping3/"));
        stack.add(tool("iperf3", "Reference for true throughput testing outside baseline sweep", "https://iperf.fr/"));
        return stack;
    }

    private Map<String, Object> tool(String name, String purpose, String reference) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", name);
        map.put("purpose", purpose);
        map.put("reference", reference);
        return map;
    }

    private Map<String, Object> buildExecutionMetadata(
            ScanConfig config,
            ExecutionDiagnostics diagnostics,
            long startedAt) {

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("tools_used", new ArrayList<>(diagnostics.toolUsage));
        metadata.put("command_executions", diagnostics.commandExecutions);
        metadata.put("executed_commands", diagnostics.executedCommands);
        metadata.put("warnings", diagnostics.warnings);
        metadata.put("timeout_ms", config.timeoutMs);
        metadata.put("probe_count", config.probeCount);
        metadata.put("concurrency", config.concurrency);
        metadata.put("elapsed_ms", System.currentTimeMillis() - startedAt);
        return metadata;
    }

    private Map<String, Object> buildNormalizedOutput(
            Map<String, Object> summary,
            List<Map<String, Object>> hosts,
            ScanConfig config) {

        Map<String, Object> normalized = new LinkedHashMap<>();

        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("summary", summary);
        raw.put("host_count", hosts.size());
        normalized.put("raw_output", raw);

        Map<String, Object> parsed = new LinkedHashMap<>();
        long responsive = ((Number) summary.getOrDefault("responsive_hosts", 0)).longValue();
        parsed.put("status", responsive > 0 ? "LIVE_HOSTS_IDENTIFIED" : "NO_LIVE_HOSTS_IDENTIFIED");
        parsed.put("vulnerable", false);
        parsed.put("details", summary);
        parsed.put("evidence", hosts);
        normalized.put("parsed_output", parsed);

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("module", MODULE_ID);
        metadata.put("mode", config.mode.value);
        metadata.put("target", firstNonBlank(config.targetSubnet, config.confirmationTarget));
        normalized.put("metadata", metadata);

        return normalized;
    }

    private List<String> validateConfig(ScanConfig config) {
        List<String> errors = new ArrayList<>();

        if (config.mode != ModuleMode.HOST_CONFIRMATION && config.targetSubnet.isBlank()) {
            errors.add("target_subnet is required");
        }

        if (config.mode == ModuleMode.HOST_CONFIRMATION
                && firstNonBlank(config.confirmationTarget, config.targetSubnet).isBlank()) {
            errors.add("confirmation_target is required when mode=host_confirmation");
        }

        if (!config.targetSubnet.isBlank() && config.targetSubnet.contains("/") && !isValidCidr(config.targetSubnet)) {
            errors.add("target_subnet must be a valid IPv4 CIDR");
        }

        if (config.timeoutMs < 100 || config.timeoutMs > 60_000) {
            errors.add("timeout_ms must be between 100 and 60000");
        }

        if (config.probeCount < 1 || config.probeCount > 10) {
            errors.add("probe_count must be between 1 and 10");
        }

        if (config.confirmationAttempts < 1 || config.confirmationAttempts > 20) {
            errors.add("confirmation_attempts must be between 1 and 20");
        }

        if (config.concurrency < 1 || config.concurrency > MAX_CONCURRENCY_LIMIT) {
            errors.add("concurrency must be between 1 and " + MAX_CONCURRENCY_LIMIT);
        }

        if (config.maxHosts < 1 || config.maxHosts > MAX_HOSTS_LIMIT) {
            errors.add("max_hosts must be between 1 and " + MAX_HOSTS_LIMIT);
        }

        if (config.interProbeDelayMs < 0 || config.interProbeDelayMs > 10_000) {
            errors.add("inter_probe_delay_ms must be between 0 and 10000");
        }

        if (!isValidPortList(config.tcpFallbackPorts)) {
            errors.add("tcp_fallback_ports must be a comma-separated list of 1-65535");
        }

        if (!isValidPortList(config.servicePorts)) {
            errors.add("service_ports must be a comma-separated list of 1-65535");
        }

        return errors;
    }

    private ScanConfig parseConfig(Map<String, String> input) {
        ScanConfig config = new ScanConfig();

        config.mode = ModuleMode.fromInput(firstNonBlank(input.get("mode"), "host_discovery"));
        config.targetSubnet = firstNonBlank(input.get("target_subnet"), input.get("target"), input.get("subnet"));
        config.confirmationTarget = firstNonBlank(input.get("confirmation_target"), input.get("identify_target"));

        config.timeoutMs = parseInteger(firstNonBlank(input.get("timeout_ms"), input.get("timeout")), DEFAULT_TIMEOUT_MS);
        config.probeCount = parseInteger(input.get("probe_count"), DEFAULT_PROBE_COUNT);
        config.confirmationAttempts = parseInteger(input.get("confirmation_attempts"), DEFAULT_CONFIRMATION_ATTEMPTS);
        config.concurrency = parseInteger(input.get("concurrency"), DEFAULT_CONCURRENCY);
        config.maxHosts = parseInteger(input.get("max_hosts"), DEFAULT_MAX_HOSTS);
        config.interProbeDelayMs = parseInteger(input.get("inter_probe_delay_ms"), 0);

        config.resolveDns = parseBoolean(input.get("resolve_dns"), false);
        config.includeNonResponsive = parseBoolean(input.get("include_nonresponsive"), true);

        config.useNmap = parseBoolean(input.get("use_nmap"), true);
        config.useFping = parseBoolean(input.get("use_fping"), true);
        config.useArpScan = parseBoolean(input.get("use_arp_scan"), false);
        config.arpInterface = trim(input.get("arp_interface"));
        config.useHping3 = parseBoolean(input.get("use_hping3"), false);
        config.useMasscan = parseBoolean(input.get("use_masscan"), false);
        config.enableTcpFallback = parseBoolean(input.get("enable_tcp_fallback"), true);
        config.tcpFallbackPorts = firstNonBlank(input.get("tcp_fallback_ports"), DEFAULT_TCP_FALLBACK_PORTS);

        config.enableServiceProbe = parseBoolean(input.get("enable_service_probe"), false);
        config.servicePorts = firstNonBlank(input.get("service_ports"), DEFAULT_SERVICE_PORTS);
        config.enableThroughputEstimate = parseBoolean(input.get("enable_throughput_estimate"), false);
        return config;
    }

    private List<String> buildPingCommand(String target, int timeoutMs) {
        if (isWindows()) {
            return List.of("ping", "-n", "1", "-w", String.valueOf(timeoutMs), target);
        }
        if (isMac()) {
            return List.of("ping", "-n", "-c", "1", "-W", String.valueOf(timeoutMs), target);
        }

        int timeoutSeconds = Math.max(1, (int) Math.ceil(timeoutMs / 1000.0));
        return List.of("ping", "-n", "-c", "1", "-W", String.valueOf(timeoutSeconds), target);
    }

    private Set<String> parseNmapHosts(String output) {
        Set<String> hosts = new LinkedHashSet<>();
        Matcher matcher = NMAP_HOST_PATTERN.matcher(output == null ? "" : output);
        while (matcher.find()) {
            String candidate = matcher.group(1);
            if (isIpv4(candidate)) {
                hosts.add(candidate);
            }
        }
        return hosts;
    }

    private Set<String> parseArpScanHosts(String output) {
        Set<String> hosts = new LinkedHashSet<>();
        if (output == null || output.isBlank()) {
            return hosts;
        }

        for (String line : output.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isBlank()) {
                continue;
            }

            String[] tokens = trimmed.split("\\s+");
            if (tokens.length == 0) {
                continue;
            }

            String candidate = tokens[0];
            if (isIpv4(candidate)) {
                hosts.add(candidate);
            }
        }

        return hosts;
    }

    private Set<String> parseIpLines(String output) {
        Set<String> hosts = new LinkedHashSet<>();
        if (output == null || output.isBlank()) {
            return hosts;
        }

        for (String line : output.split("\\R")) {
            Matcher matcher = IPV4_PATTERN.matcher(line);
            if (matcher.find()) {
                String candidate = matcher.group(1);
                if (isIpv4(candidate)) {
                    hosts.add(candidate);
                }
            }
        }
        return hosts;
    }

    private List<Double> extractRttSamples(String output) {
        List<Double> samples = new ArrayList<>();
        if (output == null || output.isBlank()) {
            return samples;
        }

        Matcher matcher = RTT_PATTERN.matcher(output);
        while (matcher.find()) {
            samples.add(Double.parseDouble(matcher.group(1)));
        }

        if (samples.isEmpty()) {
            Matcher windows = WINDOWS_AVERAGE_PATTERN.matcher(output);
            if (windows.find()) {
                samples.add(Double.parseDouble(windows.group(1)));
            }
        }

        return samples;
    }

    private List<String> collectNonResponsive(Map<String, HostObservation> observations) {
        List<String> nonResponsive = new ArrayList<>();
        for (HostObservation host : observations.values()) {
            if (!host.alive) {
                nonResponsive.add(host.target);
            }
        }
        return nonResponsive;
    }

    private boolean supportsSubnetCommand(String targetDefinition) {
        return targetDefinition != null && targetDefinition.contains("/");
    }

    private boolean isValidCidr(String cidr) {
        try {
            String[] parts = cidr.split("/");
            if (parts.length != 2) {
                return false;
            }

            if (!isIpv4(parts[0].trim())) {
                return false;
            }

            int prefix = Integer.parseInt(parts[1].trim());
            return prefix >= 0 && prefix <= 32;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isIpv4(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }

        String[] parts = value.split("\\.");
        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            try {
                int octet = Integer.parseInt(part);
                if (octet < 0 || octet > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }

        return true;
    }

    private boolean isValidPortList(String ports) {
        String raw = trim(ports);
        if (raw.isBlank()) {
            return false;
        }

        for (String token : raw.split(",")) {
            String value = token.trim();
            if (value.isBlank()) {
                return false;
            }
            try {
                int port = Integer.parseInt(value);
                if (port < 1 || port > 65535) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }

        return true;
    }

    private List<Integer> parsePortList(String ports) {
        List<Integer> parsed = new ArrayList<>();
        String raw = trim(ports);
        if (raw.isBlank()) {
            return parsed;
        }

        for (String token : raw.split(",")) {
            String value = token.trim();
            if (value.isBlank()) {
                continue;
            }
            try {
                int port = Integer.parseInt(value);
                if (port >= 1 && port <= 65535) {
                    parsed.add(port);
                }
            } catch (NumberFormatException ignored) {
                // skip invalid token
            }
        }
        return parsed;
    }

    private String firstLine(String text) {
        if (text == null || text.isBlank()) {
            return "";
        }
        String[] lines = text.split("\\R");
        return lines.length == 0 ? "" : lines[0].trim();
    }

    private void copyStream(InputStream stream, StringBuilder sink) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sink.append(line).append('\n');
            }
        } catch (IOException ignored) {
            // swallow stream read failures
        }
    }

    private void joinQuietly(Thread thread, long millis) {
        if (thread == null) {
            return;
        }
        try {
            thread.join(millis);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    private void sleepQuietly(int millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    private long ipSortKey(String ip) {
        if (!isIpv4(ip)) {
            return Long.MAX_VALUE;
        }
        return ipToLong(ip);
    }

    private long ipToLong(String ip) {
        String[] octets = ip.split("\\.");
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

    private double roundTwo(double value) {
        return Math.round(value * 100.0) / 100.0;
    }

    private String performanceBand(double score) {
        if (score >= 85.0) {
            return "excellent";
        }
        if (score >= 65.0) {
            return "good";
        }
        if (score >= 40.0) {
            return "moderate";
        }
        return "poor";
    }

    private int parseInteger(String value, int defaultValue) {
        String raw = trim(value);
        if (raw.isBlank()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private boolean parseBoolean(String value, boolean defaultValue) {
        String raw = trim(value);
        if (raw.isBlank()) {
            return defaultValue;
        }
        return Boolean.parseBoolean(raw);
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

    private boolean isWindows() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        return os.contains("win");
    }

    private boolean isMac() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        return os.contains("mac");
    }

    private String serviceName(int port) {
        return switch (port) {
            case 21 -> "ftp";
            case 22 -> "ssh";
            case 25 -> "smtp";
            case 53 -> "dns";
            case 80 -> "http";
            case 110 -> "pop3";
            case 135 -> "msrpc";
            case 139 -> "netbios-ssn";
            case 143 -> "imap";
            case 389 -> "ldap";
            case 443 -> "https";
            case 445 -> "smb";
            case 3306 -> "mysql";
            case 3389 -> "rdp";
            case 5432 -> "postgresql";
            case 5985 -> "winrm-http";
            case 5986 -> "winrm-https";
            case 8080 -> "http-alt";
            default -> "unknown";
        };
    }

    protected static final class CommandExecutionResult {
        protected final int exitCode;
        protected final String stdout;
        protected final String stderr;
        protected final boolean timedOut;
        protected final long durationMs;

        protected CommandExecutionResult(
                int exitCode,
                String stdout,
                String stderr,
                boolean timedOut,
                long durationMs) {
            this.exitCode = exitCode;
            this.stdout = stdout == null ? "" : stdout;
            this.stderr = stderr == null ? "" : stderr;
            this.timedOut = timedOut;
            this.durationMs = durationMs;
        }

        protected String combinedOutput() {
            if (stderr.isBlank()) {
                return stdout;
            }
            if (stdout.isBlank()) {
                return stderr;
            }
            return stdout + "\n" + stderr;
        }
    }

    private static final class ProbeOutcome {
        private final String target;
        private boolean alive;
        private int sent;
        private int received;
        private final List<Double> rttSamples = new ArrayList<>();
        private final List<String> evidenceCommands = new ArrayList<>();
        private String lastError = "";

        private ProbeOutcome(String target) {
            this.target = target;
        }
    }

    private static final class HostObservation {
        private final String target;
        private boolean alive;
        private String state = "NO_REPLY";
        private final Set<String> methods = new LinkedHashSet<>();
        private final List<Double> rttSamples = new ArrayList<>();
        private int probesSent;
        private int probesReceived;
        private double packetLossPercent = 100.0;
        private String dnsName = "";
        private String note = "";
        private final Map<Integer, String> openPorts = new LinkedHashMap<>();
        private double performanceScore;
        private String performanceBand = "unknown";
        private double estimatedThroughputMbps;

        private HostObservation(String target) {
            this.target = target;
        }

        private void markAlive(String method, String note) {
            this.alive = true;
            this.state = "ALIVE";
            if (method != null && !method.isBlank()) {
                this.methods.add(method);
            }
            if (this.note.isBlank() && note != null && !note.isBlank()) {
                this.note = note;
            }
            if (this.probesSent == 0) {
                this.packetLossPercent = 0.0;
            }
        }

        private void applyProbeOutcome(ProbeOutcome outcome, String method) {
            this.probesSent += outcome.sent;
            this.probesReceived += outcome.received;
            this.rttSamples.addAll(outcome.rttSamples);
            this.packetLossPercent = probesSent == 0
                ? (alive ? 0.0 : 100.0)
                : ((probesSent - probesReceived) * 100.0) / probesSent;

            if (method != null && !method.isBlank()) {
                this.methods.add(method);
            }

            if (outcome.alive) {
                this.alive = true;
                this.state = "ALIVE";
            } else if (!this.alive) {
                this.state = "NO_REPLY";
            }

            if (!outcome.lastError.isBlank() && this.note.isBlank()) {
                this.note = outcome.lastError;
            }
        }

        private Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("ip", target);
            map.put("alive", alive);
            map.put("state", state);
            map.put("discovery_methods", new ArrayList<>(methods));
            map.put("probes_sent", probesSent);
            map.put("probes_received", probesReceived);
            map.put("packet_loss_percent", round(packetLossPercent));
            map.put("response_rate_percent", round(Math.max(0.0, 100.0 - packetLossPercent)));

            if (!rttSamples.isEmpty()) {
                map.put("rtt_min_ms", round(rttSamples.stream().min(Double::compareTo).orElse(0.0)));
                map.put("rtt_avg_ms", round(rttSamples.stream().mapToDouble(Double::doubleValue).average().orElse(0.0)));
                map.put("rtt_max_ms", round(rttSamples.stream().max(Double::compareTo).orElse(0.0)));
            }

            if (!dnsName.isBlank()) {
                map.put("dns_name", dnsName);
            }

            if (!openPorts.isEmpty()) {
                map.put("open_ports", new ArrayList<>(openPorts.keySet()));
                map.put("open_services", new ArrayList<>(openPorts.values()));
                List<String> detailed = openPorts.entrySet().stream()
                    .map(entry -> entry.getKey() + "(" + entry.getValue() + ")")
                    .toList();
                map.put("service_exposure", detailed);
            }

            map.put("performance_score", round(performanceScore));
            map.put("performance_band", performanceBand);
            map.put("estimated_throughput_mbps", round(estimatedThroughputMbps));
            map.put("throughput_model", "estimated_from_latency_and_packet_loss");

            if (!note.isBlank()) {
                map.put("note", note);
            }

            return map;
        }

        private static double round(double value) {
            return Math.round(value * 100.0) / 100.0;
        }
    }

    protected static final class ExecutionDiagnostics {
        private final Set<String> toolUsage = new LinkedHashSet<>();
        private final List<String> executedCommands = new ArrayList<>();
        private final List<String> warnings = new ArrayList<>();
        private int commandExecutions;
    }

    protected static final class ScanConfig {
        private ModuleMode mode = ModuleMode.HOST_DISCOVERY;
        private String targetSubnet = "";
        private String confirmationTarget = "";
        private int timeoutMs = DEFAULT_TIMEOUT_MS;
        private int probeCount = DEFAULT_PROBE_COUNT;
        private int confirmationAttempts = DEFAULT_CONFIRMATION_ATTEMPTS;
        private int concurrency = DEFAULT_CONCURRENCY;
        private int maxHosts = DEFAULT_MAX_HOSTS;
        private int interProbeDelayMs;
        private boolean resolveDns;
        private boolean includeNonResponsive = true;

        private boolean useNmap = true;
        private boolean useFping = true;
        private boolean useArpScan;
        private String arpInterface = "";
        private boolean useHping3;
        private boolean useMasscan;
        private boolean enableTcpFallback = true;
        private String tcpFallbackPorts = DEFAULT_TCP_FALLBACK_PORTS;

        private boolean enableServiceProbe;
        private String servicePorts = DEFAULT_SERVICE_PORTS;
        private boolean enableThroughputEstimate;
    }

    private enum ModuleMode {
        HOST_DISCOVERY("host_discovery"),
        LATENCY_PROFILE("latency_profile"),
        ENHANCED_DISCOVERY("enhanced_discovery"),
        HOST_CONFIRMATION("host_confirmation");

        private final String value;

        ModuleMode(String value) {
            this.value = value;
        }

        private static ModuleMode fromInput(String raw) {
            String normalized = raw == null
                ? ""
                : raw.trim().toLowerCase(Locale.ROOT).replace('-', '_').replace(' ', '_');

            return switch (normalized) {
                case "latency_profile", "response_profile", "latency" -> LATENCY_PROFILE;
                case "enhanced_discovery", "enhanced", "priority", "enriched" -> ENHANCED_DISCOVERY;
                case "host_confirmation", "identify", "identification" -> HOST_CONFIRMATION;
                default -> HOST_DISCOVERY;
            };
        }
    }
}
