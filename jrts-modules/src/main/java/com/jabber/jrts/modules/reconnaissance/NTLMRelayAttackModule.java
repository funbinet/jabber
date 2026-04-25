package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.Category;
import com.jabber.jrts.data.model.JRTSModule;
import com.jabber.jrts.data.model.JRTSModuleInterface;
import com.jabber.jrts.data.model.ModuleInputField;
import com.jabber.jrts.data.model.ModuleResult;
import com.jabber.jrts.data.model.RiskLevel;
import com.jabber.jrts.data.model.TaskContext;
import com.jabber.jrts.data.model.TaskStatus;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@JRTSModule(
    id = "recon-ntlm-relay-attack",
    name = "NTLM Relay Attack",
    description = "Map NTLM relay surface across LDAP, SMB, HTTP/HTTPS, AD CS, and MSSQL by validating service reachability and protection posture.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.HIGH,
    sourceRef = "nmap/smb2-security-mode/http probes/ldap posture",
    author = "JRTS"
)
public class NTLMRelayAttackModule implements JRTSModuleInterface {

    private static final String MODULE_ID = "recon-ntlm-relay-attack";
    private static final String STANDARD_SCAN_PORTS = "389,636,445,80,443,1433";
    private static final List<Integer> RELAY_PORT_SET = List.of(389, 636, 445, 80, 443, 1433);

    private static final int DEFAULT_TIMEOUT_MS = 6000;
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 2500;
    private static final int DEFAULT_MAX_HOSTS = 1024;
    private static final int DEFAULT_MAX_SERVICE_CHECKS = 128;
    private static final int DEFAULT_MAX_LDAP_CHECKS = 32;
    private static final int MAX_HOSTS_LIMIT = 65534;

    private static final Pattern IPV4_PATTERN = Pattern.compile("((?:\\d{1,3}\\.){3}\\d{1,3})");
    private static final Pattern NMAP_PORT_LINE = Pattern.compile("^(\\d+)/tcp\\s+open\\s+([^\\s]+).*$", Pattern.CASE_INSENSITIVE);
    private static final Pattern HTTP_STATUS_PATTERN = Pattern.compile("HTTP/\\S+\\s+(\\d{3})", Pattern.CASE_INSENSITIVE);

    private final Map<String, Boolean> commandAvailabilityCache = new ConcurrentHashMap<>();

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of(
                    "relay_surface_map", "protection_assessment", "abuse_path_validation", "host_confirmation"
                ))
                .required()
                .defaultValue("relay_surface_map")
                .group("Mode")
                .helpText("Controls relay-surface mapping depth and target strategy."),
            ModuleInputField.text("target_subnet", "Target Subnet / Host List")
                .placeholder("10.10.0.0/24 or 10.10.0.10,10.10.0.20")
                .group("Target")
                .modes("relay_surface_map", "protection_assessment", "abuse_path_validation")
                .helpText("Primary target scope for relay surface mapping."),
            ModuleInputField.text("focus_host", "Focus Host")
                .placeholder("10.10.0.10")
                .group("Mode")
                .modes("host_confirmation")
                .helpText("Required when mode=host_confirmation."),
            ModuleInputField.text("domain", "Domain Context")
                .placeholder("contoso.local")
                .group("Target")
                .helpText("Optional AD domain context for LDAP posture checks."),

            ModuleInputField.text("username", "Username")
                .placeholder("CONTOSO\\operator or operator@contoso.local")
                .group("Authentication"),
            ModuleInputField.password("password", "Password")
                .group("Authentication"),
            ModuleInputField.checkbox("use_kerberos", "Use Kerberos for LDAP Posture Checks")
                .defaultValue("false")
                .group("Authentication"),

            ModuleInputField.text("timeout_ms", "Command Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_TIMEOUT_MS))
                .group("Execution"),
            ModuleInputField.text("connect_timeout_ms", "Connect Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_CONNECT_TIMEOUT_MS))
                .group("Execution"),
            ModuleInputField.text("max_hosts", "Maximum Hosts")
                .placeholder(String.valueOf(DEFAULT_MAX_HOSTS))
                .group("Execution")
                .modes("relay_surface_map", "protection_assessment", "abuse_path_validation"),
            ModuleInputField.text("max_service_checks", "Maximum Service Deep Checks")
                .placeholder(String.valueOf(DEFAULT_MAX_SERVICE_CHECKS))
                .group("Execution"),
            ModuleInputField.text("max_ldap_checks", "Maximum LDAP Posture Checks")
                .placeholder(String.valueOf(DEFAULT_MAX_LDAP_CHECKS))
                .group("Execution"),

            ModuleInputField.checkbox("use_nmap", "Use Nmap for Service Discovery")
                .defaultValue("true")
                .group("Tools"),
            ModuleInputField.checkbox("use_curl", "Use curl for HTTP/ADCS Probes")
                .defaultValue("true")
                .group("Tools"),
            ModuleInputField.checkbox("use_ldap_status_checker", "Use LDAP Status Checker for LDAP Relay Posture")
                .defaultValue("true")
                .group("Tools"),
            ModuleInputField.checkbox("check_smb_signing_in_surface_map", "Check SMB Signing in Surface Map Mode")
                .defaultValue("true")
                .modes("relay_surface_map")
                .group("Tools"),

            ModuleInputField.checkbox("include_non_relayable", "Include Non-Relayable Hosts in Output")
                .defaultValue("true")
                .group("Output"),
            ModuleInputField.checkbox("resolve_dns", "Resolve DNS Names")
                .defaultValue("false")
                .group("Output"),
            ModuleInputField.checkbox("risk_on_unknown_signing", "Treat Unknown Signing as Potential Relay Risk")
                .defaultValue("true")
                .group("Output")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), MODULE_ID);
            long startedAt = System.currentTimeMillis();

            try {
                ctx.log("[*] Starting NTLM Relay Attack surface mapping module");
                ctx.reportProgress(5);

                ScanConfig config = parseConfig(input);
                List<String> validationErrors = validateConfig(config);
                if (!validationErrors.isEmpty()) {
                    String message = String.join("; ", validationErrors);
                    result.fail("Validation failed: " + message);
                    ctx.log("[!] Validation failed: " + message);
                    return result;
                }

                String targetExpression = resolveTargetExpression(config);
                ctx.log("[*] Mode: " + config.mode.value);
                ctx.log("[*] Target expression: " + targetExpression);
                ctx.reportProgress(15);

                ExecutionDiagnostics diagnostics = new ExecutionDiagnostics();
                Map<String, HostSurface> hostMap = discoverTargetsAndServices(config, targetExpression, diagnostics, ctx);

                if (hostMap.isEmpty()) {
                    Map<String, Object> summary = emptySummary(config);
                    Map<String, Object> output = new LinkedHashMap<>();
                    output.put("pipeline", pipeline());
                    output.put("mode", config.mode.value);
                    output.put("target_expression", targetExpression);
                    output.put("hosts", List.of());
                    output.put("summary", summary);
                    output.put("operational_stack", buildOperationalStack());
                    output.put("recommended_commands", buildRecommendedCommands(List.of(), config));
                    output.put("execution_metadata", buildExecutionMetadata(config, diagnostics, startedAt));

                    result.setNormalizedOutput(buildNormalizedOutput(summary, List.of(), config));
                    result.complete(output);
                    ctx.log("[+] No relay-surface hosts found in target scope");
                    ctx.reportProgress(100);
                    return result;
                }

                List<HostSurface> hosts = sortHosts(hostMap);
                ctx.log("[*] Hosts with relay-relevant services: " + hosts.size());
                ctx.reportProgress(35);

                analyzeServiceProtections(hosts, config, diagnostics, ctx);
                ctx.reportProgress(88);

                if (config.resolveDns) {
                    enrichDns(hosts, ctx);
                }

                List<Map<String, Object>> hostOutput = new ArrayList<>();
                for (HostSurface host : hosts) {
                    if (!config.includeNonRelayable && host.relayableProtocols.isEmpty()) {
                        continue;
                    }

                    Map<String, Object> map = host.toOutput(config.mode);
                    hostOutput.add(map);
                    result.addFinding(map);
                }

                Map<String, Object> summary = buildSummary(hosts, config);
                List<Map<String, Object>> relayPaths = buildRelayPaths(hosts);
                List<Map<String, Object>> recommendedCommands = buildRecommendedCommands(hosts, config);

                Map<String, Object> output = new LinkedHashMap<>();
                output.put("pipeline", pipeline());
                output.put("mode", config.mode.value);
                output.put("target_expression", targetExpression);
                output.put("hosts", hostOutput);
                output.put("summary", summary);
                output.put("relay_paths", relayPaths);
                output.put("operational_stack", buildOperationalStack());
                output.put("recommended_commands", recommendedCommands);
                output.put("execution_metadata", buildExecutionMetadata(config, diagnostics, startedAt));

                result.setNormalizedOutput(buildNormalizedOutput(summary, hostOutput, config));
                result.complete(output);

                ctx.log("[+] NTLM relay surface mapping completed");
                ctx.reportProgress(100);
            } catch (Exception e) {
                result.fail("NTLM relay surface mapping failed: " + e.getMessage());
                ctx.log("[!] ERROR: " + e.getMessage());
            }

            return result;
        });
    }

    private List<String> pipeline() {
        return List.of(
            "mode_selection",
            "input_validation",
            "processing_engine",
            "execution_checks",
            "relay_decision_model",
            "result_normalization",
            "structured_output"
        );
    }

    private Map<String, HostSurface> discoverTargetsAndServices(
            ScanConfig config,
            String targetExpression,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx) {

        Map<String, HostSurface> hostMap = new LinkedHashMap<>();

        if (config.useNmap && isCommandAvailable("nmap")) {
            hostMap.putAll(runNmapServiceDiscovery(targetExpression, config, diagnostics));
            if (!hostMap.isEmpty()) {
                ctx.log("[*] Base nmap service discovery identified " + hostMap.size() + " host(s)");
            }
        } else if (config.useNmap) {
            diagnostics.warnings.add("nmap requested but not available. Falling back to socket checks.");
        }

        if (hostMap.isEmpty()) {
            List<String> candidates = resolveHostCandidates(config, targetExpression);
            hostMap.putAll(runSocketDiscovery(candidates, config, diagnostics, ctx));
        }

        if (config.mode == ModuleMode.HOST_CONFIRMATION) {
            String focusHost = normalizeTarget(config.focusHost);
            hostMap.computeIfAbsent(focusHost, HostSurface::new);
        }

        return hostMap;
    }

    private Map<String, HostSurface> runNmapServiceDiscovery(
            String targetExpression,
            ScanConfig config,
            ExecutionDiagnostics diagnostics) {

        List<String> command = new ArrayList<>();
        command.add("nmap");
        command.add("-n");
        command.add("-Pn");
        command.add("-p");
        command.add(STANDARD_SCAN_PORTS);
        command.add("--open");
        command.add(normalizeTargetExpression(targetExpression));

        long timeout = Math.max(10_000L, config.timeoutMs * 25L);
        CommandExecutionResult result = runCommand(command, timeout);

        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("nmap");
        diagnostics.executedCommands.add(String.join(" ", command));

        if (result.timedOut) {
            diagnostics.warnings.add("nmap base scan timed out");
            return Map.of();
        }
        if (result.exitCode != 0 && result.stdout.isBlank() && result.stderr.isBlank()) {
            diagnostics.warnings.add("nmap base scan returned no output and non-zero exit code");
            return Map.of();
        }

        return parseNmapServiceScan(result.combinedOutput());
    }

    private Map<String, HostSurface> runSocketDiscovery(
            List<String> candidates,
            ScanConfig config,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx) {

        if (candidates.isEmpty()) {
            return Map.of();
        }

        Map<String, HostSurface> surfaces = new LinkedHashMap<>();
        for (String host : candidates) {
            surfaces.put(host, new HostSurface(host));
        }

        ThreadFactory threadFactory = Thread.ofVirtual().name("jrts-ntlm-socket-discovery-", 0).factory();
        ExecutorService executor = Executors.newThreadPerTaskExecutor(threadFactory);
        ExecutorCompletionService<PortProbeResult> completion = new ExecutorCompletionService<>(executor);

        int submitted = 0;
        try {
            for (String host : candidates) {
                for (int port : RELAY_PORT_SET) {
                    String hostCopy = host;
                    int portCopy = port;
                    completion.submit(() -> new PortProbeResult(
                        hostCopy,
                        portCopy,
                        checkTcpPort(hostCopy, portCopy, config.connectTimeoutMs)
                    ));
                    submitted++;
                }
            }

            int completed = 0;
            for (int i = 0; i < submitted; i++) {
                Future<PortProbeResult> future = completion.take();
                PortProbeResult probe = future.get();
                HostSurface host = surfaces.get(probe.host);
                if (host != null && probe.open) {
                    host.openPorts.add(probe.port);
                    host.portServices.put(probe.port, standardServiceName(probe.port));
                    host.discoveryMethods.add("SOCKET_TCP_CONNECT");
                }

                completed++;
                if (submitted > 0 && completed % Math.max(1, submitted / 8) == 0) {
                    ctx.log("[*] Socket discovery progress: " + completed + "/" + submitted);
                }
            }
        } catch (Exception e) {
            diagnostics.warnings.add("socket discovery error: " + e.getMessage());
        } finally {
            executor.shutdownNow();
        }

        diagnostics.toolUsage.add("java_socket_connect");

        if (config.mode != ModuleMode.HOST_CONFIRMATION) {
            surfaces.entrySet().removeIf(entry -> entry.getValue().openPorts.isEmpty());
        }
        return surfaces;
    }

    private void analyzeServiceProtections(
            List<HostSurface> hosts,
            ScanConfig config,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx) {

        int ldapChecks = 0;
        int deepChecks = 0;
        int total = hosts.size();

        for (int i = 0; i < hosts.size(); i++) {
            HostSurface host = hosts.get(i);

            boolean runSmbCheck = host.hasPort(445)
                && (config.mode != ModuleMode.RELAY_SURFACE_MAP || config.checkSmbSigningInSurfaceMap);

            if (runSmbCheck) {
                analyzeSmbSigning(host, config, diagnostics);
            }

            boolean analysisMode = config.mode == ModuleMode.PROTECTION_ASSESSMENT
                || config.mode == ModuleMode.ABUSE_PATH_VALIDATION
                || config.mode == ModuleMode.HOST_CONFIRMATION;

            if (analysisMode && host.hasAnyPort(389, 636) && config.useLdapStatusChecker) {
                if (ldapChecks < config.maxLdapChecks) {
                    host.ldapPosture = executeLdapStatusCheck(host.host, config);
                    ldapChecks++;
                } else {
                    host.ldapPosture = LdapRelayPosture.unknown("ldap posture limit reached");
                    diagnostics.warnings.add("LDAP posture checks capped at max_ldap_checks");
                }
            }

            boolean deepMode = config.mode == ModuleMode.ABUSE_PATH_VALIDATION
                || config.mode == ModuleMode.HOST_CONFIRMATION;
            if (deepMode && deepChecks < config.maxServiceChecks) {
                if (host.hasAnyPort(80, 443)) {
                    analyzeWebRelaySurface(host, config, diagnostics);
                    deepChecks++;
                }

                if (host.hasPort(1433)) {
                    analyzeMssqlNtlm(host, config, diagnostics);
                    deepChecks++;
                }
            }

            evaluateHostRelayability(host, config);

            int pct = 35 + (int) (((i + 1) / (double) Math.max(1, total)) * 50);
            ctx.reportProgress(Math.min(85, pct));
        }
    }

    private void analyzeSmbSigning(HostSurface host, ScanConfig config, ExecutionDiagnostics diagnostics) {
        if (!isCommandAvailable("nmap")) {
            host.smbSigning = SmbSigningState.UNKNOWN;
            host.evidence.add("SMB signing check skipped: nmap unavailable");
            return;
        }

        List<String> command = List.of(
            "nmap",
            "-n",
            "-Pn",
            "-p445",
            "--script",
            "smb2-security-mode",
            host.host
        );

        CommandExecutionResult scriptResult = runCommand(command, Math.max(6_000L, config.timeoutMs * 2L));
        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("nmap");
        diagnostics.executedCommands.add(String.join(" ", command));

        if (scriptResult.timedOut) {
            host.smbSigning = SmbSigningState.UNKNOWN;
            host.evidence.add("SMB signing check timed out");
            return;
        }

        String output = scriptResult.combinedOutput();
        host.smbSigning = parseSmbSigningState(output);
        host.evidence.add("SMB signing assessment: " + host.smbSigning.value);
    }

    private void analyzeWebRelaySurface(HostSurface host, ScanConfig config, ExecutionDiagnostics diagnostics) {
        if (config.useCurl && !isCommandAvailable("curl")) {
            diagnostics.warnings.add("curl requested but unavailable; HTTP/ADCS probes skipped for " + host.host);
            host.evidence.add("HTTP probes skipped: curl unavailable");
            return;
        }

        if (host.hasPort(80)) {
            HttpProbeResult root = probeHttpHeaders("http://" + host.host + "/", config.timeoutMs);
            host.httpNtlmAccepted = root.supportsNtlm || root.supportsNegotiate;
            host.httpStatusCode = root.statusCode;
            if (!root.error.isBlank()) {
                host.evidence.add("HTTP probe error: " + root.error);
            }

            HttpProbeResult certsrv = probeHttpHeaders("http://" + host.host + "/certsrv/", config.timeoutMs);
            host.adcsHttpExposed = certsrv.statusCode > 0 && certsrv.statusCode != 404;
            host.adcsNtlmAccepted = host.adcsNtlmAccepted || certsrv.supportsNtlm || certsrv.supportsNegotiate;
        }

        if (host.hasPort(443)) {
            HttpProbeResult rootTls = probeHttpHeaders("https://" + host.host + "/", config.timeoutMs);
            host.httpsNtlmAccepted = rootTls.supportsNtlm || rootTls.supportsNegotiate;
            host.httpsStatusCode = rootTls.statusCode;
            if (!rootTls.error.isBlank()) {
                host.evidence.add("HTTPS probe error: " + rootTls.error);
            }

            HttpProbeResult certsrvTls = probeHttpHeaders("https://" + host.host + "/certsrv/", config.timeoutMs);
            host.adcsHttpsExposed = certsrvTls.statusCode > 0 && certsrvTls.statusCode != 404;
            host.adcsNtlmAccepted = host.adcsNtlmAccepted || certsrvTls.supportsNtlm || certsrvTls.supportsNegotiate;
        }
    }

    private void analyzeMssqlNtlm(HostSurface host, ScanConfig config, ExecutionDiagnostics diagnostics) {
        if (!isCommandAvailable("nmap")) {
            host.mssqlNtlmState = SecurityState.UNKNOWN;
            host.evidence.add("MSSQL NTLM probe skipped: nmap unavailable");
            return;
        }

        List<String> command = List.of(
            "nmap",
            "-n",
            "-Pn",
            "-p1433",
            "--script",
            "ms-sql-ntlm-info",
            host.host
        );

        CommandExecutionResult scriptResult = runCommand(command, Math.max(8_000L, config.timeoutMs * 2L));
        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("nmap");
        diagnostics.executedCommands.add(String.join(" ", command));

        if (scriptResult.timedOut) {
            host.mssqlNtlmState = SecurityState.UNKNOWN;
            host.evidence.add("MSSQL NTLM probe timed out");
            return;
        }

        String lowered = scriptResult.combinedOutput().toLowerCase(Locale.ROOT);
        if (lowered.contains("ntlm")) {
            host.mssqlNtlmState = SecurityState.YES;
        } else if (lowered.contains("closed") || lowered.contains("filtered")) {
            host.mssqlNtlmState = SecurityState.NO;
        } else {
            host.mssqlNtlmState = SecurityState.UNKNOWN;
        }
    }

    private void evaluateHostRelayability(HostSurface host, ScanConfig config) {
        host.relayableProtocols.clear();
        host.relayReasons.clear();

        if (host.hasPort(445)) {
            if (host.smbSigning == SmbSigningState.OPTIONAL || host.smbSigning == SmbSigningState.DISABLED) {
                host.relayableProtocols.add("SMB");
                host.relayReasons.add("SMB signing is not mandatory.");
            } else if (host.smbSigning == SmbSigningState.UNKNOWN && config.riskOnUnknownSigning) {
                host.relayableProtocols.add("SMB_POTENTIAL");
                host.relayReasons.add("SMB signing state is unknown.");
            }
        }

        if (host.hasAnyPort(389, 636)) {
            if (host.ldapPosture != null) {
                if (host.ldapPosture.relayViable) {
                    host.relayableProtocols.add("LDAP");
                    host.relayReasons.add("LDAP posture indicates relay viability.");
                } else if (isLdapSigningWeak(host.ldapPosture.signingMode)) {
                    host.relayableProtocols.add("LDAP");
                    host.relayReasons.add("LDAP signing is not strictly required.");
                } else if ("unknown".equals(host.ldapPosture.signingMode) && config.riskOnUnknownSigning) {
                    host.relayableProtocols.add("LDAP_POTENTIAL");
                    host.relayReasons.add("LDAP signing/channel binding posture is unknown.");
                }
            } else if (host.hasPort(389) && config.riskOnUnknownSigning) {
                host.relayableProtocols.add("LDAP_POTENTIAL");
                host.relayReasons.add("LDAP reachable but posture was not checked.");
            }
        }

        if (host.httpNtlmAccepted || host.httpsNtlmAccepted) {
            host.relayableProtocols.add("HTTP");
            host.relayReasons.add("HTTP endpoint advertises NTLM/Negotiate authentication.");
        }

        if ((host.adcsHttpExposed || host.adcsHttpsExposed)
                && (host.httpNtlmAccepted || host.httpsNtlmAccepted || host.adcsNtlmAccepted)) {
            host.relayableProtocols.add("ADCS");
            host.relayReasons.add("AD CS web enrollment endpoint appears exposed for relayed authentication.");
        }

        if (host.hasPort(1433) && host.mssqlNtlmState != SecurityState.NO) {
            host.relayableProtocols.add("MSSQL");
            if (host.mssqlNtlmState == SecurityState.YES) {
                host.relayReasons.add("MSSQL NTLM support detected.");
            } else {
                host.relayReasons.add("MSSQL reachable; NTLM state uncertain.");
            }
        }

        if (containsAny(host.relayableProtocols, "ADCS", "LDAP", "SMB")) {
            host.risk = RiskLabel.HIGH;
        } else if (!host.relayableProtocols.isEmpty()) {
            host.risk = RiskLabel.MEDIUM;
        } else if (host.hasAnyPort(389, 636, 445, 80, 443, 1433)) {
            host.risk = RiskLabel.LOW;
        } else {
            host.risk = RiskLabel.INFO;
        }
    }

    private boolean containsAny(Set<String> values, String... probes) {
        for (String probe : probes) {
            if (values.contains(probe)) {
                return true;
            }
        }
        return false;
    }

    private boolean isLdapSigningWeak(String signingMode) {
        String mode = trim(signingMode).toLowerCase(Locale.ROOT);
        return "none".equals(mode) || "negotiate".equals(mode);
    }

    private void enrichDns(List<HostSurface> hosts, TaskContext ctx) {
        int resolved = 0;
        for (HostSurface host : hosts) {
            String dns = resolveDnsName(host.host);
            if (!dns.isBlank() && !dns.equalsIgnoreCase(host.host)) {
                host.dnsName = dns;
                resolved++;
            }
        }
        ctx.log("[*] DNS enrichment resolved " + resolved + " hostnames");
    }

    protected String resolveDnsName(String host) {
        try {
            return InetAddress.getByName(host).getCanonicalHostName();
        } catch (Exception e) {
            return "";
        }
    }

    protected LdapRelayPosture executeLdapStatusCheck(String host, ScanConfig config) {
        LDAPStatusCheckerModule ldapModule = new LDAPStatusCheckerModule();
        Map<String, String> input = new LinkedHashMap<>();
        input.put("mode", "controller_confirmation");
        input.put("controller_target", host);
        input.put("timeout_ms", String.valueOf(config.timeoutMs));
        input.put("connect_timeout_ms", String.valueOf(config.connectTimeoutMs));
        input.put("run_bind_tests", "true");

        if (!config.domain.isBlank()) {
            input.put("domain", config.domain);
        }
        if (!config.username.isBlank()) {
            input.put("username", config.username);
        }
        if (!config.password.isBlank()) {
            input.put("password", config.password);
        }
        if (config.useKerberos) {
            input.put("use_kerberos", "true");
        }

        TaskContext subCtx = new TaskContext(UUID.randomUUID().toString(), "relay-ldap-subtask");
        subCtx.setLogCallback(line -> {});
        subCtx.setProgressCallback(progress -> {});

        try {
            ModuleResult result = ldapModule.execute(input, subCtx).get(45, TimeUnit.SECONDS);
            if (result.getStatus() != TaskStatus.COMPLETED) {
                return LdapRelayPosture.unknown(firstNonBlank(result.getErrorMessage(), "ldap status checker failed"));
            }

            Map<String, Object> confirmation = asMap(result.getOutput().get("confirmation_result"));
            Map<String, Object> checks = asMap(confirmation.get("checks"));
            Map<String, Object> relay = asMap(confirmation.get("relay_assessment"));

            LdapRelayPosture posture = new LdapRelayPosture();
            posture.success = true;
            posture.signingMode = asString(checks.get("ldap_signing_mode"), "unknown");
            posture.channelBindingMode = asString(checks.get("channel_binding_mode"), "unknown");
            posture.relayViable = asBoolean(relay.get("relay_viable"));
            posture.riskLevel = asString(relay.get("risk_level"), "unknown");
            posture.reasons = asStringList(relay.get("reasons"));
            posture.raw = confirmation;
            return posture;
        } catch (Exception e) {
            return LdapRelayPosture.unknown(e.getMessage());
        }
    }

    protected HttpProbeResult probeHttpHeaders(String url, int timeoutMs) {
        if (!isCommandAvailable("curl")) {
            HttpProbeResult unavailable = new HttpProbeResult();
            unavailable.error = "curl unavailable";
            return unavailable;
        }

        int timeoutSeconds = Math.max(1, (int) Math.ceil(timeoutMs / 1000.0));
        List<String> command = List.of(
            "curl",
            "-k",
            "-sS",
            "--max-time",
            String.valueOf(timeoutSeconds),
            "-o",
            "/dev/null",
            "-D",
            "-",
            url
        );

        CommandExecutionResult result = runCommand(command, Math.max(3_000L, timeoutMs * 2L));
        if (result.timedOut) {
            HttpProbeResult timedOut = new HttpProbeResult();
            timedOut.error = "timeout";
            return timedOut;
        }

        String output = result.combinedOutput();
        HttpProbeResult probe = parseHttpHeaders(output);
        if (probe.statusCode <= 0 && result.exitCode != 0 && probe.error.isBlank()) {
            probe.error = firstNonBlank(firstLine(result.stderr), "http probe failed");
        }
        return probe;
    }

    private HttpProbeResult parseHttpHeaders(String output) {
        HttpProbeResult probe = new HttpProbeResult();
        if (output == null || output.isBlank()) {
            probe.error = "no header output";
            return probe;
        }

        for (String rawLine : output.split("\\R")) {
            String line = rawLine.trim();
            if (line.isBlank()) {
                continue;
            }

            Matcher statusMatcher = HTTP_STATUS_PATTERN.matcher(line);
            if (statusMatcher.find()) {
                probe.statusCode = parseInteger(statusMatcher.group(1), 0);
                continue;
            }

            int separator = line.indexOf(':');
            if (separator <= 0 || separator + 1 >= line.length()) {
                continue;
            }

            String key = line.substring(0, separator).trim();
            String value = line.substring(separator + 1).trim();
            probe.headers.put(key, value);
            if ("www-authenticate".equalsIgnoreCase(key)) {
                String lower = value.toLowerCase(Locale.ROOT);
                if (lower.contains("ntlm")) {
                    probe.supportsNtlm = true;
                }
                if (lower.contains("negotiate")) {
                    probe.supportsNegotiate = true;
                }
            }
        }

        probe.success = probe.statusCode > 0;
        return probe;
    }

    protected boolean checkTcpPort(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    protected boolean isCommandAvailable(String command) {
        return commandAvailabilityCache.computeIfAbsent(command, cmd -> {
            List<String> checkCommand = isWindows()
                ? List.of("where", cmd)
                : List.of("which", cmd);

            CommandExecutionResult result = runCommand(checkCommand, 2_000);
            return !result.timedOut && result.exitCode == 0;
        });
    }

    protected CommandExecutionResult runCommand(List<String> command, long timeoutMs) {
        long startedAt = System.currentTimeMillis();
        Process process = null;

        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            Process running = builder.start();
            process = running;

            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();

            Thread outThread = Thread.ofVirtual().start(() -> copyStream(running.getInputStream(), stdout));
            Thread errThread = Thread.ofVirtual().start(() -> copyStream(running.getErrorStream(), stderr));

            boolean finished = running.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            if (!finished) {
                running.destroyForcibly();
                joinQuietly(outThread, 200);
                joinQuietly(errThread, 200);
                return new CommandExecutionResult(
                    -1,
                    stdout.toString(),
                    stderr.toString(),
                    true,
                    System.currentTimeMillis() - startedAt
                );
            }

            joinQuietly(outThread, 300);
            joinQuietly(errThread, 300);

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

    private Map<String, HostSurface> parseNmapServiceScan(String output) {
        Map<String, HostSurface> surfaces = new LinkedHashMap<>();
        HostSurface current = null;

        for (String rawLine : output.split("\\R")) {
            String line = rawLine.trim();
            if (line.isBlank()) {
                continue;
            }

            if (line.startsWith("Nmap scan report for ")) {
                String host = parseHostFromNmapHeader(line);
                current = surfaces.computeIfAbsent(host, HostSurface::new);
                current.discoveryMethods.add("NMAP_SERVICE_SCAN");
                continue;
            }

            if (current == null) {
                continue;
            }

            Matcher portMatcher = NMAP_PORT_LINE.matcher(line);
            if (portMatcher.find()) {
                int port = parseInteger(portMatcher.group(1), -1);
                if (port > 0) {
                    current.openPorts.add(port);
                    current.portServices.put(port, portMatcher.group(2));
                }
            }
        }

        surfaces.entrySet().removeIf(entry -> entry.getValue().openPorts.isEmpty());
        return surfaces;
    }

    private String parseHostFromNmapHeader(String line) {
        String raw = line.replace("Nmap scan report for", "").trim();
        Matcher ipMatch = IPV4_PATTERN.matcher(raw);
        if (ipMatch.find()) {
            return ipMatch.group(1);
        }
        return raw;
    }

    private List<HostSurface> sortHosts(Map<String, HostSurface> map) {
        List<HostSurface> hosts = new ArrayList<>(map.values());
        hosts.sort(Comparator
            .comparingLong((HostSurface host) -> ipSortKey(host.host))
            .thenComparing(host -> host.host));
        return hosts;
    }

    private Map<String, Object> buildSummary(List<HostSurface> hosts, ScanConfig config) {
        long withRelayPorts = hosts.stream().filter(host -> host.hasAnyPort(389, 636, 445, 80, 443, 1433)).count();
        long relayable = hosts.stream().filter(host -> !host.relayableProtocols.isEmpty()).count();
        long highRisk = hosts.stream().filter(host -> host.risk == RiskLabel.HIGH).count();

        long smbSigningRequired = hosts.stream().filter(host -> host.smbSigning == SmbSigningState.REQUIRED).count();
        long smbSigningWeak = hosts.stream().filter(host ->
            host.smbSigning == SmbSigningState.OPTIONAL || host.smbSigning == SmbSigningState.DISABLED
        ).count();

        long ldapSigningRequired = hosts.stream().filter(host ->
            host.ldapPosture != null && "require".equals(host.ldapPosture.signingMode)
        ).count();
        long ldapSigningWeak = hosts.stream().filter(host ->
            host.ldapPosture != null && isLdapSigningWeak(host.ldapPosture.signingMode)
        ).count();

        long adcsExposed = hosts.stream().filter(host -> host.adcsHttpExposed || host.adcsHttpsExposed).count();

        Map<String, Integer> protocolCounts = new LinkedHashMap<>();
        for (String protocol : List.of("SMB", "SMB_POTENTIAL", "LDAP", "LDAP_POTENTIAL", "HTTP", "ADCS", "MSSQL")) {
            protocolCounts.put(protocol, 0);
        }

        for (HostSurface host : hosts) {
            for (String protocol : host.relayableProtocols) {
                protocolCounts.put(protocol, protocolCounts.getOrDefault(protocol, 0) + 1);
            }
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", config.mode.value);
        summary.put("hosts_profiled", hosts.size());
        summary.put("hosts_with_relay_ports", withRelayPorts);
        summary.put("relayable_targets", relayable);
        summary.put("high_risk_targets", highRisk);
        summary.put("smb_signing_required_count", smbSigningRequired);
        summary.put("smb_signing_weak_count", smbSigningWeak);
        summary.put("ldap_signing_required_count", ldapSigningRequired);
        summary.put("ldap_signing_weak_count", ldapSigningWeak);
        summary.put("adcs_exposed_targets", adcsExposed);
        summary.put("protocol_relayable_counts", protocolCounts);
        return summary;
    }

    private Map<String, Object> emptySummary(ScanConfig config) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", config.mode.value);
        summary.put("hosts_profiled", 0);
        summary.put("hosts_with_relay_ports", 0);
        summary.put("relayable_targets", 0);
        summary.put("high_risk_targets", 0);
        summary.put("smb_signing_required_count", 0);
        summary.put("smb_signing_weak_count", 0);
        summary.put("ldap_signing_required_count", 0);
        summary.put("ldap_signing_weak_count", 0);
        summary.put("adcs_exposed_targets", 0);
        summary.put("protocol_relayable_counts", Map.of());
        return summary;
    }

    private List<Map<String, Object>> buildRelayPaths(List<HostSurface> hosts) {
        List<Map<String, Object>> paths = new ArrayList<>();

        for (HostSurface host : hosts) {
            for (String protocol : host.relayableProtocols) {
                Map<String, Object> path = new LinkedHashMap<>();
                path.put("source", "captured_ntlm_authentication");
                path.put("relay_target", host.host);
                path.put("protocol", protocol);
                path.put("risk_level", host.risk.value);

                switch (protocol) {
                    case "SMB", "SMB_POTENTIAL" -> path.put("outcome", "remote file/service access and possible command execution");
                    case "LDAP", "LDAP_POTENTIAL" -> path.put("outcome", "directory object modification and privilege escalation path creation");
                    case "ADCS" -> path.put("outcome", "certificate enrollment abuse and identity impersonation");
                    case "HTTP" -> path.put("outcome", "web authentication context relay and unauthorized application access");
                    case "MSSQL" -> path.put("outcome", "database access and execution via relayed integrated auth");
                    default -> path.put("outcome", "unknown");
                }

                paths.add(path);
            }
        }

        return paths;
    }

    private List<Map<String, Object>> buildOperationalStack() {
        List<Map<String, Object>> stack = new ArrayList<>();

        stack.add(tool("Responder", "NTLM capture baseline and poisoning framework", "https://github.com/lgandx/Responder"));
        stack.add(tool("ntlmrelayx", "Relay execution engine for SMB/LDAP/HTTP/MSSQL/ADCS", "https://github.com/fortra/impacket"));
        stack.add(tool("CrackMapExec", "SMB/LDAP auth posture testing and signing visibility", "https://github.com/byt3bl33d3r/CrackMapExec"));
        stack.add(tool("Nmap", "Service discovery and SMB signing / NTLM script checks", "https://nmap.org"));
        stack.add(tool("ldapdomaindump", "LDAP exposure and structure validation", "https://github.com/dirkjanm/ldapdomaindump"));

        return stack;
    }

    private Map<String, Object> tool(String name, String purpose, String reference) {
        Map<String, Object> tool = new LinkedHashMap<>();
        tool.put("name", name);
        tool.put("purpose", purpose);
        tool.put("reference", reference);
        return tool;
    }

    private List<Map<String, Object>> buildRecommendedCommands(List<HostSurface> hosts, ScanConfig config) {
        List<Map<String, Object>> commands = new ArrayList<>();

        commands.add(commandHint(
            "surface_scan",
            "nmap -p 389,636,445,80,443,1433 --script smb2-security-mode <target_scope>",
            "Discover relay-relevant services and SMB signing posture"
        ));
        commands.add(commandHint(
            "capture_baseline",
            "responder -I <interface> -wrf",
            "Capture inbound NTLM authentication attempts"
        ));

        List<String> smbTargets = new ArrayList<>();
        List<String> ldapTargets = new ArrayList<>();
        List<String> adcsTargets = new ArrayList<>();
        for (HostSurface host : hosts) {
            if (host.relayableProtocols.contains("SMB") || host.relayableProtocols.contains("SMB_POTENTIAL")) {
                smbTargets.add(host.host);
            }
            if (host.relayableProtocols.contains("LDAP") || host.relayableProtocols.contains("LDAP_POTENTIAL")) {
                ldapTargets.add(host.host);
            }
            if (host.relayableProtocols.contains("ADCS")) {
                adcsTargets.add(host.host);
            }
        }

        if (!smbTargets.isEmpty() || !ldapTargets.isEmpty()) {
            commands.add(commandHint(
                "relay_engine",
                "ntlmrelayx.py -tf relay_targets.txt -smb2support",
                "Run relay checks against curated SMB/LDAP targets"
            ));
        }

        if (!adcsTargets.isEmpty()) {
            commands.add(commandHint(
                "adcs_relay",
                "ntlmrelayx.py -tf adcs_targets.txt --adcs --template Machine",
                "Assess AD CS web enrollment relay exposure"
            ));
        }

        if (!config.domain.isBlank()) {
            commands.add(commandHint(
                "ldap_exposure",
                "ldapdomaindump -u '<domain>\\<user>' -p '<password>' <dc_host>",
                "Validate LDAP-readable object surface and ACL context"
            ));
        }

        return commands;
    }

    private Map<String, Object> commandHint(String id, String command, String purpose) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        map.put("command", command);
        map.put("purpose", purpose);
        return map;
    }

    private Map<String, Object> buildExecutionMetadata(
            ScanConfig config,
            ExecutionDiagnostics diagnostics,
            long startedAt) {

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("module", MODULE_ID);
        metadata.put("mode", config.mode.value);
        metadata.put("tools_used", new ArrayList<>(diagnostics.toolUsage));
        metadata.put("command_executions", diagnostics.commandExecutions);
        metadata.put("executed_commands", diagnostics.executedCommands);
        metadata.put("warnings", diagnostics.warnings);
        metadata.put("timeout_ms", config.timeoutMs);
        metadata.put("connect_timeout_ms", config.connectTimeoutMs);
        metadata.put("max_hosts", config.maxHosts);
        metadata.put("max_service_checks", config.maxServiceChecks);
        metadata.put("max_ldap_checks", config.maxLdapChecks);
        metadata.put("elapsed_ms", System.currentTimeMillis() - startedAt);
        return metadata;
    }

    private Map<String, Object> buildNormalizedOutput(
            Map<String, Object> summary,
            List<Map<String, Object>> hostOutput,
            ScanConfig config) {

        Map<String, Object> normalized = new LinkedHashMap<>();

        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("summary", summary);
        raw.put("host_count", hostOutput.size());
        normalized.put("raw_output", raw);

        long relayableTargets = ((Number) summary.getOrDefault("relayable_targets", 0)).longValue();

        Map<String, Object> parsed = new LinkedHashMap<>();
        parsed.put("status", relayableTargets > 0 ? "NTLM_RELAY_SURFACE_PRESENT" : "NTLM_RELAY_SURFACE_NOT_CONFIRMED");
        parsed.put("vulnerable", relayableTargets > 0);
        parsed.put("details", summary);
        parsed.put("evidence", hostOutput);
        normalized.put("parsed_output", parsed);

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("mode", config.mode.value);
        metadata.put("target", config.mode == ModuleMode.HOST_CONFIRMATION ? config.focusHost : config.targetSubnet);
        normalized.put("metadata", metadata);

        return normalized;
    }

    private String resolveTargetExpression(ScanConfig config) {
        if (config.mode == ModuleMode.HOST_CONFIRMATION) {
            return normalizeTarget(config.focusHost);
        }
        return firstNonBlank(config.targetSubnet);
    }

    private List<String> resolveHostCandidates(ScanConfig config, String targetExpression) {
        Set<String> candidates = new LinkedHashSet<>();

        for (String token : splitTargets(targetExpression)) {
            String trimmed = token.trim();
            if (trimmed.isBlank()) {
                continue;
            }

            if (isValidCidr(trimmed)) {
                candidates.addAll(expandCidr(trimmed, config.maxHosts - candidates.size()));
            } else {
                candidates.add(normalizeTarget(trimmed));
            }

            if (candidates.size() >= config.maxHosts) {
                break;
            }
        }

        return new ArrayList<>(candidates);
    }

    private List<String> splitTargets(String expression) {
        String raw = trim(expression);
        if (raw.isBlank()) {
            return List.of();
        }
        return Arrays.stream(raw.split(","))
            .map(String::trim)
            .filter(token -> !token.isBlank())
            .toList();
    }

    private ScanConfig parseConfig(Map<String, String> input) {
        ScanConfig config = new ScanConfig();
        config.mode = ModuleMode.fromInput(firstNonBlank(input.get("mode"), "relay_surface_map"));

        config.targetSubnet = firstNonBlank(
            input.get("target_subnet"),
            input.get("subnet"),
            input.get("target"),
            input.get("cidr")
        );
        config.focusHost = firstNonBlank(
            input.get("focus_host"),
            input.get("identify_target")
        );
        config.domain = trim(input.get("domain"));

        config.username = trim(input.get("username"));
        config.password = trim(input.get("password"));
        config.useKerberos = parseBoolean(input.get("use_kerberos"), false);

        config.timeoutMs = parseInteger(firstNonBlank(input.get("timeout_ms"), input.get("timeout")), DEFAULT_TIMEOUT_MS);
        config.connectTimeoutMs = parseInteger(input.get("connect_timeout_ms"), DEFAULT_CONNECT_TIMEOUT_MS);
        config.maxHosts = parseInteger(input.get("max_hosts"), DEFAULT_MAX_HOSTS);
        config.maxServiceChecks = parseInteger(input.get("max_service_checks"), DEFAULT_MAX_SERVICE_CHECKS);
        config.maxLdapChecks = parseInteger(input.get("max_ldap_checks"), DEFAULT_MAX_LDAP_CHECKS);

        config.useNmap = parseBoolean(input.get("use_nmap"), true);
        config.useCurl = parseBoolean(input.get("use_curl"), true);
        config.useLdapStatusChecker = parseBoolean(input.get("use_ldap_status_checker"), true);
        config.checkSmbSigningInSurfaceMap = parseBoolean(
            firstNonBlank(input.get("check_smb_signing_in_surface_map"), input.get("check_smb_signing_in_discovery")),
            true
        );

        config.includeNonRelayable = parseBoolean(input.get("include_non_relayable"), true);
        config.resolveDns = parseBoolean(input.get("resolve_dns"), false);
        config.riskOnUnknownSigning = parseBoolean(input.get("risk_on_unknown_signing"), true);

        return config;
    }

    private List<String> validateConfig(ScanConfig config) {
        List<String> errors = new ArrayList<>();

        if (config.mode == ModuleMode.HOST_CONFIRMATION) {
            if (config.focusHost.isBlank()) {
                errors.add("focus_host is required when mode=host_confirmation");
            }
        } else {
            if (config.targetSubnet.isBlank()) {
                errors.add("target_subnet is required unless mode=host_confirmation");
            }
        }

        if (!config.username.isBlank() && config.password.isBlank() && !config.useKerberos) {
            errors.add("password is required when username is provided for LDAP posture checks");
        }

        if (config.timeoutMs < 500 || config.timeoutMs > 120_000) {
            errors.add("timeout_ms must be between 500 and 120000");
        }
        if (config.connectTimeoutMs < 200 || config.connectTimeoutMs > 60_000) {
            errors.add("connect_timeout_ms must be between 200 and 60000");
        }
        if (config.maxHosts < 1 || config.maxHosts > MAX_HOSTS_LIMIT) {
            errors.add("max_hosts must be between 1 and " + MAX_HOSTS_LIMIT);
        }
        if (config.maxServiceChecks < 1 || config.maxServiceChecks > 1000) {
            errors.add("max_service_checks must be between 1 and 1000");
        }
        if (config.maxLdapChecks < 1 || config.maxLdapChecks > 512) {
            errors.add("max_ldap_checks must be between 1 and 512");
        }

        if (config.mode != ModuleMode.HOST_CONFIRMATION && isValidCidr(config.targetSubnet)) {
            long estimated = estimateCidrHosts(config.targetSubnet);
            if (estimated > config.maxHosts) {
                errors.add("target subnet expands to " + estimated + " hosts, exceeding max_hosts=" + config.maxHosts);
            }
        }

        return errors;
    }

    private long estimateCidrHosts(String cidr) {
        if (!isValidCidr(cidr)) {
            return 0;
        }
        int prefix = Integer.parseInt(cidr.split("/")[1].trim());
        if (prefix == 32) {
            return 1;
        }
        if (prefix == 31) {
            return 2;
        }
        return Math.max(0, (1L << (32 - prefix)) - 2);
    }

    private String normalizeTargetExpression(String expression) {
        return String.join(",", splitTargets(expression));
    }

    private String normalizeTarget(String target) {
        String value = trim(target);
        if (value.isBlank()) {
            return "";
        }
        if (isIpv4(value)) {
            return value;
        }
        return value;
    }

    private List<String> expandCidr(String cidr, int remainingCapacity) {
        if (remainingCapacity <= 0) {
            return List.of();
        }

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
            if (hosts.size() >= remainingCapacity) {
                break;
            }
        }
        return hosts;
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

    private long ipSortKey(String candidate) {
        if (!isIpv4(candidate)) {
            return Long.MAX_VALUE;
        }
        return ipToLong(candidate);
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

    private boolean isValidCidr(String value) {
        String cidr = trim(value);
        if (!cidr.contains("/")) {
            return false;
        }

        String[] parts = cidr.split("/");
        if (parts.length != 2 || !isIpv4(parts[0].trim())) {
            return false;
        }

        try {
            int prefix = Integer.parseInt(parts[1].trim());
            return prefix >= 0 && prefix <= 32;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private SmbSigningState parseSmbSigningState(String output) {
        String lowered = output == null ? "" : output.toLowerCase(Locale.ROOT);
        if (lowered.contains("enabled and required")) {
            return SmbSigningState.REQUIRED;
        }
        if (lowered.contains("enabled but not required")) {
            return SmbSigningState.OPTIONAL;
        }
        if (lowered.contains("signing disabled") || lowered.contains("disabled")) {
            return SmbSigningState.DISABLED;
        }
        if (lowered.contains("not required")) {
            return SmbSigningState.OPTIONAL;
        }
        return SmbSigningState.UNKNOWN;
    }

    private String standardServiceName(int port) {
        return switch (port) {
            case 389 -> "ldap";
            case 636 -> "ldaps";
            case 445 -> "smb";
            case 80 -> "http";
            case 443 -> "https";
            case 1433 -> "mssql";
            default -> "unknown";
        };
    }

    private String firstLine(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String[] lines = value.split("\\R");
        return lines.length == 0 ? "" : lines[0].trim();
    }

    private void copyStream(InputStream stream, StringBuilder sink) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sink.append(line).append('\n');
            }
        } catch (IOException ignored) {
            // stream read best-effort
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

    private Map<String, Object> asMap(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> typed = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getKey() != null) {
                    typed.put(String.valueOf(entry.getKey()), entry.getValue());
                }
            }
            return typed;
        }
        return Map.of();
    }

    private List<String> asStringList(Object value) {
        if (value instanceof List<?> list) {
            List<String> out = new ArrayList<>();
            for (Object item : list) {
                if (item != null) {
                    out.add(String.valueOf(item));
                }
            }
            return out;
        }
        return List.of();
    }

    private String asString(Object value, String defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        String text = String.valueOf(value).trim();
        return text.isBlank() ? defaultValue : text;
    }

    private boolean asBoolean(Object value) {
        if (value instanceof Boolean b) {
            return b;
        }
        if (value instanceof Number n) {
            return n.intValue() != 0;
        }
        if (value != null) {
            return Boolean.parseBoolean(String.valueOf(value));
        }
        return false;
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

    private String trim(String value) {
        return value == null ? "" : value.trim();
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.trim().isBlank()) {
                return value.trim();
            }
        }
        return "";
    }

    private boolean isWindows() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        return os.contains("win");
    }

    protected static class ScanConfig {
        protected ModuleMode mode = ModuleMode.RELAY_SURFACE_MAP;

        protected String targetSubnet = "";
        protected String focusHost = "";
        protected String domain = "";

        protected String username = "";
        protected String password = "";
        protected boolean useKerberos;

        protected int timeoutMs = DEFAULT_TIMEOUT_MS;
        protected int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
        protected int maxHosts = DEFAULT_MAX_HOSTS;
        protected int maxServiceChecks = DEFAULT_MAX_SERVICE_CHECKS;
        protected int maxLdapChecks = DEFAULT_MAX_LDAP_CHECKS;

        protected boolean useNmap = true;
        protected boolean useCurl = true;
        protected boolean useLdapStatusChecker = true;
        protected boolean checkSmbSigningInSurfaceMap = true;

        protected boolean includeNonRelayable = true;
        protected boolean resolveDns;
        protected boolean riskOnUnknownSigning = true;
    }

    protected enum ModuleMode {
        RELAY_SURFACE_MAP("relay_surface_map"),
        PROTECTION_ASSESSMENT("protection_assessment"),
        ABUSE_PATH_VALIDATION("abuse_path_validation"),
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
                case "protection_assessment", "analysis" -> PROTECTION_ASSESSMENT;
                case "abuse_path_validation", "deep_scan", "deepscan" -> ABUSE_PATH_VALIDATION;
                case "host_confirmation", "identify", "identification" -> HOST_CONFIRMATION;
                default -> RELAY_SURFACE_MAP;
            };
        }
    }

    private enum SmbSigningState {
        REQUIRED("required"),
        OPTIONAL("optional"),
        DISABLED("disabled"),
        UNKNOWN("unknown");

        private final String value;

        SmbSigningState(String value) {
            this.value = value;
        }
    }

    private enum SecurityState {
        YES,
        NO,
        UNKNOWN
    }

    private enum RiskLabel {
        HIGH("high"),
        MEDIUM("medium"),
        LOW("low"),
        INFO("info");

        private final String value;

        RiskLabel(String value) {
            this.value = value;
        }
    }

    protected static class LdapRelayPosture {
        protected boolean success;
        protected boolean relayViable;
        protected String signingMode = "unknown";
        protected String channelBindingMode = "unknown";
        protected String riskLevel = "unknown";
        protected String error = "";
        protected List<String> reasons = new ArrayList<>();
        protected Map<String, Object> raw = new LinkedHashMap<>();

        protected static LdapRelayPosture unknown(String error) {
            LdapRelayPosture posture = new LdapRelayPosture();
            posture.success = false;
            posture.error = error == null ? "unknown" : error;
            return posture;
        }

        protected Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("success", success);
            map.put("relay_viable", relayViable);
            map.put("signing_mode", signingMode);
            map.put("channel_binding_mode", channelBindingMode);
            map.put("risk_level", riskLevel);
            if (!error.isBlank()) {
                map.put("error", error);
            }
            map.put("reasons", reasons);
            return map;
        }
    }

    protected static class HttpProbeResult {
        protected boolean success;
        protected int statusCode;
        protected boolean supportsNtlm;
        protected boolean supportsNegotiate;
        protected String error = "";
        protected Map<String, String> headers = new LinkedHashMap<>();

        protected Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("success", success);
            map.put("status_code", statusCode);
            map.put("supports_ntlm", supportsNtlm);
            map.put("supports_negotiate", supportsNegotiate);
            if (!error.isBlank()) {
                map.put("error", error);
            }
            map.put("headers", headers);
            return map;
        }
    }

    protected static class CommandExecutionResult {
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

    private static final class PortProbeResult {
        private final String host;
        private final int port;
        private final boolean open;

        private PortProbeResult(String host, int port, boolean open) {
            this.host = host;
            this.port = port;
            this.open = open;
        }
    }

    private static final class HostSurface {
        private final String host;
        private String dnsName = "";

        private final Set<Integer> openPorts = new LinkedHashSet<>();
        private final Set<String> discoveryMethods = new LinkedHashSet<>();
        private final Map<Integer, String> portServices = new LinkedHashMap<>();

        private SmbSigningState smbSigning = SmbSigningState.UNKNOWN;
        private LdapRelayPosture ldapPosture;
        private boolean httpNtlmAccepted;
        private boolean httpsNtlmAccepted;
        private boolean adcsHttpExposed;
        private boolean adcsHttpsExposed;
        private boolean adcsNtlmAccepted;
        private int httpStatusCode;
        private int httpsStatusCode;
        private SecurityState mssqlNtlmState = SecurityState.UNKNOWN;

        private final Set<String> relayableProtocols = new LinkedHashSet<>();
        private final List<String> relayReasons = new ArrayList<>();
        private final List<String> evidence = new ArrayList<>();
        private RiskLabel risk = RiskLabel.INFO;

        private HostSurface(String host) {
            this.host = host;
        }

        private boolean hasPort(int port) {
            return openPorts.contains(port);
        }

        private boolean hasAnyPort(int... ports) {
            for (int port : ports) {
                if (openPorts.contains(port)) {
                    return true;
                }
            }
            return false;
        }

        private Map<String, Object> toOutput(ModuleMode mode) {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("host", host);
            if (!dnsName.isBlank()) {
                map.put("dns_name", dnsName);
            }
            map.put("open_ports", new ArrayList<>(openPorts));
            map.put("port_services", portServices);
            map.put("discovery_methods", new ArrayList<>(discoveryMethods));
            map.put("smb_signing", smbSigning.value);

            if (ldapPosture != null && mode != ModuleMode.RELAY_SURFACE_MAP) {
                map.put("ldap_posture", ldapPosture.toMap());
            }

            if (mode == ModuleMode.ABUSE_PATH_VALIDATION || mode == ModuleMode.HOST_CONFIRMATION) {
                map.put("http_ntlm", httpNtlmAccepted);
                map.put("https_ntlm", httpsNtlmAccepted);
                map.put("http_status", httpStatusCode);
                map.put("https_status", httpsStatusCode);
                map.put("adcs_http_exposed", adcsHttpExposed);
                map.put("adcs_https_exposed", adcsHttpsExposed);
                map.put("adcs_ntlm", adcsNtlmAccepted);
                map.put("mssql_ntlm", mssqlNtlmState.name().toLowerCase(Locale.ROOT));
            }

            map.put("relayable_protocols", new ArrayList<>(relayableProtocols));
            map.put("relay_reasons", relayReasons);
            map.put("risk_level", risk.value);
            map.put("evidence", evidence);
            return map;
        }
    }

    private static final class ExecutionDiagnostics {
        private int commandExecutions;
        private final Set<String> toolUsage = new LinkedHashSet<>();
        private final List<String> executedCommands = new ArrayList<>();
        private final List<String> warnings = new ArrayList<>();
    }
}
