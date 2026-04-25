package com.jabber.jrts.modules.reconnaissance;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.jabber.jrts.data.model.Category;
import com.jabber.jrts.data.model.JRTSModule;
import com.jabber.jrts.data.model.JRTSModuleInterface;
import com.jabber.jrts.data.model.ModuleInputField;
import com.jabber.jrts.data.model.ModuleResult;
import com.jabber.jrts.data.model.RiskLevel;
import com.jabber.jrts.data.model.TaskContext;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

@JRTSModule(
    id = "recon-banner-grab",
    name = "Banner Grabber & Exploitability Mapper",
    description = "Perform deep service fingerprinting, correlate banners with CVE intelligence, and build exploit-prioritized recon datasets with stealth-aware probing.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.MEDIUM,
    sourceRef = "nmap/masscan/whatweb/wappalyzer/searchsploit/custom socket probes",
    author = "JRTS"
)
public class BannerGrabberModule implements JRTSModuleInterface {

    private static final String MODULE_ID = "recon-banner-grab";
    private static final String DEFAULT_PORT_SPEC = "21,22,25,53,80,110,143,443,445,587,993,995,1433,3306,3389,6379,8080";
    private static final int DEFAULT_TIMEOUT_MS = 8000;
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 3000;
    private static final int DEFAULT_MAX_HOSTS = 512;
    private static final int DEFAULT_MAX_PORTS_PER_HOST = 32;
    private static final int DEFAULT_INTER_PROBE_DELAY_MS = 120;
    private static final int MAX_HOSTS_LIMIT = 65534;

    private static final Pattern NMAP_PORT_LINE =
        Pattern.compile("^(\\d+)/tcp\\s+open\\s+([A-Za-z0-9_.-]+)(?:\\s+(.*))?$");
    private static final Pattern MASSCAN_DISCOVERY_LINE =
        Pattern.compile("Discovered\\s+open\\s+port\\s+(\\d+)/tcp\\s+on\\s+((?:\\d{1,3}\\.){3}\\d{1,3})", Pattern.CASE_INSENSITIVE);
    private static final Pattern HTTP_STATUS_PATTERN = Pattern.compile("HTTP/\\S+\\s+(\\d{3})", Pattern.CASE_INSENSITIVE);
    private static final Pattern PRODUCT_VERSION_PATTERN =
        Pattern.compile("([A-Za-z][A-Za-z0-9_.-]{1,40})[/_\\-]([0-9][A-Za-z0-9._-]*)");
    private static final Pattern SSH_BANNER_PATTERN =
        Pattern.compile("OpenSSH[_/-]([0-9][A-Za-z0-9._-]*)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SMTP_PRODUCT_PATTERN =
        Pattern.compile("(Postfix|Exim|Sendmail|Exchange|Haraka)(?:[\\s/_-]*([0-9][A-Za-z0-9._-]*))?", Pattern.CASE_INSENSITIVE);
    private static final Pattern FTP_PRODUCT_PATTERN =
        Pattern.compile("(vsftpd|ProFTPD|Pure-FTPd|FileZilla\\s+Server)(?:[\\s/_-]*([0-9][A-Za-z0-9._-]*))?", Pattern.CASE_INSENSITIVE);
    private static final Pattern IPV4_PATTERN = Pattern.compile("^(?:\\d{1,3}\\.){3}\\d{1,3}$");

    private static final Map<Integer, String> PORT_PROTOCOL_HINT = Map.ofEntries(
        Map.entry(21, "ftp"),
        Map.entry(22, "ssh"),
        Map.entry(25, "smtp"),
        Map.entry(53, "dns"),
        Map.entry(80, "http"),
        Map.entry(110, "pop3"),
        Map.entry(143, "imap"),
        Map.entry(443, "https"),
        Map.entry(445, "smb"),
        Map.entry(465, "smtps"),
        Map.entry(587, "smtp"),
        Map.entry(636, "ldaps"),
        Map.entry(993, "imaps"),
        Map.entry(995, "pop3s"),
        Map.entry(1433, "mssql"),
        Map.entry(3306, "mysql"),
        Map.entry(3389, "rdp"),
        Map.entry(6379, "redis"),
        Map.entry(8080, "http")
    );

    private static final List<CveRule> CVE_RULES = List.of(
        new CveRule("apache", "http", "2.4.49", "CVE-2021-41773", Severity.HIGH,
            "Path traversal leading to RCE", true, "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"),
        new CveRule("apache", "http", "2.4.50", "CVE-2021-42013", Severity.CRITICAL,
            "RCE via path traversal bypass", true, "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"),
        new CveRule("openssh", "ssh", "8.4", "CVE-2021-41617", Severity.MEDIUM,
            "Privilege escalation in sshd", false, "https://nvd.nist.gov/vuln/detail/CVE-2021-41617"),
        new CveRule("vsftpd", "ftp", "2.3.4", "CVE-2011-2523", Severity.CRITICAL,
            "Backdoored vsftpd release enabling command execution", true, "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"),
        new CveRule("nginx", "http", "1.20.0", "CVE-2021-23017", Severity.MEDIUM,
            "Resolver off-by-one leading to potential DoS", false, "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"),
        new CveRule("mysql", "mysql", "5.5.23", "CVE-2012-2122", Severity.HIGH,
            "Authentication bypass condition", true, "https://nvd.nist.gov/vuln/detail/CVE-2012-2122"),
        new CveRule("microsoft-iis", "http", "6.0", "CVE-2017-7269", Severity.CRITICAL,
            "WebDAV stack overflow leading to RCE", true, "https://nvd.nist.gov/vuln/detail/CVE-2017-7269")
    );

    private final Map<String, Boolean> commandAvailabilityCache = new ConcurrentHashMap<>();

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of(
                    "service_fingerprint",
                    "cve_mapping",
                    "enumeration_fusion",
                    "stealth_banner"
                ))
                .required()
                .defaultValue("service_fingerprint")
                .group("Mode")
                .helpText("Controls deep fingerprinting, CVE mapping depth, fusion modeling, and stealth profile behavior."),

            ModuleInputField.text("target_host", "Target Host")
                .placeholder("10.10.10.5 or app.contoso.local")
                .group("Target")
                .modes("service_fingerprint", "cve_mapping", "stealth_banner"),
            ModuleInputField.text("target_scope", "Target Scope")
                .placeholder("10.10.10.0/24 or 10.10.10.5,10.10.10.8")
                .group("Target")
                .modes("enumeration_fusion"),
            ModuleInputField.text("ports", "Ports")
                .placeholder(DEFAULT_PORT_SPEC)
                .defaultValue(DEFAULT_PORT_SPEC)
                .group("Target")
                .helpText("Comma-separated ports and ranges, for example 22,80,443,8000-8010"),
            ModuleInputField.text("service_hint", "Service Hint")
                .placeholder("ssh, http, smtp")
                .group("Target")
                .modes("service_fingerprint", "cve_mapping", "stealth_banner"),

            ModuleInputField.checkbox("force_tls", "Force TLS Handshake")
                .defaultValue("false")
                .group("Probe"),
            ModuleInputField.checkbox("use_nmap", "Use Nmap -sV when available")
                .defaultValue("true")
                .group("Probe")
                .modes("service_fingerprint", "cve_mapping", "enumeration_fusion"),
            ModuleInputField.checkbox("use_masscan", "Use Masscan host-port seed when available")
                .defaultValue("false")
                .group("Probe")
                .modes("enumeration_fusion"),
            ModuleInputField.checkbox("use_whatweb", "Use WhatWeb when available")
                .defaultValue("false")
                .group("Probe")
                .modes("service_fingerprint", "cve_mapping", "enumeration_fusion"),
            ModuleInputField.checkbox("use_wappalyzer", "Use Wappalyzer CLI when available")
                .defaultValue("false")
                .group("Probe")
                .modes("service_fingerprint", "cve_mapping", "enumeration_fusion"),
            ModuleInputField.checkbox("use_searchsploit", "Use searchsploit for exploit evidence")
                .defaultValue("true")
                .group("Probe")
                .modes("cve_mapping", "enumeration_fusion"),

            ModuleInputField.text("timeout_ms", "Read Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_TIMEOUT_MS))
                .group("Execution"),
            ModuleInputField.text("connect_timeout_ms", "Connect Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_CONNECT_TIMEOUT_MS))
                .group("Execution"),
            ModuleInputField.text("max_hosts", "Maximum Hosts")
                .placeholder(String.valueOf(DEFAULT_MAX_HOSTS))
                .group("Execution")
                .modes("enumeration_fusion"),
            ModuleInputField.text("max_ports_per_host", "Maximum Ports Per Host")
                .placeholder(String.valueOf(DEFAULT_MAX_PORTS_PER_HOST))
                .group("Execution"),
            ModuleInputField.text("inter_probe_delay_ms", "Inter-Probe Delay (ms)")
                .placeholder(String.valueOf(DEFAULT_INTER_PROBE_DELAY_MS))
                .defaultValue(String.valueOf(DEFAULT_INTER_PROBE_DELAY_MS))
                .group("Execution")
                .modes("stealth_banner"),
            ModuleInputField.checkbox("randomize_stealth_delays", "Randomize Stealth Delays")
                .defaultValue("true")
                .group("Execution")
                .modes("stealth_banner"),

            ModuleInputField.checkbox("resolve_dns", "Resolve DNS Names")
                .defaultValue("false")
                .group("Output"),
            ModuleInputField.checkbox("include_raw", "Include Raw Probe Data")
                .defaultValue("false")
                .group("Output")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), MODULE_ID);
            long startedAt = System.currentTimeMillis();

            try {
                ctx.log("[*] Starting Banner Grabber & Exploitability Mapper");
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
                    result.fail("No targets resolved from input");
                    ctx.log("[!] No targets resolved from input");
                    return result;
                }

                ctx.log("[*] Mode: " + config.mode.value);
                ctx.log("[*] Targets resolved: " + targets.size());
                ctx.reportProgress(15);

                ExecutionDiagnostics diagnostics = new ExecutionDiagnostics();
                List<HostService> candidates = discoverServiceCandidates(config, targets, diagnostics, ctx);

                if (candidates.isEmpty()) {
                    Map<String, Object> summary = buildEmptySummary(config, targets.size());
                    Map<String, Object> modeResult = buildModeResult(config, List.of(), List.of(), summary, diagnostics);

                    Map<String, Object> output = new LinkedHashMap<>();
                    output.put("pipeline", pipeline());
                    output.put("mode", config.mode.value);
                    output.put("targets", targets);
                    output.put("service_assessments", List.of());
                    output.put("fusion_dataset", List.of());
                    output.put("summary", summary);
                    output.put(config.mode.resultKey, modeResult);
                    output.put("execution_metadata", buildExecutionMetadata(config, diagnostics, startedAt));

                    result.setNormalizedOutput(buildNormalizedOutput(config, summary, List.of(), modeResult));
                    result.complete(output);

                    ctx.log("[+] No candidate services discovered");
                    ctx.reportProgress(100);
                    return result;
                }

                ctx.log("[*] Candidate services: " + candidates.size());
                ctx.reportProgress(30);

                List<ServiceAssessment> assessments = new ArrayList<>();
                for (int i = 0; i < candidates.size(); i++) {
                    HostService candidate = candidates.get(i);

                    if (config.mode == ModuleMode.STEALTH_BANNER) {
                        int delay = computeStealthDelay(config, candidate);
                        if (delay > 0) {
                            sleepQuietly(delay);
                            diagnostics.delayAppliedMs += delay;
                        }
                    }

                    ProbeObservation probe = probeService(candidate, config, diagnostics);
                    diagnostics.probeCount++;
                    if (probe.minimalQuery) {
                        diagnostics.minimalProbeCount++;
                    }

                    NormalizedFingerprint fingerprint = normalizeFingerprint(candidate, probe);
                    applyWebFingerprintEnrichment(candidate, fingerprint, config, diagnostics);
                    CveCorrelation cve = correlateCves(fingerprint, config, diagnostics);

                    ServiceAssessment assessment = new ServiceAssessment(candidate, probe, fingerprint, cve);
                    if (config.resolveDns && !assessment.host.isBlank()) {
                        assessment.dnsName = resolveDnsName(assessment.host);
                    }
                    assessments.add(assessment);

                    int progress = 30 + (int) (((i + 1) / (double) candidates.size()) * 50);
                    ctx.reportProgress(Math.min(85, progress));
                }

                List<HostFusionRecord> fusionRecords = buildFusionDataset(assessments);
                Map<String, Object> summary = buildSummary(config, targets.size(), assessments, fusionRecords);
                Map<String, Object> modeResult = buildModeResult(config, assessments, fusionRecords, summary, diagnostics);

                List<Map<String, Object>> serviceMaps = toServiceMapList(assessments, config.includeRaw);
                List<Map<String, Object>> fusionMaps = toFusionMapList(fusionRecords);

                Map<String, Object> output = new LinkedHashMap<>();
                output.put("pipeline", pipeline());
                output.put("mode", config.mode.value);
                output.put("targets", targets);
                output.put("service_assessments", serviceMaps);
                output.put("fusion_dataset", fusionMaps);
                output.put("summary", summary);
                output.put(config.mode.resultKey, modeResult);
                output.put("execution_metadata", buildExecutionMetadata(config, diagnostics, startedAt));

                appendFindings(result, assessments, fusionRecords, summary);
                result.setNormalizedOutput(buildNormalizedOutput(config, summary, serviceMaps, modeResult));
                result.complete(output);

                ctx.log("[+] Banner correlation completed with " + serviceMaps.size() + " service assessment(s)");
                ctx.reportProgress(100);
            } catch (Exception e) {
                result.fail("Execution failed: " + e.getMessage());
                ctx.log("[!] ERROR: " + e.getMessage());
            }

            return result;
        });
    }

    protected List<HostService> discoverServiceCandidates(
            ScanConfig config,
            List<String> targets,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx) {

        List<Integer> ports = parsePortSpec(config.portsSpec, config.maxPortsPerHost);
        List<HostService> discovered = new ArrayList<>();
        Map<String, HostService> dedup = new LinkedHashMap<>();

        if (config.mode == ModuleMode.ENUMERATION_FUSION) {
            if (config.useMasscan && isCommandAvailable("masscan")) {
                List<HostService> masscanSeed = runMasscanDiscovery(config, diagnostics);
                for (HostService item : masscanSeed) {
                    dedup.put(item.key(), item);
                }
                if (!masscanSeed.isEmpty()) {
                    ctx.log("[*] Masscan seed discovered " + masscanSeed.size() + " service candidate(s)");
                }
            } else if (config.useMasscan) {
                diagnostics.warnings.add("masscan requested but unavailable");
            }

            if (config.useNmap && isCommandAvailable("nmap")) {
                List<HostService> nmapDiscovered = runNmapServiceDiscovery(config, diagnostics);
                for (HostService item : nmapDiscovered) {
                    dedup.put(item.key(), item);
                }
                if (!nmapDiscovered.isEmpty()) {
                    ctx.log("[*] Nmap -sV discovered " + nmapDiscovered.size() + " service candidate(s)");
                }
            } else if (config.useNmap) {
                diagnostics.warnings.add("nmap requested but unavailable");
            }

            if (dedup.isEmpty()) {
                for (HostService fallback : runSocketDiscovery(targets, ports, config, diagnostics)) {
                    dedup.put(fallback.key(), fallback);
                }
            }

            discovered.addAll(dedup.values());
            return discovered;
        }

        String host = normalizeHostToken(config.targetHost);

        if (config.useNmap && isCommandAvailable("nmap")) {
            List<HostService> nmapCandidates = runNmapTargetDiscovery(host, config.portsSpec, config, diagnostics);
            if (!nmapCandidates.isEmpty()) {
                return nmapCandidates;
            }
        }

        for (int port : ports) {
            HostService service = new HostService(host, port);
            service.serviceHint = normalizeProtocol(config.serviceHint);
            service.discoveryMethod = "direct_input";

            if (config.mode == ModuleMode.STEALTH_BANNER) {
                discovered.add(service);
                continue;
            }

            if (isPortOpen(host, port, config.connectTimeoutMs)) {
                discovered.add(service);
            } else {
                service.discoveryMethod = "direct_input_unconfirmed";
                discovered.add(service);
            }
        }

        return discovered;
    }

    private List<HostService> runMasscanDiscovery(ScanConfig config, ExecutionDiagnostics diagnostics) {
        List<String> command = List.of(
            "masscan",
            normalizeTargetExpression(config.targetScope),
            "-p" + config.portsSpec,
            "--rate", "1000",
            "--wait", "0"
        );

        CommandExecutionResult result = runCommand(command, Math.max(12_000L, config.timeoutMs * 4L));
        recordCommandExecution(diagnostics, "masscan", command, result);

        if (result.timedOut || result.combinedOutput().isBlank()) {
            if (result.timedOut) {
                diagnostics.warnings.add("masscan discovery timed out");
            } else if (result.exitCode != 0 && !result.stderr.isBlank()) {
                diagnostics.warnings.add("masscan discovery failed: " + firstLine(result.stderr));
            }
            return List.of();
        }

        List<HostService> out = new ArrayList<>();
        for (String line : result.combinedOutput().split("\\R")) {
            Matcher matcher = MASSCAN_DISCOVERY_LINE.matcher(line);
            if (!matcher.find()) {
                continue;
            }
            int port = parseInteger(matcher.group(1), -1);
            String host = matcher.group(2);
            if (port <= 0 || host.isBlank()) {
                continue;
            }

            HostService service = new HostService(host, port);
            service.discoveryMethod = "masscan";
            service.serviceHint = detectProtocolHint(port, "");
            out.add(service);
        }
        return out;
    }

    private List<HostService> runNmapServiceDiscovery(ScanConfig config, ExecutionDiagnostics diagnostics) {
        List<String> command = List.of(
            "nmap",
            "-n",
            "-Pn",
            "-sV",
            "--version-light",
            "-p",
            config.portsSpec,
            "--open",
            normalizeTargetExpression(config.targetScope)
        );

        CommandExecutionResult result = runCommand(command, Math.max(15_000L, config.timeoutMs * 5L));
        recordCommandExecution(diagnostics, "nmap", command, result);

        if (result.timedOut || result.combinedOutput().isBlank()) {
            if (result.timedOut) {
                diagnostics.warnings.add("nmap service discovery timed out");
            } else if (result.exitCode != 0 && !result.stderr.isBlank()) {
                diagnostics.warnings.add("nmap service discovery failed: " + firstLine(result.stderr));
            }
            return List.of();
        }

        return parseNmapServiceOutput(result.combinedOutput());
    }

    private List<HostService> runNmapTargetDiscovery(
            String targetHost,
            String portSpec,
            ScanConfig config,
            ExecutionDiagnostics diagnostics) {

        List<String> command = List.of(
            "nmap",
            "-n",
            "-Pn",
            "-sV",
            "--version-light",
            "-p",
            portSpec,
            "--open",
            targetHost
        );

        CommandExecutionResult result = runCommand(command, Math.max(12_000L, config.timeoutMs * 4L));
        recordCommandExecution(diagnostics, "nmap", command, result);

        if (result.timedOut || result.exitCode != 0 || result.combinedOutput().isBlank()) {
            return List.of();
        }

        return parseNmapServiceOutput(result.combinedOutput());
    }

    private List<HostService> parseNmapServiceOutput(String output) {
        List<HostService> services = new ArrayList<>();
        String currentHost = "";

        for (String rawLine : output.split("\\R")) {
            String line = rawLine.trim();
            if (line.isBlank()) {
                continue;
            }

            if (line.startsWith("Nmap scan report for")) {
                currentHost = parseHostFromNmapHeader(line);
                continue;
            }

            if (currentHost.isBlank()) {
                continue;
            }

            Matcher matcher = NMAP_PORT_LINE.matcher(line);
            if (!matcher.find()) {
                continue;
            }

            int port = parseInteger(matcher.group(1), -1);
            String serviceName = normalizeProtocol(matcher.group(2));
            String banner = trim(matcher.group(3));
            if (port <= 0) {
                continue;
            }

            HostService service = new HostService(currentHost, port);
            service.discoveryMethod = "nmap_sV";
            service.serviceHint = firstNonBlank(serviceName, detectProtocolHint(port, banner));
            service.seedBanner = banner;
            services.add(service);
        }

        return services;
    }

    private List<HostService> runSocketDiscovery(
            List<String> targets,
            List<Integer> ports,
            ScanConfig config,
            ExecutionDiagnostics diagnostics) {

        List<HostService> discovered = new ArrayList<>();
        for (String target : targets) {
            for (int port : ports) {
                if (isPortOpen(target, port, config.connectTimeoutMs)) {
                    HostService service = new HostService(target, port);
                    service.discoveryMethod = "tcp_connect";
                    service.serviceHint = detectProtocolHint(port, "");
                    discovered.add(service);
                }
            }
        }
        diagnostics.toolUsage.add("java_socket_connect");
        return discovered;
    }

    protected ProbeObservation probeService(HostService candidate, ScanConfig config, ExecutionDiagnostics diagnostics) {
        String protocol = detectProtocolHint(candidate.port, firstNonBlank(candidate.serviceHint, candidate.seedBanner));
        boolean minimal = config.mode == ModuleMode.STEALTH_BANNER;
        boolean tls = shouldUseTls(candidate.port, protocol, config.forceTls);

        ProbeObservation observation;
        if (isHttpProtocol(protocol, candidate.port)) {
            observation = probeHttp(candidate, tls, minimal, config, diagnostics);
        } else if (isLineProtocol(protocol)) {
            observation = probeLineProtocol(candidate, protocol, tls, minimal, config, diagnostics);
        } else {
            observation = probeRawProtocol(candidate, protocol, tls, minimal, config, diagnostics);
        }

        if (!candidate.seedBanner.isBlank() && observation.firstLine.isBlank()) {
            observation.firstLine = candidate.seedBanner;
            if (observation.rawText.isBlank()) {
                observation.rawText = candidate.seedBanner;
            }
        }
        return observation;
    }

    private void applyWebFingerprintEnrichment(
            HostService candidate,
            NormalizedFingerprint fingerprint,
            ScanConfig config,
            ExecutionDiagnostics diagnostics) {

        if ((!config.useWhatWeb && !config.useWappalyzer) || !isHttpProtocol(fingerprint.protocol, candidate.port)) {
            return;
        }

        boolean tls = shouldUseTls(candidate.port, fingerprint.protocol, config.forceTls);
        String scheme = tls ? "https" : "http";
        String url = scheme + "://" + candidate.host
            + ((candidate.port == 80 || candidate.port == 443) ? "" : ":" + candidate.port)
            + "/";

        if (config.useWhatWeb) {
            if (isCommandAvailable("whatweb")) {
                List<String> command = List.of("whatweb", "--log-brief=-", url);
                CommandExecutionResult result = runCommand(command, Math.max(5000L, config.timeoutMs * 2L));
                recordCommandExecution(diagnostics, "whatweb", command, result);

                if (!result.timedOut && result.exitCode == 0) {
                    String line = firstLine(result.stdout);
                    if (!line.isBlank()) {
                        fingerprint.signals.put("whatweb", line);
                        mergeFingerprintToken(fingerprint, line, "whatweb");
                    }
                } else {
                    String failure = firstNonBlank(firstLine(result.stderr), firstLine(result.stdout), "whatweb execution failed");
                    diagnostics.warnings.add("whatweb failed for " + candidate.host + ": " + failure);
                }
            } else {
                diagnostics.warnings.add("whatweb requested but unavailable");
            }
        }

        if (config.useWappalyzer) {
            if (isCommandAvailable("wappalyzer")) {
                List<String> command = List.of("wappalyzer", url);
                CommandExecutionResult result = runCommand(command, Math.max(5000L, config.timeoutMs * 2L));
                recordCommandExecution(diagnostics, "wappalyzer", command, result);

                if (!result.timedOut && result.exitCode == 0) {
                    String line = firstLine(result.stdout);
                    if (!line.isBlank()) {
                        fingerprint.signals.put("wappalyzer", line);
                        mergeFingerprintToken(fingerprint, line, "wappalyzer");
                    }
                } else {
                    String failure = firstNonBlank(firstLine(result.stderr), firstLine(result.stdout), "wappalyzer execution failed");
                    diagnostics.warnings.add("wappalyzer failed for " + candidate.host + ": " + failure);
                }
            } else {
                diagnostics.warnings.add("wappalyzer requested but unavailable");
            }
        }
    }

    private void mergeFingerprintToken(NormalizedFingerprint fingerprint, String text, String source) {
        ProductVersion token = parseProductVersion(text);
        if (!token.product.isBlank() && (fingerprint.product.equals("unknown") || fingerprint.product.equals("http"))) {
            fingerprint.product = normalizeProduct(token.product);
            fingerprint.signals.put(source + "_product_hint", fingerprint.product);
        }
        if (!token.version.isBlank() && fingerprint.version.isBlank()) {
            fingerprint.version = token.version;
            fingerprint.signals.put(source + "_version_hint", token.version);
        }
    }

    private void recordCommandExecution(
            ExecutionDiagnostics diagnostics,
            String tool,
            List<String> command,
            CommandExecutionResult result) {

        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add(tool);

        String commandText = String.join(" ", command);
        diagnostics.executedCommands.add(commandText);

        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("tool", tool);
        entry.put("command", commandText);
        entry.put("status", result.timedOut ? "timeout" : (result.exitCode == 0 ? "success" : "failed"));
        entry.put("exit_code", result.exitCode);
        entry.put("timed_out", result.timedOut);
        entry.put("duration_ms", result.durationMs);

        String stdoutPreview = truncatePreview(firstLine(result.stdout), 260);
        if (!stdoutPreview.isBlank()) {
            entry.put("stdout_preview", stdoutPreview);
        }
        String stderrPreview = truncatePreview(firstLine(result.stderr), 260);
        if (!stderrPreview.isBlank()) {
            entry.put("stderr_preview", stderrPreview);
        }

        diagnostics.commandLog.add(entry);
    }

    private String truncatePreview(String value, int maxLength) {
        String text = trim(value).replaceAll("\\s+", " ");
        if (text.length() <= maxLength) {
            return text;
        }
        return text.substring(0, maxLength - 3) + "...";
    }

    private ProbeObservation probeHttp(
            HostService candidate,
            boolean tls,
            boolean minimal,
            ScanConfig config,
            ExecutionDiagnostics diagnostics) {

        ProbeObservation observation = ProbeObservation.base(candidate.host, candidate.port);
        observation.protocol = tls ? "https" : "http";
        observation.minimalQuery = minimal;
        observation.probeMethod = minimal ? "minimal_http_head" : "http_header_probe";

        long startedAt = System.currentTimeMillis();
        try (Socket socket = openSocket(candidate.host, candidate.port, tls, config.connectTimeoutMs, config.timeoutMs)) {
            observation.connected = true;
            if (socket instanceof SSLSocket sslSocket) {
                captureTlsMetadata(sslSocket, observation, diagnostics);
            }

            String request = minimal
                ? "HEAD / HTTP/1.0\\r\\nHost: " + candidate.host + "\\r\\nConnection: close\\r\\n\\r\\n"
                : "GET / HTTP/1.1\\r\\nHost: " + candidate.host + "\\r\\nUser-Agent: jrts-banner/1.0\\r\\nAccept: */*\\r\\nConnection: close\\r\\n\\r\\n";

            Writer writer = new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.US_ASCII);
            writer.write(request);
            writer.flush();

            byte[] payload = readBytes(socket.getInputStream(), minimal ? 2048 : 8192);
            observation.bytesRead = payload.length;
            observation.packetSize = payload.length;
            observation.rawText = new String(payload, StandardCharsets.ISO_8859_1);
            parseHttpResponse(observation);

        } catch (Exception e) {
            observation.error = firstNonBlank(e.getMessage(), "http_probe_failed");
        }

        observation.responseTimeMs = System.currentTimeMillis() - startedAt;
        return observation;
    }

    private void parseHttpResponse(ProbeObservation observation) {
        if (observation.rawText.isBlank()) {
            return;
        }

        String[] lines = observation.rawText.split("\\R");
        if (lines.length == 0) {
            return;
        }

        observation.firstLine = lines[0].trim();
        Matcher status = HTTP_STATUS_PATTERN.matcher(observation.firstLine);
        if (status.find()) {
            observation.statusCode = parseInteger(status.group(1), 0);
        }

        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isBlank()) {
                break;
            }

            int separator = line.indexOf(':');
            if (separator <= 0 || separator + 1 >= line.length()) {
                continue;
            }

            String key = line.substring(0, separator).trim();
            String value = line.substring(separator + 1).trim();
            observation.headers.put(key, value);
        }
    }

    private ProbeObservation probeLineProtocol(
            HostService candidate,
            String protocol,
            boolean tls,
            boolean minimal,
            ScanConfig config,
            ExecutionDiagnostics diagnostics) {

        ProbeObservation observation = ProbeObservation.base(candidate.host, candidate.port);
        observation.protocol = protocol;
        observation.minimalQuery = minimal;
        observation.probeMethod = minimal ? "single_packet_greeting" : "extended_protocol_interrogation";

        long startedAt = System.currentTimeMillis();
        try (Socket socket = openSocket(candidate.host, candidate.port, tls, config.connectTimeoutMs, config.timeoutMs);
             BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
             Writer writer = new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.US_ASCII)) {

            observation.connected = true;
            if (socket instanceof SSLSocket sslSocket) {
                captureTlsMetadata(sslSocket, observation, diagnostics);
            }

            List<String> transcript = new ArrayList<>();

            String greeting = safeReadLine(reader);
            if (!greeting.isBlank()) {
                transcript.add(greeting);
                observation.firstLine = greeting;
            }

            if (!minimal) {
                switch (protocol) {
                    case "smtp", "smtps" -> {
                        sendLine(writer, "EHLO jrts.local");
                        transcript.addAll(readLineBlock(reader, 6));
                    }
                    case "ftp" -> {
                        sendLine(writer, "FEAT");
                        transcript.addAll(readLineBlock(reader, 6));
                    }
                    case "pop3", "pop3s" -> {
                        sendLine(writer, "CAPA");
                        transcript.addAll(readLineBlock(reader, 6));
                    }
                    case "imap", "imaps" -> {
                        sendLine(writer, "a1 CAPABILITY");
                        transcript.addAll(readLineBlock(reader, 6));
                    }
                    default -> {
                    }
                }
            }

            observation.rawText = String.join("\\n", transcript);
            observation.bytesRead = observation.rawText.getBytes(StandardCharsets.UTF_8).length;
            observation.packetSize = observation.bytesRead;

        } catch (Exception e) {
            observation.error = firstNonBlank(e.getMessage(), "line_protocol_probe_failed");
        }

        observation.responseTimeMs = System.currentTimeMillis() - startedAt;
        return observation;
    }

    private ProbeObservation probeRawProtocol(
            HostService candidate,
            String protocol,
            boolean tls,
            boolean minimal,
            ScanConfig config,
            ExecutionDiagnostics diagnostics) {

        ProbeObservation observation = ProbeObservation.base(candidate.host, candidate.port);
        observation.protocol = protocol;
        observation.minimalQuery = minimal;
        observation.probeMethod = minimal ? "single_packet_probe" : "raw_socket_probe";

        long startedAt = System.currentTimeMillis();
        try (Socket socket = openSocket(candidate.host, candidate.port, tls, config.connectTimeoutMs, config.timeoutMs)) {
            observation.connected = true;
            if (socket instanceof SSLSocket sslSocket) {
                captureTlsMetadata(sslSocket, observation, diagnostics);
            }

            byte[] payload = readBytes(socket.getInputStream(), minimal ? 512 : 4096);
            observation.bytesRead = payload.length;
            observation.packetSize = payload.length;
            observation.rawText = new String(payload, StandardCharsets.UTF_8);
            observation.firstLine = firstLine(observation.rawText);
        } catch (Exception e) {
            observation.error = firstNonBlank(e.getMessage(), "raw_probe_failed");
        }

        observation.responseTimeMs = System.currentTimeMillis() - startedAt;
        return observation;
    }

    private Socket openSocket(String host, int port, boolean tls, int connectTimeoutMs, int readTimeoutMs) throws IOException {
        if (tls) {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket();
            socket.connect(new InetSocketAddress(host, port), Math.max(250, connectTimeoutMs));
            socket.setSoTimeout(Math.max(250, readTimeoutMs));
            socket.startHandshake();
            return socket;
        }

        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(host, port), Math.max(250, connectTimeoutMs));
        socket.setSoTimeout(Math.max(250, readTimeoutMs));
        return socket;
    }

    private void captureTlsMetadata(SSLSocket socket, ProbeObservation observation, ExecutionDiagnostics diagnostics) {
        try {
            SSLSession session = socket.getSession();
            if (session != null) {
                observation.tlsProtocol = firstNonBlank(session.getProtocol());
                observation.tlsCipher = firstNonBlank(session.getCipherSuite());
                diagnostics.tlsHandshakes++;

                Certificate[] chain = session.getPeerCertificates();
                if (chain != null && chain.length > 0 && chain[0] instanceof X509Certificate cert) {
                    observation.tlsSubject = cert.getSubjectX500Principal().getName();
                    observation.tlsIssuer = cert.getIssuerX500Principal().getName();
                }
            }
        } catch (Exception e) {
            observation.error = firstNonBlank(observation.error, e.getMessage());
        }
    }

    private byte[] readBytes(InputStream stream, int maxBytes) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] chunk = new byte[512];

        while (output.size() < maxBytes) {
            int toRead = Math.min(chunk.length, maxBytes - output.size());
            int read = stream.read(chunk, 0, toRead);
            if (read < 0) {
                break;
            }
            if (read == 0) {
                break;
            }
            output.write(chunk, 0, read);

            if (read < toRead) {
                break;
            }
        }

        return output.toByteArray();
    }

    private String safeReadLine(BufferedReader reader) {
        try {
            String line = reader.readLine();
            return line == null ? "" : line;
        } catch (Exception e) {
            return "";
        }
    }

    private List<String> readLineBlock(BufferedReader reader, int maxLines) {
        List<String> lines = new ArrayList<>();
        for (int i = 0; i < maxLines; i++) {
            String line = safeReadLine(reader);
            if (line.isBlank()) {
                break;
            }
            lines.add(line);
            if (line.length() >= 4 && Character.isDigit(line.charAt(0)) && line.charAt(3) == ' ') {
                break;
            }
        }
        return lines;
    }

    private void sendLine(Writer writer, String line) throws IOException {
        writer.write(line);
        writer.write("\\r\\n");
        writer.flush();
    }

    private NormalizedFingerprint normalizeFingerprint(HostService candidate, ProbeObservation probe) {
        NormalizedFingerprint fingerprint = new NormalizedFingerprint();
        fingerprint.protocol = firstNonBlank(probe.protocol, detectProtocolHint(candidate.port, candidate.serviceHint));
        fingerprint.service = firstNonBlank(normalizeProtocol(candidate.serviceHint), fingerprint.protocol, detectProtocolHint(candidate.port, ""));
        fingerprint.product = "unknown";
        fingerprint.version = "";

        String banner = firstNonBlank(
            probe.firstLine,
            probe.headers.get("Server"),
            candidate.seedBanner,
            firstLine(probe.rawText)
        );

        if (!probe.headers.isEmpty()) {
            String serverHeader = firstHeaderValueIgnoreCase(probe.headers, "Server");
            if (!serverHeader.isBlank()) {
                ProductVersion httpToken = parseProductVersion(serverHeader);
                if (!httpToken.product.isBlank()) {
                    fingerprint.product = normalizeProduct(httpToken.product);
                    fingerprint.version = httpToken.version;
                    fingerprint.service = firstNonBlank(fingerprint.service, "http");
                    fingerprint.signals.put("server_header", serverHeader);
                }
            }
        }

        if (("ssh".equals(fingerprint.protocol) || banner.toLowerCase(Locale.ROOT).contains("ssh")) && fingerprint.product.equals("unknown")) {
            Matcher matcher = SSH_BANNER_PATTERN.matcher(banner);
            if (matcher.find()) {
                fingerprint.product = "openssh";
                fingerprint.version = matcher.group(1);
                fingerprint.service = "ssh";
            }
        }

        if (("smtp".equals(fingerprint.protocol) || "smtps".equals(fingerprint.protocol)) && fingerprint.product.equals("unknown")) {
            Matcher matcher = SMTP_PRODUCT_PATTERN.matcher(banner);
            if (matcher.find()) {
                fingerprint.product = normalizeProduct(matcher.group(1));
                fingerprint.version = trim(matcher.group(2));
                fingerprint.service = "smtp";
            }
        }

        if (("ftp".equals(fingerprint.protocol)) && fingerprint.product.equals("unknown")) {
            Matcher matcher = FTP_PRODUCT_PATTERN.matcher(banner);
            if (matcher.find()) {
                fingerprint.product = normalizeProduct(matcher.group(1));
                fingerprint.version = trim(matcher.group(2));
                fingerprint.service = "ftp";
            }
        }

        if (fingerprint.product.equals("unknown") && !candidate.seedBanner.isBlank()) {
            ProductVersion seed = parseProductVersion(candidate.seedBanner);
            if (!seed.product.isBlank()) {
                fingerprint.product = normalizeProduct(seed.product);
                fingerprint.version = firstNonBlank(seed.version, fingerprint.version);
            }
        }

        if (fingerprint.product.equals("unknown") && !banner.isBlank()) {
            ProductVersion token = parseProductVersion(banner);
            if (!token.product.isBlank()) {
                fingerprint.product = normalizeProduct(token.product);
                fingerprint.version = firstNonBlank(token.version, fingerprint.version);
            }
        }

        if (fingerprint.product.equals("unknown") && !candidate.serviceHint.isBlank()) {
            fingerprint.product = normalizeProduct(candidate.serviceHint);
        }

        if (fingerprint.service.isBlank()) {
            fingerprint.service = detectProtocolHint(candidate.port, fingerprint.product);
        }

        if (!probe.tlsSubject.isBlank()) {
            fingerprint.signals.put("tls_subject", probe.tlsSubject);
            fingerprint.signals.put("tls_issuer", probe.tlsIssuer);
            fingerprint.signals.put("tls_protocol", probe.tlsProtocol);
            fingerprint.signals.put("tls_cipher", probe.tlsCipher);
        }
        if (!probe.firstLine.isBlank()) {
            fingerprint.signals.put("first_line", probe.firstLine);
        }
        if (!probe.headers.isEmpty()) {
            fingerprint.signals.put("header_order", new ArrayList<>(probe.headers.keySet()));
        }

        fingerprint.signals.put("response_time_ms", probe.responseTimeMs);
        fingerprint.signals.put("bytes_read", probe.bytesRead);
        fingerprint.signals.put("timing_profile", classifyTiming(probe.responseTimeMs));
        fingerprint.signals.put("packet_profile", classifyPacketSize(probe.packetSize));

        fingerprint.confidence = computeFingerprintConfidence(fingerprint, probe, candidate);
        return fingerprint;
    }

    protected CveCorrelation correlateCves(
            NormalizedFingerprint fingerprint,
            ScanConfig config,
            ExecutionDiagnostics diagnostics) {

        CveCorrelation correlation = new CveCorrelation();
        correlation.category = "no_known_cves";

        int bestSeverityScore = 0;
        for (CveRule rule : CVE_RULES) {
            if (rule.matches(fingerprint)) {
                CveFinding finding = new CveFinding();
                finding.cveId = rule.cveId;
                finding.severity = rule.severity.value;
                finding.exploitClass = rule.exploitClass;
                finding.exploitAvailable = rule.exploitAvailable;
                finding.reference = rule.reference;
                finding.evidence = "fingerprint=" + fingerprint.product + " " + fingerprint.version;
                correlation.matches.add(finding);
                bestSeverityScore = Math.max(bestSeverityScore, rule.severity.score);
            }
        }

        boolean hasProductRules = hasRulesForProduct(fingerprint.product);
        SearchsploitEvidence externalEvidence = SearchsploitEvidence.empty();

        if (config.useSearchsploit && !fingerprint.product.equals("unknown") && isCommandAvailable("searchsploit")) {
            externalEvidence = querySearchsploit(fingerprint, config, diagnostics);
            if (externalEvidence.hitCount > 0) {
                correlation.externalEvidence.addAll(externalEvidence.entries);
            }
        }

        if (!correlation.matches.isEmpty()) {
            boolean criticalExploit = correlation.matches.stream().anyMatch(item ->
                item.exploitAvailable && ("critical".equals(item.severity) || "high".equals(item.severity))
            );
            if (criticalExploit || externalEvidence.hitCount > 0) {
                correlation.category = "critical_exploit_available";
            } else {
                correlation.category = "known_cves_identified";
            }
        } else if (hasProductRules && !fingerprint.version.isBlank()) {
            correlation.category = "known_but_patched_versions_nearby";
        } else if (hasProductRules || !fingerprint.product.equals("unknown")) {
            correlation.category = "unconfirmed_version_fingerprint";
        } else {
            correlation.category = "no_known_cves";
        }

        correlation.riskScore = deriveRiskScore(correlation.category, bestSeverityScore, fingerprint.confidence, externalEvidence.hitCount);
        correlation.priority = priorityFromScore(correlation.riskScore);
        return correlation;
    }

    private SearchsploitEvidence querySearchsploit(
            NormalizedFingerprint fingerprint,
            ScanConfig config,
            ExecutionDiagnostics diagnostics) {

        String query = fingerprint.product + (fingerprint.version.isBlank() ? "" : " " + fingerprint.version);
        List<String> command = List.of("searchsploit", "--json", query);
        CommandExecutionResult result = runCommand(command, Math.max(5_000L, config.timeoutMs * 2L));

        recordCommandExecution(diagnostics, "searchsploit", command, result);

        if (result.timedOut || result.exitCode != 0 || result.stdout.isBlank()) {
            if (result.timedOut) {
                diagnostics.warnings.add("searchsploit timed out for query: " + query);
            } else if (result.exitCode != 0 && !result.stderr.isBlank()) {
                diagnostics.warnings.add("searchsploit failed for query " + query + ": " + firstLine(result.stderr));
            }
            return SearchsploitEvidence.empty();
        }

        try {
            JsonObject root = JsonParser.parseString(result.stdout).getAsJsonObject();
            JsonObject results = root.getAsJsonObject("RESULTS_EXPLOIT");
            if (results == null || results.size() == 0) {
                return SearchsploitEvidence.empty();
            }

            List<String> entries = new ArrayList<>();
            int hitCount = 0;
            for (Map.Entry<String, JsonElement> item : results.entrySet()) {
                if (!item.getValue().isJsonArray()) {
                    continue;
                }

                JsonArray array = item.getValue().getAsJsonArray();
                for (JsonElement element : array) {
                    if (!element.isJsonObject()) {
                        continue;
                    }

                    JsonObject exploit = element.getAsJsonObject();
                    String title = asJsonText(exploit, "Title");
                    String path = asJsonText(exploit, "Path");
                    if (!title.isBlank()) {
                        entries.add(title + (path.isBlank() ? "" : " [" + path + "]"));
                        hitCount++;
                    }
                    if (entries.size() >= 6) {
                        break;
                    }
                }
                if (entries.size() >= 6) {
                    break;
                }
            }

            return new SearchsploitEvidence(hitCount, entries);
        } catch (Exception e) {
            diagnostics.warnings.add("searchsploit JSON parse error: " + e.getMessage());
            return SearchsploitEvidence.empty();
        }
    }

    private String asJsonText(JsonObject object, String key) {
        JsonElement element = object.get(key);
        if (element == null || element.isJsonNull()) {
            return "";
        }
        if (element.isJsonPrimitive()) {
            return element.getAsString();
        }
        return "";
    }

    private int deriveRiskScore(String category, int bestSeverityScore, double confidence, int externalHits) {
        int score;
        switch (category) {
            case "critical_exploit_available" -> score = Math.max(85, bestSeverityScore + 10);
            case "known_cves_identified" -> score = Math.max(55, bestSeverityScore);
            case "known_but_patched_versions_nearby" -> score = 38;
            case "unconfirmed_version_fingerprint" -> score = 26;
            default -> score = 12;
        }

        score += Math.min(12, (int) Math.round(confidence * 12));
        score += Math.min(8, externalHits * 2);
        return Math.max(0, Math.min(100, score));
    }

    private String priorityFromScore(int score) {
        if (score >= 85) {
            return "critical";
        }
        if (score >= 70) {
            return "high";
        }
        if (score >= 50) {
            return "medium";
        }
        return "low";
    }

    private List<HostFusionRecord> buildFusionDataset(List<ServiceAssessment> assessments) {
        Map<String, HostFusionRecord> grouped = new LinkedHashMap<>();

        for (ServiceAssessment assessment : assessments) {
            HostFusionRecord record = grouped.computeIfAbsent(assessment.host, HostFusionRecord::new);
            record.services.add(assessment);
            record.maxRiskScore = Math.max(record.maxRiskScore, assessment.cve.riskScore);
            if (!assessment.dnsName.isBlank()) {
                record.dnsName = assessment.dnsName;
            }
            for (CveFinding finding : assessment.cve.matches) {
                record.cves.add(finding.cveId);
            }
        }

        for (HostFusionRecord record : grouped.values()) {
            record.services.sort(Comparator.comparingInt(item -> item.port));
            record.riskLevel = priorityFromScore(record.maxRiskScore);
        }

        List<HostFusionRecord> out = new ArrayList<>(grouped.values());
        out.sort(Comparator.comparingLong((HostFusionRecord item) -> ipSortKey(item.host)).thenComparing(item -> item.host));
        return out;
    }

    private Map<String, Object> buildSummary(
            ScanConfig config,
            int resolvedTargets,
            List<ServiceAssessment> assessments,
            List<HostFusionRecord> fusionRecords) {

        int identifiedProducts = 0;
        int cveMatches = 0;
        int criticalExploitAvailable = 0;
        int connectedServices = 0;
        double confidenceSum = 0.0;

        Map<String, Integer> priorityDistribution = new LinkedHashMap<>();
        priorityDistribution.put("critical", 0);
        priorityDistribution.put("high", 0);
        priorityDistribution.put("medium", 0);
        priorityDistribution.put("low", 0);

        for (ServiceAssessment assessment : assessments) {
            if (!assessment.fingerprint.product.equals("unknown")) {
                identifiedProducts++;
            }
            if (assessment.probe.connected) {
                connectedServices++;
            }
            confidenceSum += assessment.fingerprint.confidence;
            cveMatches += assessment.cve.matches.size();
            if ("critical_exploit_available".equals(assessment.cve.category)) {
                criticalExploitAvailable++;
            }
            priorityDistribution.put(
                assessment.cve.priority,
                priorityDistribution.getOrDefault(assessment.cve.priority, 0) + 1
            );
        }

        List<Map<String, Object>> highRiskHosts = fusionRecords.stream()
            .filter(record -> record.maxRiskScore >= 70)
            .sorted(Comparator.comparingInt((HostFusionRecord record) -> record.maxRiskScore).reversed())
            .limit(10)
            .map(record -> Map.<String, Object>of(
                "host", record.host,
                "risk_score", record.maxRiskScore,
                "risk_level", record.riskLevel
            ))
            .toList();

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", config.mode.value);
        summary.put("resolved_targets", resolvedTargets);
        summary.put("services_evaluated", assessments.size());
        summary.put("connected_services", connectedServices);
        summary.put("identified_products", identifiedProducts);
        summary.put("cve_matches", cveMatches);
        summary.put("critical_exploit_available_count", criticalExploitAvailable);
        summary.put("fusion_hosts", fusionRecords.size());
        summary.put("priority_distribution", priorityDistribution);
        summary.put("average_confidence", roundDouble(assessments.isEmpty() ? 0.0 : confidenceSum / assessments.size()));
        summary.put("high_risk_hosts", highRiskHosts);
        return summary;
    }

    private Map<String, Object> buildEmptySummary(ScanConfig config, int resolvedTargets) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", config.mode.value);
        summary.put("resolved_targets", resolvedTargets);
        summary.put("services_evaluated", 0);
        summary.put("connected_services", 0);
        summary.put("identified_products", 0);
        summary.put("cve_matches", 0);
        summary.put("critical_exploit_available_count", 0);
        summary.put("fusion_hosts", 0);
        summary.put("priority_distribution", Map.of(
            "critical", 0,
            "high", 0,
            "medium", 0,
            "low", 0
        ));
        summary.put("average_confidence", 0.0);
        summary.put("high_risk_hosts", List.of());
        return summary;
    }

    private Map<String, Object> buildModeResult(
            ScanConfig config,
            List<ServiceAssessment> assessments,
            List<HostFusionRecord> fusionRecords,
            Map<String, Object> summary,
            ExecutionDiagnostics diagnostics) {

        Map<String, Object> modeResult = new LinkedHashMap<>();
        switch (config.mode) {
            case SERVICE_FINGERPRINT -> {
                modeResult.put("fingerprints", toServiceMapList(assessments, config.includeRaw));
                modeResult.put("identified_services", assessments.stream()
                    .filter(item -> !item.fingerprint.product.equals("unknown"))
                    .count());
                modeResult.put("confidence_average", summary.get("average_confidence"));
            }
            case CVE_MAPPING -> {
                modeResult.put("correlations", toServiceMapList(assessments, config.includeRaw));
                modeResult.put("critical_exploit_available_count", summary.get("critical_exploit_available_count"));

                Map<String, Integer> categories = new LinkedHashMap<>();
                for (ServiceAssessment item : assessments) {
                    categories.put(item.cve.category, categories.getOrDefault(item.cve.category, 0) + 1);
                }
                modeResult.put("category_breakdown", categories);
            }
            case ENUMERATION_FUSION -> {
                modeResult.put("dataset", toFusionMapList(fusionRecords));
                modeResult.put("target_chain", buildTargetChain(fusionRecords));
            }
            case STEALTH_BANNER -> {
                modeResult.put("dataset", toFusionMapList(fusionRecords));
                modeResult.put("stealth_profile", buildStealthProfile(config, diagnostics, assessments));
            }
        }
        modeResult.put("signal_count", countSignals(modeResult));
        return modeResult;
    }

    private List<String> buildTargetChain(List<HostFusionRecord> fusionRecords) {
        List<String> chain = new ArrayList<>();
        for (HostFusionRecord record : fusionRecords) {
            StringBuilder builder = new StringBuilder();
            builder.append(record.host);
            if (!record.dnsName.isBlank()) {
                builder.append(" (").append(record.dnsName).append(")");
            }

            for (ServiceAssessment service : record.services) {
                builder.append(" -> ")
                    .append(service.port)
                    .append("/tcp ")
                    .append(service.fingerprint.product)
                    .append(service.fingerprint.version.isBlank() ? "" : " " + service.fingerprint.version)
                    .append(" -> ")
                    .append(service.cve.priority)
                    .append("(")
                    .append(service.cve.matches.size())
                    .append(" CVE)");
            }

            chain.add(builder.toString());
        }
        return chain;
    }

    private Map<String, Object> buildStealthProfile(
            ScanConfig config,
            ExecutionDiagnostics diagnostics,
            List<ServiceAssessment> assessments) {

        Map<String, Object> profile = new LinkedHashMap<>();
        profile.put("single_packet_strategy", true);
        profile.put("minimal_protocol_queries", true);
        profile.put("retries_per_target", 0);
        profile.put("inter_probe_delay_ms", config.interProbeDelayMs);
        profile.put("randomized_delay_enabled", config.randomizeStealthDelays);
        profile.put("probes_executed", diagnostics.probeCount);
        profile.put("minimal_probes", diagnostics.minimalProbeCount);
        profile.put("total_delay_applied_ms", diagnostics.delayAppliedMs);

        long fullSessionCount = assessments.stream()
            .filter(item -> !item.probe.minimalQuery)
            .count();
        profile.put("full_session_probes", fullSessionCount);

        int stealthScore = 100;
        stealthScore -= Math.min(25, diagnostics.commandExecutions * 2);
        stealthScore -= Math.min(20, (int) fullSessionCount * 5);
        stealthScore -= Math.min(20, diagnostics.probeCount > 0 ? diagnostics.probeCount / 3 : 0);
        profile.put("stealth_score", Math.max(0, stealthScore));
        return profile;
    }

    private Map<String, Object> buildExecutionMetadata(
            ScanConfig config,
            ExecutionDiagnostics diagnostics,
            long startedAt) {

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("module", MODULE_ID);
        metadata.put("mode", config.mode.value);
        metadata.put("tool_usage", new ArrayList<>(diagnostics.toolUsage));
        metadata.put("command_executions", diagnostics.commandExecutions);
        metadata.put("executed_commands", diagnostics.executedCommands);
        metadata.put("command_log", diagnostics.commandLog);
        metadata.put("warnings", diagnostics.warnings);
        metadata.put("probe_count", diagnostics.probeCount);
        metadata.put("minimal_probe_count", diagnostics.minimalProbeCount);
        metadata.put("tls_handshakes", diagnostics.tlsHandshakes);
        metadata.put("delay_applied_ms", diagnostics.delayAppliedMs);
        metadata.put("timeout_ms", config.timeoutMs);
        metadata.put("connect_timeout_ms", config.connectTimeoutMs);
        metadata.put("use_whatweb", config.useWhatWeb);
        metadata.put("use_wappalyzer", config.useWappalyzer);
        metadata.put("elapsed_ms", System.currentTimeMillis() - startedAt);
        return metadata;
    }

    private void appendFindings(
            ModuleResult result,
            List<ServiceAssessment> assessments,
            List<HostFusionRecord> fusionRecords,
            Map<String, Object> summary) {

        Map<String, Object> overview = new LinkedHashMap<>();
        overview.put("type", "banner_grabber_summary");
        overview.put("summary", summary);
        result.addFinding(overview);

        for (ServiceAssessment assessment : assessments) {
            Map<String, Object> finding = new LinkedHashMap<>();
            finding.put("type", "service_fingerprint");
            finding.put("host", assessment.host);
            finding.put("port", assessment.port);
            finding.put("service", assessment.fingerprint.service);
            finding.put("product", assessment.fingerprint.product);
            finding.put("version", assessment.fingerprint.version);
            finding.put("cve_category", assessment.cve.category);
            finding.put("risk_score", assessment.cve.riskScore);
            finding.put("priority", assessment.cve.priority);
            finding.put("cves", assessment.cve.matches.stream().map(item -> item.cveId).toList());
            result.addFinding(finding);
        }

        for (HostFusionRecord record : fusionRecords) {
            Map<String, Object> finding = new LinkedHashMap<>();
            finding.put("type", "fusion_host");
            finding.put("host", record.host);
            finding.put("risk_score", record.maxRiskScore);
            finding.put("risk_level", record.riskLevel);
            finding.put("cve_count", record.cves.size());
            result.addFinding(finding);
        }
    }

    private Map<String, Object> buildNormalizedOutput(
            ScanConfig config,
            Map<String, Object> summary,
            List<Map<String, Object>> serviceMaps,
            Map<String, Object> modeResult) {

        Map<String, Object> normalized = new LinkedHashMap<>();

        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("summary", summary);
        raw.put("services", serviceMaps);
        raw.put("mode_result", modeResult);
        normalized.put("raw_output", raw);

        long highOrCritical = serviceMaps.stream()
            .filter(item -> {
                Object priority = item.get("priority");
                return "high".equals(priority) || "critical".equals(priority);
            })
            .count();

        Map<String, Object> parsed = new LinkedHashMap<>();
        parsed.put("status", highOrCritical > 0
            ? "EXPLOIT_RELEVANT_BANNER_INTEL_FOUND"
            : "LIMITED_BANNER_INTEL");
        parsed.put("vulnerable", highOrCritical > 0);
        parsed.put("details", summary);
        parsed.put("evidence", serviceMaps);
        normalized.put("parsed_output", parsed);

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("module", MODULE_ID);
        metadata.put("mode", config.mode.value);
        normalized.put("metadata", metadata);

        return normalized;
    }

    private List<Map<String, Object>> toServiceMapList(List<ServiceAssessment> assessments, boolean includeRaw) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (ServiceAssessment assessment : assessments) {
            out.add(assessment.toMap(includeRaw));
        }
        return out;
    }

    private List<Map<String, Object>> toFusionMapList(List<HostFusionRecord> records) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (HostFusionRecord record : records) {
            out.add(record.toMap());
        }
        return out;
    }

    private ScanConfig parseConfig(Map<String, String> input) {
        ScanConfig config = new ScanConfig();

        config.mode = ModuleMode.fromInput(firstNonBlank(input.get("mode"), "service_fingerprint"));
        config.targetHost = firstNonBlank(input.get("target_host"), input.get("target"));
        config.targetScope = firstNonBlank(input.get("target_scope"), input.get("subnet"), input.get("cidr"));
        config.portsSpec = firstNonBlank(input.get("ports"), DEFAULT_PORT_SPEC);
        config.serviceHint = normalizeProtocol(input.get("service_hint"));

        config.forceTls = parseBoolean(input.get("force_tls"), false);
        config.useNmap = parseBoolean(input.get("use_nmap"), true);
        config.useMasscan = parseBoolean(input.get("use_masscan"), false);
        config.useWhatWeb = parseBoolean(input.get("use_whatweb"), false);
        config.useWappalyzer = parseBoolean(input.get("use_wappalyzer"), false);
        config.useSearchsploit = parseBoolean(input.get("use_searchsploit"), true);

        config.timeoutMs = parseInteger(input.get("timeout_ms"), DEFAULT_TIMEOUT_MS);
        config.connectTimeoutMs = parseInteger(input.get("connect_timeout_ms"), DEFAULT_CONNECT_TIMEOUT_MS);
        config.maxHosts = parseInteger(input.get("max_hosts"), DEFAULT_MAX_HOSTS);
        config.maxPortsPerHost = parseInteger(input.get("max_ports_per_host"), DEFAULT_MAX_PORTS_PER_HOST);
        config.interProbeDelayMs = parseInteger(input.get("inter_probe_delay_ms"), DEFAULT_INTER_PROBE_DELAY_MS);
        config.randomizeStealthDelays = parseBoolean(input.get("randomize_stealth_delays"), true);

        config.resolveDns = parseBoolean(input.get("resolve_dns"), false);
        config.includeRaw = parseBoolean(input.get("include_raw"), false);
        return config;
    }

    private List<String> validateConfig(ScanConfig config) {
        List<String> errors = new ArrayList<>();

        switch (config.mode) {
            case ENUMERATION_FUSION -> {
                if (trim(config.targetScope).isBlank()) {
                    errors.add("target_scope is required when mode=enumeration_fusion");
                }
            }
            case SERVICE_FINGERPRINT, CVE_MAPPING, STEALTH_BANNER -> {
                if (trim(config.targetHost).isBlank()) {
                    errors.add("target_host is required for selected mode");
                }
            }
        }

        if (config.timeoutMs < 500 || config.timeoutMs > 180_000) {
            errors.add("timeout_ms must be between 500 and 180000");
        }
        if (config.connectTimeoutMs < 200 || config.connectTimeoutMs > 120_000) {
            errors.add("connect_timeout_ms must be between 200 and 120000");
        }
        if (config.maxHosts < 1 || config.maxHosts > MAX_HOSTS_LIMIT) {
            errors.add("max_hosts must be between 1 and " + MAX_HOSTS_LIMIT);
        }
        if (config.maxPortsPerHost < 1 || config.maxPortsPerHost > 1024) {
            errors.add("max_ports_per_host must be between 1 and 1024");
        }
        if (config.interProbeDelayMs < 0 || config.interProbeDelayMs > 30_000) {
            errors.add("inter_probe_delay_ms must be between 0 and 30000");
        }

        List<Integer> ports = parsePortSpec(config.portsSpec, config.maxPortsPerHost);
        if (ports.isEmpty()) {
            errors.add("ports must include at least one valid TCP port");
        }

        if (config.mode == ModuleMode.ENUMERATION_FUSION && !trim(config.targetScope).isBlank()) {
            long estimate = estimateTargetCount(config.targetScope);
            if (estimate > config.maxHosts && estimate > 0) {
                errors.add("target_scope expands to " + estimate + " hosts, exceeding max_hosts=" + config.maxHosts);
            }
        }

        return errors;
    }

    private List<String> resolveTargets(ScanConfig config) {
        if (config.mode == ModuleMode.ENUMERATION_FUSION) {
            Set<String> targets = new LinkedHashSet<>();
            for (String token : splitTargetScope(config.targetScope)) {
                if (targets.size() >= config.maxHosts) {
                    break;
                }

                if (isValidCidr(token)) {
                    int remaining = config.maxHosts - targets.size();
                    targets.addAll(expandCidr(token, remaining));
                } else {
                    targets.add(normalizeHostToken(token));
                }
            }
            targets.removeIf(String::isBlank);
            return new ArrayList<>(targets);
        }

        String host = normalizeHostToken(config.targetHost);
        if (host.isBlank()) {
            return List.of();
        }
        return List.of(host);
    }

    private long estimateTargetCount(String targetScope) {
        long total = 0;
        for (String token : splitTargetScope(targetScope)) {
            if (isValidCidr(token)) {
                total += estimateCidrHosts(token);
            } else if (!token.isBlank()) {
                total += 1;
            }
        }
        return total;
    }

    private long estimateCidrHosts(String cidr) {
        String[] parts = cidr.split("/");
        int prefix = parseInteger(parts[1], 32);
        if (prefix == 32) {
            return 1;
        }
        if (prefix == 31) {
            return 2;
        }
        return Math.max(0, (1L << (32 - prefix)) - 2);
    }

    private List<String> splitTargetScope(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return Arrays.stream(value.split(","))
            .map(String::trim)
            .filter(token -> !token.isBlank())
            .toList();
    }

    private List<String> expandCidr(String cidr, int maxHosts) {
        if (maxHosts <= 0) {
            return List.of();
        }

        String[] parts = cidr.split("/");
        String baseIp = parts[0].trim();
        int prefix = parseInteger(parts[1], 32);

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

    protected boolean isPortOpen(String host, int port, int connectTimeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), Math.max(250, connectTimeoutMs));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    protected String resolveDnsName(String host) {
        try {
            return InetAddress.getByName(host).getCanonicalHostName();
        } catch (Exception e) {
            return "";
        }
    }

    protected boolean isCommandAvailable(String command) {
        return commandAvailabilityCache.computeIfAbsent(command, cmd -> {
            List<String> check = isWindows() ? List.of("where", cmd) : List.of("which", cmd);
            CommandExecutionResult result = runCommand(check, 2000);
            return !result.timedOut && result.exitCode == 0;
        });
    }

    protected CommandExecutionResult runCommand(List<String> command, long timeoutMs) {
        long startedAt = System.currentTimeMillis();
        Process process = null;

        try {
            process = new ProcessBuilder(command).start();

            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();

            Process running = process;
            Thread outThread = Thread.ofVirtual().start(() -> copyStream(running.getInputStream(), stdout));
            Thread errThread = Thread.ofVirtual().start(() -> copyStream(running.getErrorStream(), stderr));

            boolean finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
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

            joinQuietly(outThread, 400);
            joinQuietly(errThread, 400);

            return new CommandExecutionResult(
                process.exitValue(),
                stdout.toString(),
                stderr.toString(),
                false,
                System.currentTimeMillis() - startedAt
            );
        } catch (Exception e) {
            return new CommandExecutionResult(
                -1,
                "",
                firstNonBlank(e.getMessage(), "command_failed"),
                false,
                System.currentTimeMillis() - startedAt
            );
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    private List<Map<String, Object>> pipeline() {
        return List.of(
            Map.of("step", "mode_selection", "description", "Select operational mode and probe profile"),
            Map.of("step", "target_resolution", "description", "Resolve host scope and port candidates"),
            Map.of("step", "service_interrogation", "description", "Collect active and passive protocol signals"),
            Map.of("step", "fingerprint_normalization", "description", "Normalize product, version, and confidence"),
            Map.of("step", "cve_correlation", "description", "Map fingerprints to CVE and exploit references"),
            Map.of("step", "fusion_scoring", "description", "Assemble host-service exploit-priority dataset"),
            Map.of("step", "structured_output", "description", "Emit findings and normalized output")
        );
    }

    private List<Integer> parsePortSpec(String spec, int maxPortsPerHost) {
        LinkedHashSet<Integer> ports = new LinkedHashSet<>();
        String value = firstNonBlank(spec, DEFAULT_PORT_SPEC);

        for (String token : value.split(",")) {
            String part = token.trim();
            if (part.isBlank()) {
                continue;
            }

            if (part.contains("-")) {
                String[] range = part.split("-");
                if (range.length != 2) {
                    continue;
                }

                int start = parseInteger(range[0], -1);
                int end = parseInteger(range[1], -1);
                if (start <= 0 || end <= 0 || end < start) {
                    continue;
                }

                for (int port = start; port <= end; port++) {
                    if (port > 65535) {
                        break;
                    }
                    ports.add(port);
                    if (ports.size() >= maxPortsPerHost) {
                        break;
                    }
                }
            } else {
                int port = parseInteger(part, -1);
                if (port > 0 && port <= 65535) {
                    ports.add(port);
                }
            }

            if (ports.size() >= maxPortsPerHost) {
                break;
            }
        }

        return new ArrayList<>(ports);
    }

    private ProductVersion parseProductVersion(String text) {
        String source = trim(text);
        if (source.isBlank()) {
            return ProductVersion.empty();
        }

        Matcher matcher = PRODUCT_VERSION_PATTERN.matcher(source);
        if (matcher.find()) {
            return new ProductVersion(normalizeProduct(matcher.group(1)), trim(matcher.group(2)));
        }

        String[] parts = source.split("\\s+");
        if (parts.length >= 2) {
            String maybeProduct = normalizeProduct(parts[0]);
            String maybeVersion = trim(parts[1]);
            if (isVersionToken(maybeVersion)) {
                return new ProductVersion(maybeProduct, maybeVersion);
            }
        }

        return new ProductVersion(normalizeProduct(source), "");
    }

    private boolean isVersionToken(String token) {
        return token != null && token.matches("[0-9][A-Za-z0-9._-]*");
    }

    private String firstHeaderValueIgnoreCase(Map<String, String> headers, String key) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(key)) {
                return entry.getValue();
            }
        }
        return "";
    }

    private boolean hasRulesForProduct(String product) {
        if (product == null || product.isBlank() || "unknown".equals(product)) {
            return false;
        }
        String normalized = normalizeProduct(product);
        return CVE_RULES.stream().anyMatch(rule -> normalized.contains(rule.productToken));
    }

    private double computeFingerprintConfidence(
            NormalizedFingerprint fingerprint,
            ProbeObservation probe,
            HostService candidate) {

        double score = 0.0;
        if (probe.connected) {
            score += 0.25;
        }
        if (!probe.firstLine.isBlank()) {
            score += 0.20;
        }
        if (!probe.headers.isEmpty()) {
            score += 0.15;
        }
        if (!probe.tlsSubject.isBlank()) {
            score += 0.15;
        }
        if (!fingerprint.product.equals("unknown")) {
            score += 0.15;
        }
        if (!fingerprint.version.isBlank()) {
            score += 0.10;
        }
        if (!candidate.seedBanner.isBlank()) {
            score += 0.05;
        }

        return Math.min(1.0, roundDouble(score));
    }

    private String classifyTiming(long durationMs) {
        if (durationMs <= 0) {
            return "unknown";
        }
        if (durationMs < 80) {
            return "fast";
        }
        if (durationMs < 300) {
            return "normal";
        }
        if (durationMs < 1200) {
            return "slow";
        }
        return "very_slow";
    }

    private String classifyPacketSize(int bytes) {
        if (bytes <= 0) {
            return "none";
        }
        if (bytes <= 128) {
            return "minimal";
        }
        if (bytes <= 1024) {
            return "compact";
        }
        if (bytes <= 4096) {
            return "standard";
        }
        return "large";
    }

    private String detectProtocolHint(int port, String signal) {
        String lowerSignal = trim(signal).toLowerCase(Locale.ROOT);
        if (!lowerSignal.isBlank()) {
            if (lowerSignal.contains("ssh")) {
                return "ssh";
            }
            if (lowerSignal.contains("smtp")) {
                return "smtp";
            }
            if (lowerSignal.contains("http")) {
                return port == 443 ? "https" : "http";
            }
            if (lowerSignal.contains("ftp")) {
                return "ftp";
            }
            if (lowerSignal.contains("imap")) {
                return "imap";
            }
            if (lowerSignal.contains("pop3")) {
                return "pop3";
            }
            if (lowerSignal.contains("mysql")) {
                return "mysql";
            }
            if (lowerSignal.contains("mssql") || lowerSignal.contains("ms-sql")) {
                return "mssql";
            }
            if (lowerSignal.contains("redis")) {
                return "redis";
            }
        }

        return PORT_PROTOCOL_HINT.getOrDefault(port, "unknown");
    }

    private boolean shouldUseTls(int port, String protocol, boolean forceTls) {
        if (forceTls) {
            return true;
        }
        if (protocol == null || protocol.isBlank()) {
            return port == 443 || port == 636 || port == 993 || port == 995 || port == 465;
        }
        return switch (protocol) {
            case "https", "ldaps", "imaps", "pop3s", "smtps" -> true;
            default -> port == 443 || port == 636 || port == 993 || port == 995 || port == 465;
        };
    }

    private boolean isHttpProtocol(String protocol, int port) {
        if ("http".equals(protocol) || "https".equals(protocol)) {
            return true;
        }
        return port == 80 || port == 443 || port == 8080;
    }

    private boolean isLineProtocol(String protocol) {
        return switch (protocol) {
            case "ssh", "smtp", "smtps", "ftp", "pop3", "pop3s", "imap", "imaps" -> true;
            default -> false;
        };
    }

    private int computeStealthDelay(ScanConfig config, HostService candidate) {
        if (config.mode != ModuleMode.STEALTH_BANNER || config.interProbeDelayMs <= 0) {
            return 0;
        }

        if (!config.randomizeStealthDelays) {
            return config.interProbeDelayMs;
        }

        int spread = Math.max(1, config.interProbeDelayMs / 2);
        int jitter = Math.abs((candidate.host + ":" + candidate.port).hashCode()) % (spread + 1);
        return config.interProbeDelayMs + jitter;
    }

    private long ipSortKey(String candidate) {
        if (!isIpv4(candidate)) {
            return Long.MAX_VALUE;
        }
        return ipToLong(candidate);
    }

    private long ipToLong(String ip) {
        String[] parts = ip.split("\\.");
        long value = 0;
        for (String part : parts) {
            value = (value << 8) | parseInteger(part, 0);
        }
        return value & 0xFFFFFFFFL;
    }

    private String longToIp(long ip) {
        return ((ip >>> 24) & 0xFF) + "."
            + ((ip >>> 16) & 0xFF) + "."
            + ((ip >>> 8) & 0xFF) + "."
            + (ip & 0xFF);
    }

    private boolean isValidCidr(String value) {
        String token = trim(value);
        if (!token.contains("/")) {
            return false;
        }

        String[] parts = token.split("/");
        if (parts.length != 2) {
            return false;
        }
        if (!isIpv4(parts[0].trim())) {
            return false;
        }

        int prefix = parseInteger(parts[1], -1);
        return prefix >= 0 && prefix <= 32;
    }

    private boolean isIpv4(String value) {
        if (value == null || !IPV4_PATTERN.matcher(value).matches()) {
            return false;
        }

        String[] parts = value.split("\\.");
        for (String part : parts) {
            int octet = parseInteger(part, -1);
            if (octet < 0 || octet > 255) {
                return false;
            }
        }
        return true;
    }

    private String parseHostFromNmapHeader(String line) {
        String value = line.replace("Nmap scan report for", "").trim();
        if (value.contains("(")) {
            Matcher matcher = Pattern.compile("\\(([^)]+)\\)").matcher(value);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }

        String[] parts = value.split("\\s+");
        if (parts.length == 0) {
            return value;
        }
        return parts[parts.length - 1];
    }

    private String normalizeTargetExpression(String value) {
        String expression = trim(value);
        if (expression.isBlank()) {
            return "";
        }

        return expression.replaceAll(",\\s+", ",");
    }

    private String normalizeHostToken(String token) {
        String value = trim(token);
        if (value.isBlank()) {
            return "";
        }

        if (value.startsWith("http://") || value.startsWith("https://")) {
            value = value.replaceFirst("^https?://", "");
        }

        int slash = value.indexOf('/');
        if (slash >= 0) {
            value = value.substring(0, slash);
        }

        if (value.chars().filter(ch -> ch == ':').count() == 1 && value.contains(".")) {
            String[] parts = value.split(":", 2);
            if (parts.length == 2 && parts[1].matches("\\d{1,5}")) {
                value = parts[0];
            }
        }

        return value.trim();
    }

    private String normalizeProtocol(String protocol) {
        String value = trim(protocol).toLowerCase(Locale.ROOT);
        if (value.isBlank()) {
            return "";
        }
        return switch (value) {
            case "www", "web", "http/1.1", "http/2" -> "http";
            case "ssl", "tls" -> "https";
            default -> value;
        };
    }

    private String normalizeProduct(String value) {
        String product = trim(value).toLowerCase(Locale.ROOT);
        product = product.replaceAll("\\(.*?\\)", "").trim();
        product = product.replaceAll("[^a-z0-9._ -]", "").trim();
        product = product.replaceAll("\\s+", " ");
        if (product.startsWith("microsoft iis")) {
            return "microsoft-iis";
        }
        return product;
    }

    private static int compareVersions(String leftRaw, String rightRaw) {
        List<Integer> left = parseVersionTokens(leftRaw);
        List<Integer> right = parseVersionTokens(rightRaw);

        int length = Math.max(left.size(), right.size());
        for (int i = 0; i < length; i++) {
            int leftValue = i < left.size() ? left.get(i) : 0;
            int rightValue = i < right.size() ? right.get(i) : 0;
            if (leftValue != rightValue) {
                return Integer.compare(leftValue, rightValue);
            }
        }
        return 0;
    }

    private static List<Integer> parseVersionTokens(String version) {
        if (version == null || version.isBlank()) {
            return List.of();
        }

        List<Integer> tokens = new ArrayList<>();
        Matcher matcher = Pattern.compile("(\\d+)").matcher(version);
        while (matcher.find()) {
            try {
                tokens.add(Integer.parseInt(matcher.group(1)));
            } catch (NumberFormatException ignored) {
                tokens.add(0);
            }
            if (tokens.size() >= 6) {
                break;
            }
        }
        return tokens;
    }

    private int countSignals(Map<String, Object> map) {
        int count = 0;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (entry.getValue() instanceof List<?> list && !list.isEmpty()) {
                count++;
            } else if (entry.getValue() instanceof Map<?, ?> nested && !nested.isEmpty()) {
                count++;
            } else if (entry.getValue() instanceof Boolean bool && bool) {
                count++;
            } else if (entry.getValue() instanceof Number number && number.doubleValue() > 0) {
                count++;
            } else if (entry.getValue() instanceof String text && !text.isBlank()) {
                count++;
            }
        }
        return count;
    }

    private double roundDouble(double value) {
        return Math.round(value * 100.0) / 100.0;
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

    private String firstLine(String text) {
        if (text == null || text.isBlank()) {
            return "";
        }
        String[] lines = text.split("\\R");
        return lines.length == 0 ? "" : lines[0].trim();
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

    private void sleepQuietly(int millis) {
        if (millis <= 0) {
            return;
        }
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    private void copyStream(InputStream stream, StringBuilder sink) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sink.append(line).append('\n');
            }
        } catch (IOException ignored) {
            // best-effort capture
        }
    }

    private void joinQuietly(Thread thread, long timeoutMs) {
        if (thread == null) {
            return;
        }
        try {
            thread.join(timeoutMs);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    private boolean isWindows() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        return os.contains("win");
    }

    protected enum ModuleMode {
        SERVICE_FINGERPRINT("service_fingerprint", "service_fingerprint_result"),
        CVE_MAPPING("cve_mapping", "cve_mapping_result"),
        ENUMERATION_FUSION("enumeration_fusion", "enumeration_fusion_result"),
        STEALTH_BANNER("stealth_banner", "stealth_banner_result");

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
                case "cve_mapping", "cve_map", "vuln_mapping" -> CVE_MAPPING;
                case "enumeration_fusion", "fusion", "recon_fusion" -> ENUMERATION_FUSION;
                case "stealth_banner", "stealth", "low_noise" -> STEALTH_BANNER;
                default -> SERVICE_FINGERPRINT;
            };
        }
    }

    protected static final class ScanConfig {
        private ModuleMode mode = ModuleMode.SERVICE_FINGERPRINT;

        private String targetHost = "";
        private String targetScope = "";
        private String portsSpec = DEFAULT_PORT_SPEC;
        private String serviceHint = "";

        private boolean forceTls;
        private boolean useNmap = true;
        private boolean useMasscan;
        private boolean useWhatWeb;
        private boolean useWappalyzer;
        private boolean useSearchsploit = true;

        private int timeoutMs = DEFAULT_TIMEOUT_MS;
        private int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
        private int maxHosts = DEFAULT_MAX_HOSTS;
        private int maxPortsPerHost = DEFAULT_MAX_PORTS_PER_HOST;
        private int interProbeDelayMs = DEFAULT_INTER_PROBE_DELAY_MS;
        private boolean randomizeStealthDelays = true;

        private boolean resolveDns;
        private boolean includeRaw;
    }

    protected static final class HostService {
        protected final String host;
        protected final int port;
        protected String serviceHint = "";
        protected String seedBanner = "";
        protected String discoveryMethod = "";

        public HostService(String host, int port) {
            this.host = host == null ? "" : host;
            this.port = port;
        }

        public HostService withServiceHint(String value) {
            this.serviceHint = value == null ? "" : value;
            return this;
        }

        public HostService withSeedBanner(String value) {
            this.seedBanner = value == null ? "" : value;
            return this;
        }

        public HostService withDiscoveryMethod(String value) {
            this.discoveryMethod = value == null ? "" : value;
            return this;
        }

        private String key() {
            return host.toLowerCase(Locale.ROOT) + "|" + port;
        }
    }

    protected static final class ProbeObservation {
        protected String host = "";
        protected int port;
        protected String protocol = "unknown";
        protected boolean connected;
        protected boolean minimalQuery;
        protected String probeMethod = "";

        protected long responseTimeMs;
        protected int bytesRead;
        protected int packetSize;
        protected int statusCode;

        protected String firstLine = "";
        protected String rawText = "";
        protected String error = "";

        protected String tlsProtocol = "";
        protected String tlsCipher = "";
        protected String tlsSubject = "";
        protected String tlsIssuer = "";

        protected final Map<String, String> headers = new LinkedHashMap<>();

        protected static ProbeObservation base(String host, int port) {
            ProbeObservation observation = new ProbeObservation();
            observation.host = host;
            observation.port = port;
            return observation;
        }

        private Map<String, Object> toMap(boolean includeRaw) {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("host", host);
            map.put("port", port);
            map.put("protocol", protocol);
            map.put("connected", connected);
            map.put("minimal_query", minimalQuery);
            map.put("probe_method", probeMethod);
            map.put("response_time_ms", responseTimeMs);
            map.put("bytes_read", bytesRead);
            map.put("packet_size", packetSize);
            map.put("status_code", statusCode);
            map.put("first_line", firstLine);
            map.put("headers", headers);
            map.put("tls_protocol", tlsProtocol);
            map.put("tls_cipher", tlsCipher);
            map.put("tls_subject", tlsSubject);
            map.put("tls_issuer", tlsIssuer);
            map.put("error", error);
            if (includeRaw) {
                map.put("raw_text", rawText);
            }
            return map;
        }
    }

    protected static final class NormalizedFingerprint {
        private String protocol = "unknown";
        private String service = "unknown";
        private String product = "unknown";
        private String version = "";
        private double confidence;
        private final Map<String, Object> signals = new LinkedHashMap<>();

        private Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("protocol", protocol);
            map.put("service", service);
            map.put("product", product);
            map.put("version", version);
            map.put("confidence", confidence);
            map.put("signals", signals);
            return map;
        }
    }

    protected static final class CveFinding {
        private String cveId = "";
        private String severity = "";
        private String exploitClass = "";
        private boolean exploitAvailable;
        private String reference = "";
        private String evidence = "";

        private Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("cve_id", cveId);
            map.put("severity", severity);
            map.put("exploit_class", exploitClass);
            map.put("exploit_available", exploitAvailable);
            map.put("reference", reference);
            map.put("evidence", evidence);
            return map;
        }
    }

    protected static final class CveCorrelation {
        private String category = "no_known_cves";
        private int riskScore;
        private String priority = "low";
        private final List<CveFinding> matches = new ArrayList<>();
        private final List<String> externalEvidence = new ArrayList<>();

        private Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("category", category);
            map.put("risk_score", riskScore);
            map.put("priority", priority);
            map.put("matches", matches.stream().map(CveFinding::toMap).toList());
            map.put("external_evidence", externalEvidence);
            return map;
        }
    }

    private static final class ServiceAssessment {
        private String host = "";
        private int port;
        private String dnsName = "";
        private String discoveryMethod = "";

        private ProbeObservation probe;
        private NormalizedFingerprint fingerprint;
        private CveCorrelation cve;

        private ServiceAssessment(HostService candidate, ProbeObservation probe, NormalizedFingerprint fingerprint, CveCorrelation cve) {
            this.host = candidate.host;
            this.port = candidate.port;
            this.discoveryMethod = candidate.discoveryMethod;
            this.probe = probe;
            this.fingerprint = fingerprint;
            this.cve = cve;
        }

        private Map<String, Object> toMap(boolean includeRaw) {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("host", host);
            map.put("port", port);
            if (!dnsName.isBlank()) {
                map.put("dns_name", dnsName);
            }
            map.put("discovery_method", discoveryMethod);
            map.put("probe", probe.toMap(includeRaw));
            map.put("fingerprint", fingerprint.toMap());
            map.put("cve_correlation", cve.toMap());

            map.put("product", fingerprint.product);
            map.put("version", fingerprint.version);
            map.put("service", fingerprint.service);
            map.put("protocol", fingerprint.protocol);
            map.put("confidence", fingerprint.confidence);
            map.put("cve_count", cve.matches.size());
            map.put("priority", cve.priority);
            map.put("risk_score", cve.riskScore);
            map.put("category", cve.category);
            return map;
        }
    }

    private static final class HostFusionRecord {
        private final String host;
        private String dnsName = "";
        private final List<ServiceAssessment> services = new ArrayList<>();
        private final Set<String> cves = new LinkedHashSet<>();
        private int maxRiskScore;
        private String riskLevel = "low";

        private HostFusionRecord(String host) {
            this.host = host;
        }

        private Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("host", host);
            if (!dnsName.isBlank()) {
                map.put("dns_name", dnsName);
            }

            List<Map<String, Object>> serviceMaps = new ArrayList<>();
            List<String> chain = new ArrayList<>();
            for (ServiceAssessment service : services) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("port", service.port);
                item.put("service", service.fingerprint.service);
                item.put("product", service.fingerprint.product);
                item.put("version", service.fingerprint.version);
                item.put("cves", service.cve.matches.stream().map(match -> match.cveId).toList());
                item.put("priority", service.cve.priority);
                item.put("risk_score", service.cve.riskScore);
                serviceMaps.add(item);

                chain.add(service.port + "/tcp -> " + service.fingerprint.product
                    + (service.fingerprint.version.isBlank() ? "" : " " + service.fingerprint.version)
                    + " -> " + service.cve.priority);
            }

            map.put("services", serviceMaps);
            map.put("chain", chain);
            map.put("cves", new ArrayList<>(cves));
            map.put("host_risk_score", maxRiskScore);
            map.put("host_risk_level", riskLevel);
            return map;
        }
    }

    protected static final class CommandExecutionResult {
        protected final int exitCode;
        protected final String stdout;
        protected final String stderr;
        protected final boolean timedOut;
        protected final long durationMs;

        protected CommandExecutionResult(int exitCode, String stdout, String stderr, boolean timedOut, long durationMs) {
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
            return stdout + "\\n" + stderr;
        }
    }

    private static final class ProductVersion {
        private final String product;
        private final String version;

        private ProductVersion(String product, String version) {
            this.product = product == null ? "" : product;
            this.version = version == null ? "" : version;
        }

        private static ProductVersion empty() {
            return new ProductVersion("", "");
        }
    }

    private static final class SearchsploitEvidence {
        private final int hitCount;
        private final List<String> entries;

        private SearchsploitEvidence(int hitCount, List<String> entries) {
            this.hitCount = hitCount;
            this.entries = entries == null ? List.of() : entries;
        }

        private static SearchsploitEvidence empty() {
            return new SearchsploitEvidence(0, List.of());
        }
    }

    protected static final class ExecutionDiagnostics {
        private int commandExecutions;
        private int probeCount;
        private int minimalProbeCount;
        private int tlsHandshakes;
        private long delayAppliedMs;

        private final Set<String> toolUsage = new LinkedHashSet<>();
        private final List<String> warnings = new ArrayList<>();
        private final List<String> executedCommands = new ArrayList<>();
        private final List<Map<String, Object>> commandLog = new ArrayList<>();
    }

    private static final class CveRule {
        private final String productToken;
        private final String protocol;
        private final String maxAffectedVersion;
        private final String cveId;
        private final Severity severity;
        private final String exploitClass;
        private final boolean exploitAvailable;
        private final String reference;

        private CveRule(
                String productToken,
                String protocol,
                String maxAffectedVersion,
                String cveId,
                Severity severity,
                String exploitClass,
                boolean exploitAvailable,
                String reference) {
            this.productToken = productToken;
            this.protocol = protocol;
            this.maxAffectedVersion = maxAffectedVersion;
            this.cveId = cveId;
            this.severity = severity;
            this.exploitClass = exploitClass;
            this.exploitAvailable = exploitAvailable;
            this.reference = reference;
        }

        private boolean matches(NormalizedFingerprint fingerprint) {
            if (fingerprint == null || fingerprint.product == null) {
                return false;
            }

            String product = fingerprint.product.toLowerCase(Locale.ROOT);
            if (!product.contains(productToken)) {
                return false;
            }

            if (!"any".equals(protocol)) {
                String service = fingerprint.protocol == null || fingerprint.protocol.isBlank()
                    ? String.valueOf(fingerprint.service)
                    : String.valueOf(fingerprint.protocol);
                service = service.toLowerCase(Locale.ROOT);
                if (!service.contains(protocol)) {
                    return false;
                }
            }

            if (fingerprint.version == null || fingerprint.version.isBlank()) {
                return false;
            }

            return BannerGrabberModule.compareVersions(fingerprint.version, maxAffectedVersion) <= 0;
        }
    }

    private enum Severity {
        CRITICAL("critical", 92),
        HIGH("high", 78),
        MEDIUM("medium", 56),
        LOW("low", 34);

        private final String value;
        private final int score;

        Severity(String value, int score) {
            this.value = value;
            this.score = score;
        }
    }
}