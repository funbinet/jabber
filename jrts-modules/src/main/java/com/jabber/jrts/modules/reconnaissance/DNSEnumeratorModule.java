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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

@JRTSModule(
    id = "gen-dnsenumerator",
    name = "DNS Enumerator",
    description = "Enumerate DNS namespace relationships with forward records, reverse PTR mappings, subdomain discovery, and optional AXFR checks.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.MEDIUM,
    sourceRef = "dig/nslookup/dnsrecon/amass",
    author = "JRTS"
)
public class DNSEnumeratorModule implements JRTSModuleInterface {

    private static final String MODULE_ID = "gen-dnsenumerator";

    private static final int DEFAULT_TIMEOUT_MS = 2500;
    private static final int DEFAULT_MAX_SUBDOMAINS = 512;
    private static final int DEFAULT_MAX_REVERSE_TARGETS = 256;

    private static final String DEFAULT_SUBDOMAIN_WORDLIST =
        "www,mail,api,dev,test,staging,admin,portal,vpn,ns1,ns2,mx,autodiscover";

    private static final Pattern IPV4_PATTERN = Pattern.compile("^(?:\\d{1,3}\\.){3}\\d{1,3}$");
    private static final Pattern NSLOOKUP_IP_PATTERN = Pattern.compile("Address:\\s*((?:\\d{1,3}\\.){3}\\d{1,3})");

    private final Map<String, Boolean> commandAvailabilityCache = new ConcurrentHashMap<>();

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of(
                    "namespace_map",
                    "forward_lookup",
                    "reverse_lookup",
                    "subdomain_discovery",
                    "zone_transfer",
                    "record_enumeration"
                ))
                .required()
                .defaultValue("namespace_map")
                .group("Mode")
                .helpText("Comprehensive namespace map or targeted forward/reverse/subdomain/AXFR/record modes."),

            ModuleInputField.text("domain", "Target Domain")
                .placeholder("example.com")
                .group("Target")
                .modes("namespace_map", "forward_lookup", "subdomain_discovery", "zone_transfer", "record_enumeration")
                .helpText("Primary target DNS domain."),
            ModuleInputField.text("reverse_targets", "Reverse Targets (CSV IPs)")
                .placeholder("192.168.1.10,192.168.1.11")
                .group("Target")
                .modes("namespace_map", "reverse_lookup")
                .helpText("Comma-separated IPv4 addresses for PTR lookups."),
            ModuleInputField.text("dns_server", "DNS Server")
                .placeholder("8.8.8.8")
                .group("Target")
                .helpText("Optional DNS resolver override used by JNDI and dig.")
                .build(),

            ModuleInputField.text("timeout_ms", "DNS Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_TIMEOUT_MS))
                .group("Execution")
                .build(),
            ModuleInputField.checkbox("include_ipv6", "Include AAAA Queries")
                .defaultValue("true")
                .group("Execution")
                .build(),
            ModuleInputField.checkbox("include_txt", "Include TXT Queries")
                .defaultValue("true")
                .group("Execution")
                .modes("namespace_map", "record_enumeration")
                .build(),
            ModuleInputField.text("max_subdomains", "Maximum Subdomains")
                .placeholder(String.valueOf(DEFAULT_MAX_SUBDOMAINS))
                .group("Execution")
                .modes("namespace_map", "subdomain_discovery")
                .build(),
            ModuleInputField.text("max_reverse_targets", "Maximum Reverse Targets")
                .placeholder(String.valueOf(DEFAULT_MAX_REVERSE_TARGETS))
                .group("Execution")
                .modes("namespace_map", "reverse_lookup")
                .build(),

            ModuleInputField.checkbox("enable_subdomain_bruteforce", "Enable Subdomain Brute-force")
                .defaultValue("true")
                .group("Subdomain Discovery")
                .modes("namespace_map", "subdomain_discovery")
                .build(),
            ModuleInputField.checkbox("include_common_subdomains", "Include Common Subdomain List")
                .defaultValue("true")
                .group("Subdomain Discovery")
                .modes("namespace_map", "subdomain_discovery")
                .build(),
            ModuleInputField.text("subdomain_wordlist", "Subdomain Wordlist (CSV or newline)")
                .placeholder(DEFAULT_SUBDOMAIN_WORDLIST)
                .group("Subdomain Discovery")
                .modes("namespace_map", "subdomain_discovery")
                .helpText("Inline labels or FQDN values used for brute-force discovery.")
                .build(),
            ModuleInputField.checkbox("use_osint_tools", "Use OSINT Enumeration Tools")
                .defaultValue("false")
                .group("Subdomain Discovery")
                .modes("namespace_map", "subdomain_discovery")
                .helpText("Attempts amass/sublist3r/dnsrecon/dnsenum when available.")
                .build(),
            ModuleInputField.checkbox("include_unresolved_candidates", "Include Unresolved Candidates")
                .defaultValue("false")
                .group("Subdomain Discovery")
                .modes("namespace_map", "subdomain_discovery")
                .build(),

            ModuleInputField.checkbox("attempt_zone_transfer", "Attempt Zone Transfer")
                .defaultValue("true")
                .group("Zone Transfer")
                .modes("namespace_map", "zone_transfer")
                .helpText("Attempts AXFR against discovered/provided nameservers.")
                .build(),
            ModuleInputField.text("nameservers", "Nameserver Overrides (CSV)")
                .placeholder("ns1.example.com,ns2.example.com")
                .group("Zone Transfer")
                .modes("namespace_map", "zone_transfer")
                .build(),

            ModuleInputField.checkbox("use_dig", "Use dig Fallback")
                .defaultValue("true")
                .group("Tooling")
                .build(),
            ModuleInputField.checkbox("use_nslookup", "Use nslookup Fallback")
                .defaultValue("true")
                .group("Tooling")
                .build()
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), MODULE_ID);

            try {
                long startedAt = System.currentTimeMillis();
                ctx.log("[*] Starting DNS Enumerator module");
                ctx.reportProgress(5);

                ModuleConfig config = parseConfig(input);
                List<String> validationErrors = validateConfig(config);
                if (!validationErrors.isEmpty()) {
                    String message = String.join("; ", validationErrors);
                    result.fail("Validation failed: " + message);
                    ctx.log("[!] Validation failed: " + message);
                    return result;
                }

                ctx.log("[*] Mode: " + config.mode.value);
                ctx.log("[*] Domain: " + config.domain);
                ctx.reportProgress(20);

                ExecutionDiagnostics diagnostics = new ExecutionDiagnostics();
                EnumerationBundle bundle = new EnumerationBundle(config.domain);

                switch (config.mode) {
                    case FORWARD_LOOKUP -> enumerateForward(config, bundle, diagnostics, ctx);
                    case REVERSE_LOOKUP -> enumerateReverse(config, bundle, diagnostics, ctx);
                    case SUBDOMAIN_DISCOVERY -> enumerateSubdomains(config, bundle, diagnostics, ctx);
                    case ZONE_TRANSFER -> enumerateZoneTransfer(config, bundle, diagnostics, ctx);
                    case RECORD_ENUMERATION -> enumerateRecords(config, bundle, diagnostics, ctx);
                    case NAMESPACE_MAP -> enumerateNamespaceMap(config, bundle, diagnostics, ctx);
                }

                List<Map<String, Object>> findings = bundle.records.stream()
                    .map(this::toFinding)
                    .toList();

                for (Map<String, Object> finding : findings) {
                    result.addFinding(finding);
                }

                Map<String, Object> summary = buildSummary(bundle, config);

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
                output.put("target_domain", config.domain);
                output.put("summary", summary);
                output.put("dns_records", findings);
                output.put("namespace_map", buildNamespaceMap(bundle));
                output.put(config.mode.resultKey, buildModeResult(bundle, config));
                output.put("operational_stack", buildOperationalStack());
                output.put("execution_metadata", buildExecutionMetadata(config, diagnostics, startedAt));

                result.setNormalizedOutput(buildNormalizedOutput(summary, findings, config, bundle));
                result.complete(output);

                ctx.log("[+] DNS enumeration completed with " + findings.size() + " record(s)");
                ctx.reportProgress(100);
            } catch (Exception e) {
                result.fail("DNS enumeration failed: " + e.getMessage());
                ctx.log("[!] ERROR: " + e.getMessage());
            }

            return result;
        });
    }

    protected List<String> queryRecordValues(String query, String type, ModuleConfig config) {
        DirContext dns = null;
        try {
            dns = openDnsContext(config);
            Attributes attrs = dns.getAttributes(query, new String[] {type});
            Attribute attr = attrs.get(type);
            if (attr == null || attr.size() == 0) {
                return List.of();
            }

            List<String> values = new ArrayList<>();
            for (int i = 0; i < attr.size(); i++) {
                Object raw = attr.get(i);
                if (raw != null) {
                    String normalized = normalizeRecordValue(type, String.valueOf(raw));
                    if (!normalized.isBlank()) {
                        values.add(normalized);
                    }
                }
            }
            return values;
        } catch (Exception ignored) {
            return List.of();
        } finally {
            if (dns != null) {
                try {
                    dns.close();
                } catch (Exception ignored) {
                    // no-op
                }
            }
        }
    }

    protected DirContext openDnsContext(ModuleConfig config) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");

        String dnsServer = trim(config.dnsServer);
        if (!dnsServer.isBlank()) {
            String provider = dnsServer.startsWith("dns://") ? dnsServer : "dns://" + dnsServer;
            if (!provider.endsWith("/")) {
                provider = provider + "/";
            }
            env.put(Context.PROVIDER_URL, provider);
        }

        env.put("com.sun.jndi.dns.timeout.initial", String.valueOf(Math.max(500, config.timeoutMs)));
        env.put("com.sun.jndi.dns.timeout.retries", "1");
        return new InitialDirContext(env);
    }

    protected boolean isCommandAvailable(String command) {
        return commandAvailabilityCache.computeIfAbsent(command, cmd -> {
            List<String> checkCommand = isWindows() ? List.of("where", cmd) : List.of("which", cmd);
            CommandExecutionResult result = runCommand(checkCommand, 2_000L);
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
                return new CommandExecutionResult(
                    -1,
                    stdout.toString(),
                    stderr.toString(),
                    true,
                    System.currentTimeMillis() - startedAt
                );
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

    private void enumerateNamespaceMap(
            ModuleConfig config,
            EnumerationBundle bundle,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx) {

        enumerateRecords(config, bundle, diagnostics, ctx);
        enumerateSubdomains(config, bundle, diagnostics, ctx);

        if (config.attemptZoneTransfer) {
            enumerateZoneTransfer(config, bundle, diagnostics, ctx);
        }

        List<String> reverseTargets = new ArrayList<>();
        reverseTargets.addAll(config.reverseTargets);
        if (reverseTargets.isEmpty()) {
            reverseTargets.addAll(bundle.resolvedIpv4);
        }
        if (reverseTargets.size() > config.maxReverseTargets) {
            reverseTargets = reverseTargets.subList(0, config.maxReverseTargets);
        }

        if (!reverseTargets.isEmpty()) {
            enumerateReverseTargets(reverseTargets, config, bundle, diagnostics);
            ctx.log("[*] Reverse PTR mappings attempted for " + reverseTargets.size() + " IP(s)");
        }
    }

    private void enumerateForward(
            ModuleConfig config,
            EnumerationBundle bundle,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx) {

        List<String> types = new ArrayList<>(List.of("A", "CNAME"));
        if (config.includeIpv6) {
            types.add("AAAA");
        }

        queryAndAddRecords(config.domain, config.domain, types, "forward_lookup", config, bundle, diagnostics);
        ctx.log("[*] Forward lookup completed for " + config.domain);
    }

    private void enumerateRecords(
            ModuleConfig config,
            EnumerationBundle bundle,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx) {

        List<String> types = new ArrayList<>(List.of("A", "MX", "NS", "CNAME"));
        if (config.includeIpv6) {
            types.add("AAAA");
        }
        if (config.includeTxt) {
            types.add("TXT");
        }

        queryAndAddRecords(config.domain, config.domain, types, "record_enumeration", config, bundle, diagnostics);
        ctx.log("[*] Record enumeration completed for " + config.domain);
    }

    private void enumerateReverse(
            ModuleConfig config,
            EnumerationBundle bundle,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx) {

        enumerateReverseTargets(config.reverseTargets, config, bundle, diagnostics);
        ctx.log("[*] Reverse lookup completed for " + config.reverseTargets.size() + " target(s)");
    }

    private void enumerateReverseTargets(
            List<String> reverseTargets,
            ModuleConfig config,
            EnumerationBundle bundle,
            ExecutionDiagnostics diagnostics) {

        for (String ip : reverseTargets) {
            String target = trim(ip);
            if (!isIpv4(target)) {
                continue;
            }

            List<String> ptrValues = resolveDnsValues(toPtrQuery(target), "PTR", config, diagnostics, true, target);
            for (String ptr : ptrValues) {
                addRecord(bundle, "PTR", target, stripTrailingDot(ptr), "PTR_LOOKUP", false);
            }
        }
    }

    private void enumerateSubdomains(
            ModuleConfig config,
            EnumerationBundle bundle,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx) {

        if (!config.enableSubdomainBruteforce && !config.useOsintTools) {
            return;
        }

        Set<String> candidates = new LinkedHashSet<>();

        if (config.enableSubdomainBruteforce) {
            if (config.includeCommonSubdomains) {
                candidates.addAll(parseSubdomainWordlist(DEFAULT_SUBDOMAIN_WORDLIST, config.domain));
            }
            candidates.addAll(parseSubdomainWordlist(config.subdomainWordlist, config.domain));
        }

        if (config.useOsintTools) {
            candidates.addAll(discoverSubdomainsFromTools(config, diagnostics));
        }

        if (candidates.size() > config.maxSubdomains) {
            List<String> capped = new ArrayList<>(candidates).subList(0, config.maxSubdomains);
            candidates = new LinkedHashSet<>(capped);
        }

        for (String fqdn : candidates) {
            List<String> types = new ArrayList<>(List.of("A", "CNAME"));
            if (config.includeIpv6) {
                types.add("AAAA");
            }

            int before = bundle.records.size();
            queryAndAddRecords(fqdn, fqdn, types, "subdomain_discovery", config, bundle, diagnostics);
            int after = bundle.records.size();

            if (after > before) {
                bundle.discoveredSubdomains.add(fqdn);
            } else {
                bundle.unresolvedSubdomainCandidates++;
                if (config.includeUnresolvedCandidates) {
                    addRecord(bundle, "CANDIDATE", fqdn, "unresolved", "subdomain_bruteforce", false);
                }
            }
        }

        ctx.log("[*] Subdomain discovery identified " + bundle.discoveredSubdomains.size() + " resolvable subdomain(s)");
    }

    private void enumerateZoneTransfer(
            ModuleConfig config,
            EnumerationBundle bundle,
            ExecutionDiagnostics diagnostics,
            TaskContext ctx) {

        if (!config.attemptZoneTransfer) {
            return;
        }

        Set<String> nameservers = new LinkedHashSet<>(config.nameservers);
        if (nameservers.isEmpty()) {
            List<String> nsFromDns = resolveDnsValues(config.domain, "NS", config, diagnostics, true, null);
            for (String ns : nsFromDns) {
                if (!ns.isBlank()) {
                    nameservers.add(stripTrailingDot(ns));
                }
            }
        }

        if (nameservers.isEmpty()) {
            diagnostics.warnings.add("No nameservers available for zone transfer attempts");
            return;
        }

        for (String ns : nameservers) {
            ZoneTransferAttempt attempt = tryAxfr(ns, config, diagnostics);
            bundle.zoneTransferAttempts.add(attempt);

            if (attempt.success) {
                for (DnsRecord record : attempt.records) {
                    addRecord(bundle, record.type, record.name, record.value, record.source, true);
                }
            }
        }

        long successful = bundle.zoneTransferAttempts.stream().filter(a -> a.success).count();
        ctx.log("[*] Zone transfer attempts complete: " + successful + " successful");
    }

    private ZoneTransferAttempt tryAxfr(String nameserver, ModuleConfig config, ExecutionDiagnostics diagnostics) {
        ZoneTransferAttempt attempt = new ZoneTransferAttempt();
        attempt.nameserver = nameserver;

        if (!config.useDig || !isCommandAvailable("dig")) {
            attempt.success = false;
            attempt.error = "dig unavailable for AXFR attempt";
            return attempt;
        }

        List<String> command = List.of("dig", "axfr", "@" + nameserver, config.domain);
        CommandExecutionResult commandResult = runCommand(command, Math.max(6_000L, config.timeoutMs * 6L));

        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("dig");
        diagnostics.executedCommands.add(String.join(" ", command));

        if (commandResult.timedOut) {
            attempt.success = false;
            attempt.error = "axfr_timed_out";
            return attempt;
        }

        String output = commandResult.combinedOutput();
        if (output.toLowerCase(Locale.ROOT).contains("transfer failed")
                || output.toLowerCase(Locale.ROOT).contains("refused")
                || output.toLowerCase(Locale.ROOT).contains("denied")) {
            attempt.success = false;
            attempt.error = firstLine(output);
            return attempt;
        }

        List<DnsRecord> records = parseAxfrRecords(output, nameserver);
        attempt.records.addAll(records);
        attempt.success = !records.isEmpty();
        if (!attempt.success) {
            attempt.error = commandResult.exitCode == 0 ? "no_records_transferred" : "axfr_failed";
        }

        return attempt;
    }

    private List<DnsRecord> parseAxfrRecords(String output, String nameserver) {
        List<DnsRecord> parsed = new ArrayList<>();
        if (output == null || output.isBlank()) {
            return parsed;
        }

        for (String rawLine : output.split("\\R")) {
            String line = trim(rawLine);
            if (line.isBlank() || line.startsWith(";")) {
                continue;
            }

            String[] tokens = line.split("\\s+");
            if (tokens.length < 5) {
                continue;
            }
            if (!"IN".equalsIgnoreCase(tokens[2])) {
                continue;
            }

            String name = stripTrailingDot(tokens[0]);
            String type = tokens[3].toUpperCase(Locale.ROOT);
            StringBuilder value = new StringBuilder();
            for (int i = 4; i < tokens.length; i++) {
                if (i > 4) {
                    value.append(' ');
                }
                value.append(tokens[i]);
            }

            DnsRecord record = new DnsRecord();
            record.type = type;
            record.name = name;
            record.value = normalizeRecordValue(type, value.toString());
            record.source = "AXFR@" + nameserver;
            record.authoritative = true;

            if (!record.value.isBlank()) {
                parsed.add(record);
            }
        }

        return parsed;
    }

    private void queryAndAddRecords(
            String queryName,
            String displayName,
            List<String> recordTypes,
            String source,
            ModuleConfig config,
            EnumerationBundle bundle,
            ExecutionDiagnostics diagnostics) {

        for (String type : recordTypes) {
            List<String> values = resolveDnsValues(queryName, type, config, diagnostics, true, null);
            for (String value : values) {
                addRecord(bundle, type, displayName, value, source, false);
            }
        }
    }

    private List<String> resolveDnsValues(
            String query,
            String type,
            ModuleConfig config,
            ExecutionDiagnostics diagnostics,
            boolean allowNslookupFallback,
            String reverseIpForDig) {

        List<String> values = queryRecordValues(query, type, config);
        if (!values.isEmpty()) {
            return values;
        }

        if (config.useDig && isCommandAvailable("dig")) {
            List<String> digValues = queryWithDig(query, type, config, diagnostics, reverseIpForDig);
            if (!digValues.isEmpty()) {
                return digValues;
            }
        }

        if (allowNslookupFallback && "A".equals(type) && config.useNslookup && isCommandAvailable("nslookup")) {
            return queryWithNslookup(query, config, diagnostics);
        }

        return List.of();
    }

    private List<String> queryWithDig(
            String query,
            String type,
            ModuleConfig config,
            ExecutionDiagnostics diagnostics,
            String reverseIpForDig) {

        List<String> command = new ArrayList<>();
        command.add("dig");
        command.add("+short");
        if (!config.dnsServer.isBlank()) {
            command.add("@" + config.dnsServer);
        }

        if ("PTR".equals(type) && reverseIpForDig != null && !reverseIpForDig.isBlank()) {
            command.add("-x");
            command.add(reverseIpForDig);
        } else {
            command.add(query);
            command.add(type);
        }

        CommandExecutionResult result = runCommand(command, Math.max(3_000L, config.timeoutMs * 3L));
        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("dig");
        diagnostics.executedCommands.add(String.join(" ", command));

        if (result.timedOut) {
            diagnostics.warnings.add("dig query timed out for " + query + " " + type);
            return List.of();
        }

        List<String> values = new ArrayList<>();
        for (String rawLine : result.stdout.split("\\R")) {
            String value = normalizeRecordValue(type, rawLine);
            if (!value.isBlank()) {
                values.add(value);
            }
        }
        return values;
    }

    private List<String> queryWithNslookup(String query, ModuleConfig config, ExecutionDiagnostics diagnostics) {
        List<String> command = new ArrayList<>(List.of("nslookup", query));
        if (!config.dnsServer.isBlank()) {
            command.add(config.dnsServer);
        }

        CommandExecutionResult result = runCommand(command, Math.max(3_000L, config.timeoutMs * 3L));
        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("nslookup");
        diagnostics.executedCommands.add(String.join(" ", command));

        if (result.timedOut) {
            diagnostics.warnings.add("nslookup timed out for " + query);
            return List.of();
        }

        Set<String> ips = new LinkedHashSet<>();
        Matcher matcher = NSLOOKUP_IP_PATTERN.matcher(result.combinedOutput());
        while (matcher.find()) {
            String ip = trim(matcher.group(1));
            if (isIpv4(ip)) {
                ips.add(ip);
            }
        }

        return new ArrayList<>(ips);
    }

    private Set<String> discoverSubdomainsFromTools(ModuleConfig config, ExecutionDiagnostics diagnostics) {
        Set<String> discovered = new LinkedHashSet<>();
        String domain = config.domain.toLowerCase(Locale.ROOT);

        if (isCommandAvailable("amass")) {
            List<String> command = List.of("amass", "enum", "-passive", "-d", domain);
            discovered.addAll(executeSubdomainTool(command, domain, "amass", config.timeoutMs, diagnostics));
        }

        if (isCommandAvailable("sublist3r")) {
            List<String> command = List.of("sublist3r", "-d", domain);
            discovered.addAll(executeSubdomainTool(command, domain, "sublist3r", config.timeoutMs, diagnostics));
        }

        if (isCommandAvailable("dnsrecon")) {
            List<String> command = List.of("dnsrecon", "-d", domain, "-t", "std");
            discovered.addAll(executeSubdomainTool(command, domain, "dnsrecon", config.timeoutMs, diagnostics));
        }

        if (isCommandAvailable("dnsenum")) {
            List<String> command = List.of("dnsenum", domain);
            discovered.addAll(executeSubdomainTool(command, domain, "dnsenum", config.timeoutMs, diagnostics));
        }

        return discovered;
    }

    private Set<String> executeSubdomainTool(
            List<String> command,
            String domain,
            String toolName,
            int timeoutMs,
            ExecutionDiagnostics diagnostics) {

        CommandExecutionResult result = runCommand(command, Math.max(6_000L, timeoutMs * 8L));
        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add(toolName);
        diagnostics.executedCommands.add(String.join(" ", command));

        if (result.timedOut) {
            diagnostics.warnings.add(toolName + " timed out during subdomain discovery");
            return Set.of();
        }

        return parseDomainMentions(result.combinedOutput(), domain);
    }

    private Set<String> parseDomainMentions(String text, String domain) {
        Set<String> found = new LinkedHashSet<>();
        if (text == null || text.isBlank()) {
            return found;
        }

        String escapedDomain = Pattern.quote(domain);
        Pattern pattern = Pattern.compile("([a-zA-Z0-9][a-zA-Z0-9._-]*\\." + escapedDomain + ")", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            String candidate = matcher.group(1).toLowerCase(Locale.ROOT);
            if (candidate.endsWith("." + domain) || candidate.equals(domain)) {
                found.add(stripTrailingDot(candidate));
            }
        }

        return found;
    }

    private Set<String> parseSubdomainWordlist(String wordlist, String domain) {
        Set<String> subdomains = new LinkedHashSet<>();
        String raw = trim(wordlist);
        if (raw.isBlank()) {
            return subdomains;
        }

        for (String token : raw.split("[\\n,\\r\\t ]+")) {
            String value = trim(token).toLowerCase(Locale.ROOT);
            if (value.isBlank()) {
                continue;
            }

            if (value.endsWith("." + domain) || value.equals(domain)) {
                subdomains.add(stripTrailingDot(value));
                continue;
            }

            if (value.contains(".")) {
                continue;
            }

            subdomains.add(value + "." + domain);
        }

        return subdomains;
    }

    private Map<String, Object> buildSummary(EnumerationBundle bundle, ModuleConfig config) {
        long aCount = bundle.records.stream().filter(r -> "A".equals(r.type)).count();
        long aaaaCount = bundle.records.stream().filter(r -> "AAAA".equals(r.type)).count();
        long mxCount = bundle.records.stream().filter(r -> "MX".equals(r.type)).count();
        long nsCount = bundle.records.stream().filter(r -> "NS".equals(r.type)).count();
        long cnameCount = bundle.records.stream().filter(r -> "CNAME".equals(r.type)).count();
        long txtCount = bundle.records.stream().filter(r -> "TXT".equals(r.type)).count();
        long ptrCount = bundle.records.stream().filter(r -> "PTR".equals(r.type)).count();
        long axfrRecords = bundle.records.stream().filter(r -> r.source.startsWith("AXFR@")).count();
        long zoneSuccess = bundle.zoneTransferAttempts.stream().filter(attempt -> attempt.success).count();

        Set<String> uniqueHosts = new HashSet<>();
        for (DnsRecord record : bundle.records) {
            uniqueHosts.add(record.name);
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", config.mode.value);
        summary.put("total_records", bundle.records.size());
        summary.put("unique_host_count", uniqueHosts.size());
        summary.put("a_count", aCount);
        summary.put("aaaa_count", aaaaCount);
        summary.put("mx_count", mxCount);
        summary.put("ns_count", nsCount);
        summary.put("cname_count", cnameCount);
        summary.put("txt_count", txtCount);
        summary.put("ptr_count", ptrCount);
        summary.put("subdomain_count", bundle.discoveredSubdomains.size());
        summary.put("unresolved_subdomain_candidates", bundle.unresolvedSubdomainCandidates);
        summary.put("zone_transfer_attempts", bundle.zoneTransferAttempts.size());
        summary.put("zone_transfer_success_count", zoneSuccess);
        summary.put("zone_transfer_record_count", axfrRecords);
        return summary;
    }

    private Map<String, Object> buildNamespaceMap(EnumerationBundle bundle) {
        Map<String, Set<String>> hostToIps = new LinkedHashMap<>();
        Map<String, Set<String>> ipToHosts = new LinkedHashMap<>();

        for (DnsRecord record : bundle.records) {
            if ("A".equals(record.type) || "AAAA".equals(record.type)) {
                hostToIps.computeIfAbsent(record.name, ignored -> new LinkedHashSet<>()).add(record.value);
                ipToHosts.computeIfAbsent(record.value, ignored -> new LinkedHashSet<>()).add(record.name);
            }
            if ("PTR".equals(record.type)) {
                ipToHosts.computeIfAbsent(record.name, ignored -> new LinkedHashSet<>()).add(record.value);
                hostToIps.computeIfAbsent(record.value, ignored -> new LinkedHashSet<>()).add(record.name);
            }
        }

        Map<String, Object> map = new LinkedHashMap<>();
        map.put("domain", bundle.domain);
        map.put("subdomains", bundle.discoveredSubdomains.stream().sorted().toList());
        map.put("host_to_ips", toSortedMap(hostToIps));
        map.put("ip_to_hosts", toSortedMap(ipToHosts));
        map.put("mx_hosts", recordsByType(bundle, "MX").stream().map(r -> r.value).distinct().sorted().toList());
        map.put("ns_hosts", recordsByType(bundle, "NS").stream().map(r -> r.value).distinct().sorted().toList());
        return map;
    }

    private Map<String, List<String>> toSortedMap(Map<String, Set<String>> source) {
        Map<String, List<String>> sorted = new LinkedHashMap<>();
        source.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .forEach(entry -> sorted.put(entry.getKey(), entry.getValue().stream().sorted().toList()));
        return sorted;
    }

    private Map<String, Object> buildModeResult(EnumerationBundle bundle, ModuleConfig config) {
        return switch (config.mode) {
            case FORWARD_LOOKUP -> buildForwardResult(bundle, config);
            case REVERSE_LOOKUP -> buildReverseResult(bundle, config);
            case SUBDOMAIN_DISCOVERY -> buildSubdomainResult(bundle, config);
            case ZONE_TRANSFER -> buildZoneTransferResult(bundle, config);
            case RECORD_ENUMERATION -> buildRecordEnumerationResult(bundle, config);
            case NAMESPACE_MAP -> buildNamespaceMapResult(bundle, config);
        };
    }

    private Map<String, Object> buildForwardResult(EnumerationBundle bundle, ModuleConfig config) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("domain", config.domain);
        result.put("a_records", valuesByType(bundle, "A"));
        result.put("aaaa_records", valuesByType(bundle, "AAAA"));
        result.put("cname_records", valuesByType(bundle, "CNAME"));
        return result;
    }

    private Map<String, Object> buildReverseResult(EnumerationBundle bundle, ModuleConfig config) {
        List<Map<String, Object>> mappings = recordsByType(bundle, "PTR").stream()
            .map(record -> {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("ip", record.name);
                row.put("hostname", record.value);
                return row;
            })
            .toList();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("requested_targets", config.reverseTargets);
        result.put("reverse_mappings", mappings);
        result.put("resolved_count", mappings.size());
        return result;
    }

    private Map<String, Object> buildSubdomainResult(EnumerationBundle bundle, ModuleConfig config) {
        List<Map<String, Object>> hosts = new ArrayList<>();
        for (String subdomain : bundle.discoveredSubdomains.stream().sorted().toList()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("subdomain", subdomain);
            row.put("a", valuesByNameAndType(bundle, subdomain, "A"));
            row.put("aaaa", valuesByNameAndType(bundle, subdomain, "AAAA"));
            row.put("cname", valuesByNameAndType(bundle, subdomain, "CNAME"));
            hosts.add(row);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("domain", config.domain);
        result.put("discovered_subdomain_count", bundle.discoveredSubdomains.size());
        result.put("subdomains", hosts);
        result.put("unresolved_candidates", bundle.unresolvedSubdomainCandidates);
        return result;
    }

    private Map<String, Object> buildZoneTransferResult(EnumerationBundle bundle, ModuleConfig config) {
        List<Map<String, Object>> attempts = new ArrayList<>();
        for (ZoneTransferAttempt attempt : bundle.zoneTransferAttempts) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("nameserver", attempt.nameserver);
            row.put("success", attempt.success);
            row.put("record_count", attempt.records.size());
            row.put("error", attempt.error);
            attempts.add(row);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("domain", config.domain);
        result.put("attempts", attempts);
        result.put("transferred_records", bundle.records.stream()
            .filter(record -> record.source.startsWith("AXFR@"))
            .map(this::toFinding)
            .toList());
        return result;
    }

    private Map<String, Object> buildRecordEnumerationResult(EnumerationBundle bundle, ModuleConfig config) {
        Map<String, List<String>> grouped = new LinkedHashMap<>();
        for (String type : List.of("A", "AAAA", "MX", "NS", "CNAME", "TXT")) {
            grouped.put(type, valuesByType(bundle, type));
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("domain", config.domain);
        result.put("record_groups", grouped);
        return result;
    }

    private Map<String, Object> buildNamespaceMapResult(EnumerationBundle bundle, ModuleConfig config) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("domain", config.domain);
        result.put("namespace_map", buildNamespaceMap(bundle));
        result.put("zone_transfer_succeeded", bundle.zoneTransferAttempts.stream().anyMatch(attempt -> attempt.success));
        return result;
    }

    private List<String> valuesByType(EnumerationBundle bundle, String type) {
        return recordsByType(bundle, type).stream()
            .map(record -> record.value)
            .distinct()
            .sorted()
            .toList();
    }

    private List<String> valuesByNameAndType(EnumerationBundle bundle, String name, String type) {
        return bundle.records.stream()
            .filter(record -> record.name.equalsIgnoreCase(name))
            .filter(record -> record.type.equalsIgnoreCase(type))
            .map(record -> record.value)
            .distinct()
            .sorted()
            .toList();
    }

    private List<DnsRecord> recordsByType(EnumerationBundle bundle, String type) {
        return bundle.records.stream()
            .filter(record -> record.type.equalsIgnoreCase(type))
            .toList();
    }

    private Map<String, Object> toFinding(DnsRecord record) {
        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("type", record.type);
        finding.put("name", record.name);
        finding.put("value", record.value);
        finding.put("source", record.source);
        finding.put("authoritative", record.authoritative);
        return finding;
    }

    private List<Map<String, Object>> buildOperationalStack() {
        List<Map<String, Object>> stack = new ArrayList<>();
        stack.add(tool("dig", "Primary DNS record, reverse, and AXFR probing", "https://linux.die.net/man/1/dig"));
        stack.add(tool("nslookup", "Fallback DNS query execution", "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nslookup"));
        stack.add(tool("dnsenum", "Domain record and host discovery automation", "https://github.com/fwaeytens/dnsenum"));
        stack.add(tool("dnsrecon", "Comprehensive DNS recon and zone transfer checks", "https://github.com/darkoperator/dnsrecon"));
        stack.add(tool("amass", "OSINT-assisted subdomain discovery", "https://github.com/owasp-amass/amass"));
        stack.add(tool("sublist3r", "Passive subdomain intelligence collection", "https://github.com/aboul3la/Sublist3r"));
        stack.add(tool("RFC 1035", "DNS protocol reference for record semantics", "https://www.rfc-editor.org/rfc/rfc1035"));
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
            ModuleConfig config,
            ExecutionDiagnostics diagnostics,
            long startedAt) {

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("dns_server", config.dnsServer);
        metadata.put("timeout_ms", config.timeoutMs);
        metadata.put("tools_used", new ArrayList<>(diagnostics.toolUsage));
        metadata.put("command_executions", diagnostics.commandExecutions);
        metadata.put("executed_commands", diagnostics.executedCommands);
        metadata.put("warnings", diagnostics.warnings);
        metadata.put("elapsed_ms", System.currentTimeMillis() - startedAt);
        return metadata;
    }

    private Map<String, Object> buildNormalizedOutput(
            Map<String, Object> summary,
            List<Map<String, Object>> findings,
            ModuleConfig config,
            EnumerationBundle bundle) {

        long zoneTransferSuccess = bundle.zoneTransferAttempts.stream().filter(attempt -> attempt.success).count();
        long totalRecords = ((Number) summary.getOrDefault("total_records", 0)).longValue();

        Map<String, Object> rawOutput = new LinkedHashMap<>();
        rawOutput.put("summary", summary);
        rawOutput.put("record_count", findings.size());

        Map<String, Object> parsedOutput = new LinkedHashMap<>();
        parsedOutput.put("status", totalRecords > 0
            ? "DNS_INFRASTRUCTURE_ENUMERATED"
            : "NO_DNS_INFRASTRUCTURE_ENUMERATED");
        parsedOutput.put("vulnerable", zoneTransferSuccess > 0);
        parsedOutput.put("details", summary);
        parsedOutput.put("evidence", findings);

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("module", MODULE_ID);
        metadata.put("mode", config.mode.value);
        metadata.put("domain", config.domain);

        Map<String, Object> normalized = new LinkedHashMap<>();
        normalized.put("raw_output", rawOutput);
        normalized.put("parsed_output", parsedOutput);
        normalized.put("metadata", metadata);
        return normalized;
    }

    private void addRecord(
            EnumerationBundle bundle,
            String type,
            String name,
            String value,
            String source,
            boolean authoritative) {

        String normalizedType = trim(type).toUpperCase(Locale.ROOT);
        String normalizedName = stripTrailingDot(trim(name).toLowerCase(Locale.ROOT));
        String normalizedValue = normalizeRecordValue(normalizedType, value);
        String normalizedSource = trim(source);

        if (normalizedType.isBlank() || normalizedName.isBlank() || normalizedValue.isBlank()) {
            return;
        }

        String key = normalizedType + "|" + normalizedName + "|" + normalizedValue + "|" + normalizedSource;
        if (!bundle.recordKeys.add(key)) {
            return;
        }

        DnsRecord record = new DnsRecord();
        record.type = normalizedType;
        record.name = normalizedName;
        record.value = normalizedValue;
        record.source = normalizedSource;
        record.authoritative = authoritative;
        bundle.records.add(record);

        if (("A".equals(normalizedType) || "AAAA".equals(normalizedType)) && normalizedName.endsWith("." + bundle.domain)) {
            bundle.discoveredSubdomains.add(normalizedName);
        }

        if ("A".equals(normalizedType) && isIpv4(normalizedValue)) {
            bundle.resolvedIpv4.add(normalizedValue);
        }
    }

    private String normalizeRecordValue(String type, String rawValue) {
        String value = trim(rawValue);
        if (value.isBlank()) {
            return "";
        }

        if ("TXT".equalsIgnoreCase(type)) {
            value = value.replace("\"", "").trim();
            return value;
        }

        if ("MX".equalsIgnoreCase(type)) {
            String[] tokens = value.split("\\s+");
            if (tokens.length >= 2) {
                return tokens[0] + " " + stripTrailingDot(tokens[1]);
            }
            return stripTrailingDot(value);
        }

        if ("NS".equalsIgnoreCase(type)
                || "CNAME".equalsIgnoreCase(type)
                || "PTR".equalsIgnoreCase(type)) {
            return stripTrailingDot(value);
        }

        return stripTrailingDot(value);
    }

    private String toPtrQuery(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return "";
        }
        return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ".in-addr.arpa";
    }

    private String stripTrailingDot(String value) {
        String token = trim(value);
        while (token.endsWith(".")) {
            token = token.substring(0, token.length() - 1).trim();
        }
        return token;
    }

    private List<String> validateConfig(ModuleConfig config) {
        List<String> errors = new ArrayList<>();

        if (config.mode != ModuleMode.REVERSE_LOOKUP && config.domain.isBlank()) {
            errors.add("domain is required");
        }

        if (config.mode == ModuleMode.REVERSE_LOOKUP && config.reverseTargets.isEmpty()) {
            errors.add("reverse_targets is required when mode=reverse_lookup");
        }

        if (!config.domain.isBlank() && !looksLikeDomain(config.domain)) {
            errors.add("domain must be a valid DNS domain name");
        }

        for (String ip : config.reverseTargets) {
            if (!isIpv4(ip)) {
                errors.add("reverse_targets contains invalid IPv4 value: " + ip);
            }
        }

        if (config.timeoutMs < 250 || config.timeoutMs > 120_000) {
            errors.add("timeout_ms must be between 250 and 120000");
        }

        if (config.maxSubdomains < 1 || config.maxSubdomains > 100_000) {
            errors.add("max_subdomains must be between 1 and 100000");
        }

        if (config.maxReverseTargets < 1 || config.maxReverseTargets > 20_000) {
            errors.add("max_reverse_targets must be between 1 and 20000");
        }

        return errors;
    }

    private ModuleConfig parseConfig(Map<String, String> input) {
        ModuleConfig config = new ModuleConfig();
        config.mode = ModuleMode.fromInput(firstNonBlank(input.get("mode"), "namespace_map"));

        config.domain = trim(firstNonBlank(input.get("domain"), input.get("target"))).toLowerCase(Locale.ROOT);
        config.reverseTargets = parseCsvIps(firstNonBlank(input.get("reverse_targets"), input.get("target_ip")));
        config.dnsServer = trim(input.get("dns_server"));

        config.timeoutMs = parseInteger(firstNonBlank(input.get("timeout_ms"), input.get("timeout")), DEFAULT_TIMEOUT_MS);
        config.includeIpv6 = parseBoolean(input.get("include_ipv6"), true);
        config.includeTxt = parseBoolean(input.get("include_txt"), true);
        config.maxSubdomains = parseInteger(input.get("max_subdomains"), DEFAULT_MAX_SUBDOMAINS);
        config.maxReverseTargets = parseInteger(input.get("max_reverse_targets"), DEFAULT_MAX_REVERSE_TARGETS);

        config.enableSubdomainBruteforce = parseBoolean(input.get("enable_subdomain_bruteforce"), true);
        config.includeCommonSubdomains = parseBoolean(input.get("include_common_subdomains"), true);
        config.subdomainWordlist = firstNonBlank(input.get("subdomain_wordlist"), DEFAULT_SUBDOMAIN_WORDLIST);
        config.useOsintTools = parseBoolean(input.get("use_osint_tools"), false);
        config.includeUnresolvedCandidates = parseBoolean(input.get("include_unresolved_candidates"), false);

        config.attemptZoneTransfer = parseBoolean(input.get("attempt_zone_transfer"), true);
        config.nameservers = parseCsvHosts(input.get("nameservers"));

        config.useDig = parseBoolean(input.get("use_dig"), true);
        config.useNslookup = parseBoolean(input.get("use_nslookup"), true);
        return config;
    }

    private List<String> parseCsvIps(String csv) {
        List<String> ips = new ArrayList<>();
        for (String token : splitCsv(csv)) {
            String ip = trim(token);
            if (!ip.isBlank()) {
                ips.add(ip);
            }
        }
        return ips;
    }

    private List<String> parseCsvHosts(String csv) {
        List<String> hosts = new ArrayList<>();
        for (String token : splitCsv(csv)) {
            String host = stripTrailingDot(trim(token).toLowerCase(Locale.ROOT));
            if (!host.isBlank()) {
                hosts.add(host);
            }
        }
        return hosts;
    }

    private List<String> splitCsv(String value) {
        String raw = trim(value);
        if (raw.isBlank()) {
            return List.of();
        }

        List<String> values = new ArrayList<>();
        for (String token : raw.split("[\\n,\\r\\t ]+")) {
            String trimmed = trim(token);
            if (!trimmed.isBlank()) {
                values.add(trimmed);
            }
        }
        return values;
    }

    private boolean looksLikeDomain(String value) {
        String domain = trim(value).toLowerCase(Locale.ROOT);
        if (domain.isBlank() || !domain.contains(".")) {
            return false;
        }

        for (String label : domain.split("\\.")) {
            if (label.isBlank()) {
                return false;
            }
            if (!label.matches("[a-z0-9-]{1,63}")) {
                return false;
            }
            if (label.startsWith("-") || label.endsWith("-")) {
                return false;
            }
        }
        return true;
    }

    private boolean isIpv4(String value) {
        String ip = trim(value);
        if (!IPV4_PATTERN.matcher(ip).matches()) {
            return false;
        }

        for (String token : ip.split("\\.")) {
            int octet = Integer.parseInt(token);
            if (octet < 0 || octet > 255) {
                return false;
            }
        }
        return true;
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
        if (thread == null) {
            return;
        }
        try {
            thread.join(timeoutMs);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    private String firstLine(String text) {
        if (text == null || text.isBlank()) {
            return "";
        }
        String[] lines = text.split("\\R");
        return lines.length == 0 ? "" : lines[0].trim();
    }

    private int parseInteger(String value, int defaultValue) {
        String raw = trim(value);
        if (raw.isBlank()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException ignored) {
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

    private static final class DnsRecord {
        private String type = "";
        private String name = "";
        private String value = "";
        private String source = "";
        private boolean authoritative;
    }

    private static final class ZoneTransferAttempt {
        private String nameserver = "";
        private boolean success;
        private String error = "";
        private final List<DnsRecord> records = new ArrayList<>();
    }

    private static final class EnumerationBundle {
        private final String domain;
        private final List<DnsRecord> records = new ArrayList<>();
        private final Set<String> recordKeys = new LinkedHashSet<>();
        private final Set<String> discoveredSubdomains = new LinkedHashSet<>();
        private final Set<String> resolvedIpv4 = new LinkedHashSet<>();
        private final List<ZoneTransferAttempt> zoneTransferAttempts = new ArrayList<>();
        private int unresolvedSubdomainCandidates;

        private EnumerationBundle(String domain) {
            this.domain = domain == null ? "" : domain;
        }
    }

    private static final class ExecutionDiagnostics {
        private final Set<String> toolUsage = new LinkedHashSet<>();
        private final List<String> executedCommands = new ArrayList<>();
        private final List<String> warnings = new ArrayList<>();
        private int commandExecutions;
    }

    protected static final class ModuleConfig {
        private ModuleMode mode = ModuleMode.NAMESPACE_MAP;
        private String domain = "";
        private List<String> reverseTargets = new ArrayList<>();
        private String dnsServer = "";

        private int timeoutMs = DEFAULT_TIMEOUT_MS;
        private boolean includeIpv6 = true;
        private boolean includeTxt = true;
        private int maxSubdomains = DEFAULT_MAX_SUBDOMAINS;
        private int maxReverseTargets = DEFAULT_MAX_REVERSE_TARGETS;

        private boolean enableSubdomainBruteforce = true;
        private boolean includeCommonSubdomains = true;
        private String subdomainWordlist = DEFAULT_SUBDOMAIN_WORDLIST;
        private boolean useOsintTools;
        private boolean includeUnresolvedCandidates;

        private boolean attemptZoneTransfer = true;
        private List<String> nameservers = new ArrayList<>();

        private boolean useDig = true;
        private boolean useNslookup = true;
    }

    protected enum ModuleMode {
        NAMESPACE_MAP("namespace_map", "namespace_map_result"),
        FORWARD_LOOKUP("forward_lookup", "forward_lookup_result"),
        REVERSE_LOOKUP("reverse_lookup", "reverse_lookup_result"),
        SUBDOMAIN_DISCOVERY("subdomain_discovery", "subdomain_discovery_result"),
        ZONE_TRANSFER("zone_transfer", "zone_transfer_result"),
        RECORD_ENUMERATION("record_enumeration", "record_enumeration_result");

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
                case "forward", "forward_lookup", "resolve" -> FORWARD_LOOKUP;
                case "reverse", "reverse_lookup", "ptr_lookup" -> REVERSE_LOOKUP;
                case "subdomain", "subdomain_discovery", "subdomains" -> SUBDOMAIN_DISCOVERY;
                case "zone_transfer", "axfr", "axfr_attempt" -> ZONE_TRANSFER;
                case "record_enumeration", "records", "record_inventory" -> RECORD_ENUMERATION;
                default -> NAMESPACE_MAP;
            };
        }
    }
}
