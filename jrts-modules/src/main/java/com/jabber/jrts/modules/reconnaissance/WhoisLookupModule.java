package com.jabber.jrts.modules.reconnaissance;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.jabber.jrts.data.model.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
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

@JRTSModule(
    id = "gen-whoislookup",
    name = "WHOIS & OSINT Correlator",
    description = "Collect domain/IP registration metadata and correlate public username/email footprint signals for reconnaissance attribution mapping.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.MEDIUM,
    sourceRef = "WHOIS/RDAP/dig/sherlock/holehe/theHarvester/amass",
    author = "JRTS"
)
public class WhoisLookupModule implements JRTSModuleInterface {

    private static final String MODULE_ID = "gen-whoislookup";

    private static final int DEFAULT_TIMEOUT_MS = 12_000;
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 6_000;
    private static final int DEFAULT_MAX_PASSIVE_RECORDS = 200;

    private static final Pattern DOMAIN_PATTERN = Pattern.compile("^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$$");
    private static final Pattern IPV4_PATTERN = Pattern.compile("^(?:\\d{1,3}\\.){3}\\d{1,3}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final Pattern WHOIS_KV_PATTERN = Pattern.compile("^\\s*([A-Za-z0-9_./ -]{2,80})\\s*:\\s*(.+?)\\s*$");
    private static final Pattern SHERLOCK_FOUND_PATTERN = Pattern.compile("^\\[\\+\\]\\s*([^:]+):\\s*(https?://\\S+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SIMPLE_URL_PATTERN = Pattern.compile("https?://\\S+", Pattern.CASE_INSENSITIVE);
    private static final Pattern EMAIL_EXTRACT_PATTERN = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");

    private final Map<String, Boolean> commandAvailabilityCache = new ConcurrentHashMap<>();
    private final HttpClient httpClient = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NORMAL)
        .connectTimeout(Duration.ofSeconds(8))
        .build();

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of(
                    "registration_seed",
                    "infrastructure_attribution",
                    "identity_correlation",
                    "attribution_fusion"
                ))
                .required()
                .defaultValue("registration_seed")
                .group("Mode")
                .helpText("WHOIS/OSINT module-specific modes with distinct execution depth and correlation logic."),

            ModuleInputField.text("query", "Domain/IP Seed")
                .placeholder("example.com or 8.8.8.8")
                .group("Seed")
                .modes("registration_seed", "infrastructure_attribution", "attribution_fusion")
                .helpText("Primary infrastructure seed for WHOIS, RDAP, DNS, and attribution mapping."),
            ModuleInputField.text("username", "Username Seed")
                .placeholder("target_handle")
                .group("Seed")
                .modes("identity_correlation", "attribution_fusion")
                .helpText("Public handle seed for cross-platform presence checks."),
            ModuleInputField.text("email", "Email Seed")
                .placeholder("user@example.com")
                .group("Seed")
                .modes("identity_correlation", "attribution_fusion")
                .helpText("Email seed for service footprint and profile correlation."),
            ModuleInputField.text("org_hint", "Organization Hint")
                .placeholder("Contoso Security")
                .group("Seed")
                .modes("attribution_fusion")
                .helpText("Optional analyst hint used for confidence scoring and graph labeling."),

            ModuleInputField.checkbox("use_whois_cli", "Use WHOIS CLI")
                .defaultValue("true")
                .group("Collection")
                .modes("registration_seed", "infrastructure_attribution", "attribution_fusion"),
            ModuleInputField.checkbox("use_rdap", "Use RDAP")
                .defaultValue("true")
                .group("Collection")
                .modes("registration_seed", "infrastructure_attribution", "attribution_fusion"),
            ModuleInputField.checkbox("use_dns", "Use DNS Enrichment")
                .defaultValue("true")
                .group("Collection")
                .modes("registration_seed", "infrastructure_attribution", "attribution_fusion"),
            ModuleInputField.checkbox("use_asn_lookup", "Use ASN/Provider Correlation")
                .defaultValue("true")
                .group("Collection")
                .modes("infrastructure_attribution", "attribution_fusion"),
            ModuleInputField.checkbox("use_amass", "Use Amass (if installed)")
                .defaultValue("false")
                .group("Collection")
                .modes("infrastructure_attribution", "attribution_fusion"),
            ModuleInputField.checkbox("use_theharvester", "Use theHarvester (if installed)")
                .defaultValue("false")
                .group("Collection")
                .modes("infrastructure_attribution", "attribution_fusion"),
            ModuleInputField.checkbox("use_sherlock", "Use Sherlock (if installed)")
                .defaultValue("true")
                .group("Collection")
                .modes("identity_correlation", "attribution_fusion"),
            ModuleInputField.checkbox("use_holehe", "Use Holehe (if installed)")
                .defaultValue("true")
                .group("Collection")
                .modes("identity_correlation", "attribution_fusion"),
            ModuleInputField.checkbox("use_gravatar", "Use Gravatar Profile Check")
                .defaultValue("true")
                .group("Collection")
                .modes("identity_correlation", "attribution_fusion"),

            ModuleInputField.text("timeout_ms", "Command Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_TIMEOUT_MS))
                .group("Execution"),
            ModuleInputField.text("connect_timeout_ms", "Socket/HTTP Connect Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_CONNECT_TIMEOUT_MS))
                .group("Execution"),
            ModuleInputField.text("max_passive_records", "Max Passive Records")
                .placeholder(String.valueOf(DEFAULT_MAX_PASSIVE_RECORDS))
                .group("Execution")
                .modes("infrastructure_attribution", "attribution_fusion"),

            ModuleInputField.checkbox("include_raw", "Include Raw Tool/API Output")
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
                ctx.log("[*] Starting WHOIS & OSINT Correlator module");
                ctx.reportProgress(5);

                ScanConfig config = parseConfig(input);
                List<String> validationErrors = validateConfig(config);
                if (!validationErrors.isEmpty()) {
                    String message = String.join("; ", validationErrors);
                    result.fail("Validation failed: " + message);
                    ctx.log("[!] Validation failed: " + message);
                    return result;
                }

                SeedSet seeds = buildSeedSet(config);
                ExecutionDiagnostics diagnostics = new ExecutionDiagnostics();
                CorrelationGraph graph = new CorrelationGraph();

                ctx.log("[*] Mode: " + config.mode.value);
                ctx.log("[*] Seeds: " + seeds.toLogString());
                ctx.reportProgress(15);

                Map<String, Object> registrationResult = Map.of();
                Map<String, Object> infrastructureResult = Map.of();
                Map<String, Object> identityResult = Map.of();
                Map<String, Object> fusionResult = Map.of();

                switch (config.mode) {
                    case REGISTRATION_SEED -> {
                        registrationResult = collectRegistrationSeed(config, seeds, diagnostics, graph, ctx);
                        ctx.reportProgress(85);
                    }
                    case INFRASTRUCTURE_ATTRIBUTION -> {
                        infrastructureResult = collectInfrastructureAttribution(config, seeds, diagnostics, graph, ctx);
                        ctx.reportProgress(85);
                    }
                    case IDENTITY_CORRELATION -> {
                        identityResult = collectIdentityCorrelation(config, seeds, diagnostics, graph, ctx);
                        ctx.reportProgress(85);
                    }
                    case ATTRIBUTION_FUSION -> {
                        fusionResult = collectAttributionFusion(config, seeds, diagnostics, graph, ctx);
                        ctx.reportProgress(85);
                    }
                }

                Map<String, Object> summary = buildSummary(config, registrationResult, infrastructureResult, identityResult, fusionResult, graph, diagnostics);
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
                output.put("seeds", seeds.toMap());
                output.put("summary", summary);
                output.put("graph", graph.toMap());

                if (!registrationResult.isEmpty()) {
                    output.put("registration_seed_result", registrationResult);
                }
                if (!infrastructureResult.isEmpty()) {
                    output.put("infrastructure_attribution_result", infrastructureResult);
                }
                if (!identityResult.isEmpty()) {
                    output.put("identity_correlation_result", identityResult);
                }
                if (!fusionResult.isEmpty()) {
                    output.put("attribution_fusion_result", fusionResult);
                }

                output.put("execution_metadata", buildExecutionMetadata(config, diagnostics, startedAt));

                appendFindings(result, summary, graph, seeds);
                result.setNormalizedOutput(buildNormalizedOutput(config, summary, graph));
                result.complete(output);

                ctx.log("[+] WHOIS & OSINT Correlator completed");
                ctx.reportProgress(100);
            } catch (Exception e) {
                result.fail("Execution failed: " + e.getMessage());
                ctx.log("[!] ERROR: " + e.getMessage());
            }

            return result;
        });
    }

    private Map<String, Object> collectRegistrationSeed(
            ScanConfig config,
            SeedSet seeds,
            ExecutionDiagnostics diagnostics,
            CorrelationGraph graph,
            TaskContext ctx) {

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("mode", config.mode.value);

        String query = firstNonBlank(seeds.domain, seeds.ip);
        if (query.isBlank()) {
            return result;
        }

        String queryNode = graph.upsertNode(
            seeds.domain.isBlank() ? "ip" : "domain",
            query,
            Map.of("seed", true)
        );

        if (config.useWhoisCli) {
            WhoisAcquisition whois = acquireWhois(query, config, diagnostics);
            if (!whois.rawText.isBlank()) {
                Map<String, Object> whoisParsed = parseWhoisRecord(whois.rawText);
                result.put("whois_profile", whoisParsed);
                result.put("whois_source", whois.source);
                if (config.includeRaw) {
                    result.put("whois_raw", whois.rawText);
                }

                enrichGraphWithWhois(queryNode, whoisParsed, graph);
            }
        }

        if (config.useRdap) {
            Map<String, Object> rdap = collectRdap(query, seeds, config, diagnostics, graph, queryNode);
            if (!rdap.isEmpty()) {
                result.put("rdap_profile", rdap);
            }
        }

        if (config.useDns && !seeds.domain.isBlank()) {
            Map<String, Object> dns = collectDnsProfile(seeds.domain, config, diagnostics);
            if (!dns.isEmpty()) {
                result.put("dns_profile", dns);
                enrichGraphWithDns(queryNode, dns, graph);
            }
        }

        result.put("signal_count", countSignals(result));
        return result;
    }

    private Map<String, Object> collectInfrastructureAttribution(
            ScanConfig config,
            SeedSet seeds,
            ExecutionDiagnostics diagnostics,
            CorrelationGraph graph,
            TaskContext ctx) {

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("mode", config.mode.value);

        Map<String, Object> registration = collectRegistrationSeed(config, seeds, diagnostics, graph, ctx);
        if (!registration.isEmpty()) {
            result.put("registration_context", registration);
        }

        Set<String> ips = collectInfrastructureIps(seeds, registration);
        if (config.useAsnLookup && !ips.isEmpty()) {
            List<Map<String, Object>> asnProfiles = new ArrayList<>();
            for (String ip : ips) {
                Map<String, Object> profile = collectAsnProfile(ip, config, diagnostics, graph);
                if (!profile.isEmpty()) {
                    asnProfiles.add(profile);
                }
            }
            result.put("asn_profiles", asnProfiles);
        }

        if (config.useAmass && !seeds.domain.isBlank()) {
            Map<String, Object> amass = runAmassIntel(seeds.domain, config, diagnostics, graph);
            if (!amass.isEmpty()) {
                result.put("amass_intel", amass);
            }
        }

        if (config.useTheHarvester && !seeds.domain.isBlank()) {
            Map<String, Object> harvester = runTheHarvester(seeds.domain, config, diagnostics, graph);
            if (!harvester.isEmpty()) {
                result.put("harvester_intel", harvester);
            }
        }

        result.put("signal_count", countSignals(result));
        return result;
    }

    private Map<String, Object> collectIdentityCorrelation(
            ScanConfig config,
            SeedSet seeds,
            ExecutionDiagnostics diagnostics,
            CorrelationGraph graph,
            TaskContext ctx) {

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("mode", config.mode.value);

        String usernameNode = "";
        String emailNode = "";

        if (!seeds.username.isBlank()) {
            usernameNode = graph.upsertNode("username", seeds.username, Map.of("seed", true));
        }
        if (!seeds.email.isBlank()) {
            emailNode = graph.upsertNode("email", seeds.email, Map.of("seed", true));
        }

        if (config.useSherlock && !seeds.username.isBlank()) {
            Map<String, Object> sherlock = runSherlock(seeds.username, config, diagnostics, graph, usernameNode);
            if (!sherlock.isEmpty()) {
                result.put("username_presence", sherlock);
            }
        }

        if (config.useHolehe && !seeds.email.isBlank()) {
            Map<String, Object> holehe = runHolehe(seeds.email, config, diagnostics, graph, emailNode);
            if (!holehe.isEmpty()) {
                result.put("email_service_exposure", holehe);
            }
        }

        if (config.useGravatar && !seeds.email.isBlank()) {
            Map<String, Object> gravatar = runGravatarLookup(seeds.email, config, diagnostics, graph, emailNode);
            if (!gravatar.isEmpty()) {
                result.put("gravatar_profile", gravatar);
            }
        }

        if (!seeds.email.isBlank() && !seeds.username.isBlank()) {
            String localPart = seeds.email.substring(0, seeds.email.indexOf('@')).toLowerCase(Locale.ROOT);
            if (localPart.contains(seeds.username.toLowerCase(Locale.ROOT))
                    || seeds.username.toLowerCase(Locale.ROOT).contains(localPart)) {
                graph.link(usernameNode, emailNode, "possible_identity_reuse", 0.71, Map.of("heuristic", "username_email_localpart"));
            }
        }

        result.put("signal_count", countSignals(result));
        return result;
    }

    private Map<String, Object> collectAttributionFusion(
            ScanConfig config,
            SeedSet seeds,
            ExecutionDiagnostics diagnostics,
            CorrelationGraph graph,
            TaskContext ctx) {

        Map<String, Object> fusion = new LinkedHashMap<>();
        fusion.put("mode", config.mode.value);

        Map<String, Object> registration = Map.of();
        Map<String, Object> infra = Map.of();
        Map<String, Object> identity = Map.of();

        if (!firstNonBlank(seeds.domain, seeds.ip).isBlank()) {
            infra = collectInfrastructureAttribution(config, seeds, diagnostics, graph, ctx);
            registration = asMap(infra.get("registration_context"));
        }

        if (!seeds.username.isBlank() || !seeds.email.isBlank()) {
            identity = collectIdentityCorrelation(config, seeds, diagnostics, graph, ctx);
        }

        if (!registration.isEmpty()) {
            fusion.put("registration_context", registration);
        }
        if (!infra.isEmpty()) {
            fusion.put("infrastructure_context", infra);
        }
        if (!identity.isEmpty()) {
            fusion.put("identity_context", identity);
        }

        correlateFusionEdges(seeds, registration, identity, graph);

        if (!seeds.orgHint.isBlank()) {
            String orgNode = graph.upsertNode("organization_hint", seeds.orgHint, Map.of("seed", true));
            String domain = firstNonBlank(seeds.domain);
            if (!domain.isBlank()) {
                String domainNode = graph.upsertNode("domain", domain, Map.of());
                graph.link(orgNode, domainNode, "analyst_hint_association", 0.52, Map.of("source", "org_hint"));
            }
        }

        fusion.put("signal_count", countSignals(fusion));
        return fusion;
    }

    private void correlateFusionEdges(
            SeedSet seeds,
            Map<String, Object> registration,
            Map<String, Object> identity,
            CorrelationGraph graph) {

        if (seeds.email.isBlank()) {
            return;
        }

        String emailDomain = seeds.email.substring(seeds.email.indexOf('@') + 1).toLowerCase(Locale.ROOT);
        if (!seeds.domain.isBlank() && emailDomain.equalsIgnoreCase(seeds.domain)) {
            String emailNode = graph.upsertNode("email", seeds.email, Map.of());
            String domainNode = graph.upsertNode("domain", seeds.domain, Map.of());
            graph.link(emailNode, domainNode, "email_domain_matches_target", 0.78, Map.of());
        }

        Set<String> regEmails = extractRegistrationEmails(registration);
        if (!regEmails.isEmpty()) {
            String emailNode = graph.upsertNode("email", seeds.email, Map.of());
            for (String candidate : regEmails) {
                if (candidate.equalsIgnoreCase(seeds.email)) {
                    String candidateNode = graph.upsertNode("email", candidate, Map.of());
                    graph.link(emailNode, candidateNode, "exact_registration_email_match", 0.96, Map.of());
                }
            }
        }

        Map<String, Object> usernamePresence = asMap(identity.get("username_presence"));
        List<Map<String, Object>> profiles = asListMap(usernamePresence.get("profiles"));
        if (!profiles.isEmpty() && !seeds.username.isBlank()) {
            String usernameNode = graph.upsertNode("username", seeds.username, Map.of());
            String emailNode = graph.upsertNode("email", seeds.email, Map.of());
            graph.link(usernameNode, emailNode, "co_observed_seed_pair", 0.61, Map.of("platform_hits", profiles.size()));
        }
    }

    private Map<String, Object> collectRdap(
            String query,
            SeedSet seeds,
            ScanConfig config,
            ExecutionDiagnostics diagnostics,
            CorrelationGraph graph,
            String queryNode) {

        String path = seeds.domain.isBlank() ? "ip/" : "domain/";
        String encoded = URLEncoder.encode(query, StandardCharsets.UTF_8);
        String url = "https://rdap.org/" + path + encoded;

        HttpFetchResult fetch = fetchUrl(url, config.timeoutMs, config.connectTimeoutMs);
        diagnostics.httpRequests++;
        diagnostics.urlsFetched.add(url);

        if (!fetch.success) {
            diagnostics.warnings.add("RDAP lookup failed for " + query + ": " + fetch.error);
            return Map.of();
        }

        Map<String, Object> parsed = parseRdapJson(fetch.body);
        if (parsed.isEmpty()) {
            return Map.of();
        }

        enrichGraphWithRdap(queryNode, parsed, graph);
        if (config.includeRaw) {
            parsed.put("raw_json", fetch.body);
        }
        return parsed;
    }

    private WhoisAcquisition acquireWhois(String query, ScanConfig config, ExecutionDiagnostics diagnostics) {
        WhoisAcquisition acquisition = new WhoisAcquisition();

        if (isCommandAvailable("whois")) {
            List<String> command = List.of("whois", query);
            CommandExecutionResult commandResult = runCommand(command, config.timeoutMs * 2L);
            diagnostics.commandExecutions++;
            diagnostics.toolUsage.add("whois");
            diagnostics.executedCommands.add(String.join(" ", command));

            if (!commandResult.timedOut && !commandResult.stdout.isBlank()) {
                acquisition.rawText = commandResult.stdout;
                acquisition.source = "whois_cli";
                return acquisition;
            }

            if (commandResult.timedOut) {
                diagnostics.warnings.add("WHOIS CLI timed out for " + query);
            }
        }

        String ianaResponse = queryWhoisServer("whois.iana.org", query, config.connectTimeoutMs, config.timeoutMs);
        if (!ianaResponse.isBlank()) {
            String referralServer = extractReferralWhoisServer(ianaResponse);
            if (!referralServer.isBlank()) {
                String referredResponse = queryWhoisServer(referralServer, query, config.connectTimeoutMs, config.timeoutMs);
                if (!referredResponse.isBlank()) {
                    acquisition.rawText = referredResponse;
                    acquisition.source = "whois_socket_referred";
                    return acquisition;
                }
            }

            acquisition.rawText = ianaResponse;
            acquisition.source = "whois_socket_iana";
        }

        return acquisition;
    }

    private String extractReferralWhoisServer(String ianaResponse) {
        if (ianaResponse == null || ianaResponse.isBlank()) {
            return "";
        }

        for (String line : ianaResponse.split("\\R")) {
            String lower = line.toLowerCase(Locale.ROOT);
            if (lower.startsWith("whois:")) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    return parts[1].trim();
                }
            }
            if (lower.startsWith("refer:") || lower.startsWith("referralserver:")) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    String candidate = parts[1].trim().replace("whois://", "");
                    return candidate;
                }
            }
        }
        return "";
    }

    protected String queryWhoisServer(String server, String query, int connectTimeoutMs, int readTimeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(server, 43), connectTimeoutMs);
            socket.setSoTimeout(readTimeoutMs);

            socket.getOutputStream().write((query + "\\r\\n").getBytes(StandardCharsets.UTF_8));
            socket.getOutputStream().flush();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append('\n');
                }
            }
            return output.toString();
        } catch (Exception ignored) {
            return "";
        }
    }

    private Map<String, Object> parseWhoisRecord(String rawWhois) {
        Map<String, List<String>> grouped = new LinkedHashMap<>();

        for (String line : rawWhois.split("\\R")) {
            Matcher matcher = WHOIS_KV_PATTERN.matcher(line);
            if (!matcher.matches()) {
                continue;
            }

            String key = normalizeWhoisKey(matcher.group(1));
            String value = matcher.group(2).trim();
            if (key.isBlank() || value.isBlank()) {
                continue;
            }
            grouped.computeIfAbsent(key, ignored -> new ArrayList<>()).add(value);
        }

        Map<String, Object> parsed = new LinkedHashMap<>();
        parsed.put("registrar", firstValue(grouped,
            "registrar",
            "sponsoring registrar",
            "registrar name"
        ));
        parsed.put("registrant_name", firstValue(grouped,
            "registrant name",
            "person",
            "orgname"
        ));
        parsed.put("organization", firstValue(grouped,
            "registrant organization",
            "orgname",
            "organization",
            "owner"
        ));
        parsed.put("country", firstValue(grouped,
            "registrant country",
            "country"
        ));
        parsed.put("creation_date", firstValue(grouped,
            "creation date",
            "created",
            "registered on"
        ));
        parsed.put("expiry_date", firstValue(grouped,
            "registry expiry date",
            "expiration date",
            "expires",
            "paid-till"
        ));
        parsed.put("updated_date", firstValue(grouped,
            "updated date",
            "last updated"
        ));
        parsed.put("abuse_email", firstValue(grouped,
            "registrar abuse contact email",
            "orgabuseemail",
            "abuse-mailbox"
        ));

        List<String> nameservers = collectValuesByPrefix(grouped,
            List.of("name server", "nserver", "nameserver"));
        parsed.put("nameservers", nameservers);

        List<String> emails = extractEmailsFromWhois(grouped, rawWhois);
        parsed.put("contact_emails", emails);

        Map<String, Object> net = new LinkedHashMap<>();
        net.put("netname", firstValue(grouped, "netname"));
        net.put("asn", firstValue(grouped, "originas", "origin", "aut-num", "asn"));
        net.put("provider", firstValue(grouped, "orgname", "descr", "owner", "organization"));
        parsed.put("network_profile", net);

        parsed.put("field_count", grouped.size());
        return parsed;
    }

    private String normalizeWhoisKey(String raw) {
        String key = raw == null ? "" : raw.trim().toLowerCase(Locale.ROOT);
        key = key.replaceAll("\\s+", " ");
        return key;
    }

    private String firstValue(Map<String, List<String>> grouped, String... candidates) {
        for (String candidate : candidates) {
            List<String> values = grouped.get(candidate);
            if (values != null && !values.isEmpty()) {
                return values.get(0);
            }
        }
        return "";
    }

    private List<String> collectValuesByPrefix(Map<String, List<String>> grouped, List<String> prefixes) {
        Set<String> out = new LinkedHashSet<>();
        for (Map.Entry<String, List<String>> entry : grouped.entrySet()) {
            String key = entry.getKey();
            for (String prefix : prefixes) {
                if (key.startsWith(prefix)) {
                    out.addAll(entry.getValue());
                    break;
                }
            }
        }
        return new ArrayList<>(out);
    }

    private List<String> extractEmailsFromWhois(Map<String, List<String>> grouped, String rawWhois) {
        Set<String> emails = new LinkedHashSet<>();
        for (Map.Entry<String, List<String>> entry : grouped.entrySet()) {
            if (!entry.getKey().contains("email") && !entry.getKey().contains("mail")) {
                continue;
            }
            for (String value : entry.getValue()) {
                Matcher matcher = EMAIL_EXTRACT_PATTERN.matcher(value);
                while (matcher.find()) {
                    emails.add(matcher.group().toLowerCase(Locale.ROOT));
                }
            }
        }

        if (emails.isEmpty() && rawWhois != null) {
            Matcher matcher = EMAIL_EXTRACT_PATTERN.matcher(rawWhois);
            while (matcher.find()) {
                emails.add(matcher.group().toLowerCase(Locale.ROOT));
            }
        }
        return new ArrayList<>(emails);
    }

    private Map<String, Object> parseRdapJson(String rawJson) {
        try {
            JsonObject root = JsonParser.parseString(rawJson).getAsJsonObject();
            Map<String, Object> parsed = new LinkedHashMap<>();

            parsed.put("handle", asText(root, "handle"));
            parsed.put("ldh_name", asText(root, "ldhName"));
            parsed.put("object_class", asText(root, "objectClassName"));

            List<Map<String, Object>> events = new ArrayList<>();
            JsonArray eventArray = asArray(root, "events");
            for (JsonElement element : eventArray) {
                if (!element.isJsonObject()) {
                    continue;
                }
                JsonObject event = element.getAsJsonObject();
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("action", asText(event, "eventAction"));
                item.put("date", asText(event, "eventDate"));
                events.add(item);
            }
            parsed.put("events", events);

            List<String> nameservers = new ArrayList<>();
            JsonArray nameserverArray = asArray(root, "nameservers");
            for (JsonElement element : nameserverArray) {
                if (element.isJsonObject()) {
                    String ns = asText(element.getAsJsonObject(), "ldhName");
                    if (!ns.isBlank()) {
                        nameservers.add(ns);
                    }
                }
            }
            parsed.put("nameservers", nameservers);

            List<Map<String, Object>> contacts = new ArrayList<>();
            JsonArray entities = asArray(root, "entities");
            for (JsonElement element : entities) {
                if (!element.isJsonObject()) {
                    continue;
                }
                JsonObject entity = element.getAsJsonObject();
                Map<String, Object> contact = new LinkedHashMap<>();
                contact.put("handle", asText(entity, "handle"));
                contact.put("roles", asStringList(asArray(entity, "roles")));

                JsonArray vcardArray = asArray(entity, "vcardArray");
                Map<String, String> vcard = parseVcard(vcardArray);
                contact.put("name", vcard.getOrDefault("fn", ""));
                contact.put("organization", vcard.getOrDefault("org", ""));
                contact.put("email", vcard.getOrDefault("email", ""));
                contacts.add(contact);
            }
            parsed.put("contacts", contacts);
            return parsed;
        } catch (Exception ignored) {
            return Map.of();
        }
    }

    private Map<String, String> parseVcard(JsonArray vcardArray) {
        Map<String, String> out = new LinkedHashMap<>();
        if (vcardArray.size() < 2 || !vcardArray.get(1).isJsonArray()) {
            return out;
        }

        JsonArray entries = vcardArray.get(1).getAsJsonArray();
        for (JsonElement entryElement : entries) {
            if (!entryElement.isJsonArray()) {
                continue;
            }
            JsonArray entry = entryElement.getAsJsonArray();
            if (entry.size() < 4 || !entry.get(0).isJsonPrimitive()) {
                continue;
            }

            String key = entry.get(0).getAsString().toLowerCase(Locale.ROOT);
            String value = "";
            JsonElement valueElement = entry.get(3);
            if (valueElement.isJsonPrimitive()) {
                value = valueElement.getAsString();
            }
            if (!value.isBlank()) {
                out.putIfAbsent(key, value);
            }
        }
        return out;
    }

    private String asText(JsonObject object, String key) {
        JsonElement element = object.get(key);
        if (element == null || element.isJsonNull()) {
            return "";
        }
        if (element.isJsonPrimitive()) {
            return element.getAsString();
        }
        return "";
    }

    private JsonArray asArray(JsonObject object, String key) {
        JsonElement element = object.get(key);
        if (element == null || !element.isJsonArray()) {
            return new JsonArray();
        }
        return element.getAsJsonArray();
    }

    private List<String> asStringList(JsonArray array) {
        List<String> out = new ArrayList<>();
        for (JsonElement element : array) {
            if (element.isJsonPrimitive()) {
                out.add(element.getAsString());
            }
        }
        return out;
    }

    private Map<String, Object> collectDnsProfile(String domain, ScanConfig config, ExecutionDiagnostics diagnostics) {
        Map<String, Object> profile = new LinkedHashMap<>();
        Set<String> aRecords = new LinkedHashSet<>();
        Set<String> aaaaRecords = new LinkedHashSet<>();
        Set<String> nameservers = new LinkedHashSet<>();
        Set<String> mxRecords = new LinkedHashSet<>();

        if (isCommandAvailable("dig")) {
            diagnostics.toolUsage.add("dig");
            aRecords.addAll(runDigShort(domain, "A", config, diagnostics));
            aaaaRecords.addAll(runDigShort(domain, "AAAA", config, diagnostics));
            nameservers.addAll(runDigShort(domain, "NS", config, diagnostics));
            mxRecords.addAll(runDigShort(domain, "MX", config, diagnostics));
        } else {
            try {
                InetAddress[] addresses = InetAddress.getAllByName(domain);
                for (InetAddress address : addresses) {
                    if (isIpv4(address.getHostAddress())) {
                        aRecords.add(address.getHostAddress());
                    } else {
                        aaaaRecords.add(address.getHostAddress());
                    }
                }
            } catch (Exception e) {
                diagnostics.warnings.add("DNS fallback resolution failed for " + domain + ": " + e.getMessage());
            }
        }

        profile.put("a_records", new ArrayList<>(aRecords));
        profile.put("aaaa_records", new ArrayList<>(aaaaRecords));
        profile.put("nameservers", new ArrayList<>(nameservers));
        profile.put("mx_records", new ArrayList<>(mxRecords));
        profile.put("record_count", aRecords.size() + aaaaRecords.size() + nameservers.size() + mxRecords.size());
        return profile;
    }

    private List<String> runDigShort(String domain, String recordType, ScanConfig config, ExecutionDiagnostics diagnostics) {
        List<String> command = List.of("dig", "+short", recordType, domain);
        CommandExecutionResult result = runCommand(command, config.timeoutMs);

        diagnostics.commandExecutions++;
        diagnostics.executedCommands.add(String.join(" ", command));

        if (result.timedOut || result.stdout.isBlank()) {
            return List.of();
        }

        List<String> parsed = new ArrayList<>();
        for (String line : result.stdout.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isBlank()) {
                continue;
            }
            parsed.add(trimmed.replaceAll("\\.$", ""));
        }
        return parsed;
    }

    private Set<String> collectInfrastructureIps(SeedSet seeds, Map<String, Object> registrationContext) {
        Set<String> ips = new LinkedHashSet<>();
        if (!seeds.ip.isBlank()) {
            ips.add(seeds.ip);
        }

        Map<String, Object> dnsProfile = asMap(registrationContext.get("dns_profile"));
        List<String> aRecords = asStringList(dnsProfile.get("a_records"));
        for (String ip : aRecords) {
            if (isIpv4(ip)) {
                ips.add(ip);
            }
        }
        return ips;
    }

    private Map<String, Object> collectAsnProfile(String ip, ScanConfig config, ExecutionDiagnostics diagnostics, CorrelationGraph graph) {
        Map<String, Object> profile = new LinkedHashMap<>();
        profile.put("ip", ip);

        if (!isCommandAvailable("whois")) {
            diagnostics.warnings.add("WHOIS command unavailable for ASN/provider lookup of " + ip);
            return profile;
        }

        List<String> whoisCommand = List.of("whois", ip);
        CommandExecutionResult whoisResult = runCommand(whoisCommand, config.timeoutMs * 2L);
        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("whois");
        diagnostics.executedCommands.add(String.join(" ", whoisCommand));

        if (whoisResult.timedOut || whoisResult.stdout.isBlank()) {
            return profile;
        }

        Map<String, Object> parsed = parseWhoisRecord(whoisResult.stdout);
        Map<String, Object> net = asMap(parsed.get("network_profile"));

        String asn = firstNonBlank(String.valueOf(net.getOrDefault("asn", ""))).replaceAll("[^A-Za-z0-9-]", "");
        String provider = firstNonBlank(
            String.valueOf(net.getOrDefault("provider", "")),
            String.valueOf(parsed.getOrDefault("organization", ""))
        );
        String netname = firstNonBlank(String.valueOf(net.getOrDefault("netname", "")));

        profile.put("asn", asn);
        profile.put("provider", provider);
        profile.put("netname", netname);
        profile.put("abuse_email", String.valueOf(parsed.getOrDefault("abuse_email", "")));
        if (config.includeRaw) {
            profile.put("whois_raw", whoisResult.stdout);
        }

        String ipNode = graph.upsertNode("ip", ip, Map.of());
        if (!asn.isBlank()) {
            String asnNode = graph.upsertNode("asn", asn, Map.of("provider", provider));
            graph.link(ipNode, asnNode, "allocated_under", 0.88, Map.of());
        }
        if (!provider.isBlank()) {
            String providerNode = graph.upsertNode("provider", provider, Map.of());
            graph.link(ipNode, providerNode, "registered_to", 0.73, Map.of("netname", netname));
        }
        return profile;
    }

    private Map<String, Object> runAmassIntel(String domain, ScanConfig config, ExecutionDiagnostics diagnostics, CorrelationGraph graph) {
        if (!isCommandAvailable("amass")) {
            diagnostics.warnings.add("amass requested but not available");
            return Map.of();
        }

        List<String> command = List.of("amass", "intel", "-whois", "-d", domain);
        CommandExecutionResult result = runCommand(command, config.timeoutMs * 3L);

        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("amass");
        diagnostics.executedCommands.add(String.join(" ", command));

        if (result.timedOut || result.stdout.isBlank()) {
            return Map.of();
        }

        List<String> lines = Arrays.stream(result.stdout.split("\\R"))
            .map(String::trim)
            .filter(line -> !line.isBlank())
            .limit(config.maxPassiveRecords)
            .toList();

        Set<String> relatedDomains = new LinkedHashSet<>();
        Set<String> relatedIps = new LinkedHashSet<>();

        for (String line : lines) {
            for (String token : line.split("\\s+")) {
                String candidate = token.trim();
                if (isIpv4(candidate)) {
                    relatedIps.add(candidate);
                } else if (isValidDomain(candidate)) {
                    relatedDomains.add(candidate.toLowerCase(Locale.ROOT));
                }
            }
        }

        String domainNode = graph.upsertNode("domain", domain, Map.of());
        for (String relatedDomain : relatedDomains) {
            String relatedNode = graph.upsertNode("domain", relatedDomain, Map.of());
            graph.link(domainNode, relatedNode, "passive_related_domain", 0.52, Map.of("source", "amass"));
        }
        for (String ip : relatedIps) {
            String ipNode = graph.upsertNode("ip", ip, Map.of());
            graph.link(domainNode, ipNode, "passive_related_ip", 0.56, Map.of("source", "amass"));
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("related_domains", new ArrayList<>(relatedDomains));
        out.put("related_ips", new ArrayList<>(relatedIps));
        out.put("line_count", lines.size());
        if (config.includeRaw) {
            out.put("raw_output", result.stdout);
        }
        return out;
    }

    private Map<String, Object> runTheHarvester(String domain, ScanConfig config, ExecutionDiagnostics diagnostics, CorrelationGraph graph) {
        if (!isCommandAvailable("theHarvester")) {
            diagnostics.warnings.add("theHarvester requested but not available");
            return Map.of();
        }

        List<String> command = List.of(
            "theHarvester",
            "-d", domain,
            "-b", "crtsh,duckduckgo",
            "-l", String.valueOf(Math.max(10, config.maxPassiveRecords))
        );

        CommandExecutionResult result = runCommand(command, config.timeoutMs * 4L);
        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("theHarvester");
        diagnostics.executedCommands.add(String.join(" ", command));

        if (result.timedOut || result.stdout.isBlank()) {
            return Map.of();
        }

        Set<String> emails = new LinkedHashSet<>();
        Set<String> hosts = new LinkedHashSet<>();

        Matcher emailMatcher = EMAIL_EXTRACT_PATTERN.matcher(result.stdout);
        while (emailMatcher.find() && emails.size() < config.maxPassiveRecords) {
            emails.add(emailMatcher.group().toLowerCase(Locale.ROOT));
        }

        for (String line : result.stdout.split("\\R")) {
            String trimmed = line.trim().toLowerCase(Locale.ROOT);
            if (trimmed.isBlank()) {
                continue;
            }
            if (isValidDomain(trimmed) && hosts.size() < config.maxPassiveRecords) {
                hosts.add(trimmed);
            }
        }

        String domainNode = graph.upsertNode("domain", domain, Map.of());
        for (String email : emails) {
            String emailNode = graph.upsertNode("email", email, Map.of("source", "theHarvester"));
            graph.link(domainNode, emailNode, "harvested_contact", 0.61, Map.of());
        }
        for (String host : hosts) {
            if (host.equalsIgnoreCase(domain)) {
                continue;
            }
            String hostNode = graph.upsertNode("domain", host, Map.of("source", "theHarvester"));
            graph.link(domainNode, hostNode, "harvested_related_host", 0.47, Map.of());
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("emails", new ArrayList<>(emails));
        out.put("hosts", new ArrayList<>(hosts));
        out.put("email_count", emails.size());
        out.put("host_count", hosts.size());
        if (config.includeRaw) {
            out.put("raw_output", result.stdout);
        }
        return out;
    }

    private Map<String, Object> runSherlock(
            String username,
            ScanConfig config,
            ExecutionDiagnostics diagnostics,
            CorrelationGraph graph,
            String usernameNode) {

        String sherlockCommand = isCommandAvailable("sherlock") ? "sherlock" : "";
        if (sherlockCommand.isBlank()) {
            diagnostics.warnings.add("sherlock requested but not available");
            return Map.of();
        }

        List<String> command = List.of(sherlockCommand, username, "--print-found");
        CommandExecutionResult result = runCommand(command, config.timeoutMs * 3L);

        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("sherlock");
        diagnostics.executedCommands.add(String.join(" ", command));

        if (result.timedOut || result.stdout.isBlank()) {
            return Map.of();
        }

        List<Map<String, Object>> profiles = new ArrayList<>();
        for (String line : result.stdout.split("\\R")) {
            Matcher matcher = SHERLOCK_FOUND_PATTERN.matcher(line.trim());
            if (matcher.find()) {
                String platform = matcher.group(1).trim();
                String url = matcher.group(2).trim();

                Map<String, Object> profile = new LinkedHashMap<>();
                profile.put("platform", platform);
                profile.put("url", url);
                profiles.add(profile);

                String platformNode = graph.upsertNode("platform", platform, Map.of());
                graph.link(usernameNode, platformNode, "username_present_on", 0.81, Map.of("url", url));
            }
        }

        if (profiles.isEmpty()) {
            for (String line : result.stdout.split("\\R")) {
                Matcher urlMatcher = SIMPLE_URL_PATTERN.matcher(line);
                if (!urlMatcher.find()) {
                    continue;
                }
                String url = urlMatcher.group();
                String platform = inferPlatformFromUrl(url);
                Map<String, Object> profile = new LinkedHashMap<>();
                profile.put("platform", platform);
                profile.put("url", url);
                profiles.add(profile);

                String platformNode = graph.upsertNode("platform", platform, Map.of());
                graph.link(usernameNode, platformNode, "username_present_on", 0.57, Map.of("url", url));
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("profiles", profiles);
        out.put("profile_count", profiles.size());
        if (config.includeRaw) {
            out.put("raw_output", result.stdout);
        }
        return out;
    }

    private Map<String, Object> runHolehe(
            String email,
            ScanConfig config,
            ExecutionDiagnostics diagnostics,
            CorrelationGraph graph,
            String emailNode) {

        if (!isCommandAvailable("holehe")) {
            diagnostics.warnings.add("holehe requested but not available");
            return Map.of();
        }

        List<String> command = List.of("holehe", email);
        CommandExecutionResult result = runCommand(command, config.timeoutMs * 3L);

        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add("holehe");
        diagnostics.executedCommands.add(String.join(" ", command));

        if (result.timedOut || result.stdout.isBlank()) {
            return Map.of();
        }

        Set<String> services = new LinkedHashSet<>();
        for (String line : result.stdout.split("\\R")) {
            String trimmed = line.trim();
            if (!trimmed.startsWith("[+]")) {
                continue;
            }

            String value = trimmed.substring(3).trim();
            if (value.isBlank()) {
                continue;
            }
            services.add(value);
        }

        for (String service : services) {
            String serviceNode = graph.upsertNode("service", service, Map.of("source", "holehe"));
            graph.link(emailNode, serviceNode, "email_registered_on", 0.72, Map.of());
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("services", new ArrayList<>(services));
        out.put("service_count", services.size());
        if (config.includeRaw) {
            out.put("raw_output", result.stdout);
        }
        return out;
    }

    private Map<String, Object> runGravatarLookup(
            String email,
            ScanConfig config,
            ExecutionDiagnostics diagnostics,
            CorrelationGraph graph,
            String emailNode) {

        String emailHash = md5LowerHex(email.trim().toLowerCase(Locale.ROOT));
        if (emailHash.isBlank()) {
            return Map.of();
        }

        String url = "https://www.gravatar.com/" + emailHash + ".json";
        HttpFetchResult fetch = fetchUrl(url, config.timeoutMs, config.connectTimeoutMs);

        diagnostics.httpRequests++;
        diagnostics.urlsFetched.add(url);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("hash", emailHash);
        out.put("profile_found", fetch.statusCode == 200 && fetch.success);

        if (!fetch.success || fetch.statusCode != 200) {
            if (fetch.statusCode != 404) {
                diagnostics.warnings.add("Gravatar lookup failed for " + email + ": " + fetch.error);
            }
            return out;
        }

        try {
            JsonObject root = JsonParser.parseString(fetch.body).getAsJsonObject();
            JsonArray entries = root.has("entry") && root.get("entry").isJsonArray()
                ? root.getAsJsonArray("entry")
                : new JsonArray();

            if (entries.size() > 0 && entries.get(0).isJsonObject()) {
                JsonObject profile = entries.get(0).getAsJsonObject();
                String displayName = asText(profile, "displayName");
                String profileUrl = asText(profile, "profileUrl");
                String preferredUsername = asText(profile, "preferredUsername");

                out.put("display_name", displayName);
                out.put("profile_url", profileUrl);
                out.put("preferred_username", preferredUsername);

                String profileNode = graph.upsertNode("profile", firstNonBlank(profileUrl, "gravatar:" + emailHash),
                    Map.of("display_name", displayName));
                graph.link(emailNode, profileNode, "gravatar_profile", 0.63, Map.of());

                if (!preferredUsername.isBlank()) {
                    String usernameNode = graph.upsertNode("username", preferredUsername, Map.of("source", "gravatar"));
                    graph.link(profileNode, usernameNode, "profile_username", 0.67, Map.of());
                }
            }

            if (config.includeRaw) {
                out.put("raw_json", fetch.body);
            }
        } catch (Exception e) {
            diagnostics.warnings.add("Gravatar JSON parse error: " + e.getMessage());
        }

        return out;
    }

    private String inferPlatformFromUrl(String url) {
        try {
            URI uri = URI.create(url);
            String host = firstNonBlank(uri.getHost()).toLowerCase(Locale.ROOT);
            if (host.startsWith("www.")) {
                host = host.substring(4);
            }
            return host.isBlank() ? "unknown_platform" : host;
        } catch (Exception ignored) {
            return "unknown_platform";
        }
    }

    private Map<String, Object> buildSummary(
            ScanConfig config,
            Map<String, Object> registrationResult,
            Map<String, Object> infrastructureResult,
            Map<String, Object> identityResult,
            Map<String, Object> fusionResult,
            CorrelationGraph graph,
            ExecutionDiagnostics diagnostics) {

        int exposureSignals = 0;
        exposureSignals += countEmailsInResult(registrationResult);
        exposureSignals += countIdentityProfiles(identityResult);
        exposureSignals += countIdentityProfiles(fusionResult);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", config.mode.value);
        summary.put("graph_nodes", graph.nodeCount());
        summary.put("graph_edges", graph.edgeCount());
        summary.put("registration_signals", countSignals(registrationResult));
        summary.put("infrastructure_signals", countSignals(infrastructureResult));
        summary.put("identity_signals", countSignals(identityResult));
        summary.put("fusion_signals", countSignals(fusionResult));
        summary.put("exposure_signals", exposureSignals);
        summary.put("warnings", diagnostics.warnings.size());
        summary.put("confidence_score", computeConfidenceScore(config, graph, exposureSignals));
        return summary;
    }

    private int computeConfidenceScore(ScanConfig config, CorrelationGraph graph, int exposureSignals) {
        int score = Math.min(30, graph.nodeCount() * 2) + Math.min(30, graph.edgeCount() * 2) + Math.min(40, exposureSignals * 4);
        if (config.mode == ModuleMode.ATTRIBUTION_FUSION) {
            score = Math.min(100, score + 10);
        }
        return Math.min(100, score);
    }

    private int countEmailsInResult(Map<String, Object> registrationResult) {
        Map<String, Object> whois = asMap(registrationResult.get("whois_profile"));
        List<String> emails = asStringList(whois.get("contact_emails"));
        return emails.size();
    }

    private int countIdentityProfiles(Map<String, Object> identityResult) {
        if (identityResult.isEmpty()) {
            return 0;
        }

        int count = 0;
        Map<String, Object> usernamePresence = asMap(identityResult.get("username_presence"));
        count += asListMap(usernamePresence.get("profiles")).size();

        Map<String, Object> emailExposure = asMap(identityResult.get("email_service_exposure"));
        count += asStringList(emailExposure.get("services")).size();
        return count;
    }

    private Map<String, Object> buildExecutionMetadata(ScanConfig config, ExecutionDiagnostics diagnostics, long startedAt) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("module", MODULE_ID);
        metadata.put("mode", config.mode.value);
        metadata.put("tools_used", new ArrayList<>(diagnostics.toolUsage));
        metadata.put("command_executions", diagnostics.commandExecutions);
        metadata.put("http_requests", diagnostics.httpRequests);
        metadata.put("executed_commands", diagnostics.executedCommands);
        metadata.put("urls_fetched", diagnostics.urlsFetched);
        metadata.put("warnings", diagnostics.warnings);
        metadata.put("timeout_ms", config.timeoutMs);
        metadata.put("connect_timeout_ms", config.connectTimeoutMs);
        metadata.put("elapsed_ms", System.currentTimeMillis() - startedAt);
        return metadata;
    }

    private Map<String, Object> buildNormalizedOutput(ScanConfig config, Map<String, Object> summary, CorrelationGraph graph) {
        Map<String, Object> normalized = new LinkedHashMap<>();

        Map<String, Object> rawOutput = new LinkedHashMap<>();
        rawOutput.put("summary", summary);
        rawOutput.put("node_count", graph.nodeCount());
        rawOutput.put("edge_count", graph.edgeCount());
        normalized.put("raw_output", rawOutput);

        int exposureSignals = ((Number) summary.getOrDefault("exposure_signals", 0)).intValue();
        Map<String, Object> parsedOutput = new LinkedHashMap<>();
        parsedOutput.put("status", exposureSignals > 0
            ? "ATTRIBUTION_SIGNALS_IDENTIFIED"
            : "ATTRIBUTION_SIGNALS_MINIMAL");
        parsedOutput.put("vulnerable", exposureSignals > 0);
        parsedOutput.put("details", summary);
        parsedOutput.put("evidence", graph.toMap());
        normalized.put("parsed_output", parsedOutput);

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("module", MODULE_ID);
        metadata.put("mode", config.mode.value);
        normalized.put("metadata", metadata);

        return normalized;
    }

    private void appendFindings(ModuleResult result, Map<String, Object> summary, CorrelationGraph graph, SeedSet seeds) {
        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("type", "attribution_summary");
        finding.put("seeds", seeds.toMap());
        finding.put("summary", summary);
        finding.put("graph_edges", graph.edgeCount());
        result.addFinding(finding);

        for (Map<String, Object> edge : graph.edges()) {
            result.addFinding(edge);
        }
    }

    private void enrichGraphWithWhois(String queryNode, Map<String, Object> whoisParsed, CorrelationGraph graph) {
        String registrar = firstNonBlank(String.valueOf(whoisParsed.getOrDefault("registrar", "")));
        if (!registrar.isBlank()) {
            String registrarNode = graph.upsertNode("registrar", registrar, Map.of());
            graph.link(queryNode, registrarNode, "registered_via", 0.84, Map.of());
        }

        String organization = firstNonBlank(String.valueOf(whoisParsed.getOrDefault("organization", "")));
        if (!organization.isBlank()) {
            String orgNode = graph.upsertNode("organization", organization, Map.of());
            graph.link(queryNode, orgNode, "registered_to", 0.76, Map.of());
        }

        List<String> nameservers = asStringList(whoisParsed.get("nameservers"));
        for (String nameserver : nameservers) {
            String nsNode = graph.upsertNode("nameserver", nameserver, Map.of());
            graph.link(queryNode, nsNode, "delegated_dns", 0.73, Map.of());
        }

        List<String> emails = asStringList(whoisParsed.get("contact_emails"));
        for (String email : emails) {
            String emailNode = graph.upsertNode("email", email, Map.of("source", "whois"));
            graph.link(queryNode, emailNode, "registration_contact", 0.69, Map.of());
        }
    }

    private void enrichGraphWithRdap(String queryNode, Map<String, Object> rdapParsed, CorrelationGraph graph) {
        List<String> nameservers = asStringList(rdapParsed.get("nameservers"));
        for (String nameserver : nameservers) {
            String nsNode = graph.upsertNode("nameserver", nameserver, Map.of("source", "rdap"));
            graph.link(queryNode, nsNode, "rdap_nameserver", 0.74, Map.of());
        }

        List<Map<String, Object>> contacts = asListMap(rdapParsed.get("contacts"));
        for (Map<String, Object> contact : contacts) {
            String handle = firstNonBlank(String.valueOf(contact.getOrDefault("handle", "")));
            String email = firstNonBlank(String.valueOf(contact.getOrDefault("email", "")));

            String entityNode = "";
            if (!handle.isBlank()) {
                entityNode = graph.upsertNode("rdap_entity", handle, Map.of(
                    "name", String.valueOf(contact.getOrDefault("name", "")),
                    "organization", String.valueOf(contact.getOrDefault("organization", ""))
                ));
                graph.link(queryNode, entityNode, "rdap_entity", 0.71, Map.of());
            }

            if (!email.isBlank()) {
                String emailNode = graph.upsertNode("email", email.toLowerCase(Locale.ROOT), Map.of("source", "rdap"));
                graph.link(queryNode, emailNode, "rdap_contact_email", 0.77, Map.of());
                if (!entityNode.isBlank()) {
                    graph.link(entityNode, emailNode, "entity_email", 0.79, Map.of());
                }
            }
        }
    }

    private void enrichGraphWithDns(String queryNode, Map<String, Object> dnsProfile, CorrelationGraph graph) {
        for (String ip : asStringList(dnsProfile.get("a_records"))) {
            if (!isIpv4(ip)) {
                continue;
            }
            String ipNode = graph.upsertNode("ip", ip, Map.of());
            graph.link(queryNode, ipNode, "resolves_to", 0.86, Map.of("record", "A"));
        }

        for (String nameserver : asStringList(dnsProfile.get("nameservers"))) {
            String nsNode = graph.upsertNode("nameserver", nameserver, Map.of("source", "dns"));
            graph.link(queryNode, nsNode, "dns_ns", 0.81, Map.of());
        }

        for (String mx : asStringList(dnsProfile.get("mx_records"))) {
            String mxNode = graph.upsertNode("mail_exchange", mx, Map.of("source", "dns"));
            graph.link(queryNode, mxNode, "dns_mx", 0.78, Map.of());
        }
    }

    private Set<String> extractRegistrationEmails(Map<String, Object> registration) {
        Set<String> emails = new LinkedHashSet<>();
        Map<String, Object> whois = asMap(registration.get("whois_profile"));
        emails.addAll(asStringList(whois.get("contact_emails")));

        Map<String, Object> rdap = asMap(registration.get("rdap_profile"));
        List<Map<String, Object>> contacts = asListMap(rdap.get("contacts"));
        for (Map<String, Object> contact : contacts) {
            String email = firstNonBlank(String.valueOf(contact.getOrDefault("email", "")));
            if (!email.isBlank()) {
                emails.add(email.toLowerCase(Locale.ROOT));
            }
        }
        return emails;
    }

    private int countSignals(Map<String, Object> map) {
        if (map == null || map.isEmpty()) {
            return 0;
        }

        int count = 0;
        for (Object value : map.values()) {
            if (value instanceof List<?> list) {
                count += list.size();
            } else if (value instanceof Map<?, ?> nested) {
                count += nested.size();
            } else if (value != null && !String.valueOf(value).isBlank()) {
                count++;
            }
        }
        return count;
    }

    private SeedSet buildSeedSet(ScanConfig config) {
        SeedSet seeds = new SeedSet();
        seeds.username = trim(config.username);
        seeds.email = normalizeEmail(trim(config.email));
        seeds.orgHint = trim(config.orgHint);

        String query = normalizeQuery(config.query);
        if (!query.isBlank()) {
            if (isIpv4(query)) {
                seeds.ip = query;
            } else {
                seeds.domain = normalizeDomain(query);
            }
        }

        return seeds;
    }

    private List<String> validateConfig(ScanConfig config) {
        List<String> errors = new ArrayList<>();

        switch (config.mode) {
            case REGISTRATION_SEED, INFRASTRUCTURE_ATTRIBUTION -> {
                if (trim(config.query).isBlank()) {
                    errors.add("query is required when mode=" + config.mode.value);
                }
            }
            case IDENTITY_CORRELATION -> {
                if (trim(config.username).isBlank() && trim(config.email).isBlank()) {
                    errors.add("username or email is required when mode=identity_correlation");
                }
            }
            case ATTRIBUTION_FUSION -> {
                if (trim(config.query).isBlank()
                        && trim(config.username).isBlank()
                        && trim(config.email).isBlank()
                        && trim(config.orgHint).isBlank()) {
                    errors.add("at least one of query, username, email, or org_hint is required when mode=attribution_fusion");
                }
            }
        }

        if (!trim(config.query).isBlank()) {
            String normalizedQuery = normalizeQuery(config.query);
            if (!isIpv4(normalizedQuery) && !isValidDomain(normalizedQuery)) {
                errors.add("query must be a valid domain or IPv4 address");
            }
        }

        if (!trim(config.email).isBlank() && !EMAIL_PATTERN.matcher(trim(config.email)).matches()) {
            errors.add("email must be a valid email address");
        }

        if (config.timeoutMs < 500 || config.timeoutMs > 180_000) {
            errors.add("timeout_ms must be between 500 and 180000");
        }

        if (config.connectTimeoutMs < 200 || config.connectTimeoutMs > 120_000) {
            errors.add("connect_timeout_ms must be between 200 and 120000");
        }

        if (config.maxPassiveRecords < 1 || config.maxPassiveRecords > 5_000) {
            errors.add("max_passive_records must be between 1 and 5000");
        }

        return errors;
    }

    private ScanConfig parseConfig(Map<String, String> input) {
        ScanConfig config = new ScanConfig();
        config.mode = ModuleMode.fromInput(firstNonBlank(input.get("mode"), "registration_seed"));

        config.query = firstNonBlank(input.get("query"), input.get("target"), input.get("domain"));
        config.username = trim(input.get("username"));
        config.email = trim(input.get("email"));
        config.orgHint = trim(input.get("org_hint"));

        config.useWhoisCli = parseBoolean(input.get("use_whois_cli"), true);
        config.useRdap = parseBoolean(input.get("use_rdap"), true);
        config.useDns = parseBoolean(input.get("use_dns"), true);
        config.useAsnLookup = parseBoolean(input.get("use_asn_lookup"), true);
        config.useAmass = parseBoolean(input.get("use_amass"), false);
        config.useTheHarvester = parseBoolean(input.get("use_theharvester"), false);
        config.useSherlock = parseBoolean(input.get("use_sherlock"), true);
        config.useHolehe = parseBoolean(input.get("use_holehe"), true);
        config.useGravatar = parseBoolean(input.get("use_gravatar"), true);

        config.timeoutMs = parseInteger(firstNonBlank(input.get("timeout_ms"), input.get("timeout")), DEFAULT_TIMEOUT_MS);
        config.connectTimeoutMs = parseInteger(input.get("connect_timeout_ms"), DEFAULT_CONNECT_TIMEOUT_MS);
        config.maxPassiveRecords = parseInteger(input.get("max_passive_records"), DEFAULT_MAX_PASSIVE_RECORDS);
        config.includeRaw = parseBoolean(input.get("include_raw"), false);
        return config;
    }

    protected HttpFetchResult fetchUrl(String url, int timeoutMs, int connectTimeoutMs) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofMillis(Math.max(500, timeoutMs)))
                .header("Accept", "application/json,text/plain,*/*")
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return new HttpFetchResult(
                response.statusCode() >= 200 && response.statusCode() < 300,
                response.statusCode(),
                response.body(),
                ""
            );
        } catch (Exception e) {
            return new HttpFetchResult(false, -1, "", e.getMessage());
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
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            Process runningProcess = processBuilder.start();
            process = runningProcess;

            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();

            Thread outThread = Thread.ofVirtual().start(() -> copyStream(runningProcess.getInputStream(), stdout));
            Thread errThread = Thread.ofVirtual().start(() -> copyStream(runningProcess.getErrorStream(), stderr));

            boolean finished = runningProcess.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            if (!finished) {
                runningProcess.destroyForcibly();
                joinQuietly(outThread, 200);
                joinQuietly(errThread, 200);
                return new CommandExecutionResult(-1, stdout.toString(), stderr.toString(), true, System.currentTimeMillis() - startedAt);
            }

            joinQuietly(outThread, 500);
            joinQuietly(errThread, 500);

            return new CommandExecutionResult(
                runningProcess.exitValue(),
                stdout.toString(),
                stderr.toString(),
                false,
                System.currentTimeMillis() - startedAt
            );
        } catch (Exception e) {
            return new CommandExecutionResult(-1, "", e.getMessage(), false, System.currentTimeMillis() - startedAt);
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    private Map<String, Object> asMap(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getKey() != null) {
                    out.put(String.valueOf(entry.getKey()), entry.getValue());
                }
            }
            return out;
        }
        return Map.of();
    }

    private List<Map<String, Object>> asListMap(Object value) {
        if (value instanceof List<?> list) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Object item : list) {
                out.add(asMap(item));
            }
            return out;
        }
        return List.of();
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

    private String normalizeQuery(String rawQuery) {
        String query = trim(rawQuery).toLowerCase(Locale.ROOT);
        if (query.startsWith("http://") || query.startsWith("https://")) {
            try {
                URI uri = URI.create(query);
                query = firstNonBlank(uri.getHost());
            } catch (Exception ignored) {
                // Keep original query.
            }
        }
        return query;
    }

    private String normalizeDomain(String raw) {
        String domain = trim(raw).toLowerCase(Locale.ROOT);
        domain = domain.replaceAll("\\.$", "");
        return domain;
    }

    private String normalizeEmail(String email) {
        return trim(email).toLowerCase(Locale.ROOT);
    }

    private String md5LowerHex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

    private boolean isIpv4(String value) {
        if (!IPV4_PATTERN.matcher(value).matches()) {
            return false;
        }
        String[] octets = value.split("\\.");
        for (String octet : octets) {
            int candidate = parseInteger(octet, -1);
            if (candidate < 0 || candidate > 255) {
                return false;
            }
        }
        return true;
    }

    private boolean isValidDomain(String value) {
        return DOMAIN_PATTERN.matcher(value).matches();
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

    private void copyStream(InputStream stream, StringBuilder sink) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sink.append(line).append('\n');
            }
        } catch (IOException ignored) {
            // Best effort stream capture.
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

    private enum ModuleMode {
        REGISTRATION_SEED("registration_seed"),
        INFRASTRUCTURE_ATTRIBUTION("infrastructure_attribution"),
        IDENTITY_CORRELATION("identity_correlation"),
        ATTRIBUTION_FUSION("attribution_fusion");

        private final String value;

        ModuleMode(String value) {
            this.value = value;
        }

        private static ModuleMode fromInput(String raw) {
            String normalized = raw == null
                ? ""
                : raw.trim().toLowerCase(Locale.ROOT).replace('-', '_').replace(' ', '_');

            return switch (normalized) {
                case "infrastructure_attribution", "infrastructure" -> INFRASTRUCTURE_ATTRIBUTION;
                case "identity_correlation", "identity" -> IDENTITY_CORRELATION;
                case "attribution_fusion", "fusion" -> ATTRIBUTION_FUSION;
                default -> REGISTRATION_SEED;
            };
        }
    }

    protected static final class ScanConfig {
        private ModuleMode mode = ModuleMode.REGISTRATION_SEED;
        private String query = "";
        private String username = "";
        private String email = "";
        private String orgHint = "";

        private boolean useWhoisCli = true;
        private boolean useRdap = true;
        private boolean useDns = true;
        private boolean useAsnLookup = true;
        private boolean useAmass;
        private boolean useTheHarvester;
        private boolean useSherlock = true;
        private boolean useHolehe = true;
        private boolean useGravatar = true;

        private int timeoutMs = DEFAULT_TIMEOUT_MS;
        private int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
        private int maxPassiveRecords = DEFAULT_MAX_PASSIVE_RECORDS;
        private boolean includeRaw;
    }

    private static final class SeedSet {
        private String domain = "";
        private String ip = "";
        private String username = "";
        private String email = "";
        private String orgHint = "";

        private Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("domain", domain);
            map.put("ip", ip);
            map.put("username", username);
            map.put("email", email);
            map.put("org_hint", orgHint);
            return map;
        }

        private String toLogString() {
            List<String> parts = new ArrayList<>();
            if (!domain.isBlank()) {
                parts.add("domain=" + domain);
            }
            if (!ip.isBlank()) {
                parts.add("ip=" + ip);
            }
            if (!username.isBlank()) {
                parts.add("username=" + username);
            }
            if (!email.isBlank()) {
                parts.add("email=" + email);
            }
            if (!orgHint.isBlank()) {
                parts.add("org_hint=" + orgHint);
            }
            return parts.isEmpty() ? "none" : String.join(", ", parts);
        }
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
    }

    protected static final class HttpFetchResult {
        protected final boolean success;
        protected final int statusCode;
        protected final String body;
        protected final String error;

        protected HttpFetchResult(boolean success, int statusCode, String body, String error) {
            this.success = success;
            this.statusCode = statusCode;
            this.body = body == null ? "" : body;
            this.error = error == null ? "" : error;
        }
    }

    private static final class WhoisAcquisition {
        private String source = "";
        private String rawText = "";
    }

    private static final class ExecutionDiagnostics {
        private int commandExecutions;
        private int httpRequests;
        private final Set<String> toolUsage = new LinkedHashSet<>();
        private final List<String> executedCommands = new ArrayList<>();
        private final List<String> urlsFetched = new ArrayList<>();
        private final List<String> warnings = new ArrayList<>();
    }

    private static final class CorrelationGraph {
        private final Map<String, Map<String, Object>> nodesByKey = new LinkedHashMap<>();
        private final List<Map<String, Object>> edges = new ArrayList<>();

        private String upsertNode(String type, String value, Map<String, Object> attributes) {
            String normalizedType = valueOrUnknown(type).toLowerCase(Locale.ROOT);
            String normalizedValue = valueOrUnknown(value).trim();
            String key = normalizedType + "::" + normalizedValue.toLowerCase(Locale.ROOT);

            Map<String, Object> existing = nodesByKey.get(key);
            if (existing == null) {
                Map<String, Object> node = new LinkedHashMap<>();
                String id = "n" + (nodesByKey.size() + 1);
                node.put("id", id);
                node.put("type", normalizedType);
                node.put("value", normalizedValue);
                node.put("attributes", new LinkedHashMap<String, Object>());
                nodesByKey.put(key, node);
                existing = node;
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> existingAttributes = (Map<String, Object>) existing.get("attributes");
            if (attributes != null) {
                for (Map.Entry<String, Object> entry : attributes.entrySet()) {
                    if (entry.getValue() != null && !String.valueOf(entry.getValue()).isBlank()) {
                        existingAttributes.put(entry.getKey(), entry.getValue());
                    }
                }
            }

            return String.valueOf(existing.get("id"));
        }

        private void link(String fromNodeId, String toNodeId, String relation, double confidence, Map<String, Object> metadata) {
            if (fromNodeId == null || fromNodeId.isBlank() || toNodeId == null || toNodeId.isBlank()) {
                return;
            }

            Map<String, Object> edge = new LinkedHashMap<>();
            edge.put("from", fromNodeId);
            edge.put("to", toNodeId);
            edge.put("relation", valueOrUnknown(relation));
            edge.put("confidence", round(confidence));
            edge.put("metadata", metadata == null ? Map.of() : metadata);
            edges.add(edge);
        }

        private Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            List<Map<String, Object>> nodes = new ArrayList<>(nodesByKey.values());
            nodes.sort(Comparator.comparing(node -> String.valueOf(node.get("id"))));
            map.put("nodes", nodes);
            map.put("edges", edges);
            return map;
        }

        private List<Map<String, Object>> edges() {
            return edges;
        }

        private int nodeCount() {
            return nodesByKey.size();
        }

        private int edgeCount() {
            return edges.size();
        }

        private static String valueOrUnknown(String value) {
            return value == null || value.isBlank() ? "unknown" : value;
        }

        private static double round(double value) {
            return Math.round(value * 100.0) / 100.0;
        }
    }
}
