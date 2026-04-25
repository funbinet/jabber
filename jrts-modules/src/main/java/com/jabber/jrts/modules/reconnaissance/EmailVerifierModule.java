package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.*;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
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

@JRTSModule(
    id = "recon-email-verify",
    name = "Email Verifier & SMTP Surface Mapper",
    description = "Validate mailbox acceptance behavior, detect catch-all domains, and extract SMTP server intelligence for reconnaissance.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.MEDIUM,
    sourceRef = "RFC5321/dig/swaks/smtp-cli/theHarvester/holehe",
    author = "JRTS"
)
public class EmailVerifierModule implements JRTSModuleInterface {

    private static final String MODULE_ID = "recon-email-verify";

    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 5_000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 5_000;
    private static final int DEFAULT_COMMAND_TIMEOUT_MS = 12_000;
    private static final int DEFAULT_CATCHALL_PROBE_COUNT = 3;
    private static final int DEFAULT_MAX_MX_HOSTS = 3;

    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$");
    private static final Pattern SMTP_RESPONSE_PATTERN = Pattern.compile("^(\\d{3})([-\\s])(.*)$");
    private static final Pattern DIG_MX_PATTERN = Pattern.compile("^\\s*(\\d+)\\s+([A-Za-z0-9.-]+)\\.?\\s*$");
    private static final Pattern NSLOOKUP_MX_PATTERN = Pattern.compile("mail exchanger\\s*=\\s*(\\d+)\\s+([A-Za-z0-9.-]+)\\.?", Pattern.CASE_INSENSITIVE);
    private static final Pattern THEHARVESTER_EMAIL_PATTERN = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");
    private static final Pattern HOLEHE_SERVICE_PATTERN = Pattern.compile("^\\[\\+\\]\\s*(.+?)\\s*$");
    private static final Pattern AUTH_LINE_PATTERN = Pattern.compile("^AUTH\\s+(.+)$", Pattern.CASE_INSENSITIVE);

    private final Map<String, Boolean> commandAvailabilityCache = new ConcurrentHashMap<>();

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of(
                    "syntax_mx_screen",
                    "smtp_recipient_probe",
                    "catch_all_assessment",
                    "mail_surface_intel"
                ))
                .required()
                .defaultValue("syntax_mx_screen")
                .group("Mode")
                .helpText("Email module-specific operational modes with dedicated SMTP workflows."),

            ModuleInputField.text("target_email", "Target Email")
                .placeholder("user@domain.com")
                .group("Seed")
                .modes("syntax_mx_screen", "smtp_recipient_probe", "catch_all_assessment", "mail_surface_intel"),
            ModuleInputField.text("target_domain", "Target Domain")
                .placeholder("domain.com")
                .group("Seed")
                .modes("syntax_mx_screen", "smtp_recipient_probe", "catch_all_assessment", "mail_surface_intel"),
            ModuleInputField.textarea("email_list", "Email List")
                .placeholder("alice@domain.com\nbob@domain.com")
                .group("Seed")
                .modes("smtp_recipient_probe"),

            ModuleInputField.text("smtp_host_override", "SMTP Host Override")
                .placeholder("mail.domain.com or mail.domain.com:25")
                .group("SMTP")
                .modes("smtp_recipient_probe", "catch_all_assessment", "mail_surface_intel"),
            ModuleInputField.text("smtp_ports", "SMTP Ports")
                .placeholder("25,587")
                .group("SMTP")
                .modes("syntax_mx_screen", "smtp_recipient_probe", "catch_all_assessment", "mail_surface_intel"),
            ModuleInputField.text("mail_from", "MAIL FROM")
                .placeholder("verifier@local.test")
                .defaultValue("verifier@local.test")
                .group("SMTP")
                .modes("smtp_recipient_probe", "catch_all_assessment", "mail_surface_intel"),
            ModuleInputField.text("helo_identity", "HELO/EHLO Identity")
                .placeholder("jrts.local")
                .defaultValue("jrts.local")
                .group("SMTP")
                .modes("smtp_recipient_probe", "catch_all_assessment", "mail_surface_intel"),

            ModuleInputField.text("catchall_probe_count", "Catch-All Decoy Count")
                .placeholder(String.valueOf(DEFAULT_CATCHALL_PROBE_COUNT))
                .group("Assessment")
                .modes("catch_all_assessment"),
            ModuleInputField.checkbox("probe_relay_restrictions", "Probe Relay Restrictions")
                .defaultValue("false")
                .group("Assessment")
                .modes("mail_surface_intel"),
            ModuleInputField.text("max_mx_hosts", "Max MX Hosts")
                .placeholder(String.valueOf(DEFAULT_MAX_MX_HOSTS))
                .group("Assessment")
                .modes("smtp_recipient_probe", "catch_all_assessment", "mail_surface_intel"),

            ModuleInputField.checkbox("use_swaks", "Use swaks (if installed)")
                .defaultValue("true")
                .group("Tooling")
                .modes("smtp_recipient_probe", "mail_surface_intel"),
            ModuleInputField.checkbox("use_smtp_cli", "Use smtp-cli (if installed)")
                .defaultValue("false")
                .group("Tooling")
                .modes("smtp_recipient_probe", "mail_surface_intel"),
            ModuleInputField.checkbox("use_theharvester", "Use theHarvester (if installed)")
                .defaultValue("false")
                .group("Tooling")
                .modes("mail_surface_intel"),
            ModuleInputField.checkbox("use_holehe", "Use Holehe (if installed)")
                .defaultValue("false")
                .group("Tooling")
                .modes("mail_surface_intel"),

            ModuleInputField.text("connect_timeout_ms", "Connect Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_CONNECT_TIMEOUT_MS))
                .group("Execution"),
            ModuleInputField.text("read_timeout_ms", "Read Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_READ_TIMEOUT_MS))
                .group("Execution"),
            ModuleInputField.text("command_timeout_ms", "Command Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_COMMAND_TIMEOUT_MS))
                .group("Execution"),
            ModuleInputField.checkbox("include_raw", "Include Raw Tool/SMTP Transcript")
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
                ctx.log("[*] Starting Email Verifier & SMTP Surface Mapper");
                ctx.reportProgress(5);

                ScanConfig config = parseConfig(input);
                SeedSet seeds = buildSeedSet(config);

                List<String> validationErrors = validateConfig(config, seeds);
                if (!validationErrors.isEmpty()) {
                    String message = String.join("; ", validationErrors);
                    result.fail("Validation failed: " + message);
                    ctx.log("[!] Validation failed: " + message);
                    return result;
                }

                ctx.log("[*] Mode: " + config.mode.value);
                ctx.log("[*] Domain seed: " + firstNonBlank(seeds.domain, "n/a"));
                ctx.log("[*] Recipient candidates: " + seeds.recipients.size());
                ctx.reportProgress(15);

                ExecutionDiagnostics diagnostics = new ExecutionDiagnostics();
                Map<String, Object> modeResult;

                switch (config.mode) {
                    case SYNTAX_MX_SCREEN -> {
                        modeResult = collectSyntaxMxScreen(config, seeds, diagnostics, ctx);
                        ctx.reportProgress(85);
                    }
                    case SMTP_RECIPIENT_PROBE -> {
                        modeResult = collectSmtpRecipientProbe(config, seeds, diagnostics, ctx);
                        ctx.reportProgress(85);
                    }
                    case CATCH_ALL_ASSESSMENT -> {
                        modeResult = collectCatchAllAssessment(config, seeds, diagnostics, ctx);
                        ctx.reportProgress(85);
                    }
                    case MAIL_SURFACE_INTEL -> {
                        modeResult = collectMailSurfaceIntel(config, seeds, diagnostics, ctx);
                        ctx.reportProgress(85);
                    }
                    default -> modeResult = Map.of();
                }

                Map<String, Object> summary = buildSummary(config, modeResult, diagnostics);
                Map<String, Object> output = new LinkedHashMap<>();
                output.put("pipeline", List.of(
                    "mode_selection",
                    "input_validation",
                    "mx_resolution",
                    "smtp_interrogation",
                    "behavior_assessment",
                    "result_normalization",
                    "structured_output"
                ));
                output.put("mode", config.mode.value);
                output.put("seeds", seeds.toMap());
                output.put("summary", summary);
                output.put(config.mode.resultKey, modeResult);
                output.put("execution_metadata", buildExecutionMetadata(config, diagnostics, startedAt));

                result.setNormalizedOutput(buildNormalizedOutput(config, summary, modeResult));
                appendFindings(result, config, summary, modeResult, seeds);
                result.complete(output);

                ctx.log("[+] Email Verifier completed");
                ctx.reportProgress(100);
            } catch (Exception e) {
                result.fail("Execution failed: " + e.getMessage());
                ctx.log("[!] ERROR: " + e.getMessage());
            }

            return result;
        });
    }

    private Map<String, Object> collectSyntaxMxScreen(
        ScanConfig config,
        SeedSet seeds,
        ExecutionDiagnostics diagnostics,
        TaskContext ctx) {

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", config.mode.value);

        if (!seeds.primaryEmail.isBlank()) {
            out.put("syntax_validation", Map.of(
                "email", seeds.primaryEmail,
                "valid", isValidEmail(seeds.primaryEmail)
            ));
        }

        if (!seeds.invalidRecipients.isEmpty()) {
            out.put("invalid_email_inputs", new ArrayList<>(seeds.invalidRecipients));
        }

        List<MxRecord> mxRecords = queryMxRecords(seeds.domain, config, diagnostics);
        diagnostics.mxHostsResolved = mxRecords.size();
        out.put("mx_records", mapMxRecords(mxRecords));

        List<SmtpTarget> targets = buildSmtpTargets(config, mxRecords);
        List<Map<String, Object>> reachability = new ArrayList<>();
        for (SmtpTarget target : targets) {
            for (Integer port : config.smtpPorts) {
                TcpReachabilityResult tcp = testTcpReachability(target.host, port, config.connectTimeoutMs);
                diagnostics.portsTested.add(port);
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("host", target.host);
                row.put("source", target.source);
                row.put("port", port);
                row.put("reachable", tcp.reachable);
                row.put("latency_ms", tcp.durationMs);
                row.put("error", tcp.error);
                reachability.add(row);
                if (tcp.reachable) {
                    break;
                }
            }
        }

        boolean anyReachable = reachability.stream().anyMatch(entry -> Boolean.TRUE.equals(entry.get("reachable")));
        out.put("mx_reachability", reachability);
        out.put("domain_has_mx", !mxRecords.isEmpty());
        out.put("mx_reachable", anyReachable);
        out.put("mail_exchange_ready", !mxRecords.isEmpty() && anyReachable);
        out.put("signal_count", countSignals(out));
        ctx.log("[*] Syntax/MX screen resolved " + mxRecords.size() + " MX host(s)");
        return out;
    }

    private Map<String, Object> collectSmtpRecipientProbe(
        ScanConfig config,
        SeedSet seeds,
        ExecutionDiagnostics diagnostics,
        TaskContext ctx) {

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", config.mode.value);

        List<MxRecord> mxRecords = queryMxRecords(seeds.domain, config, diagnostics);
        diagnostics.mxHostsResolved = mxRecords.size();
        List<SmtpTarget> targets = buildSmtpTargets(config, mxRecords);

        out.put("mx_records", mapMxRecords(mxRecords));
        out.put("smtp_targets", mapSmtpTargets(targets));

        if (targets.isEmpty()) {
            diagnostics.warnings.add("No SMTP targets available for RCPT probing");
            out.put("recipient_results", List.of());
            out.put("accepted_count", 0);
            out.put("rejected_count", 0);
            out.put("temporary_count", 0);
            out.put("unknown_count", seeds.recipients.size());
            out.put("enumeration_feasible", false);
            out.put("signal_count", countSignals(out));
            return out;
        }

        int accepted = 0;
        int rejected = 0;
        int temporary = 0;
        int unknown = 0;
        List<Map<String, Object>> recipientResults = new ArrayList<>();

        for (String recipient : seeds.recipients) {
            RecipientProbeOutcome outcome = probeRecipientAcrossTargets(config, targets, recipient, diagnostics);
            recipientResults.add(outcome.toMap(config.includeRaw));

            switch (outcome.verdict) {
                case ACCEPTED -> accepted++;
                case REJECTED -> rejected++;
                case TEMPORARY -> temporary++;
                default -> unknown++;
            }
        }

        out.put("recipient_results", recipientResults);
        out.put("accepted_count", accepted);
        out.put("rejected_count", rejected);
        out.put("temporary_count", temporary);
        out.put("unknown_count", unknown);
        out.put("enumeration_feasible", accepted > 0 && rejected > 0);

        if (config.useSwaks && !seeds.recipients.isEmpty()) {
            Map<String, Object> swaksProbe = runSwaksProbe(targets.get(0), seeds.recipients.get(0), config, diagnostics);
            if (!swaksProbe.isEmpty()) {
                out.put("swaks_probe", swaksProbe);
            }
        }

        if (config.useSmtpCli && !seeds.recipients.isEmpty()) {
            Map<String, Object> smtpCliProbe = runSmtpCliProbe(targets.get(0), seeds.recipients.get(0), config, diagnostics);
            if (!smtpCliProbe.isEmpty()) {
                out.put("smtp_cli_probe", smtpCliProbe);
            }
        }

        out.put("signal_count", countSignals(out));
        ctx.log("[*] Recipient probe complete: accepted=" + accepted + ", rejected=" + rejected);
        return out;
    }

    private Map<String, Object> collectCatchAllAssessment(
        ScanConfig config,
        SeedSet seeds,
        ExecutionDiagnostics diagnostics,
        TaskContext ctx) {

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", config.mode.value);

        List<MxRecord> mxRecords = queryMxRecords(seeds.domain, config, diagnostics);
        diagnostics.mxHostsResolved = mxRecords.size();
        List<SmtpTarget> targets = buildSmtpTargets(config, mxRecords);

        out.put("mx_records", mapMxRecords(mxRecords));
        out.put("smtp_targets", mapSmtpTargets(targets));

        if (targets.isEmpty()) {
            diagnostics.warnings.add("No SMTP targets available for catch-all assessment");
            out.put("catch_all_detected", false);
            out.put("assessment", "unable_to_assess_no_smtp_target");
            out.put("signal_count", countSignals(out));
            return out;
        }

        List<String> decoys = generateDecoyRecipients(seeds.domain, config.catchallProbeCount);
        List<Map<String, Object>> decoyResults = new ArrayList<>();

        int acceptedDecoys = 0;
        int rejectedDecoys = 0;
        int temporaryDecoys = 0;

        for (String decoy : decoys) {
            RecipientProbeOutcome outcome = probeRecipientAcrossTargets(config, targets, decoy, diagnostics);
            decoyResults.add(outcome.toMap(config.includeRaw));
            switch (outcome.verdict) {
                case ACCEPTED -> acceptedDecoys++;
                case REJECTED -> rejectedDecoys++;
                case TEMPORARY -> temporaryDecoys++;
                default -> {
                }
            }
        }

        boolean catchAllDetected = !decoys.isEmpty() && acceptedDecoys == decoys.size();
        String assessment;
        if (catchAllDetected) {
            assessment = "catch_all_likely";
        } else if (rejectedDecoys == decoys.size()) {
            assessment = "mailbox_level_validation_present";
        } else {
            assessment = "mixed_or_temporal_behavior";
        }

        out.put("decoy_recipients", decoys);
        out.put("decoy_results", decoyResults);
        out.put("accepted_decoys", acceptedDecoys);
        out.put("rejected_decoys", rejectedDecoys);
        out.put("temporary_decoys", temporaryDecoys);
        out.put("catch_all_detected", catchAllDetected);
        out.put("assessment", assessment);
        out.put("confidence_score", computeCatchAllConfidence(catchAllDetected, rejectedDecoys, temporaryDecoys, decoys.size()));

        if (!seeds.primaryEmail.isBlank()) {
            RecipientProbeOutcome control = probeRecipientAcrossTargets(config, targets, seeds.primaryEmail, diagnostics);
            out.put("control_probe", control.toMap(config.includeRaw));
        }

        out.put("signal_count", countSignals(out));
        ctx.log("[*] Catch-all assessment: " + assessment);
        return out;
    }

    private Map<String, Object> collectMailSurfaceIntel(
        ScanConfig config,
        SeedSet seeds,
        ExecutionDiagnostics diagnostics,
        TaskContext ctx) {

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", config.mode.value);

        List<MxRecord> mxRecords = queryMxRecords(seeds.domain, config, diagnostics);
        diagnostics.mxHostsResolved = mxRecords.size();
        List<SmtpTarget> targets = buildSmtpTargets(config, mxRecords);

        out.put("mx_records", mapMxRecords(mxRecords));
        out.put("smtp_targets", mapSmtpTargets(targets));

        List<Map<String, Object>> serverProfiles = new ArrayList<>();
        Set<String> authMethods = new LinkedHashSet<>();
        int startTlsHosts = 0;

        for (SmtpTarget target : targets) {
            int inspectedPorts = 0;
            for (Integer port : config.smtpPorts) {
                if (inspectedPorts >= 2) {
                    break;
                }

                SmtpProbeResult probe = probeSmtpSession(
                    target.host,
                    port,
                    config.heloIdentity,
                    config.mailFrom,
                    "",
                    "",
                    config.connectTimeoutMs,
                    config.readTimeoutMs
                );

                diagnostics.smtpSessions.add(probe.toMap(config.includeRaw));
                diagnostics.portsTested.add(port);

                Map<String, Object> profile = probe.toMap(config.includeRaw);
                profile.put("source", target.source);
                profile.put("host", target.host);
                profile.put("port", port);
                serverProfiles.add(profile);

                if (probe.starttlsSupported) {
                    startTlsHosts++;
                }
                authMethods.addAll(probe.authMechanisms);

                inspectedPorts++;
            }
        }

        out.put("smtp_server_profiles", serverProfiles);
        out.put("starttls_supported_hosts", startTlsHosts);
        out.put("auth_mechanisms", new ArrayList<>(authMethods));

        if (config.probeRelayRestrictions && !targets.isEmpty()) {
            String relayRecipient = "relay-check@" + (seeds.domain.equalsIgnoreCase("example.net") ? "example.org" : "example.net");
            List<Map<String, Object>> relayChecks = new ArrayList<>();
            boolean openRelaySuspected = false;

            for (SmtpTarget target : targets) {
                SmtpProbeResult relayProbe = probeSmtpSession(
                    target.host,
                    config.smtpPorts.get(0),
                    config.heloIdentity,
                    config.mailFrom,
                    "",
                    relayRecipient,
                    config.connectTimeoutMs,
                    config.readTimeoutMs
                );

                diagnostics.smtpSessions.add(relayProbe.toMap(config.includeRaw));
                Map<String, Object> relayMap = relayProbe.toMap(config.includeRaw);
                RcptVerdict relayVerdict = classifyRcpt(relayProbe.relayCode);
                relayMap.put("relay_recipient", relayRecipient);
                relayMap.put("relay_verdict", relayVerdict.value);
                relayChecks.add(relayMap);

                if (relayVerdict == RcptVerdict.ACCEPTED) {
                    openRelaySuspected = true;
                }
            }

            out.put("relay_checks", relayChecks);
            out.put("open_relay_suspected", openRelaySuspected);
        }

        String probeRecipient = firstNonBlank(seeds.primaryEmail, "postmaster@" + seeds.domain);

        if (config.useSwaks && !targets.isEmpty()) {
            Map<String, Object> swaksProbe = runSwaksProbe(targets.get(0), probeRecipient, config, diagnostics);
            if (!swaksProbe.isEmpty()) {
                out.put("swaks_probe", swaksProbe);
            }
        }

        if (config.useSmtpCli && !targets.isEmpty()) {
            Map<String, Object> smtpCliProbe = runSmtpCliProbe(targets.get(0), probeRecipient, config, diagnostics);
            if (!smtpCliProbe.isEmpty()) {
                out.put("smtp_cli_probe", smtpCliProbe);
            }
        }

        if (config.useTheHarvester && !seeds.domain.isBlank()) {
            Map<String, Object> harvested = runTheHarvester(seeds.domain, config, diagnostics);
            if (!harvested.isEmpty()) {
                out.put("theharvester_result", harvested);
            }
        }

        if (config.useHolehe && !seeds.primaryEmail.isBlank()) {
            Map<String, Object> holehe = runHolehe(seeds.primaryEmail, config, diagnostics);
            if (!holehe.isEmpty()) {
                out.put("holehe_result", holehe);
            }
        }

        out.put("signal_count", countSignals(out));
        ctx.log("[*] Mail surface intel collected profiles=" + serverProfiles.size());
        return out;
    }

    private RecipientProbeOutcome probeRecipientAcrossTargets(
        ScanConfig config,
        List<SmtpTarget> targets,
        String recipient,
        ExecutionDiagnostics diagnostics) {

        RecipientProbeOutcome outcome = new RecipientProbeOutcome();
        outcome.recipient = recipient;
        outcome.verdict = RcptVerdict.UNKNOWN;

        for (SmtpTarget target : targets) {
            for (Integer port : config.smtpPorts) {
                SmtpProbeResult probe = probeSmtpSession(
                    target.host,
                    port,
                    config.heloIdentity,
                    config.mailFrom,
                    recipient,
                    "",
                    config.connectTimeoutMs,
                    config.readTimeoutMs
                );

                diagnostics.smtpSessions.add(probe.toMap(config.includeRaw));
                diagnostics.portsTested.add(port);

                Map<String, Object> attempt = probe.toMap(config.includeRaw);
                attempt.put("source", target.source);
                attempt.put("host", target.host);
                attempt.put("port", port);
                outcome.attempts.add(attempt);

                RcptVerdict verdict = classifyRcpt(probe.rcptCode);
                if (verdict == RcptVerdict.ACCEPTED || verdict == RcptVerdict.REJECTED) {
                    outcome.verdict = verdict;
                    outcome.bestProbe = probe;
                    outcome.bestProbeHost = target.host;
                    outcome.bestProbePort = port;
                    return outcome;
                }

                if (outcome.bestProbe == null && (probe.rcptCode > 0 || !probe.error.isBlank())) {
                    outcome.bestProbe = probe;
                    outcome.bestProbeHost = target.host;
                    outcome.bestProbePort = port;
                    outcome.verdict = verdict;
                }
            }
        }

        if (outcome.bestProbe == null) {
            outcome.verdict = RcptVerdict.UNREACHABLE;
        }
        return outcome;
    }

    protected List<MxRecord> queryMxRecords(String domain, ScanConfig config, ExecutionDiagnostics diagnostics) {
        if (domain.isBlank()) {
            return List.of();
        }

        long startedAt = System.currentTimeMillis();
        List<MxRecord> mxRecords = new ArrayList<>();

        if (isCommandAvailable("dig")) {
            List<String> command = List.of("dig", "+short", "MX", domain);
            CommandExecutionResult result = runCommand(command, config.commandTimeoutMs);
            recordCommandExecution(diagnostics, "dig", command, result);
            if (!result.timedOut && result.exitCode == 0) {
                mxRecords.addAll(parseDigMx(result.stdout));
            } else if (!result.stderr.isBlank()) {
                diagnostics.warnings.add("dig MX lookup failed: " + result.stderr.trim());
            }
        }

        if (mxRecords.isEmpty() && isCommandAvailable("nslookup")) {
            List<String> command = List.of("nslookup", "-type=mx", domain);
            CommandExecutionResult result = runCommand(command, config.commandTimeoutMs);
            recordCommandExecution(diagnostics, "nslookup", command, result);
            if (!result.timedOut && result.exitCode == 0) {
                mxRecords.addAll(parseNslookupMx(result.stdout));
            } else if (!result.stderr.isBlank()) {
                diagnostics.warnings.add("nslookup MX lookup failed: " + result.stderr.trim());
            }
        }

        if (!config.smtpHostOverride.isBlank()) {
            mxRecords.add(new MxRecord(0, normalizeHost(config.smtpHostOverride), "smtp_host_override"));
        }

        Map<String, MxRecord> dedup = new LinkedHashMap<>();
        for (MxRecord record : mxRecords) {
            String key = record.priority + "|" + record.host.toLowerCase(Locale.ROOT);
            dedup.putIfAbsent(key, record);
        }

        List<MxRecord> ordered = new ArrayList<>(dedup.values());
        ordered.sort(Comparator.comparingInt((MxRecord item) -> item.priority).thenComparing(item -> item.host));
        diagnostics.mxLookupDurationMs = System.currentTimeMillis() - startedAt;

        if (ordered.isEmpty()) {
            diagnostics.warnings.add("No MX records resolved for domain " + domain);
        }
        return ordered;
    }

    protected TcpReachabilityResult testTcpReachability(String host, int port, int connectTimeoutMs) {
        long startedAt = System.currentTimeMillis();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), Math.max(500, connectTimeoutMs));
            return new TcpReachabilityResult(true, System.currentTimeMillis() - startedAt, "");
        } catch (Exception e) {
            return new TcpReachabilityResult(false, System.currentTimeMillis() - startedAt, e.getMessage());
        }
    }

    protected SmtpProbeResult probeSmtpSession(
        String host,
        int port,
        String heloIdentity,
        String mailFrom,
        String rcptTo,
        String relayRcptTo,
        int connectTimeoutMs,
        int readTimeoutMs) {

        SmtpProbeResult result = new SmtpProbeResult();
        result.host = host;
        result.port = port;
        long startedAt = System.currentTimeMillis();

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), Math.max(500, connectTimeoutMs));
            socket.setSoTimeout(Math.max(500, readTimeoutMs));
            result.connectionEstablished = true;

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
                 BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.US_ASCII))) {

                SmtpResponse banner = readSmtpResponse(reader);
                result.bannerCode = banner.code;
                result.bannerMessage = banner.message;
                result.transcript.addAll(banner.lines);

                sendSmtpCommand(writer, "EHLO " + firstNonBlank(heloIdentity, "jrts.local"));
                SmtpResponse ehlo = readSmtpResponse(reader);
                result.ehloCode = ehlo.code;
                result.ehloCapabilities.addAll(extractEhloCapabilities(ehlo.lines));
                result.authMechanisms.addAll(extractAuthMechanisms(result.ehloCapabilities));
                result.starttlsSupported = hasStartTls(result.ehloCapabilities);
                result.transcript.addAll(ehlo.lines);

                boolean needsMailFrom = !rcptTo.isBlank() || !relayRcptTo.isBlank();
                if (needsMailFrom) {
                    sendSmtpCommand(writer, "MAIL FROM:<" + firstNonBlank(mailFrom, "verifier@local.test") + ">");
                    SmtpResponse mailFromResponse = readSmtpResponse(reader);
                    result.mailFromCode = mailFromResponse.code;
                    result.mailFromMessage = mailFromResponse.message;
                    result.transcript.addAll(mailFromResponse.lines);
                }

                if (!rcptTo.isBlank()) {
                    sendSmtpCommand(writer, "RCPT TO:<" + rcptTo + ">");
                    SmtpResponse rcptResponse = readSmtpResponse(reader);
                    result.rcptCode = rcptResponse.code;
                    result.rcptMessage = rcptResponse.message;
                    result.transcript.addAll(rcptResponse.lines);
                }

                if (!relayRcptTo.isBlank()) {
                    sendSmtpCommand(writer, "RCPT TO:<" + relayRcptTo + ">");
                    SmtpResponse relayResponse = readSmtpResponse(reader);
                    result.relayCode = relayResponse.code;
                    result.relayMessage = relayResponse.message;
                    result.transcript.addAll(relayResponse.lines);
                }

                sendSmtpCommand(writer, "QUIT");
                SmtpResponse quit = readSmtpResponse(reader);
                result.transcript.addAll(quit.lines);
            }
        } catch (IOException e) {
            result.error = e.getMessage() == null ? "smtp_io_error" : e.getMessage();
            result.timedOut = isTimeoutMessage(result.error);
        } catch (Exception e) {
            result.error = e.getMessage() == null ? "smtp_probe_failed" : e.getMessage();
        }

        result.durationMs = System.currentTimeMillis() - startedAt;
        return result;
    }

    private Map<String, Object> runSwaksProbe(
        SmtpTarget target,
        String recipient,
        ScanConfig config,
        ExecutionDiagnostics diagnostics) {

        if (!isCommandAvailable("swaks")) {
            diagnostics.warnings.add("swaks requested but not available");
            return Map.of();
        }

        List<String> command = List.of(
            "swaks",
            "--server", target.host,
            "--port", String.valueOf(config.smtpPorts.get(0)),
            "--to", recipient,
            "--from", config.mailFrom,
            "--timeout", String.valueOf(Math.max(2, config.commandTimeoutMs / 1000)),
            "--quit-after", "RCPT"
        );

        CommandExecutionResult result = runCommand(command, config.commandTimeoutMs);
        recordCommandExecution(diagnostics, "swaks", command, result);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("available", true);
        out.put("exit_code", result.exitCode);
        out.put("timed_out", result.timedOut);
        out.put("duration_ms", result.durationMs);
        out.put("smtp_codes", extractSmtpCodes(result.stdout));

        if (!result.stderr.isBlank()) {
            out.put("stderr", result.stderr.trim());
        }
        if (config.includeRaw) {
            out.put("raw_output", result.stdout);
        }
        return out;
    }

    private Map<String, Object> runSmtpCliProbe(
        SmtpTarget target,
        String recipient,
        ScanConfig config,
        ExecutionDiagnostics diagnostics) {

        if (!isCommandAvailable("smtp-cli")) {
            diagnostics.warnings.add("smtp-cli requested but not available");
            return Map.of();
        }

        List<String> command = List.of(
            "smtp-cli",
            "--host", target.host,
            "--port", String.valueOf(config.smtpPorts.get(0)),
            "--from", config.mailFrom,
            "--to", recipient,
            "--timeout", String.valueOf(Math.max(2, config.commandTimeoutMs / 1000))
        );

        CommandExecutionResult result = runCommand(command, config.commandTimeoutMs);
        recordCommandExecution(diagnostics, "smtp-cli", command, result);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("available", true);
        out.put("exit_code", result.exitCode);
        out.put("timed_out", result.timedOut);
        out.put("duration_ms", result.durationMs);
        out.put("smtp_codes", extractSmtpCodes(result.stdout));

        if (!result.stderr.isBlank()) {
            out.put("stderr", result.stderr.trim());
        }
        if (config.includeRaw) {
            out.put("raw_output", result.stdout);
        }
        return out;
    }

    private Map<String, Object> runTheHarvester(
        String domain,
        ScanConfig config,
        ExecutionDiagnostics diagnostics) {

        if (!isCommandAvailable("theHarvester")) {
            diagnostics.warnings.add("theHarvester requested but not available");
            return Map.of();
        }

        List<String> command = List.of("theHarvester", "-d", domain, "-b", "all", "-l", "100");
        CommandExecutionResult result = runCommand(command, config.commandTimeoutMs);
        recordCommandExecution(diagnostics, "theHarvester", command, result);

        Set<String> discoveredEmails = new LinkedHashSet<>();
        Matcher matcher = THEHARVESTER_EMAIL_PATTERN.matcher(result.stdout);
        while (matcher.find()) {
            discoveredEmails.add(matcher.group().toLowerCase(Locale.ROOT));
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("available", true);
        out.put("exit_code", result.exitCode);
        out.put("timed_out", result.timedOut);
        out.put("emails", new ArrayList<>(discoveredEmails));
        out.put("email_count", discoveredEmails.size());
        if (config.includeRaw) {
            out.put("raw_output", result.stdout);
        }
        return out;
    }

    private Map<String, Object> runHolehe(
        String email,
        ScanConfig config,
        ExecutionDiagnostics diagnostics) {

        if (!isCommandAvailable("holehe")) {
            diagnostics.warnings.add("holehe requested but not available");
            return Map.of();
        }

        List<String> command = List.of("holehe", email);
        CommandExecutionResult result = runCommand(command, config.commandTimeoutMs);
        recordCommandExecution(diagnostics, "holehe", command, result);

        Set<String> services = new LinkedHashSet<>();
        for (String line : splitLines(result.stdout)) {
            Matcher matcher = HOLEHE_SERVICE_PATTERN.matcher(line.trim());
            if (matcher.find()) {
                services.add(matcher.group(1).trim());
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("available", true);
        out.put("exit_code", result.exitCode);
        out.put("timed_out", result.timedOut);
        out.put("services", new ArrayList<>(services));
        out.put("service_count", services.size());
        if (config.includeRaw) {
            out.put("raw_output", result.stdout);
        }
        return out;
    }

    private SmtpResponse readSmtpResponse(BufferedReader reader) throws IOException {
        List<String> lines = new ArrayList<>();
        int code = 0;
        String message = "";

        for (int i = 0; i < 40; i++) {
            String line = reader.readLine();
            if (line == null) {
                break;
            }

            lines.add(line);
            Matcher matcher = SMTP_RESPONSE_PATTERN.matcher(line);
            if (matcher.find()) {
                code = parseInteger(matcher.group(1), code);
                message = matcher.group(3).trim();
                String separator = matcher.group(2);
                if (" ".equals(separator)) {
                    break;
                }
            } else {
                message = line.trim();
                break;
            }
        }

        return new SmtpResponse(code, message, lines);
    }

    private void sendSmtpCommand(BufferedWriter writer, String command) throws IOException {
        writer.write(command);
        writer.write("\r\n");
        writer.flush();
    }

    private List<String> extractEhloCapabilities(List<String> ehloLines) {
        List<String> capabilities = new ArrayList<>();
        for (String line : ehloLines) {
            Matcher matcher = SMTP_RESPONSE_PATTERN.matcher(line);
            String capability = line;
            if (matcher.find()) {
                capability = matcher.group(3).trim();
            }
            if (!capability.isBlank() && !capability.equalsIgnoreCase("ok")) {
                capabilities.add(capability);
            }
        }
        return capabilities;
    }

    private List<String> extractAuthMechanisms(List<String> capabilities) {
        Set<String> methods = new LinkedHashSet<>();
        for (String capability : capabilities) {
            Matcher matcher = AUTH_LINE_PATTERN.matcher(capability);
            if (matcher.find()) {
                String[] parts = matcher.group(1).trim().split("\\s+");
                for (String part : parts) {
                    if (!part.isBlank()) {
                        methods.add(part.toUpperCase(Locale.ROOT));
                    }
                }
            }
        }
        return new ArrayList<>(methods);
    }

    private boolean hasStartTls(List<String> capabilities) {
        for (String capability : capabilities) {
            if (capability.toUpperCase(Locale.ROOT).contains("STARTTLS")) {
                return true;
            }
        }
        return false;
    }

    private List<Integer> extractSmtpCodes(String rawText) {
        if (rawText == null || rawText.isBlank()) {
            return List.of();
        }
        LinkedHashSet<Integer> codes = new LinkedHashSet<>();
        Matcher matcher = Pattern.compile("\\b([245]\\d\\d)\\b").matcher(rawText);
        while (matcher.find()) {
            codes.add(parseInteger(matcher.group(1), -1));
        }
        return new ArrayList<>(codes);
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

    private void recordCommandExecution(
        ExecutionDiagnostics diagnostics,
        String tool,
        List<String> command,
        CommandExecutionResult result) {

        diagnostics.commandExecutions++;
        diagnostics.toolUsage.add(tool);

        String commandText = String.join(" ", command);
        diagnostics.executedCommands.add(commandText);

        Map<String, Object> record = new LinkedHashMap<>();
        record.put("tool", tool);
        record.put("command", commandText);
        record.put("status", result.timedOut ? "timeout" : (result.exitCode == 0 ? "success" : "failed"));
        record.put("exit_code", result.exitCode);
        record.put("timed_out", result.timedOut);
        record.put("duration_ms", result.durationMs);

        String stdoutPreview = truncatePreview(firstNonBlank(firstLine(result.stdout), result.stdout), 260);
        if (!stdoutPreview.isBlank()) {
            record.put("stdout_preview", stdoutPreview);
        }

        String stderrPreview = truncatePreview(firstNonBlank(firstLine(result.stderr), result.stderr), 260);
        if (!stderrPreview.isBlank()) {
            record.put("stderr_preview", stderrPreview);
        }

        diagnostics.commandLog.add(record);
    }

    private String truncatePreview(String value, int maxLength) {
        String normalized = trim(value).replaceAll("\\s+", " ");
        if (normalized.length() <= maxLength) {
            return normalized;
        }
        return normalized.substring(0, maxLength - 3) + "...";
    }

    private String firstLine(String text) {
        if (text == null || text.isBlank()) {
            return "";
        }
        String[] lines = text.split("\\R", 2);
        return lines.length == 0 ? "" : lines[0].trim();
    }

    private ScanConfig parseConfig(Map<String, String> input) {
        ScanConfig config = new ScanConfig();

        config.mode = ModuleMode.fromInput(input.get("mode"));
        config.targetEmail = normalizeEmail(input.get("target_email"));
        config.targetDomain = normalizeDomain(input.get("target_domain"));
        config.emailList = trim(input.get("email_list"));

        HostPort override = parseHostPort(input.get("smtp_host_override"));
        config.smtpHostOverride = override.host;
        config.smtpPorts = parsePorts(input.get("smtp_ports"), List.of(25, 587));
        if (override.port > 0 && !config.smtpPorts.contains(override.port)) {
            config.smtpPorts.add(0, override.port);
        }

        config.mailFrom = normalizeEmail(firstNonBlank(input.get("mail_from"), "verifier@local.test"));
        config.heloIdentity = firstNonBlank(input.get("helo_identity"), "jrts.local");

        config.catchallProbeCount = Math.max(2, parseInteger(input.get("catchall_probe_count"), DEFAULT_CATCHALL_PROBE_COUNT));
        config.maxMxHosts = Math.max(1, parseInteger(input.get("max_mx_hosts"), DEFAULT_MAX_MX_HOSTS));

        config.probeRelayRestrictions = parseBoolean(input.get("probe_relay_restrictions"), false);
        config.useSwaks = parseBoolean(input.get("use_swaks"), true);
        config.useSmtpCli = parseBoolean(input.get("use_smtp_cli"), false);
        config.useTheHarvester = parseBoolean(input.get("use_theharvester"), false);
        config.useHolehe = parseBoolean(input.get("use_holehe"), false);

        config.connectTimeoutMs = parseInteger(input.get("connect_timeout_ms"), DEFAULT_CONNECT_TIMEOUT_MS);
        config.readTimeoutMs = parseInteger(input.get("read_timeout_ms"), DEFAULT_READ_TIMEOUT_MS);
        config.commandTimeoutMs = parseInteger(input.get("command_timeout_ms"), DEFAULT_COMMAND_TIMEOUT_MS);
        config.includeRaw = parseBoolean(input.get("include_raw"), false);
        return config;
    }

    private SeedSet buildSeedSet(ScanConfig config) {
        SeedSet seeds = new SeedSet();
        seeds.primaryEmail = config.targetEmail;
        seeds.domain = firstNonBlank(config.targetDomain, domainFromEmail(config.targetEmail)).toLowerCase(Locale.ROOT);

        LinkedHashSet<String> recipientSet = new LinkedHashSet<>();
        if (!config.targetEmail.isBlank()) {
            recipientSet.add(config.targetEmail);
        }

        for (String candidate : parseEmailList(config.emailList)) {
            if (isValidEmail(candidate)) {
                recipientSet.add(candidate.toLowerCase(Locale.ROOT));
            } else {
                seeds.invalidRecipients.add(candidate);
            }
        }

        seeds.recipients.addAll(recipientSet);
        return seeds;
    }

    private List<String> validateConfig(ScanConfig config, SeedSet seeds) {
        List<String> errors = new ArrayList<>();

        if (!config.targetEmail.isBlank() && !isValidEmail(config.targetEmail)) {
            errors.add("target_email must be a valid email address");
        }

        if (!seeds.domain.isBlank() && !isValidDomain(seeds.domain)) {
            errors.add("resolved domain must be a valid domain");
        }

        if (config.smtpPorts.isEmpty()) {
            errors.add("at least one valid SMTP port is required");
        }

        switch (config.mode) {
            case SYNTAX_MX_SCREEN -> {
                if (seeds.domain.isBlank() && config.targetEmail.isBlank()) {
                    errors.add("syntax_mx_screen requires target_email or target_domain");
                }
            }
            case SMTP_RECIPIENT_PROBE -> {
                if (seeds.domain.isBlank()) {
                    errors.add("smtp_recipient_probe requires target_domain or target_email");
                }
                if (seeds.recipients.isEmpty()) {
                    errors.add("smtp_recipient_probe requires at least one recipient from target_email or email_list");
                }
            }
            case CATCH_ALL_ASSESSMENT -> {
                if (seeds.domain.isBlank()) {
                    errors.add("catch_all_assessment requires target_domain or target_email");
                }
                if (config.catchallProbeCount < 2) {
                    errors.add("catchall_probe_count must be >= 2");
                }
            }
            case MAIL_SURFACE_INTEL -> {
                if (seeds.domain.isBlank()) {
                    errors.add("mail_surface_intel requires target_domain or target_email");
                }
            }
        }

        if ((config.mode == ModuleMode.SMTP_RECIPIENT_PROBE || config.mode == ModuleMode.CATCH_ALL_ASSESSMENT)
            && !seeds.invalidRecipients.isEmpty()) {
            errors.add("invalid emails in email_list: " + String.join(", ", seeds.invalidRecipients));
        }

        return errors;
    }

    private Map<String, Object> buildSummary(ScanConfig config, Map<String, Object> modeResult, ExecutionDiagnostics diagnostics) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", config.mode.value);
        summary.put("mx_hosts_resolved", diagnostics.mxHostsResolved);
        summary.put("smtp_sessions", diagnostics.smtpSessions.size());
        summary.put("warnings", diagnostics.warnings.size());

        switch (config.mode) {
            case SYNTAX_MX_SCREEN -> {
                summary.put("domain_has_mx", Boolean.TRUE.equals(modeResult.get("domain_has_mx")));
                summary.put("mx_reachable", Boolean.TRUE.equals(modeResult.get("mx_reachable")));
                summary.put("mail_exchange_ready", Boolean.TRUE.equals(modeResult.get("mail_exchange_ready")));
                summary.put("enumeration_possible", false);
                summary.put("catch_all_detected", false);
                summary.put("open_relay_suspected", false);
            }
            case SMTP_RECIPIENT_PROBE -> {
                int accepted = asInt(modeResult.get("accepted_count"));
                int rejected = asInt(modeResult.get("rejected_count"));
                summary.put("accepted_count", accepted);
                summary.put("rejected_count", rejected);
                summary.put("temporary_count", asInt(modeResult.get("temporary_count")));
                summary.put("enumeration_possible", accepted > 0 && rejected > 0);
                summary.put("catch_all_detected", false);
                summary.put("open_relay_suspected", false);
            }
            case CATCH_ALL_ASSESSMENT -> {
                summary.put("accepted_decoys", asInt(modeResult.get("accepted_decoys")));
                summary.put("rejected_decoys", asInt(modeResult.get("rejected_decoys")));
                summary.put("temporary_decoys", asInt(modeResult.get("temporary_decoys")));
                summary.put("catch_all_detected", Boolean.TRUE.equals(modeResult.get("catch_all_detected")));
                summary.put("enumeration_possible", !Boolean.TRUE.equals(modeResult.get("catch_all_detected")));
                summary.put("open_relay_suspected", false);
            }
            case MAIL_SURFACE_INTEL -> {
                summary.put("starttls_supported_hosts", asInt(modeResult.get("starttls_supported_hosts")));
                summary.put("auth_mechanism_count", asStringList(modeResult.get("auth_mechanisms")).size());
                summary.put("open_relay_suspected", Boolean.TRUE.equals(modeResult.get("open_relay_suspected")));
                summary.put("enumeration_possible", false);
                summary.put("catch_all_detected", false);
            }
        }

        summary.put("confidence_score", computeConfidenceScore(config.mode, summary));
        return summary;
    }

    private int computeConfidenceScore(ModuleMode mode, Map<String, Object> summary) {
        int score = 25 + Math.min(20, asInt(summary.get("mx_hosts_resolved")) * 8) + Math.min(10, asInt(summary.get("smtp_sessions")));

        switch (mode) {
            case SYNTAX_MX_SCREEN -> {
                if (Boolean.TRUE.equals(summary.get("mail_exchange_ready"))) {
                    score += 25;
                }
            }
            case SMTP_RECIPIENT_PROBE -> {
                if (Boolean.TRUE.equals(summary.get("enumeration_possible"))) {
                    score += 35;
                } else if (asInt(summary.get("accepted_count")) > 0 || asInt(summary.get("rejected_count")) > 0) {
                    score += 20;
                }
            }
            case CATCH_ALL_ASSESSMENT -> {
                if (Boolean.TRUE.equals(summary.get("catch_all_detected"))) {
                    score += 35;
                } else {
                    score += 20;
                }
            }
            case MAIL_SURFACE_INTEL -> {
                score += Math.min(15, asInt(summary.get("starttls_supported_hosts")) * 5);
                score += Math.min(10, asInt(summary.get("auth_mechanism_count")) * 2);
                if (Boolean.TRUE.equals(summary.get("open_relay_suspected"))) {
                    score += 20;
                }
            }
        }

        score -= Math.min(20, asInt(summary.get("warnings")) * 4);
        return Math.max(0, Math.min(100, score));
    }

    private Map<String, Object> buildExecutionMetadata(ScanConfig config, ExecutionDiagnostics diagnostics, long startedAt) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("module", MODULE_ID);
        metadata.put("mode", config.mode.value);
        metadata.put("tools_used", new ArrayList<>(diagnostics.toolUsage));
        metadata.put("mx_lookup_duration_ms", diagnostics.mxLookupDurationMs);
        metadata.put("mx_hosts_resolved", diagnostics.mxHostsResolved);
        metadata.put("smtp_sessions", diagnostics.smtpSessions);
        metadata.put("command_executions", diagnostics.commandExecutions);
        metadata.put("executed_commands", diagnostics.executedCommands);
        metadata.put("command_log", diagnostics.commandLog);
        metadata.put("ports_tested", new ArrayList<>(diagnostics.portsTested));
        metadata.put("warnings", diagnostics.warnings);
        metadata.put("elapsed_ms", System.currentTimeMillis() - startedAt);
        return metadata;
    }

    private Map<String, Object> buildNormalizedOutput(
        ScanConfig config,
        Map<String, Object> summary,
        Map<String, Object> modeResult) {

        Map<String, Object> normalized = new LinkedHashMap<>();

        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("mode", config.mode.value);
        raw.put("summary", summary);
        raw.put("result", modeResult);
        normalized.put("raw_output", raw);

        boolean enumerationPossible = Boolean.TRUE.equals(summary.get("enumeration_possible"));
        boolean catchAllDetected = Boolean.TRUE.equals(summary.get("catch_all_detected"));
        boolean openRelaySuspected = Boolean.TRUE.equals(summary.get("open_relay_suspected"));
        boolean vulnerable = enumerationPossible || catchAllDetected || openRelaySuspected;

        Map<String, Object> parsed = new LinkedHashMap<>();
        parsed.put("status", vulnerable
            ? "SMTP_ENUMERATION_SURFACE_PRESENT"
            : "SMTP_SURFACE_OBSERVED_WITH_LIMITED_ENUMERATION");
        parsed.put("vulnerable", vulnerable);
        parsed.put("details", summary);
        parsed.put("evidence", modeResult);
        normalized.put("parsed_output", parsed);

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("module", MODULE_ID);
        metadata.put("mode", config.mode.value);
        normalized.put("metadata", metadata);

        return normalized;
    }

    private void appendFindings(
        ModuleResult result,
        ScanConfig config,
        Map<String, Object> summary,
        Map<String, Object> modeResult,
        SeedSet seeds) {

        Map<String, Object> topFinding = new LinkedHashMap<>();
        topFinding.put("type", "email_verification_summary");
        topFinding.put("mode", config.mode.value);
        topFinding.put("seeds", seeds.toMap());
        topFinding.put("summary", summary);
        result.addFinding(topFinding);

        if (config.mode == ModuleMode.SMTP_RECIPIENT_PROBE) {
            for (Map<String, Object> row : asListMap(modeResult.get("recipient_results"))) {
                Map<String, Object> finding = new LinkedHashMap<>();
                finding.put("type", "recipient_probe");
                finding.put("recipient", row.get("recipient"));
                finding.put("verdict", row.get("verdict"));
                finding.put("smtp_code", row.get("rcpt_code"));
                finding.put("smtp_message", row.get("rcpt_message"));
                finding.put("host", row.get("host"));
                finding.put("port", row.get("port"));
                result.addFinding(finding);
            }
        }

        if (config.mode == ModuleMode.CATCH_ALL_ASSESSMENT) {
            Map<String, Object> finding = new LinkedHashMap<>();
            finding.put("type", "catch_all_assessment");
            finding.put("catch_all_detected", modeResult.get("catch_all_detected"));
            finding.put("assessment", modeResult.get("assessment"));
            finding.put("confidence_score", modeResult.get("confidence_score"));
            result.addFinding(finding);
        }

        if (config.mode == ModuleMode.MAIL_SURFACE_INTEL && Boolean.TRUE.equals(modeResult.get("open_relay_suspected"))) {
            Map<String, Object> finding = new LinkedHashMap<>();
            finding.put("type", "relay_restriction_signal");
            finding.put("open_relay_suspected", true);
            result.addFinding(finding);
        }
    }

    private int countSignals(Map<String, Object> map) {
        int count = 0;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if ("mode".equals(entry.getKey())) {
                continue;
            }
            Object value = entry.getValue();
            if (value instanceof Boolean b && b) {
                count++;
            } else if (value instanceof Number number && number.doubleValue() > 0) {
                count++;
            } else if (value instanceof String str && !str.isBlank()) {
                count++;
            } else if (value instanceof List<?> list && !list.isEmpty()) {
                count++;
            } else if (value instanceof Map<?, ?> nested && !nested.isEmpty()) {
                count++;
            }
        }
        return count;
    }

    private double computeCatchAllConfidence(boolean catchAllDetected, int rejected, int temporary, int sampleSize) {
        if (sampleSize <= 0) {
            return 0.0;
        }
        if (catchAllDetected) {
            double penalty = Math.min(0.3, temporary * 0.1);
            return roundDouble(0.92 - penalty);
        }
        if (rejected == sampleSize) {
            return 0.9;
        }
        return roundDouble(0.55 - Math.min(0.2, temporary * 0.05));
    }

    private double roundDouble(double value) {
        return Math.round(value * 100.0) / 100.0;
    }

    private RcptVerdict classifyRcpt(int code) {
        if (code == 250 || code == 251 || code == 252) {
            return RcptVerdict.ACCEPTED;
        }
        if (code == 550 || code == 551 || code == 553) {
            return RcptVerdict.REJECTED;
        }
        if (code == 421 || code == 450 || code == 451 || code == 452) {
            return RcptVerdict.TEMPORARY;
        }
        if (code <= 0) {
            return RcptVerdict.UNREACHABLE;
        }
        return RcptVerdict.UNKNOWN;
    }

    private List<Map<String, Object>> mapMxRecords(List<MxRecord> records) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (MxRecord record : records) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("priority", record.priority);
            row.put("host", record.host);
            row.put("source", record.source);
            out.add(row);
        }
        return out;
    }

    private List<Map<String, Object>> mapSmtpTargets(List<SmtpTarget> targets) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (SmtpTarget target : targets) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("host", target.host);
            row.put("source", target.source);
            out.add(row);
        }
        return out;
    }

    private List<SmtpTarget> buildSmtpTargets(ScanConfig config, List<MxRecord> mxRecords) {
        List<SmtpTarget> targets = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();

        if (!config.smtpHostOverride.isBlank()) {
            String host = normalizeHost(config.smtpHostOverride);
            if (!host.isBlank()) {
                targets.add(new SmtpTarget(host, "smtp_host_override"));
                seen.add(host.toLowerCase(Locale.ROOT));
            }
        }

        for (MxRecord record : mxRecords) {
            if (targets.size() >= config.maxMxHosts) {
                break;
            }
            String key = record.host.toLowerCase(Locale.ROOT);
            if (seen.add(key)) {
                targets.add(new SmtpTarget(record.host, record.source));
            }
        }

        return targets;
    }

    private List<String> generateDecoyRecipients(String domain, int count) {
        if (domain.isBlank()) {
            return List.of();
        }

        int seed = Math.abs(domain.hashCode());
        List<String> out = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            int suffix = Math.abs(seed + (i * 113)) % 10_000;
            String local = String.format("probe-%02d-%04d", i, suffix);
            out.add(local + "@" + domain);
        }
        return out;
    }

    private List<MxRecord> parseDigMx(String stdout) {
        List<MxRecord> records = new ArrayList<>();
        for (String line : splitLines(stdout)) {
            Matcher matcher = DIG_MX_PATTERN.matcher(line.trim());
            if (matcher.find()) {
                int priority = parseInteger(matcher.group(1), 0);
                String host = normalizeHost(matcher.group(2));
                if (!host.isBlank()) {
                    records.add(new MxRecord(priority, host, "dig"));
                }
            }
        }
        return records;
    }

    private List<MxRecord> parseNslookupMx(String stdout) {
        List<MxRecord> records = new ArrayList<>();
        for (String line : splitLines(stdout)) {
            Matcher matcher = NSLOOKUP_MX_PATTERN.matcher(line);
            if (matcher.find()) {
                int priority = parseInteger(matcher.group(1), 0);
                String host = normalizeHost(matcher.group(2));
                if (!host.isBlank()) {
                    records.add(new MxRecord(priority, host, "nslookup"));
                }
            }
        }
        return records;
    }

    private List<String> parseEmailList(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }

        LinkedHashSet<String> emails = new LinkedHashSet<>();
        String[] parts = raw.split("[,;\\n\\r\\s]+");
        for (String part : parts) {
            String normalized = normalizeEmail(part);
            if (!normalized.isBlank()) {
                emails.add(normalized);
            }
        }
        return new ArrayList<>(emails);
    }

    private List<Integer> parsePorts(String raw, List<Integer> defaultPorts) {
        LinkedHashSet<Integer> ports = new LinkedHashSet<>();
        String source = trim(raw);

        if (source.isBlank()) {
            ports.addAll(defaultPorts);
        } else {
            String[] parts = source.split("[,;\\s]+");
            for (String part : parts) {
                int port = parseInteger(part, -1);
                if (port > 0 && port <= 65_535) {
                    ports.add(port);
                }
            }
        }

        if (ports.isEmpty()) {
            ports.addAll(defaultPorts);
        }
        return new ArrayList<>(ports);
    }

    private HostPort parseHostPort(String raw) {
        String value = trim(raw);
        if (value.isBlank()) {
            return new HostPort("", -1);
        }

        int firstColon = value.indexOf(':');
        int lastColon = value.lastIndexOf(':');
        if (firstColon > 0 && firstColon == lastColon) {
            String host = normalizeHost(value.substring(0, lastColon));
            int port = parseInteger(value.substring(lastColon + 1), -1);
            if (port > 0 && port <= 65_535) {
                return new HostPort(host, port);
            }
            return new HostPort(host, -1);
        }

        return new HostPort(normalizeHost(value), -1);
    }

    private boolean isValidEmail(String email) {
        return EMAIL_PATTERN.matcher(trim(email)).matches();
    }

    private boolean isValidDomain(String domain) {
        return DOMAIN_PATTERN.matcher(trim(domain)).matches();
    }

    private String domainFromEmail(String email) {
        String normalized = normalizeEmail(email);
        int at = normalized.indexOf('@');
        if (at < 0 || at == normalized.length() - 1) {
            return "";
        }
        return normalizeDomain(normalized.substring(at + 1));
    }

    private String normalizeEmail(String value) {
        return trim(value).toLowerCase(Locale.ROOT);
    }

    private String normalizeDomain(String value) {
        String domain = trim(value).toLowerCase(Locale.ROOT);
        if (domain.startsWith("http://")) {
            domain = domain.substring("http://".length());
        } else if (domain.startsWith("https://")) {
            domain = domain.substring("https://".length());
        }
        int slash = domain.indexOf('/');
        if (slash >= 0) {
            domain = domain.substring(0, slash);
        }
        domain = domain.replaceAll("\\.+$", "");
        return domain;
    }

    private String normalizeHost(String value) {
        String host = normalizeDomain(value);
        if (host.startsWith("[")) {
            host = host.substring(1);
        }
        if (host.endsWith("]")) {
            host = host.substring(0, host.length() - 1);
        }
        return host;
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

    private int asInt(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String str) {
            return parseInteger(str, 0);
        }
        return 0;
    }

    private List<Map<String, Object>> asListMap(Object value) {
        if (!(value instanceof List<?> list)) {
            return List.of();
        }

        List<Map<String, Object>> out = new ArrayList<>();
        for (Object item : list) {
            if (item instanceof Map<?, ?> map) {
                Map<String, Object> row = new LinkedHashMap<>();
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (entry.getKey() != null) {
                        row.put(String.valueOf(entry.getKey()), entry.getValue());
                    }
                }
                out.add(row);
            }
        }
        return out;
    }

    private List<String> asStringList(Object value) {
        if (!(value instanceof List<?> list)) {
            return List.of();
        }

        List<String> out = new ArrayList<>();
        for (Object item : list) {
            if (item != null) {
                out.add(String.valueOf(item));
            }
        }
        return out;
    }

    private boolean isTimeoutMessage(String message) {
        if (message == null) {
            return false;
        }
        String normalized = message.toLowerCase(Locale.ROOT);
        return normalized.contains("timed out") || normalized.contains("timeout");
    }

    private List<String> splitLines(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }

        List<String> lines = new ArrayList<>();
        String[] split = text.split("\\r?\\n");
        Collections.addAll(lines, split);
        return lines;
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
        SYNTAX_MX_SCREEN("syntax_mx_screen", "syntax_mx_screen_result"),
        SMTP_RECIPIENT_PROBE("smtp_recipient_probe", "smtp_recipient_probe_result"),
        CATCH_ALL_ASSESSMENT("catch_all_assessment", "catch_all_assessment_result"),
        MAIL_SURFACE_INTEL("mail_surface_intel", "mail_surface_intel_result");

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
                case "smtp_recipient_probe", "smtp_probe", "recipient_probe" -> SMTP_RECIPIENT_PROBE;
                case "catch_all_assessment", "catchall", "catch_all" -> CATCH_ALL_ASSESSMENT;
                case "mail_surface_intel", "surface_intel", "mail_intel" -> MAIL_SURFACE_INTEL;
                default -> SYNTAX_MX_SCREEN;
            };
        }
    }

    protected static class ScanConfig {
        protected ModuleMode mode = ModuleMode.SYNTAX_MX_SCREEN;

        protected String targetEmail = "";
        protected String targetDomain = "";
        protected String emailList = "";
        protected String smtpHostOverride = "";

        protected List<Integer> smtpPorts = new ArrayList<>(List.of(25, 587));
        protected String mailFrom = "verifier@local.test";
        protected String heloIdentity = "jrts.local";

        protected int catchallProbeCount = DEFAULT_CATCHALL_PROBE_COUNT;
        protected int maxMxHosts = DEFAULT_MAX_MX_HOSTS;

        protected boolean probeRelayRestrictions;
        protected boolean useSwaks = true;
        protected boolean useSmtpCli;
        protected boolean useTheHarvester;
        protected boolean useHolehe;

        protected int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
        protected int readTimeoutMs = DEFAULT_READ_TIMEOUT_MS;
        protected int commandTimeoutMs = DEFAULT_COMMAND_TIMEOUT_MS;
        protected boolean includeRaw;
    }

    private static final class SeedSet {
        private String primaryEmail = "";
        private String domain = "";
        private final List<String> recipients = new ArrayList<>();
        private final List<String> invalidRecipients = new ArrayList<>();

        private Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("primary_email", primaryEmail);
            map.put("domain", domain);
            map.put("recipients", recipients);
            map.put("invalid_recipients", invalidRecipients);
            return map;
        }
    }

    protected static final class MxRecord {
        protected final int priority;
        protected final String host;
        protected final String source;

        public MxRecord(int priority, String host, String source) {
            this.priority = priority;
            this.host = host == null ? "" : host;
            this.source = source == null ? "" : source;
        }
    }

    private static final class SmtpTarget {
        private final String host;
        private final String source;

        private SmtpTarget(String host, String source) {
            this.host = host;
            this.source = source;
        }
    }

    private enum RcptVerdict {
        ACCEPTED("accepted"),
        REJECTED("rejected"),
        TEMPORARY("temporary"),
        UNREACHABLE("unreachable"),
        UNKNOWN("unknown");

        private final String value;

        RcptVerdict(String value) {
            this.value = value;
        }
    }

    private static final class RecipientProbeOutcome {
        private String recipient = "";
        private RcptVerdict verdict = RcptVerdict.UNKNOWN;
        private SmtpProbeResult bestProbe;
        private String bestProbeHost = "";
        private int bestProbePort = -1;
        private final List<Map<String, Object>> attempts = new ArrayList<>();

        private Map<String, Object> toMap(boolean includeRaw) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("recipient", recipient);
            out.put("verdict", verdict.value);
            out.put("attempt_count", attempts.size());
            out.put("attempts", attempts);

            if (bestProbe != null) {
                out.put("rcpt_code", bestProbe.rcptCode);
                out.put("rcpt_message", bestProbe.rcptMessage);
                out.put("host", bestProbeHost);
                out.put("port", bestProbePort);
                out.put("starttls_supported", bestProbe.starttlsSupported);
                out.put("auth_mechanisms", bestProbe.authMechanisms);
                if (includeRaw) {
                    out.put("transcript", bestProbe.transcript);
                }
            } else {
                out.put("rcpt_code", 0);
                out.put("rcpt_message", "no_response");
                out.put("host", "");
                out.put("port", -1);
                out.put("starttls_supported", false);
                out.put("auth_mechanisms", List.of());
            }

            return out;
        }
    }

    protected static class ExecutionDiagnostics {
        protected final List<String> toolUsage = new ArrayList<>();
        protected final List<String> warnings = new ArrayList<>();
        protected final List<String> executedCommands = new ArrayList<>();
        protected final List<Map<String, Object>> commandLog = new ArrayList<>();
        protected final List<Map<String, Object>> smtpSessions = new ArrayList<>();
        protected final Set<Integer> portsTested = new LinkedHashSet<>();

        protected long mxLookupDurationMs;
        protected int mxHostsResolved;
        protected int commandExecutions;
    }

    protected static final class TcpReachabilityResult {
        protected final boolean reachable;
        protected final long durationMs;
        protected final String error;

        public TcpReachabilityResult(boolean reachable, long durationMs, String error) {
            this.reachable = reachable;
            this.durationMs = durationMs;
            this.error = error == null ? "" : error;
        }
    }

    protected static class SmtpProbeResult {
        protected String host = "";
        protected int port;
        protected boolean connectionEstablished;
        protected boolean timedOut;
        protected String error = "";

        protected int bannerCode;
        protected String bannerMessage = "";
        protected int ehloCode;
        protected List<String> ehloCapabilities = new ArrayList<>();
        protected List<String> authMechanisms = new ArrayList<>();
        protected boolean starttlsSupported;

        protected int mailFromCode;
        protected String mailFromMessage = "";
        protected int rcptCode;
        protected String rcptMessage = "";
        protected int relayCode;
        protected String relayMessage = "";

        protected long durationMs;
        protected final List<String> transcript = new ArrayList<>();

        public Map<String, Object> toMap(boolean includeRaw) {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("host", host);
            map.put("port", port);
            map.put("connection_established", connectionEstablished);
            map.put("timed_out", timedOut);
            map.put("error", error);
            map.put("banner_code", bannerCode);
            map.put("banner_message", bannerMessage);
            map.put("ehlo_code", ehloCode);
            map.put("ehlo_capabilities", ehloCapabilities);
            map.put("auth_mechanisms", authMechanisms);
            map.put("starttls_supported", starttlsSupported);
            map.put("mail_from_code", mailFromCode);
            map.put("mail_from_message", mailFromMessage);
            map.put("rcpt_code", rcptCode);
            map.put("rcpt_message", rcptMessage);
            map.put("relay_code", relayCode);
            map.put("relay_message", relayMessage);
            map.put("duration_ms", durationMs);
            if (includeRaw) {
                map.put("transcript", transcript);
            }
            return map;
        }
    }

    private static final class SmtpResponse {
        private final int code;
        private final String message;
        private final List<String> lines;

        private SmtpResponse(int code, String message, List<String> lines) {
            this.code = code;
            this.message = message == null ? "" : message;
            this.lines = lines == null ? List.of() : lines;
        }
    }

    protected static final class CommandExecutionResult {
        protected final int exitCode;
        protected final String stdout;
        protected final String stderr;
        protected final boolean timedOut;
        protected final long durationMs;

        public CommandExecutionResult(int exitCode, String stdout, String stderr, boolean timedOut, long durationMs) {
            this.exitCode = exitCode;
            this.stdout = stdout == null ? "" : stdout;
            this.stderr = stderr == null ? "" : stderr;
            this.timedOut = timedOut;
            this.durationMs = durationMs;
        }
    }

    private static final class HostPort {
        private final String host;
        private final int port;

        private HostPort(String host, int port) {
            this.host = host == null ? "" : host;
            this.port = port;
        }
    }
}
