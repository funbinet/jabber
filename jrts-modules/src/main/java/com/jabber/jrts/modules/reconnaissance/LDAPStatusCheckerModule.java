package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * LDAP Signing and Channel Binding posture checker.
 *
 * Execution pipeline:
 * mode selection -> input validation -> processing engine -> execution checks -> result normalization.
 */
@JRTSModule(
    id = "ldap-status-checker",
    name = "LDAP Status Checker",
    description = "Assess LDAP signing, LDAPS availability, bind behavior, and channel binding posture on domain controllers using real LDAP/LDAPS checks.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.MEDIUM,
    sourceRef = "CheckLDAPStatus.py",
    author = "JRTS"
)
public class LDAPStatusCheckerModule implements JRTSModuleInterface {

    private static final String MODULE_ID = "ldap-status-checker";
    private static final int DEFAULT_LDAP_PORT = 389;
    private static final int DEFAULT_LDAPS_PORT = 636;
    private static final int DEFAULT_TIMEOUT_MS = 8000;
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 4000;
    private static final int DEFAULT_MAX_TARGETS = 10;

    private static final String DIRECTORY_SERVICE_CONTAINER =
        "CN=Directory Service,CN=Windows NT,CN=Services,";

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of(
                    "reachability_survey", "policy_audit", "tls_channel_audit", "controller_confirmation"
                ))
                .required()
                .defaultValue("reachability_survey")
                .group("Mode")
                .helpText("Controls LDAP posture depth and target strategy."),
            ModuleInputField.text("dc_targets", "Domain Controllers")
                .placeholder("dc01.contoso.local,10.10.10.5")
                .group("Target")
                .modes("reachability_survey", "policy_audit", "tls_channel_audit")
                .helpText("Comma-separated DC hosts/IPs."),
            ModuleInputField.text("controller_target", "Controller Target")
                .placeholder("dc01.contoso.local")
                .group("Mode")
                .modes("controller_confirmation")
                .helpText("Required when mode=controller_confirmation."),

            ModuleInputField.text("domain", "Target Domain")
                .placeholder("contoso.com")
                .group("Target")
                .modes("reachability_survey", "policy_audit", "tls_channel_audit")
                .helpText("Used for SRV-based DC discovery fallback."),
            ModuleInputField.text("dc_ip", "DC IP Address (Legacy)")
                .placeholder("192.168.1.10")
                .group("Target")
                .modes("reachability_survey", "policy_audit", "tls_channel_audit"),
            ModuleInputField.text("base_dn", "Base DN")
                .placeholder("DC=contoso,DC=com")
                .group("Target")
                .modes("policy_audit", "tls_channel_audit", "controller_confirmation")
                .helpText("Optional base DN for policy lookup fallback."),

            ModuleInputField.text("username", "Username")
                .placeholder("operator@contoso.com or CONTOSO\\operator")
                .group("Authentication")
                .modes("policy_audit", "tls_channel_audit", "controller_confirmation"),
            ModuleInputField.password("password", "Password")
                .group("Authentication")
                .modes("policy_audit", "tls_channel_audit", "controller_confirmation"),
            ModuleInputField.text("hashes", "NTLM Hashes")
                .placeholder("LMHASH:NTHASH").group("Authentication")
                .modes("policy_audit", "tls_channel_audit", "controller_confirmation")
                .helpText("Accepted for operator context; hash-only LDAP bind is not performed."),
            ModuleInputField.checkbox("use_kerberos", "Use Kerberos Auth")
                .group("Authentication")
                .modes("policy_audit", "tls_channel_audit", "controller_confirmation"),
            ModuleInputField.text("aes_key", "AES Key")
                .group("Authentication")
                .modes("policy_audit", "tls_channel_audit", "controller_confirmation")
                .helpText("Accepted as context; native LDAP checks still require system Kerberos context."),

            ModuleInputField.text("ldap_port", "LDAP Port")
                .placeholder(String.valueOf(DEFAULT_LDAP_PORT))
                .group("Connection"),
            ModuleInputField.text("ldaps_port", "LDAPS Port")
                .placeholder(String.valueOf(DEFAULT_LDAPS_PORT))
                .group("Connection"),
            ModuleInputField.text("timeout_ms", "Read Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_TIMEOUT_MS))
                .group("Connection"),
            ModuleInputField.text("connect_timeout_ms", "Connect Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_CONNECT_TIMEOUT_MS))
                .group("Connection"),

            ModuleInputField.text("max_targets", "Maximum Targets")
                .placeholder(String.valueOf(DEFAULT_MAX_TARGETS))
                .group("Execution")
                .modes("reachability_survey", "policy_audit", "tls_channel_audit"),
            ModuleInputField.checkbox("resolve_dns", "Resolve DNS")
                .defaultValue("false")
                .group("Execution"),
            ModuleInputField.checkbox("run_bind_tests", "Run Credential Bind Tests")
                .defaultValue("true")
                .group("Execution")
                .modes("policy_audit", "tls_channel_audit", "controller_confirmation")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), MODULE_ID);
            long startedAt = System.currentTimeMillis();

            try {
                ctx.log("[*] Starting LDAP Status Checker module");
                ctx.reportProgress(5);

                ScanConfig config = parseConfig(input);
                List<String> validationErrors = validateConfig(config);
                if (!validationErrors.isEmpty()) {
                    String message = String.join("; ", validationErrors);
                    result.fail("Validation failed: " + message);
                    ctx.log("[!] Validation failed: " + message);
                    return result;
                }

                List<String> targets = resolveTargets(config, ctx);
                if (targets.isEmpty()) {
                    result.fail("No domain controllers resolved from input");
                    ctx.log("[!] No targets resolved");
                    return result;
                }

                ctx.log("[*] Mode: " + config.mode.value);
                ctx.log("[*] Targets: " + targets.size());
                ctx.reportProgress(20);

                List<TargetAssessment> assessments = new ArrayList<>();
                for (int i = 0; i < targets.size(); i++) {
                    String target = targets.get(i);
                    TargetAssessment assessment = assessTarget(target, config);
                    assessments.add(assessment);
                    result.addFinding(assessment.toFinding(config.mode));

                    int pct = 20 + (int) (((i + 1) / (double) targets.size()) * 65);
                    ctx.reportProgress(Math.min(90, pct));
                }

                Map<String, Object> summary = buildSummary(assessments, config);
                Map<String, Object> output = new LinkedHashMap<>();
                output.put("pipeline", List.of(
                    "mode_selection",
                    "input_validation",
                    "processing_engine",
                    "execution_checks",
                    "result_normalization",
                    "structured_output"
                ));
                output.put("mode", config.mode.value);
                output.put("targets", targets);
                output.put("assessments", assessments.stream().map(a -> a.toOutput(config.mode)).toList());
                output.put("summary", summary);
                output.put("execution_metadata", buildExecutionMetadata(config, targets, startedAt));

                if (config.mode == ModuleMode.CONTROLLER_CONFIRMATION && !assessments.isEmpty()) {
                    output.put("confirmation_result", assessments.get(0).toOutput(config.mode));
                }

                result.setNormalizedOutput(buildNormalizedOutput(summary, assessments, config));
                result.complete(output);
                ctx.log("[+] LDAP Status Checker completed");
                ctx.reportProgress(100);

            } catch (Exception e) {
                result.fail("LDAP Status Check failed: " + e.getMessage());
                ctx.log("[!] ERROR: " + e.getMessage());
            }

            return result;
        });
    }

    private TargetAssessment assessTarget(String target, ScanConfig config) {
        TargetAssessment assessment = new TargetAssessment(target);

        if (config.resolveDns) {
            String dns = resolveDnsName(target);
            if (!dns.isBlank()) {
                assessment.resolvedDnsName = dns;
            }
        }

        assessment.ldapPortOpen = checkPortOpen(target, config.ldapPort, config.connectTimeoutMs);
        assessment.ldapsPortOpen = checkPortOpen(target, config.ldapsPort, config.connectTimeoutMs);

        if (assessment.ldapPortOpen) {
            assessment.ldapAnonymousRootDse = readRootDse(target, config.ldapPort, false, config, false);
        }
        if (assessment.ldapsPortOpen) {
            assessment.ldapsAnonymousRootDse = readRootDse(target, config.ldapsPort, true, config, false);
        }

        if (config.mode != ModuleMode.REACHABILITY_SURVEY) {
            assessment.directorySettings = queryDirectoryServiceSettings(target, config, assessment);
            assessment.signingMode = inferSigningMode(assessment);
            assessment.channelBindingMode = inferChannelBindingMode(assessment);

            if (config.runBindTests && config.hasCredential()) {
                if (assessment.ldapPortOpen) {
                    assessment.ldapSimpleBind = attemptSimpleBind(target, config.ldapPort, false, config);
                }
                if (assessment.ldapsPortOpen) {
                    assessment.ldapsSimpleBind = attemptSimpleBind(target, config.ldapsPort, true, config);
                }

                if (assessment.signingMode == SigningMode.UNKNOWN) {
                    SigningMode bindInference = inferSigningFromBindBehavior(assessment);
                    if (bindInference != SigningMode.UNKNOWN) {
                        assessment.signingMode = bindInference;
                        assessment.signingSource = "bind_behavior";
                    }
                }
            }
        }

        if (config.mode == ModuleMode.TLS_CHANNEL_AUDIT && assessment.ldapsPortOpen) {
            assessment.ldapsTls = inspectLdapsTls(target, config.ldapsPort, config);
        }

        assessment.relayAssessment = evaluateRelayFeasibility(assessment);
        return assessment;
    }

    private SigningMode inferSigningMode(TargetAssessment assessment) {
        if (assessment.directorySettings == null || !assessment.directorySettings.success) {
            return SigningMode.UNKNOWN;
        }

        String value = firstValue(assessment.directorySettings.attributes, "ldapServerIntegrity");
        if (value.isBlank()) {
            return SigningMode.UNKNOWN;
        }

        try {
            int mode = Integer.parseInt(value.trim());
            return switch (mode) {
                case 0 -> SigningMode.NONE;
                case 1 -> SigningMode.NEGOTIATE;
                case 2 -> SigningMode.REQUIRE;
                default -> SigningMode.UNKNOWN;
            };
        } catch (NumberFormatException e) {
            return SigningMode.UNKNOWN;
        }
    }

    private SigningMode inferSigningFromBindBehavior(TargetAssessment assessment) {
        BindCheckResult ldapBind = assessment.ldapSimpleBind;
        if (ldapBind == null || !ldapBind.attempted) {
            return SigningMode.UNKNOWN;
        }

        if (ldapBind.success) {
            return SigningMode.NEGOTIATE;
        }

        String error = safeLower(ldapBind.error);
        if (error.contains("stronger")
                || error.contains("00002028")
                || error.contains("confidentiality")
                || error.contains("integrity")) {
            return SigningMode.REQUIRE;
        }

        return SigningMode.UNKNOWN;
    }

    private ChannelBindingMode inferChannelBindingMode(TargetAssessment assessment) {
        if (assessment.directorySettings == null || !assessment.directorySettings.success) {
            return ChannelBindingMode.UNKNOWN;
        }

        List<String> settings = values(assessment.directorySettings.attributes, "msDS-Other-Settings");
        Map<String, String> kv = parseKeyValueSettings(settings);
        if (!kv.containsKey("ldapenforcechannelbinding")) {
            return ChannelBindingMode.UNKNOWN;
        }

        String value = kv.get("ldapenforcechannelbinding");
        return switch (value) {
            case "0" -> ChannelBindingMode.DISABLED;
            case "1" -> ChannelBindingMode.WHEN_SUPPORTED;
            case "2" -> ChannelBindingMode.ALWAYS;
            default -> ChannelBindingMode.UNKNOWN;
        };
    }

    private RelayAssessment evaluateRelayFeasibility(TargetAssessment assessment) {
        RelayAssessment relay = new RelayAssessment();

        if (!assessment.ldapPortOpen && !assessment.ldapsPortOpen) {
            relay.relayViable = false;
            relay.riskLevel = RiskLabel.LOW;
            relay.reasons.add("LDAP and LDAPS are unreachable from current vantage point.");
            return relay;
        }

        if (assessment.signingMode == SigningMode.NONE || assessment.signingMode == SigningMode.NEGOTIATE) {
            relay.relayViable = assessment.ldapPortOpen;
            relay.riskLevel = relay.relayViable ? RiskLabel.HIGH : RiskLabel.MEDIUM;
            relay.reasons.add("LDAP signing is not strictly required, enabling relay risk on LDAP 389.");
            return relay;
        }

        if (assessment.signingMode == SigningMode.REQUIRE) {
            if (!assessment.ldapsPortOpen) {
                relay.relayViable = false;
                relay.riskLevel = RiskLabel.LOW;
                relay.reasons.add("LDAP signing is required and LDAPS is unavailable for relay downgrade path.");
                return relay;
            }

            if (assessment.channelBindingMode == ChannelBindingMode.ALWAYS) {
                relay.relayViable = false;
                relay.riskLevel = RiskLabel.LOW;
                relay.reasons.add("LDAP signing required and CBT enforced (always).");
                return relay;
            }

            relay.relayViable = true;
            relay.riskLevel = assessment.channelBindingMode == ChannelBindingMode.DISABLED
                ? RiskLabel.HIGH
                : RiskLabel.MEDIUM;
            relay.reasons.add("LDAP signing is required but LDAPS exists without strict CBT enforcement.");
            return relay;
        }

        relay.relayViable = assessment.ldapPortOpen;
        relay.riskLevel = assessment.ldapPortOpen ? RiskLabel.MEDIUM : RiskLabel.UNKNOWN;
        relay.reasons.add("LDAP signing status is unknown; relay feasibility cannot be strongly confirmed.");
        return relay;
    }

    private Map<String, Object> buildSummary(List<TargetAssessment> assessments, ScanConfig config) {
        long ldapReachable = assessments.stream().filter(a -> a.ldapPortOpen).count();
        long ldapsReachable = assessments.stream().filter(a -> a.ldapsPortOpen).count();
        long signingRequired = assessments.stream().filter(a -> a.signingMode == SigningMode.REQUIRE).count();
        long cbtAlways = assessments.stream().filter(a -> a.channelBindingMode == ChannelBindingMode.ALWAYS).count();
        long relayViable = assessments.stream().filter(a -> a.relayAssessment.relayViable).count();

        Map<String, Integer> riskBreakdown = new LinkedHashMap<>();
        for (RiskLabel risk : RiskLabel.values()) {
            riskBreakdown.put(risk.value, 0);
        }
        for (TargetAssessment assessment : assessments) {
            String key = assessment.relayAssessment.riskLevel.value;
            riskBreakdown.put(key, riskBreakdown.getOrDefault(key, 0) + 1);
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", config.mode.value);
        summary.put("targets_scanned", assessments.size());
        summary.put("ldap_reachable", ldapReachable);
        summary.put("ldaps_reachable", ldapsReachable);
        summary.put("signing_required_count", signingRequired);
        summary.put("cbt_enforced_count", cbtAlways);
        summary.put("relay_viable_targets", relayViable);
        summary.put("risk_breakdown", riskBreakdown);
        return summary;
    }

    private Map<String, Object> buildExecutionMetadata(ScanConfig config, List<String> targets, long startedAt) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("mode", config.mode.value);
        metadata.put("ldap_port", config.ldapPort);
        metadata.put("ldaps_port", config.ldapsPort);
        metadata.put("timeout_ms", config.timeoutMs);
        metadata.put("connect_timeout_ms", config.connectTimeoutMs);
        metadata.put("targets_requested", targets.size());
        metadata.put("has_credentials", config.hasCredential());
        metadata.put("hash_context_supplied", !config.hashes.isBlank());
        metadata.put("aes_key_supplied", !config.aesKey.isBlank());
        metadata.put("elapsed_ms", System.currentTimeMillis() - startedAt);
        return metadata;
    }

    private Map<String, Object> buildNormalizedOutput(
            Map<String, Object> summary,
            List<TargetAssessment> assessments,
            ScanConfig config) {

        Map<String, Object> normalized = new LinkedHashMap<>();

        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("summary", summary);
        raw.put("assessment_count", assessments.size());
        normalized.put("raw_output", raw);

        long relayViable = ((Number) summary.getOrDefault("relay_viable_targets", 0)).longValue();

        Map<String, Object> parsed = new LinkedHashMap<>();
        parsed.put("status", relayViable > 0 ? "LDAP_RELAY_RISK_PRESENT" : "LDAP_RELAY_RISK_REDUCED");
        parsed.put("vulnerable", relayViable > 0);
        parsed.put("details", summary);
        parsed.put("evidence", assessments.stream().map(a -> a.toFinding(config.mode)).toList());
        normalized.put("parsed_output", parsed);

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("module", MODULE_ID);
        metadata.put("mode", config.mode.value);
        normalized.put("metadata", metadata);

        return normalized;
    }

    private List<String> resolveTargets(ScanConfig config, TaskContext ctx) {
        Set<String> targets = new LinkedHashSet<>();

        if (config.mode == ModuleMode.CONTROLLER_CONFIRMATION) {
            String confirmationTarget = firstNonBlank(config.controllerTarget, config.dcIp, config.dcTargetsRaw);
            if (!confirmationTarget.isBlank()) {
                targets.add(confirmationTarget);
            }
        } else {
            targets.addAll(splitCsv(config.dcTargetsRaw));
            if (!config.dcIp.isBlank()) {
                targets.add(config.dcIp);
            }
        }

        if (targets.isEmpty() && !config.domain.isBlank()) {
            List<String> discovered = discoverDomainControllersBySrv(config.domain, config.maxTargets);
            if (!discovered.isEmpty()) {
                targets.addAll(discovered);
                ctx.log("[*] Discovered " + discovered.size() + " DC target(s) via DNS SRV");
            }
        }

        if (targets.isEmpty() && !config.domain.isBlank()) {
            targets.add(config.domain);
        }

        List<String> resolved = targets.stream()
            .map(this::normalizeTarget)
            .filter(t -> !t.isBlank())
            .limit(config.maxTargets)
            .sorted(Comparator.naturalOrder())
            .toList();

        return new ArrayList<>(resolved);
    }

    protected List<String> discoverDomainControllersBySrv(String domain, int maxTargets) {
        List<String> targets = new ArrayList<>();
        String query = "_ldap._tcp.dc._msdcs." + domain;

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");

        try {
            DirContext dns = new InitialDirContext(env);
            Attributes attrs = dns.getAttributes(query, new String[] {"SRV"});
            Attribute srv = attrs.get("SRV");
            if (srv == null) {
                return targets;
            }

            NamingEnumeration<?> values = srv.getAll();
            try {
                while (values.hasMore() && targets.size() < maxTargets) {
                    Object value = values.next();
                    String record = String.valueOf(value);
                    String[] parts = record.trim().split("\\s+");
                    if (parts.length >= 4) {
                        String host = parts[3].replaceAll("\\.$", "");
                        if (!host.isBlank()) {
                            targets.add(host);
                        }
                    }
                }
            } finally {
                if (values != null) {
                    values.close();
                }
            }
        } catch (Exception ignored) {
            // SRV discovery best-effort fallback.
        }

        return targets;
    }

    protected boolean checkPortOpen(String host, int port, int connectTimeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    protected RootDseResult readRootDse(
            String host,
            int port,
            boolean ssl,
            ScanConfig config,
            boolean authenticated) {

        RootDseResult result = new RootDseResult();
        LdapContext context = null;

        try {
            context = createLdapContext(host, port, ssl, config, authenticated);
            Attributes attrs = context.getAttributes("", new String[] {
                "defaultNamingContext",
                "configurationNamingContext",
                "rootDomainNamingContext",
                "supportedSASLMechanisms",
                "supportedLDAPVersion",
                "supportedControl"
            });

            result.success = true;
            result.authenticated = authenticated;
            result.attributes = attributesToMap(attrs);
        } catch (Exception e) {
            result.success = false;
            result.authenticated = authenticated;
            result.error = e.getMessage();
        } finally {
            closeQuietly(context);
        }

        return result;
    }

    protected DirectorySettingsResult queryDirectoryServiceSettings(
            String host,
            ScanConfig config,
            TargetAssessment assessment) {

        DirectorySettingsResult result = new DirectorySettingsResult();

        String configurationNc = firstNonBlank(
            firstValue(assessment.ldapAnonymousRootDse.attributes, "configurationNamingContext"),
            firstValue(assessment.ldapsAnonymousRootDse.attributes, "configurationNamingContext")
        );

        if (configurationNc.isBlank() && !config.baseDn.isBlank()) {
            configurationNc = config.baseDn.toLowerCase(Locale.ROOT).startsWith("cn=configuration,")
                ? config.baseDn
                : "CN=Configuration," + config.baseDn;
        }

        if (configurationNc.isBlank()) {
            result.success = false;
            result.error = "configuration naming context unavailable";
            return result;
        }

        int port = assessment.ldapPortOpen ? config.ldapPort : config.ldapsPort;
        boolean ssl = !assessment.ldapPortOpen;

        LdapContext context = null;
        try {
            context = createLdapContext(host, port, ssl, config, config.hasCredential());
            String dn = DIRECTORY_SERVICE_CONTAINER + configurationNc;
            Attributes attrs = context.getAttributes(dn, new String[] {
                "ldapServerIntegrity",
                "msDS-Other-Settings",
                "dSHeuristics"
            });

            result.success = true;
            result.attributes = attributesToMap(attrs);
        } catch (Exception e) {
            result.success = false;
            result.error = e.getMessage();
        } finally {
            closeQuietly(context);
        }

        return result;
    }

    protected BindCheckResult attemptSimpleBind(String host, int port, boolean ssl, ScanConfig config) {
        BindCheckResult result = new BindCheckResult();
        result.attempted = true;

        if (!config.hasCredential()) {
            result.attempted = false;
            result.error = "credentials_not_provided";
            return result;
        }

        LdapContext context = null;
        try {
            context = createLdapContext(host, port, ssl, config, true);
            context.getAttributes("", new String[] {"defaultNamingContext"});
            result.success = true;
        } catch (Exception e) {
            result.success = false;
            result.error = e.getMessage();
        } finally {
            closeQuietly(context);
        }

        return result;
    }

    protected TlsHandshakeResult inspectLdapsTls(String host, int port, ScanConfig config) {
        TlsHandshakeResult result = new TlsHandshakeResult();

        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
                socket.connect(new InetSocketAddress(host, port), config.connectTimeoutMs);
                socket.setSoTimeout(config.timeoutMs);
                socket.startHandshake();

                SSLSession session = socket.getSession();
                result.success = true;
                result.protocol = session.getProtocol();
                result.cipherSuite = session.getCipherSuite();

                Certificate[] chain = session.getPeerCertificates();
                if (chain != null && chain.length > 0 && chain[0] instanceof X509Certificate cert) {
                    result.certificateSubject = cert.getSubjectX500Principal().getName();
                    result.certificateIssuer = cert.getIssuerX500Principal().getName();
                    result.certificateNotBefore = cert.getNotBefore().toInstant().toString();
                    result.certificateNotAfter = cert.getNotAfter().toInstant().toString();
                    Instant now = Instant.now();
                    result.certificateValidNow = !now.isBefore(cert.getNotBefore().toInstant())
                        && !now.isAfter(cert.getNotAfter().toInstant());
                }
            }
        } catch (Exception e) {
            result.success = false;
            result.error = e.getMessage();
        }

        return result;
    }

    protected String resolveDnsName(String target) {
        try {
            return InetAddress.getByName(target).getCanonicalHostName();
        } catch (Exception e) {
            return "";
        }
    }

    protected LdapContext createLdapContext(
            String host,
            int port,
            boolean ssl,
            ScanConfig config,
            boolean authenticated) throws NamingException {

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, (ssl ? "ldaps" : "ldap") + "://" + host + ":" + port);
        env.put(Context.REFERRAL, "ignore");
        env.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(config.connectTimeoutMs));
        env.put("com.sun.jndi.ldap.read.timeout", String.valueOf(config.timeoutMs));

        if (authenticated && config.hasCredential()) {
            if (config.useKerberos) {
                env.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");
                if (!config.username.isBlank()) {
                    env.put(Context.SECURITY_PRINCIPAL, config.username);
                }
                if (!config.password.isBlank()) {
                    env.put(Context.SECURITY_CREDENTIALS, config.password);
                }
            } else {
                env.put(Context.SECURITY_AUTHENTICATION, "simple");
                env.put(Context.SECURITY_PRINCIPAL, config.username);
                env.put(Context.SECURITY_CREDENTIALS, config.password);
            }
        } else {
            env.put(Context.SECURITY_AUTHENTICATION, "none");
        }

        return new InitialLdapContext(env, null);
    }

    private Map<String, List<String>> attributesToMap(Attributes attributes) throws NamingException {
        Map<String, List<String>> map = new LinkedHashMap<>();
        if (attributes == null) {
            return map;
        }

        NamingEnumeration<? extends Attribute> all = attributes.getAll();
        try {
            while (all.hasMore()) {
                Attribute attribute = all.next();
                List<String> values = new ArrayList<>();
                NamingEnumeration<?> valuesEnum = attribute.getAll();
                try {
                    while (valuesEnum.hasMore()) {
                        Object value = valuesEnum.next();
                        if (value != null) {
                            values.add(String.valueOf(value));
                        }
                    }
                } finally {
                    if (valuesEnum != null) {
                        valuesEnum.close();
                    }
                }
                map.put(attribute.getID(), values);
            }
        } finally {
            if (all != null) {
                all.close();
            }
        }

        return map;
    }

    private List<String> validateConfig(ScanConfig config) {
        List<String> errors = new ArrayList<>();

        boolean hasTargets = !config.dcTargetsRaw.isBlank() || !config.dcIp.isBlank() || !config.domain.isBlank();
        if (config.mode == ModuleMode.CONTROLLER_CONFIRMATION) {
            if (config.controllerTarget.isBlank()) {
                errors.add("controller_target is required when mode=controller_confirmation");
            }
        } else if (!hasTargets) {
            errors.add("dc_targets or dc_ip or domain is required");
        }

        if (!config.username.isBlank() && config.password.isBlank() && !config.useKerberos) {
            errors.add("password is required when username is provided for simple bind checks");
        }

        if (config.ldapPort < 1 || config.ldapPort > 65535) {
            errors.add("ldap_port must be between 1 and 65535");
        }
        if (config.ldapsPort < 1 || config.ldapsPort > 65535) {
            errors.add("ldaps_port must be between 1 and 65535");
        }
        if (config.timeoutMs < 500 || config.timeoutMs > 120_000) {
            errors.add("timeout_ms must be between 500 and 120000");
        }
        if (config.connectTimeoutMs < 200 || config.connectTimeoutMs > 60_000) {
            errors.add("connect_timeout_ms must be between 200 and 60000");
        }
        if (config.maxTargets < 1 || config.maxTargets > 100) {
            errors.add("max_targets must be between 1 and 100");
        }

        return errors;
    }

    private ScanConfig parseConfig(Map<String, String> input) {
        ScanConfig config = new ScanConfig();

        config.mode = ModuleMode.fromInput(firstNonBlank(input.get("mode"), "reachability_survey"));
        config.dcTargetsRaw = trim(input.get("dc_targets"));
        config.controllerTarget = firstNonBlank(
            trim(input.get("controller_target")),
            trim(input.get("identify_target"))
        );
        config.domain = trim(input.get("domain"));
        config.dcIp = trim(input.get("dc_ip"));
        config.baseDn = trim(input.get("base_dn"));

        config.username = trim(input.get("username"));
        config.password = trim(input.get("password"));
        config.hashes = trim(input.get("hashes"));
        config.useKerberos = parseBoolean(input.get("use_kerberos"), false);
        config.aesKey = trim(input.get("aes_key"));

        config.ldapPort = parseInteger(input.get("ldap_port"), DEFAULT_LDAP_PORT);
        config.ldapsPort = parseInteger(input.get("ldaps_port"), DEFAULT_LDAPS_PORT);
        config.timeoutMs = parseInteger(input.get("timeout_ms"), DEFAULT_TIMEOUT_MS);
        config.connectTimeoutMs = parseInteger(input.get("connect_timeout_ms"), DEFAULT_CONNECT_TIMEOUT_MS);
        config.maxTargets = parseInteger(input.get("max_targets"), DEFAULT_MAX_TARGETS);

        config.resolveDns = parseBoolean(input.get("resolve_dns"), false);
        config.runBindTests = parseBoolean(input.get("run_bind_tests"), true);

        return config;
    }

    private Map<String, String> parseKeyValueSettings(List<String> settings) {
        Map<String, String> map = new LinkedHashMap<>();
        for (String setting : settings) {
            if (setting == null) {
                continue;
            }
            int separator = setting.indexOf('=');
            if (separator <= 0 || separator + 1 >= setting.length()) {
                continue;
            }
            String key = setting.substring(0, separator).trim().toLowerCase(Locale.ROOT);
            String value = setting.substring(separator + 1).trim();
            map.put(key, value);
        }
        return map;
    }

    private List<String> splitCsv(String value) {
        List<String> out = new ArrayList<>();
        String raw = trim(value);
        if (raw.isBlank()) {
            return out;
        }

        for (String token : raw.split(",")) {
            String candidate = normalizeTarget(token);
            if (!candidate.isBlank()) {
                out.add(candidate);
            }
        }
        return out;
    }

    private String normalizeTarget(String value) {
        String target = trim(value);
        if (target.isBlank()) {
            return "";
        }
        return target.replaceAll("^\\[|\\]$", "");
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.trim().isBlank()) {
                return value.trim();
            }
        }
        return "";
    }

    private String firstValue(Map<String, List<String>> map, String key) {
        if (map == null || key == null) {
            return "";
        }
        List<String> values = values(map, key);
        return values.isEmpty() ? "" : values.get(0);
    }

    private List<String> values(Map<String, List<String>> map, String key) {
        if (map == null || key == null) {
            return List.of();
        }

        for (Map.Entry<String, List<String>> entry : map.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(key)) {
                return entry.getValue();
            }
        }
        return List.of();
    }

    private String safeLower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
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

    private void closeQuietly(LdapContext context) {
        if (context != null) {
            try {
                context.close();
            } catch (Exception ignored) {
                // no-op
            }
        }
    }

    protected static class ScanConfig {
        private ModuleMode mode = ModuleMode.REACHABILITY_SURVEY;
        private String dcTargetsRaw = "";
        private String controllerTarget = "";
        private String domain = "";
        private String dcIp = "";
        private String baseDn = "";

        private String username = "";
        private String password = "";
        private String hashes = "";
        private boolean useKerberos;
        private String aesKey = "";

        private int ldapPort = DEFAULT_LDAP_PORT;
        private int ldapsPort = DEFAULT_LDAPS_PORT;
        private int timeoutMs = DEFAULT_TIMEOUT_MS;
        private int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
        private int maxTargets = DEFAULT_MAX_TARGETS;
        private boolean resolveDns;
        private boolean runBindTests = true;

        private boolean hasCredential() {
            return !username.isBlank() && !password.isBlank();
        }
    }

    private enum ModuleMode {
        REACHABILITY_SURVEY("reachability_survey"),
        POLICY_AUDIT("policy_audit"),
        TLS_CHANNEL_AUDIT("tls_channel_audit"),
        CONTROLLER_CONFIRMATION("controller_confirmation");

        private final String value;

        ModuleMode(String value) {
            this.value = value;
        }

        private static ModuleMode fromInput(String raw) {
            String normalized = raw == null
                ? ""
                : raw.trim().toLowerCase(Locale.ROOT).replace('-', '_').replace(' ', '_');

            return switch (normalized) {
                case "policy_audit", "analysis" -> POLICY_AUDIT;
                case "tls_channel_audit", "deep_scan", "deepscan" -> TLS_CHANNEL_AUDIT;
                case "controller_confirmation", "identify", "identification" -> CONTROLLER_CONFIRMATION;
                default -> REACHABILITY_SURVEY;
            };
        }
    }

    private enum SigningMode {
        NONE("none"),
        NEGOTIATE("negotiate"),
        REQUIRE("require"),
        UNKNOWN("unknown");

        private final String value;

        SigningMode(String value) {
            this.value = value;
        }
    }

    private enum ChannelBindingMode {
        DISABLED("disabled"),
        WHEN_SUPPORTED("when_supported"),
        ALWAYS("always"),
        UNKNOWN("unknown");

        private final String value;

        ChannelBindingMode(String value) {
            this.value = value;
        }
    }

    private enum RiskLabel {
        HIGH("high"),
        MEDIUM("medium"),
        LOW("low"),
        UNKNOWN("unknown");

        private final String value;

        RiskLabel(String value) {
            this.value = value;
        }
    }

    protected static class RootDseResult {
        protected boolean success;
        protected boolean authenticated;
        protected String error = "";
        protected Map<String, List<String>> attributes = new LinkedHashMap<>();
    }

    protected static class DirectorySettingsResult {
        protected boolean success;
        protected String error = "";
        protected Map<String, List<String>> attributes = new LinkedHashMap<>();
    }

    protected static class BindCheckResult {
        protected boolean attempted;
        protected boolean success;
        protected String error = "";
    }

    protected static class TlsHandshakeResult {
        protected boolean success;
        protected String protocol = "";
        protected String cipherSuite = "";
        protected String certificateSubject = "";
        protected String certificateIssuer = "";
        protected String certificateNotBefore = "";
        protected String certificateNotAfter = "";
        protected boolean certificateValidNow;
        protected String error = "";

        protected Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("success", success);
            map.put("protocol", protocol);
            map.put("cipher_suite", cipherSuite);
            map.put("certificate_subject", certificateSubject);
            map.put("certificate_issuer", certificateIssuer);
            map.put("certificate_not_before", certificateNotBefore);
            map.put("certificate_not_after", certificateNotAfter);
            map.put("certificate_valid_now", certificateValidNow);
            if (!error.isBlank()) {
                map.put("error", error);
            }
            return map;
        }
    }

    private static class RelayAssessment {
        private boolean relayViable;
        private RiskLabel riskLevel = RiskLabel.UNKNOWN;
        private final List<String> reasons = new ArrayList<>();

        private Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("relay_viable", relayViable);
            map.put("risk_level", riskLevel.value);
            map.put("reasons", reasons);
            return map;
        }
    }

    protected static class TargetAssessment {
        private final String target;
        private String resolvedDnsName = "";

        private boolean ldapPortOpen;
        private boolean ldapsPortOpen;
        private RootDseResult ldapAnonymousRootDse = new RootDseResult();
        private RootDseResult ldapsAnonymousRootDse = new RootDseResult();
        private DirectorySettingsResult directorySettings = new DirectorySettingsResult();

        private SigningMode signingMode = SigningMode.UNKNOWN;
        private String signingSource = "policy_attribute";
        private ChannelBindingMode channelBindingMode = ChannelBindingMode.UNKNOWN;

        private BindCheckResult ldapSimpleBind = new BindCheckResult();
        private BindCheckResult ldapsSimpleBind = new BindCheckResult();
        private TlsHandshakeResult ldapsTls = new TlsHandshakeResult();
        private RelayAssessment relayAssessment = new RelayAssessment();

        private TargetAssessment(String target) {
            this.target = target;
        }

        private Map<String, Object> toOutput(ModuleMode mode) {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("target", target);
            if (!resolvedDnsName.isBlank()) {
                map.put("resolved_dns_name", resolvedDnsName);
            }

            Map<String, Object> checks = new LinkedHashMap<>();
            checks.put("ldap_port_open", ldapPortOpen);
            checks.put("ldaps_port_open", ldapsPortOpen);
            checks.put("ldap_rootdse_readable", ldapAnonymousRootDse.success);
            checks.put("ldaps_rootdse_readable", ldapsAnonymousRootDse.success);

            if (mode != ModuleMode.REACHABILITY_SURVEY) {
                checks.put("ldap_signing_mode", signingMode.value);
                checks.put("ldap_signing_source", signingSource);
                checks.put("channel_binding_mode", channelBindingMode.value);
                checks.put("directory_settings_readable", directorySettings.success);
                checks.put("ldap_simple_bind", bindMap(ldapSimpleBind));
                checks.put("ldaps_simple_bind", bindMap(ldapsSimpleBind));
            }

            if (mode == ModuleMode.TLS_CHANNEL_AUDIT) {
                checks.put("ldaps_tls", ldapsTls.toMap());
            }

            map.put("checks", checks);
            map.put("relay_assessment", relayAssessment.toMap());

            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("ldap_rootdse", ldapAnonymousRootDse.attributes);
            evidence.put("ldaps_rootdse", ldapsAnonymousRootDse.attributes);
            if (mode != ModuleMode.REACHABILITY_SURVEY) {
                evidence.put("directory_service_settings", directorySettings.attributes);
            }
            map.put("evidence", evidence);

            return map;
        }

        private Map<String, Object> toFinding(ModuleMode mode) {
            return toOutput(mode);
        }

        private Map<String, Object> bindMap(BindCheckResult bind) {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("attempted", bind.attempted);
            map.put("success", bind.success);
            if (!bind.error.isBlank()) {
                map.put("error", bind.error);
            }
            return map;
        }
    }
}
