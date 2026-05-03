package com.jabber.jabber.modules.reconnaissance;

import com.jabber.jabber.data.model.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

/**
 * AD Delegation Discovery Module.
 *
 * Real LDAP-backed delegation mapper for:
 * - Unconstrained Delegation (TRUSTED_FOR_DELEGATION)
 * - Constrained Delegation (msDS-AllowedToDelegateTo)
 * - Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)
 *
 * The execution pipeline is mode-driven:
 * mode selection -> input validation -> processing engine -> execution steps -> result normalization.
 */
@JABBERModule(
    id = "recon-delegation",
    name = "AD Delegation Discovery",
    description = "Enumerate and correlate AD unconstrained, constrained, and resource-based constrained delegation through live LDAP queries.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.HIGH,
    sourceRef = "findDelegation.py",
    author = "JABBER"
)
public class ADDelegationDiscoveryModule implements JABBERModuleInterface {

    private static final int UF_ACCOUNTDISABLE = 0x00000002;
    private static final int UF_TRUSTED_FOR_DELEGATION = 0x00080000;
    private static final int UF_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000;

    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 10_000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 15_000;
    private static final int DEFAULT_MAX_RESULTS = 5_000;
    private static final int MAX_ALLOWED_RESULTS = 50_000;

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of(
                    "surface_map", "abuse_graph", "rbcd_trustee_audit", "principal_trace"
                ))
                .required()
                .defaultValue("surface_map")
                .group("Mode")
                .helpText("Module-specific mode segments that reconfigure delegation processing strategy."),
            ModuleInputField.select("delegation_scope", "Delegation Scope", List.of(
                    "all", "unconstrained", "constrained", "resource_based"
                ))
                .defaultValue("all")
                .group("Mode")
                .modes("surface_map", "abuse_graph", "principal_trace")
                .helpText("Limits mapping to one delegation family or all."),
            ModuleInputField.text("trace_principal", "Principal To Trace")
                .placeholder("svc_sql, APP01$, or CN/DN fragment")
                .group("Mode")
                .modes("principal_trace")
                .helpText("Required in principal_trace mode; narrows graph to the requested identity."),
            ModuleInputField.select("trace_match_mode", "Trace Match Strategy", List.of(
                    "contains", "exact"
                ))
                .defaultValue("contains")
                .group("Mode")
                .modes("principal_trace")
                .helpText("Controls how principal_trace matching is applied to findings."),

            ModuleInputField.text("target", "Target Domain")
                .required()
                .placeholder("contoso.local or dc01.contoso.local")
                .group("Target"),
            ModuleInputField.text("dc_ip", "DC IP Address")
                .placeholder("10.10.10.10")
                .group("Target"),
            ModuleInputField.text("base_dn", "Base DN Override")
                .placeholder("DC=contoso,DC=local")
                .group("Target")
                .helpText("Optional; if omitted, defaultNamingContext is resolved from RootDSE."),

            ModuleInputField.text("username", "Username")
                .placeholder("operator or CONTOSO\\operator or operator@contoso.local")
                .group("Authentication"),
            ModuleInputField.password("password", "Password")
                .group("Authentication"),
            ModuleInputField.password("hashes", "NTLM Hashes (LM:NT)")
                .placeholder("LMHASH:NTHASH")
                .group("Authentication")
                .helpText("Accepted as input context; Java LDAP simple bind does not support hash-only auth."),
            ModuleInputField.checkbox("use_kerberos", "Use Kerberos Authentication")
                .group("Options"),
            ModuleInputField.password("aes_key", "AES Key (for Kerberos)")
                .placeholder("hex-encoded AES256 key")
                .group("Options"),
            ModuleInputField.checkbox("use_ldaps", "Use LDAPS")
                .group("Connection"),
            ModuleInputField.text("ldap_port", "LDAP Port")
                .placeholder("389 or 636")
                .group("Connection"),
            ModuleInputField.text("connect_timeout_ms", "Connect Timeout (ms)")
                .placeholder("10000")
                .group("Connection"),
            ModuleInputField.text("read_timeout_ms", "Read Timeout (ms)")
                .placeholder("15000")
                .group("Connection"),

            ModuleInputField.checkbox("include_disabled", "Include Disabled Accounts")
                .group("Options"),
            ModuleInputField.checkbox("resolve_target_objects", "Resolve Target Objects")
                .group("Options")
                .modes("abuse_graph", "principal_trace")
                .helpText("Resolve constrained delegation SPNs to concrete AD objects for relationship accuracy."),
            ModuleInputField.checkbox("include_rbcd_acl_sids", "Parse RBCD ACL Trustee SIDs")
                .group("Options")
                .modes("abuse_graph", "rbcd_trustee_audit", "principal_trace")
                .helpText("Decode msDS-AllowedToActOnBehalfOfOtherIdentity security descriptors."),
            ModuleInputField.checkbox("rbcd_resolved_only", "RBCD: Resolved Trustees Only")
                .group("Options")
                .modes("rbcd_trustee_audit")
                .helpText("Show only RBCD findings where trustee SID could be resolved to an AD principal."),
            ModuleInputField.text("max_results", "Maximum LDAP Objects")
                .placeholder("5000")
                .group("Options")
                .helpText("Upper bound for LDAP search result size per query.")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), "recon-delegation");
            LdapContext ldap = null;

            try {
                long startedAt = System.currentTimeMillis();
                ctx.log("[*] Starting AD Delegation Discovery module");
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
                ctx.log("[*] Scope: " + config.scope.value);
                ctx.log("[*] Target: " + config.target);
                ctx.log("[*] Authentication: " + authModeLabel(config));
                ctx.reportProgress(20);

                ldap = openLdapContext(config);
                ctx.log("[*] LDAP bind successful to " + buildLdapUrl(config));
                ctx.reportProgress(40);

                String baseDn = resolveBaseDn(ldap, config);
                String domain = baseDnToDomain(baseDn);
                if (domain.isBlank()) {
                    domain = config.target;
                }
                ctx.log("[*] Effective Base DN: " + baseDn);
                ctx.reportProgress(50);

                List<DirectoryObjectRecord> records = fetchDelegationObjects(ldap, baseDn, config, ctx);
                ctx.log("[*] Candidate delegation objects: " + records.size());
                ctx.reportProgress(65);

                Map<String, SidIdentity> sidDirectory = Map.of();
                if (shouldLoadSidDirectory(config)) {
                    sidDirectory = loadSidIdentityMap(ldap, baseDn, config);
                    ctx.log("[*] SID directory entries loaded: " + sidDirectory.size());
                }
                ctx.reportProgress(75);

                List<Map<String, Object>> findings = buildFindings(
                    ldap,
                    baseDn,
                    config,
                    records,
                    sidDirectory,
                    ctx
                );

                findings.sort(this::compareFindings);

                for (Map<String, Object> finding : findings) {
                    result.addFinding(finding);
                }

                List<Map<String, Object>> graphEdges = buildGraphEdges(findings, domain);
                Map<String, Object> summary = buildSummary(findings, records, config);

                Map<String, Object> executionMetadata = new LinkedHashMap<>();
                executionMetadata.put("ldap_url", buildLdapUrl(config));
                executionMetadata.put("base_dn", baseDn);
                executionMetadata.put("auth_mode", authModeLabel(config));
                executionMetadata.put("aes_key_provided", !config.aesKey.isBlank());
                executionMetadata.put("elapsed_ms", System.currentTimeMillis() - startedAt);
                executionMetadata.put("mode", config.mode.value);
                executionMetadata.put("scope", config.scope.value);

                Map<String, Object> output = new LinkedHashMap<>();
                output.put("pipeline", List.of(
                    "mode_selection",
                    "input_validation",
                    "processing_engine",
                    "execution_steps",
                    "result_normalization",
                    "structured_output"
                ));
                output.put("domain", domain);
                output.put("mode", config.mode.value);
                output.put("delegation_scope", config.scope.value);
                output.put("summary", summary);
                output.put("graph_edges", graphEdges);
                output.put("findings", findings);

                switch (config.mode) {
                    case SURFACE_MAP -> output.put("surface_inventory", buildSurfaceInventory(findings));
                    case ABUSE_GRAPH -> output.put("abuse_graph", buildAbuseGraphModel(graphEdges, findings));
                    case RBCD_TRUSTEE_AUDIT -> output.put("rbcd_trustee_matrix", buildRbcdTrusteeMatrix(findings, config));
                    case PRINCIPAL_TRACE -> output.put("principal_trace", buildPrincipalTraceOutput(findings, config));
                }

                output.put("execution_metadata", executionMetadata);

                result.setNormalizedOutput(buildNormalizedOutput(summary, findings, config));
                result.complete(output);

                ctx.log("[+] AD Delegation Discovery completed with " + findings.size() + " findings");
                ctx.reportProgress(100);

            } catch (NamingException e) {
                String message = "LDAP execution failed: " + e.getMessage();
                result.fail(message);
                ctx.log("[!] " + message);
            } catch (Exception e) {
                result.fail("Execution failed: " + e.getMessage());
                ctx.log("[!] ERROR: " + e.getMessage());
            } finally {
                closeQuietly(ldap);
            }

            return result;
        });
    }

    protected LdapContext openLdapContext(ModuleConfig config) throws NamingException {
        String ldapUrl = buildLdapUrl(config);
        String principal = normalizePrincipal(config.username, config.target);

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl);
        env.put(Context.REFERRAL, "ignore");
        env.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(config.connectTimeoutMs));
        env.put("com.sun.jndi.ldap.read.timeout", String.valueOf(config.readTimeoutMs));
        env.put("java.naming.ldap.attributes.binary",
            "objectSid msDS-AllowedToActOnBehalfOfOtherIdentity");

        if (config.useKerberos) {
            env.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");
            if (!principal.isBlank()) {
                env.put(Context.SECURITY_PRINCIPAL, principal);
            }
            if (!config.password.isBlank()) {
                env.put(Context.SECURITY_CREDENTIALS, config.password);
            }
        } else if (!config.username.isBlank()) {
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, principal);
            env.put(Context.SECURITY_CREDENTIALS, config.password);
        } else {
            env.put(Context.SECURITY_AUTHENTICATION, "none");
        }

        return new InitialLdapContext(env, null);
    }

    protected String resolveBaseDn(LdapContext ldap, ModuleConfig config) throws NamingException {
        if (!config.baseDn.isBlank()) {
            return config.baseDn;
        }

        Attributes rootDse = ldap.getAttributes("", new String[]{"defaultNamingContext"});
        Attribute defaultNamingContext = rootDse.get("defaultNamingContext");
        if (defaultNamingContext != null && defaultNamingContext.size() > 0) {
            return String.valueOf(defaultNamingContext.get()).trim();
        }

        if (looksLikeDomainName(config.target)) {
            return domainToBaseDn(config.target);
        }

        if (!config.username.isBlank() && config.username.contains("@")) {
            String domain = config.username.substring(config.username.indexOf('@') + 1);
            if (looksLikeDomainName(domain)) {
                return domainToBaseDn(domain);
            }
        }

        throw new NamingException(
            "Unable to resolve Base DN from RootDSE. Provide base_dn input explicitly.");
    }

    protected List<DirectoryObjectRecord> fetchDelegationObjects(
            LdapContext ldap,
            String baseDn,
            ModuleConfig config,
            TaskContext ctx) throws NamingException {

        String filter = buildDelegationFilter(config);
        ctx.log("[*] LDAP filter: " + filter);

        String[] attributes = new String[] {
            "sAMAccountName",
            "distinguishedName",
            "userAccountControl",
            "objectClass",
            "objectSid",
            "servicePrincipalName",
            "msDS-AllowedToDelegateTo",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            "dNSHostName",
            "cn"
        };

        List<SearchResult> results = ldapSearch(ldap, baseDn, filter, attributes, config.maxResults);
        List<DirectoryObjectRecord> records = new ArrayList<>(results.size());
        for (SearchResult searchResult : results) {
            DirectoryObjectRecord record = toDirectoryObjectRecord(searchResult);
            if (record != null) {
                records.add(record);
            }
        }
        return records;
    }

    protected Map<String, SidIdentity> loadSidIdentityMap(
            LdapContext ldap,
            String baseDn,
            ModuleConfig config) throws NamingException {

        String filter = "(|(objectClass=user)(objectClass=computer)(objectClass=group))";
        String[] attrs = new String[] {"objectSid", "sAMAccountName", "distinguishedName", "objectClass", "cn"};
        List<SearchResult> results = ldapSearch(ldap, baseDn, filter, attrs, config.maxResults);

        Map<String, SidIdentity> sidMap = new HashMap<>();
        for (SearchResult result : results) {
            Attributes attributes = result.getAttributes();
            String sid = attributeToSid(attributes, "objectSid");
            if (sid.isBlank()) {
                continue;
            }
            String account = firstNonBlank(
                getStringAttribute(attributes, "sAMAccountName"),
                getStringAttribute(attributes, "cn")
            );
            String dn = firstNonBlank(
                getStringAttribute(attributes, "distinguishedName"),
                safeNameInNamespace(result)
            );
            String objectClass = classifyObjectClass(getStringListAttribute(attributes, "objectClass"));
            sidMap.put(sid, new SidIdentity(account, dn, objectClass));
        }
        return sidMap;
    }

    protected Optional<TargetObject> resolveTargetBySpn(
            LdapContext ldap,
            String baseDn,
            String spn) throws NamingException {

        String filter = "(servicePrincipalName=" + escapeFilterValue(spn) + ")";
        String[] attrs = new String[] {"sAMAccountName", "distinguishedName", "objectClass", "cn"};
        List<SearchResult> results = ldapSearch(ldap, baseDn, filter, attrs, 1);
        if (results.isEmpty()) {
            return Optional.empty();
        }

        Attributes match = results.get(0).getAttributes();
        String account = firstNonBlank(
            getStringAttribute(match, "sAMAccountName"),
            getStringAttribute(match, "cn")
        );
        String dn = firstNonBlank(
            getStringAttribute(match, "distinguishedName"),
            safeNameInNamespace(results.get(0))
        );
        String objectClass = classifyObjectClass(getStringListAttribute(match, "objectClass"));
        return Optional.of(new TargetObject(account, dn, objectClass));
    }

    private List<Map<String, Object>> buildFindings(
            LdapContext ldap,
            String baseDn,
            ModuleConfig config,
            List<DirectoryObjectRecord> records,
            Map<String, SidIdentity> sidDirectory,
            TaskContext ctx) throws NamingException {

        List<Map<String, Object>> findings = new ArrayList<>();
        Map<String, Optional<TargetObject>> spnTargetCache = new HashMap<>();
        boolean resolveTargets = config.resolveTargetObjects
            || config.mode == ModuleMode.ABUSE_GRAPH
            || config.mode == ModuleMode.PRINCIPAL_TRACE;

        for (DirectoryObjectRecord record : records) {
            boolean unconstrained = hasUacFlag(record.userAccountControl, UF_TRUSTED_FOR_DELEGATION);
            boolean protocolTransition = hasUacFlag(record.userAccountControl, UF_TRUSTED_TO_AUTH_FOR_DELEGATION);

            if (shouldIncludeUnconstrained(config.scope) && unconstrained) {
                findings.add(buildUnconstrainedFinding(record, config));
            }

            if (shouldIncludeConstrained(config.scope) && !record.allowedToDelegateTo.isEmpty()) {
                for (String spn : record.allowedToDelegateTo) {
                    TargetObject targetObject = null;
                    if (resolveTargets) {
                        Optional<TargetObject> resolved = spnTargetCache.get(spn);
                        if (resolved == null) {
                            resolved = resolveTargetBySpn(ldap, baseDn, spn);
                            spnTargetCache.put(spn, resolved);
                        }
                        targetObject = resolved.orElse(null);
                    }

                    findings.add(buildConstrainedFinding(
                        record,
                        protocolTransition,
                        spn,
                        targetObject,
                        config
                    ));
                }
            }

            if (shouldIncludeResourceBased(config.scope) &&
                    (record.rbcdSecurityDescriptor.length > 0 || !record.rbcdTrusteeSids.isEmpty())) {

                List<String> trusteeSids = new ArrayList<>(record.rbcdTrusteeSids);
                if (trusteeSids.isEmpty() && config.includeRbcdAclSids) {
                    trusteeSids = parseRbcdTrusteeSids(record.rbcdSecurityDescriptor);
                }

                findings.addAll(buildRbcdFindings(record, trusteeSids, sidDirectory, config));
            }
        }

        if (config.mode == ModuleMode.PRINCIPAL_TRACE) {
            String needle = config.tracePrincipal.toLowerCase(Locale.ROOT);
            boolean exactMatch = config.traceMatchMode == TraceMatchMode.EXACT;
            List<Map<String, Object>> filtered = new ArrayList<>();
            for (Map<String, Object> finding : findings) {
                if (matchesPrincipalTrace(finding, needle, exactMatch)) {
                    filtered.add(finding);
                }
            }
            ctx.log("[*] Principal trace filtered findings from " + findings.size() + " to " + filtered.size());
            return filtered;
        }

        return findings;
    }

    private Map<String, Object> buildUnconstrainedFinding(DirectoryObjectRecord record, ModuleConfig config) {
        Map<String, Object> finding = buildBaseFinding(record, "UNCONSTRAINED", "CRITICAL");
        finding.put("attack_surface", "Compromised delegated host can cache inbound TGT material and impersonate users to any service.");
        finding.put("abuse_primitives", List.of("TGT harvesting", "Pass-the-ticket", "Lateral movement"));

        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("userAccountControl", record.userAccountControl);
        evidence.put("trusted_for_delegation", true);
        if (config.mode != ModuleMode.SURFACE_MAP) {
            evidence.put("service_principal_names", record.servicePrincipalNames);
        }
        finding.put("evidence", evidence);

        if (config.mode == ModuleMode.ABUSE_GRAPH || config.mode == ModuleMode.PRINCIPAL_TRACE) {
            finding.put("detection_focus", List.of(
                "Monitor privileged interactive logons on delegated hosts",
                "Alert on unusual ticket extraction behavior"
            ));
        }

        return finding;
    }

    private Map<String, Object> buildConstrainedFinding(
            DirectoryObjectRecord record,
            boolean protocolTransition,
            String spn,
            TargetObject targetObject,
            ModuleConfig config) {

        Map<String, Object> finding = buildBaseFinding(record, "CONSTRAINED", "HIGH");
        finding.put("target_spn", spn);
        finding.put("target_service_class", extractServiceClass(spn));
        finding.put("target_host", extractHostFromSpn(spn));
        finding.put("protocol_transition", protocolTransition);
        finding.put("attack_surface", protocolTransition
            ? "Supports S4U2Self + S4U2Proxy for delegated impersonation to allowed backend SPNs."
            : "Supports S4U2Proxy-only impersonation to explicit backend SPNs.");

        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("userAccountControl", record.userAccountControl);
        evidence.put("msDS-AllowedToDelegateTo", record.allowedToDelegateTo);
        evidence.put("trusted_to_auth_for_delegation", protocolTransition);
        finding.put("evidence", evidence);

        if (targetObject != null) {
            finding.put("target_object_account", targetObject.accountName);
            finding.put("target_object_dn", targetObject.distinguishedName);
            finding.put("target_object_class", targetObject.objectClass);
        }

        if (config.mode == ModuleMode.ABUSE_GRAPH || config.mode == ModuleMode.PRINCIPAL_TRACE) {
            finding.put("abuse_primitives", protocolTransition
                ? List.of("S4U2Self", "S4U2Proxy")
                : List.of("S4U2Proxy"));
        }

        return finding;
    }

    private List<Map<String, Object>> buildRbcdFindings(
            DirectoryObjectRecord resourceRecord,
            List<String> trusteeSids,
            Map<String, SidIdentity> sidDirectory,
            ModuleConfig config) {

        List<Map<String, Object>> findings = new ArrayList<>();

        if (trusteeSids.isEmpty()) {
            Map<String, Object> finding = buildBaseFinding(resourceRecord, "RESOURCE_BASED_CONSTRAINED", "HIGH");
            finding.put("target_resource_account", resourceRecord.accountName);
            finding.put("target_resource_dn", resourceRecord.distinguishedName);
            finding.put("rbcd_trustee_sid", "UNRESOLVED");

            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("rbcd_descriptor_length", resourceRecord.rbcdSecurityDescriptor.length);
            evidence.put("trustee_sid_count", 0);
            finding.put("evidence", evidence);

            finding.put("attack_surface", "Resource accepts delegated impersonation but trustee extraction failed or was disabled.");
            findings.add(finding);
            return findings;
        }

        for (String trusteeSid : trusteeSids) {
            Map<String, Object> finding = buildBaseFinding(resourceRecord, "RESOURCE_BASED_CONSTRAINED", "HIGH");
            finding.put("target_resource_account", resourceRecord.accountName);
            finding.put("target_resource_dn", resourceRecord.distinguishedName);
            finding.put("rbcd_trustee_sid", trusteeSid);
            finding.put("attack_surface", "Trustee can impersonate users to this resource using RBCD.");

            SidIdentity identity = sidDirectory.get(trusteeSid);
            if (config.rbcdResolvedOnly && identity == null) {
                continue;
            }
            if (identity != null) {
                finding.put("rbcd_trustee_account", identity.accountName);
                finding.put("rbcd_trustee_dn", identity.distinguishedName);
                finding.put("rbcd_trustee_object_class", identity.objectClass);
            }

            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("rbcd_descriptor_length", resourceRecord.rbcdSecurityDescriptor.length);
            evidence.put("trustee_sid_count", trusteeSids.size());
            finding.put("evidence", evidence);

            if (config.mode == ModuleMode.ABUSE_GRAPH
                    || config.mode == ModuleMode.RBCD_TRUSTEE_AUDIT
                    || config.mode == ModuleMode.PRINCIPAL_TRACE) {
                finding.put("abuse_primitives", List.of("Write RBCD ACL", "S4U2Proxy impersonation"));
            }

            findings.add(finding);
        }

        return findings;
    }

    private Map<String, Object> buildBaseFinding(
            DirectoryObjectRecord record,
            String delegationType,
            String riskLevel) {

        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("delegation_type", delegationType);
        finding.put("risk_level", riskLevel);
        finding.put("source_account", record.accountName);
        finding.put("source_dn", record.distinguishedName);
        finding.put("source_object_class", record.objectClass);
        finding.put("source_enabled", record.enabled);
        finding.put("source_sid", record.objectSid);
        return finding;
    }

    private Map<String, Object> buildSummary(
            List<Map<String, Object>> findings,
            List<DirectoryObjectRecord> records,
            ModuleConfig config) {

        long unconstrainedCount = findings.stream()
            .filter(f -> "UNCONSTRAINED".equals(f.get("delegation_type")))
            .count();
        long constrainedCount = findings.stream()
            .filter(f -> "CONSTRAINED".equals(f.get("delegation_type")))
            .count();
        long rbcdCount = findings.stream()
            .filter(f -> "RESOURCE_BASED_CONSTRAINED".equals(f.get("delegation_type")))
            .count();

        long criticalCount = findings.stream()
            .filter(f -> "CRITICAL".equals(f.get("risk_level")))
            .count();
        long highCount = findings.stream()
            .filter(f -> "HIGH".equals(f.get("risk_level")))
            .count();

        Set<String> uniqueSources = new LinkedHashSet<>();
        for (Map<String, Object> finding : findings) {
            uniqueSources.add(String.valueOf(finding.getOrDefault("source_account", "")));
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", config.mode.value);
        summary.put("scope", config.scope.value);
        summary.put("objects_scanned", records.size());
        summary.put("total_findings", findings.size());
        summary.put("unconstrained_count", unconstrainedCount);
        summary.put("constrained_count", constrainedCount);
        summary.put("resource_based_count", rbcdCount);
        summary.put("critical_findings", criticalCount);
        summary.put("high_findings", highCount);
        summary.put("unique_source_accounts", uniqueSources.size());
        summary.put("attack_paths_present", !findings.isEmpty());
        return summary;
    }

    private List<Map<String, Object>> buildGraphEdges(List<Map<String, Object>> findings, String domain) {
        List<Map<String, Object>> edges = new ArrayList<>();
        for (Map<String, Object> finding : findings) {
            String type = String.valueOf(finding.getOrDefault("delegation_type", ""));
            String source = String.valueOf(finding.getOrDefault("source_account", ""));

            Map<String, Object> edge = new LinkedHashMap<>();
            edge.put("delegation_type", type);
            edge.put("risk_level", finding.get("risk_level"));

            if ("UNCONSTRAINED".equals(type)) {
                edge.put("from", source);
                edge.put("to", "ANY_SERVICE@" + domain);
                edge.put("relation", "can_impersonate_to_any_service");
                edges.add(edge);
                continue;
            }

            if ("CONSTRAINED".equals(type)) {
                edge.put("from", source);
                edge.put("to", String.valueOf(finding.getOrDefault("target_spn", "")));
                edge.put("relation", "can_delegate_to");
                edges.add(edge);
                continue;
            }

            if ("RESOURCE_BASED_CONSTRAINED".equals(type)) {
                String rbcdSource = firstNonBlank(
                    String.valueOf(finding.getOrDefault("rbcd_trustee_account", "")),
                    String.valueOf(finding.getOrDefault("rbcd_trustee_sid", ""))
                );
                edge.put("from", rbcdSource);
                edge.put("to", String.valueOf(finding.getOrDefault("target_resource_account", source)));
                edge.put("relation", "can_act_on_behalf_of_users_to_resource");
                edges.add(edge);
            }
        }
        return edges;
    }

    private Map<String, Object> buildSurfaceInventory(List<Map<String, Object>> findings) {
        Map<String, Integer> delegationTypeCounts = new LinkedHashMap<>();
        Map<String, Integer> sourceClassCounts = new LinkedHashMap<>();

        for (Map<String, Object> finding : findings) {
            String delegationType = String.valueOf(finding.getOrDefault("delegation_type", "UNKNOWN"));
            String sourceClass = String.valueOf(finding.getOrDefault("source_object_class", "unknown"));

            delegationTypeCounts.put(delegationType, delegationTypeCounts.getOrDefault(delegationType, 0) + 1);
            sourceClassCounts.put(sourceClass, sourceClassCounts.getOrDefault(sourceClass, 0) + 1);
        }

        Map<String, Object> inventory = new LinkedHashMap<>();
        inventory.put("delegation_type_counts", delegationTypeCounts);
        inventory.put("source_object_class_counts", sourceClassCounts);
        inventory.put("source_nodes", findings.stream()
            .map(f -> String.valueOf(f.getOrDefault("source_account", "")))
            .filter(s -> !s.isBlank())
            .distinct()
            .sorted()
            .toList());
        return inventory;
    }

    private Map<String, Object> buildAbuseGraphModel(
            List<Map<String, Object>> graphEdges,
            List<Map<String, Object>> findings) {

        Set<String> nodes = new LinkedHashSet<>();
        for (Map<String, Object> edge : graphEdges) {
            nodes.add(String.valueOf(edge.getOrDefault("from", "")));
            nodes.add(String.valueOf(edge.getOrDefault("to", "")));
        }
        nodes.removeIf(String::isBlank);

        Map<String, Object> model = new LinkedHashMap<>();
        model.put("node_count", nodes.size());
        model.put("edge_count", graphEdges.size());
        model.put("nodes", new ArrayList<>(nodes));
        model.put("edges", graphEdges);

        Set<String> primitives = new LinkedHashSet<>();
        for (Map<String, Object> finding : findings) {
            Object value = finding.get("abuse_primitives");
            if (value instanceof List<?> list) {
                for (Object item : list) {
                    if (item != null) {
                        primitives.add(String.valueOf(item));
                    }
                }
            }
        }
        model.put("attack_primitives", primitives.stream().sorted().toList());
        return model;
    }

    private Map<String, Object> buildRbcdTrusteeMatrix(
            List<Map<String, Object>> findings,
            ModuleConfig config) {

        Map<String, List<String>> trusteeToResources = new LinkedHashMap<>();
        int unresolvedCount = 0;

        for (Map<String, Object> finding : findings) {
            if (!"RESOURCE_BASED_CONSTRAINED".equals(finding.get("delegation_type"))) {
                continue;
            }

            String trustee = firstNonBlank(
                String.valueOf(finding.getOrDefault("rbcd_trustee_account", "")),
                String.valueOf(finding.getOrDefault("rbcd_trustee_sid", ""))
            );
            if (trustee.isBlank()) {
                unresolvedCount++;
                continue;
            }

            String resource = String.valueOf(finding.getOrDefault("target_resource_account", ""));
            trusteeToResources.computeIfAbsent(trustee, ignored -> new ArrayList<>()).add(resource);
        }

        for (Map.Entry<String, List<String>> entry : trusteeToResources.entrySet()) {
            entry.setValue(entry.getValue().stream().distinct().sorted().toList());
        }

        Map<String, Object> matrix = new LinkedHashMap<>();
        matrix.put("mode", config.mode.value);
        matrix.put("trustee_count", trusteeToResources.size());
        matrix.put("unresolved_trustee_entries", unresolvedCount);
        matrix.put("trustee_to_resources", trusteeToResources);
        return matrix;
    }

    private Map<String, Object> buildPrincipalTraceOutput(
            List<Map<String, Object>> findings,
            ModuleConfig config) {

        Map<String, Object> trace = new LinkedHashMap<>();
        trace.put("trace_principal", config.tracePrincipal);
        trace.put("match_strategy", config.traceMatchMode.value);
        trace.put("matched_finding_count", findings.size());
        trace.put("matched_delegation_types", findings.stream()
            .map(f -> String.valueOf(f.getOrDefault("delegation_type", "UNKNOWN")))
            .distinct()
            .sorted()
            .toList());
        trace.put("matched_source_accounts", findings.stream()
            .map(f -> String.valueOf(f.getOrDefault("source_account", "")))
            .filter(s -> !s.isBlank())
            .distinct()
            .sorted()
            .toList());
        return trace;
    }

    private Map<String, Object> buildNormalizedOutput(
            Map<String, Object> summary,
            List<Map<String, Object>> findings,
            ModuleConfig config) {

        Map<String, Object> normalized = new LinkedHashMap<>();

        Map<String, Object> rawOutput = new LinkedHashMap<>();
        rawOutput.put("summary", summary);
        rawOutput.put("findings_count", findings.size());
        normalized.put("raw_output", rawOutput);

        Map<String, Object> parsedOutput = new LinkedHashMap<>();
        parsedOutput.put("status", findings.isEmpty()
            ? "NO_DELEGATION_RELATIONSHIPS_FOUND"
            : "DELEGATION_RELATIONSHIPS_FOUND");
        parsedOutput.put("vulnerable", !findings.isEmpty());
        parsedOutput.put("details", summary);
        parsedOutput.put("evidence", findings);
        normalized.put("parsed_output", parsedOutput);

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("mode", config.mode.value);
        metadata.put("scope", config.scope.value);
        metadata.put("module", "recon-delegation");
        normalized.put("metadata", metadata);

        return normalized;
    }

    private int compareFindings(Map<String, Object> left, Map<String, Object> right) {
        Comparator<Map<String, Object>> comparator = Comparator
            .comparing((Map<String, Object> m) -> String.valueOf(m.getOrDefault("delegation_type", "")))
            .thenComparing(m -> String.valueOf(m.getOrDefault("source_account", "")))
            .thenComparing(m -> String.valueOf(m.getOrDefault("target_spn", "")))
            .thenComparing(m -> String.valueOf(m.getOrDefault("rbcd_trustee_sid", "")));
        return comparator.compare(left, right);
    }

    private boolean matchesPrincipalTrace(Map<String, Object> finding, String needle, boolean exactMatch) {
        String[] fields = {
            "source_account",
            "source_dn",
            "source_sid",
            "target_spn",
            "target_host",
            "target_resource_account",
            "target_resource_dn",
            "rbcd_trustee_sid",
            "rbcd_trustee_account",
            "rbcd_trustee_dn"
        };

        for (String field : fields) {
            Object value = finding.get(field);
            if (value != null) {
                String candidate = String.valueOf(value).toLowerCase(Locale.ROOT);
                if (exactMatch) {
                    if (candidate.equals(needle)) {
                        return true;
                    }
                } else if (candidate.contains(needle)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean shouldLoadSidDirectory(ModuleConfig config) {
        return config.mode == ModuleMode.ABUSE_GRAPH
            || config.mode == ModuleMode.RBCD_TRUSTEE_AUDIT
            || config.mode == ModuleMode.PRINCIPAL_TRACE;
    }

    private String authModeLabel(ModuleConfig config) {
        if (config.useKerberos) {
            return "kerberos";
        }
        if (!config.username.isBlank()) {
            return "simple_bind";
        }
        return "anonymous";
    }

    private List<SearchResult> ldapSearch(
            LdapContext ldap,
            String baseDn,
            String filter,
            String[] attrs,
            long maxResults) throws NamingException {

        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(attrs);
        controls.setCountLimit(maxResults);

        List<SearchResult> collected = new ArrayList<>();
        NamingEnumeration<SearchResult> results = ldap.search(baseDn, filter, controls);
        try {
            while (results.hasMore()) {
                collected.add(results.next());
            }
        } catch (PartialResultException ignored) {
            // AD may return partial results when referrals are ignored.
        } finally {
            if (results != null) {
                results.close();
            }
        }
        return collected;
    }

    private DirectoryObjectRecord toDirectoryObjectRecord(SearchResult result) throws NamingException {
        Attributes attributes = result.getAttributes();
        if (attributes == null) {
            return null;
        }

        String account = firstNonBlank(
            getStringAttribute(attributes, "sAMAccountName"),
            getStringAttribute(attributes, "cn"),
            result.getName()
        );

        String dn = firstNonBlank(
            getStringAttribute(attributes, "distinguishedName"),
            safeNameInNamespace(result),
            result.getName()
        );

        int uac = parseInteger(getStringAttribute(attributes, "userAccountControl"), 0);
        boolean enabled = !hasUacFlag(uac, UF_ACCOUNTDISABLE);

        List<String> allowedToDelegateTo = getStringListAttribute(attributes, "msDS-AllowedToDelegateTo");
        byte[] rbcdDescriptor = getBinaryAttribute(attributes, "msDS-AllowedToActOnBehalfOfOtherIdentity");
        List<String> servicePrincipalNames = getStringListAttribute(attributes, "servicePrincipalName");
        List<String> objectClasses = getStringListAttribute(attributes, "objectClass");
        String objectClass = classifyObjectClass(objectClasses);
        String objectSid = attributeToSid(attributes, "objectSid");

        return new DirectoryObjectRecord(
            account,
            dn,
            objectClass,
            uac,
            enabled,
            allowedToDelegateTo,
            rbcdDescriptor,
            List.of(),
            servicePrincipalNames,
            objectSid
        );
    }

    private String buildDelegationFilter(ModuleConfig config) {
        StringBuilder filter = new StringBuilder();
        filter.append("(&");
        filter.append("(|(objectCategory=person)(objectCategory=computer))");

        filter.append("(|");
        if (shouldIncludeUnconstrained(config.scope)) {
            filter.append("(userAccountControl:1.2.840.113556.1.4.803:=")
                .append(UF_TRUSTED_FOR_DELEGATION)
                .append(")");
        }
        if (shouldIncludeConstrained(config.scope)) {
            filter.append("(msDS-AllowedToDelegateTo=*)");
        }
        if (shouldIncludeResourceBased(config.scope)) {
            filter.append("(msDS-AllowedToActOnBehalfOfOtherIdentity=*)");
        }
        filter.append(")");

        if (!config.includeDisabled) {
            filter.append("(!(userAccountControl:1.2.840.113556.1.4.803:=")
                .append(UF_ACCOUNTDISABLE)
                .append("))");
        }

        if (config.mode == ModuleMode.PRINCIPAL_TRACE && !config.tracePrincipal.isBlank()) {
            String escaped = escapeFilterValue(config.tracePrincipal);
            if (config.traceMatchMode == TraceMatchMode.EXACT) {
                filter.append("(|")
                    .append("(sAMAccountName=").append(escaped).append(")")
                    .append("(cn=").append(escaped).append(")")
                    .append("(distinguishedName=").append(escaped).append(")")
                    .append("(dNSHostName=").append(escaped).append(")")
                    .append(")");
            } else {
                filter.append("(|")
                    .append("(sAMAccountName=*").append(escaped).append("*)")
                    .append("(cn=*").append(escaped).append("*)")
                    .append("(distinguishedName=*").append(escaped).append("*)")
                    .append("(dNSHostName=*").append(escaped).append("*)")
                    .append(")");
            }
        }

        filter.append(")");
        return filter.toString();
    }

    private ModuleConfig parseConfig(Map<String, String> input) {
        ModuleConfig config = new ModuleConfig();

        String rawTarget = trim(input.get("target"));
        LegacyTargetInput legacyTarget = parseLegacyTarget(rawTarget);

        config.mode = ModuleMode.fromInput(firstNonBlank(input.get("mode"), "surface_map"));
        config.scope = DelegationScope.fromInput(firstNonBlank(
            input.get("delegation_scope"),
            input.get("delegation_type"),
            "all"
        ));
        if (config.mode == ModuleMode.RBCD_TRUSTEE_AUDIT) {
            config.scope = DelegationScope.RESOURCE_BASED;
        }

        config.target = firstNonBlank(
            legacyTarget.target,
            input.get("domain"),
            input.get("dc_ip")
        );
        config.dcIp = trim(input.get("dc_ip"));
        config.baseDn = trim(input.get("base_dn"));
        config.username = firstNonBlank(input.get("username"), legacyTarget.username);
        config.password = firstNonBlank(input.get("password"), legacyTarget.password);
        config.hashes = trim(input.get("hashes"));
        config.useKerberos = parseBooleanWithDefault(input.get("use_kerberos"), false);
        config.aesKey = trim(input.get("aes_key"));
        config.useLdaps = parseBooleanWithDefault(input.get("use_ldaps"), false);
        config.includeDisabled = parseBooleanWithDefault(input.get("include_disabled"), false);

        boolean resolveTargetsExplicit = input.containsKey("resolve_target_objects");
        config.resolveTargetObjects = resolveTargetsExplicit
            ? parseBooleanWithDefault(input.get("resolve_target_objects"), false)
            : (config.mode == ModuleMode.ABUSE_GRAPH || config.mode == ModuleMode.PRINCIPAL_TRACE);

        boolean includeRbcdSidsExplicit = input.containsKey("include_rbcd_acl_sids");
        config.includeRbcdAclSids = includeRbcdSidsExplicit
            ? parseBooleanWithDefault(input.get("include_rbcd_acl_sids"), true)
            : config.mode != ModuleMode.SURFACE_MAP;

        config.rbcdResolvedOnly = parseBooleanWithDefault(input.get("rbcd_resolved_only"), false);
        config.tracePrincipal = firstNonBlank(input.get("trace_principal"), input.get("identify_target"));
        config.traceMatchMode = TraceMatchMode.fromInput(firstNonBlank(input.get("trace_match_mode"), "contains"));

        int defaultPort = config.useLdaps ? 636 : 389;
        config.ldapPort = parseInteger(input.get("ldap_port"), defaultPort);
        config.connectTimeoutMs = parseInteger(input.get("connect_timeout_ms"), DEFAULT_CONNECT_TIMEOUT_MS);
        config.readTimeoutMs = parseInteger(input.get("read_timeout_ms"), DEFAULT_READ_TIMEOUT_MS);
        config.maxResults = parseInteger(input.get("max_results"), DEFAULT_MAX_RESULTS);

        return config;
    }

    private List<String> validateConfig(ModuleConfig config) {
        List<String> errors = new ArrayList<>();

        if (config.target.isBlank()) {
            errors.add("target is required");
        }

        if (config.ldapPort < 1 || config.ldapPort > 65535) {
            errors.add("ldap_port must be between 1 and 65535");
        }

        if (config.connectTimeoutMs < 1 || config.connectTimeoutMs > 300_000) {
            errors.add("connect_timeout_ms must be between 1 and 300000");
        }

        if (config.readTimeoutMs < 1 || config.readTimeoutMs > 300_000) {
            errors.add("read_timeout_ms must be between 1 and 300000");
        }

        if (config.maxResults < 1 || config.maxResults > MAX_ALLOWED_RESULTS) {
            errors.add("max_results must be between 1 and " + MAX_ALLOWED_RESULTS);
        }

        if (config.username.isBlank() && !config.password.isBlank()) {
            errors.add("username is required when password is provided");
        }

        if (!config.username.isBlank() && config.password.isBlank() && !config.useKerberos) {
            if (!config.hashes.isBlank()) {
                errors.add("hash-only LDAP bind is unsupported in native Java LDAP path; use password or Kerberos");
            } else {
                errors.add("password is required for simple LDAP bind when username is provided");
            }
        }

        if (config.mode == ModuleMode.PRINCIPAL_TRACE && config.tracePrincipal.isBlank()) {
            errors.add("trace_principal is required when mode=principal_trace");
        }

        return errors;
    }

    private String buildLdapUrl(ModuleConfig config) {
        String host = !config.dcIp.isBlank() ? config.dcIp : config.target;
        String scheme = config.useLdaps ? "ldaps" : "ldap";
        return scheme + "://" + host + ":" + config.ldapPort;
    }

    private String normalizePrincipal(String username, String target) {
        String user = trim(username);
        if (user.isBlank()) {
            return "";
        }
        if (user.contains("\\") || user.contains("@")) {
            return user;
        }
        if (looksLikeDomainName(target)) {
            return user + "@" + target;
        }
        return user;
    }

    private String domainToBaseDn(String domain) {
        List<String> labels = new ArrayList<>();
        for (String part : domain.split("\\.")) {
            String trimmed = part.trim();
            if (!trimmed.isBlank()) {
                labels.add("DC=" + trimmed);
            }
        }
        return String.join(",", labels);
    }

    private String baseDnToDomain(String baseDn) {
        if (baseDn == null || baseDn.isBlank()) {
            return "";
        }

        List<String> labels = new ArrayList<>();
        for (String token : baseDn.split(",")) {
            String trimmed = token.trim();
            if (trimmed.regionMatches(true, 0, "DC=", 0, 3) && trimmed.length() > 3) {
                labels.add(trimmed.substring(3));
            }
        }
        return String.join(".", labels);
    }

    private String classifyObjectClass(List<String> objectClasses) {
        for (String objectClass : objectClasses) {
            String lowered = objectClass.toLowerCase(Locale.ROOT);
            if ("computer".equals(lowered)) {
                return "computer";
            }
            if ("user".equals(lowered)) {
                return "user";
            }
            if ("group".equals(lowered)) {
                return "group";
            }
        }
        return objectClasses.isEmpty() ? "unknown" : objectClasses.get(objectClasses.size() - 1);
    }

    private String extractServiceClass(String spn) {
        if (spn == null || spn.isBlank()) {
            return "";
        }
        int slash = spn.indexOf('/');
        return slash > 0 ? spn.substring(0, slash) : spn;
    }

    private String extractHostFromSpn(String spn) {
        if (spn == null || spn.isBlank()) {
            return "";
        }
        int slash = spn.indexOf('/');
        if (slash < 0 || slash + 1 >= spn.length()) {
            return "";
        }

        String hostPart = spn.substring(slash + 1);
        int secondSlash = hostPart.indexOf('/');
        if (secondSlash >= 0) {
            hostPart = hostPart.substring(0, secondSlash);
        }

        int portSeparator = hostPart.indexOf(':');
        if (portSeparator >= 0) {
            hostPart = hostPart.substring(0, portSeparator);
        }
        return hostPart;
    }

    private boolean shouldIncludeUnconstrained(DelegationScope scope) {
        return scope == DelegationScope.ALL || scope == DelegationScope.UNCONSTRAINED;
    }

    private boolean shouldIncludeConstrained(DelegationScope scope) {
        return scope == DelegationScope.ALL || scope == DelegationScope.CONSTRAINED;
    }

    private boolean shouldIncludeResourceBased(DelegationScope scope) {
        return scope == DelegationScope.ALL || scope == DelegationScope.RESOURCE_BASED;
    }

    private boolean hasUacFlag(int userAccountControl, int flag) {
        return (userAccountControl & flag) != 0;
    }

    private String escapeFilterValue(String value) {
        StringBuilder escaped = new StringBuilder();
        for (char c : value.toCharArray()) {
            switch (c) {
                case '\\': escaped.append("\\5c"); break;
                case '*': escaped.append("\\2a"); break;
                case '(': escaped.append("\\28"); break;
                case ')': escaped.append("\\29"); break;
                case '\u0000': escaped.append("\\00"); break;
                default: escaped.append(c);
            }
        }
        return escaped.toString();
    }

    private List<String> parseRbcdTrusteeSids(byte[] securityDescriptor) {
        if (securityDescriptor == null || securityDescriptor.length < 20) {
            return List.of();
        }

        ByteBuffer descriptor = ByteBuffer.wrap(securityDescriptor).order(ByteOrder.LITTLE_ENDIAN);
        descriptor.get(); // revision
        descriptor.get(); // sbz1
        descriptor.getShort(); // control
        descriptor.getInt(); // owner offset
        descriptor.getInt(); // group offset
        descriptor.getInt(); // sacl offset
        int daclOffset = descriptor.getInt();

        if (daclOffset <= 0 || daclOffset + 8 > securityDescriptor.length) {
            return List.of();
        }

        int aceCount = readUInt16LE(securityDescriptor, daclOffset + 4);
        int cursor = daclOffset + 8;
        List<String> trusteeSids = new ArrayList<>();

        for (int i = 0; i < aceCount; i++) {
            if (cursor + 4 > securityDescriptor.length) {
                break;
            }

            int aceType = u8(securityDescriptor[cursor]);
            int aceSize = readUInt16LE(securityDescriptor, cursor + 2);
            if (aceSize < 4 || cursor + aceSize > securityDescriptor.length) {
                break;
            }

            int sidOffset = locateSidOffsetInAce(securityDescriptor, cursor, aceType, aceSize);
            if (sidOffset > 0) {
                String sid = parseSid(securityDescriptor, sidOffset, cursor + aceSize);
                if (!sid.isBlank()) {
                    trusteeSids.add(sid);
                }
            }

            cursor += aceSize;
        }

        return new ArrayList<>(new LinkedHashSet<>(trusteeSids));
    }

    private int locateSidOffsetInAce(byte[] data, int aceOffset, int aceType, int aceSize) {
        if (aceSize < 8) {
            return -1;
        }

        // ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE / SYSTEM_AUDIT_ACE / SYSTEM_ALARM_ACE
        if (aceType == 0x00 || aceType == 0x01 || aceType == 0x02 || aceType == 0x03) {
            return aceOffset + 8;
        }

        // *_OBJECT_ACE types where SID is after mask + flags + optional GUIDs.
        if (aceType == 0x05 || aceType == 0x06 || aceType == 0x07 || aceType == 0x08 || aceType == 0x0B || aceType == 0x0C) {
            if (aceOffset + 12 > data.length) {
                return -1;
            }
            int flags = readInt32LE(data, aceOffset + 8);
            int cursor = aceOffset + 12;
            if ((flags & 0x1) != 0) {
                cursor += 16;
            }
            if ((flags & 0x2) != 0) {
                cursor += 16;
            }
            return cursor;
        }

        int fallback = aceOffset + 8;
        if (fallback < aceOffset + aceSize) {
            return fallback;
        }
        return -1;
    }

    private String parseSid(byte[] data, int offset, int maxExclusive) {
        if (offset < 0 || offset + 8 > maxExclusive || offset + 8 > data.length) {
            return "";
        }

        int revision = u8(data[offset]);
        int subAuthorityCount = u8(data[offset + 1]);
        int requiredLength = 8 + (subAuthorityCount * 4);
        if (offset + requiredLength > maxExclusive || offset + requiredLength > data.length) {
            return "";
        }

        long identifierAuthority = 0;
        for (int i = 0; i < 6; i++) {
            identifierAuthority = (identifierAuthority << 8) | u8(data[offset + 2 + i]);
        }

        StringBuilder sid = new StringBuilder();
        sid.append("S-").append(revision).append('-').append(identifierAuthority);
        for (int i = 0; i < subAuthorityCount; i++) {
            long subAuth = readUInt32LE(data, offset + 8 + (i * 4));
            sid.append('-').append(subAuth);
        }
        return sid.toString();
    }

    private int readUInt16LE(byte[] data, int offset) {
        if (offset + 2 > data.length) {
            return 0;
        }
        return (u8(data[offset]) | (u8(data[offset + 1]) << 8));
    }

    private int readInt32LE(byte[] data, int offset) {
        if (offset + 4 > data.length) {
            return 0;
        }
        return (u8(data[offset]))
            | (u8(data[offset + 1]) << 8)
            | (u8(data[offset + 2]) << 16)
            | (u8(data[offset + 3]) << 24);
    }

    private long readUInt32LE(byte[] data, int offset) {
        return Integer.toUnsignedLong(readInt32LE(data, offset));
    }

    private int u8(byte b) {
        return b & 0xFF;
    }

    private String attributeToSid(Attributes attributes, String attributeName) throws NamingException {
        Attribute sidAttribute = findAttribute(attributes, attributeName);
        if (sidAttribute == null || sidAttribute.size() == 0) {
            return "";
        }

        Object sidValue = sidAttribute.get();
        if (sidValue instanceof byte[]) {
            byte[] sidBytes = (byte[]) sidValue;
            return parseSid(sidBytes, 0, sidBytes.length);
        }
        return String.valueOf(sidValue);
    }

    private String safeNameInNamespace(SearchResult result) {
        try {
            return result.getNameInNamespace();
        } catch (Exception ignored) {
            return result.getName();
        }
    }

    private Attribute findAttribute(Attributes attrs, String name) throws NamingException {
        if (attrs == null || name == null) {
            return null;
        }

        Attribute direct = attrs.get(name);
        if (direct != null) {
            return direct;
        }

        NamingEnumeration<? extends Attribute> all = attrs.getAll();
        try {
            while (all.hasMore()) {
                Attribute attr = all.next();
                if (attr.getID() != null && attr.getID().equalsIgnoreCase(name)) {
                    return attr;
                }
            }
        } finally {
            if (all != null) {
                all.close();
            }
        }
        return null;
    }

    private String getStringAttribute(Attributes attrs, String name) throws NamingException {
        Attribute attr = findAttribute(attrs, name);
        if (attr == null || attr.size() == 0) {
            return "";
        }
        Object value = attr.get();
        return value == null ? "" : String.valueOf(value).trim();
    }

    private List<String> getStringListAttribute(Attributes attrs, String name) throws NamingException {
        Attribute attr = findAttribute(attrs, name);
        if (attr == null || attr.size() == 0) {
            return List.of();
        }

        List<String> values = new ArrayList<>();
        NamingEnumeration<?> all = attr.getAll();
        try {
            while (all.hasMore()) {
                Object value = all.next();
                if (value != null) {
                    String text = String.valueOf(value).trim();
                    if (!text.isBlank()) {
                        values.add(text);
                    }
                }
            }
        } finally {
            if (all != null) {
                all.close();
            }
        }
        return values;
    }

    private byte[] getBinaryAttribute(Attributes attrs, String name) throws NamingException {
        Attribute attr = findAttribute(attrs, name);
        if (attr == null || attr.size() == 0) {
            return new byte[0];
        }

        Object value = attr.get();
        if (value instanceof byte[]) {
            return (byte[]) value;
        }

        if (value instanceof ByteBuffer) {
            ByteBuffer buffer = ((ByteBuffer) value).slice();
            byte[] bytes = new byte[buffer.remaining()];
            buffer.get(bytes);
            return bytes;
        }

        return new byte[0];
    }

    private LegacyTargetInput parseLegacyTarget(String targetInput) {
        LegacyTargetInput parsed = new LegacyTargetInput();
        String raw = trim(targetInput);
        if (raw.isBlank()) {
            return parsed;
        }

        if (!raw.contains("/")) {
            parsed.target = raw;
            return parsed;
        }

        String[] split = raw.split("/", 2);
        parsed.target = trim(split[0]);
        if (split.length < 2 || split[1].isBlank()) {
            return parsed;
        }

        String[] credentialSplit = split[1].split(":", 2);
        parsed.username = trim(credentialSplit[0]);
        if (credentialSplit.length > 1) {
            parsed.password = credentialSplit[1];
        }

        return parsed;
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

    private boolean parseBooleanWithDefault(String value, boolean defaultValue) {
        String raw = trim(value);
        if (raw.isBlank()) {
            return defaultValue;
        }
        return Boolean.parseBoolean(raw);
    }

    private String trim(String value) {
        return value == null ? "" : value.trim();
    }

    private String firstNonBlank(String... candidates) {
        for (String candidate : candidates) {
            if (candidate != null && !candidate.trim().isBlank()) {
                return candidate.trim();
            }
        }
        return "";
    }

    private boolean looksLikeDomainName(String value) {
        String candidate = trim(value).toLowerCase(Locale.ROOT);
        if (candidate.isBlank()) {
            return false;
        }
        if (candidate.matches("^\\d{1,3}(\\.\\d{1,3}){3}$")) {
            return false;
        }
        return candidate.contains(".");
    }

    private void closeQuietly(LdapContext ldap) {
        if (ldap != null) {
            try {
                ldap.close();
            } catch (Exception ignored) {
                // noop
            }
        }
    }

    protected static final class DirectoryObjectRecord {
        protected final String accountName;
        protected final String distinguishedName;
        protected final String objectClass;
        protected final int userAccountControl;
        protected final boolean enabled;
        protected final List<String> allowedToDelegateTo;
        protected final byte[] rbcdSecurityDescriptor;
        protected final List<String> rbcdTrusteeSids;
        protected final List<String> servicePrincipalNames;
        protected final String objectSid;

        protected DirectoryObjectRecord(
                String accountName,
                String distinguishedName,
                String objectClass,
                int userAccountControl,
                boolean enabled,
                List<String> allowedToDelegateTo,
                byte[] rbcdSecurityDescriptor,
                List<String> rbcdTrusteeSids,
                List<String> servicePrincipalNames,
                String objectSid) {
            this.accountName = accountName;
            this.distinguishedName = distinguishedName;
            this.objectClass = objectClass;
            this.userAccountControl = userAccountControl;
            this.enabled = enabled;
            this.allowedToDelegateTo = allowedToDelegateTo == null ? List.of() : List.copyOf(allowedToDelegateTo);
            this.rbcdSecurityDescriptor = rbcdSecurityDescriptor == null ? new byte[0] : Arrays.copyOf(rbcdSecurityDescriptor, rbcdSecurityDescriptor.length);
            this.rbcdTrusteeSids = rbcdTrusteeSids == null ? List.of() : List.copyOf(rbcdTrusteeSids);
            this.servicePrincipalNames = servicePrincipalNames == null ? List.of() : List.copyOf(servicePrincipalNames);
            this.objectSid = objectSid == null ? "" : objectSid;
        }
    }

    protected static final class SidIdentity {
        protected final String accountName;
        protected final String distinguishedName;
        protected final String objectClass;

        protected SidIdentity(String accountName, String distinguishedName, String objectClass) {
            this.accountName = accountName == null ? "" : accountName;
            this.distinguishedName = distinguishedName == null ? "" : distinguishedName;
            this.objectClass = objectClass == null ? "" : objectClass;
        }
    }

    protected static final class TargetObject {
        protected final String accountName;
        protected final String distinguishedName;
        protected final String objectClass;

        protected TargetObject(String accountName, String distinguishedName, String objectClass) {
            this.accountName = accountName == null ? "" : accountName;
            this.distinguishedName = distinguishedName == null ? "" : distinguishedName;
            this.objectClass = objectClass == null ? "" : objectClass;
        }
    }

    protected enum ModuleMode {
        SURFACE_MAP("surface_map"),
        ABUSE_GRAPH("abuse_graph"),
        RBCD_TRUSTEE_AUDIT("rbcd_trustee_audit"),
        PRINCIPAL_TRACE("principal_trace");

        private final String value;

        ModuleMode(String value) {
            this.value = value;
        }

        protected static ModuleMode fromInput(String raw) {
            String normalized = raw == null
                ? ""
                : raw.trim().toLowerCase(Locale.ROOT).replace('-', '_').replace(' ', '_');

            return switch (normalized) {
                case "surface_map", "surface", "discovery" -> SURFACE_MAP;
                case "abuse_graph", "abuse", "analysis", "deep_scan", "deepscan" -> ABUSE_GRAPH;
                case "rbcd_trustee_audit", "rbcd_audit", "rbcd" -> RBCD_TRUSTEE_AUDIT;
                case "principal_trace", "trace", "identify", "identification" -> PRINCIPAL_TRACE;
                default -> SURFACE_MAP;
            };
        }
    }

    protected enum TraceMatchMode {
        CONTAINS("contains"),
        EXACT("exact");

        private final String value;

        TraceMatchMode(String value) {
            this.value = value;
        }

        protected static TraceMatchMode fromInput(String raw) {
            String normalized = raw == null
                ? ""
                : raw.trim().toLowerCase(Locale.ROOT).replace('-', '_').replace(' ', '_');

            return switch (normalized) {
                case "exact", "equals" -> EXACT;
                default -> CONTAINS;
            };
        }
    }

    protected enum DelegationScope {
        ALL("all"),
        UNCONSTRAINED("unconstrained"),
        CONSTRAINED("constrained"),
        RESOURCE_BASED("resource_based");

        private final String value;

        DelegationScope(String value) {
            this.value = value;
        }

        protected static DelegationScope fromInput(String raw) {
            String normalized = raw == null
                ? ""
                : raw.trim().toLowerCase(Locale.ROOT).replace('-', '_').replace(' ', '_');

            if (normalized.contains("resource")) {
                return RESOURCE_BASED;
            }
            if (normalized.contains("unconstrained")) {
                return UNCONSTRAINED;
            }
            if (normalized.contains("constrained")) {
                return CONSTRAINED;
            }
            return ALL;
        }
    }

    protected static final class ModuleConfig {
        private ModuleMode mode = ModuleMode.SURFACE_MAP;
        private DelegationScope scope = DelegationScope.ALL;
        private String target = "";
        private String dcIp = "";
        private String baseDn = "";
        private String username = "";
        private String password = "";
        private String hashes = "";
        private boolean useKerberos;
        private String aesKey = "";
        private boolean useLdaps;
        private boolean includeDisabled;
        private boolean resolveTargetObjects;
        private boolean includeRbcdAclSids = true;
        private boolean rbcdResolvedOnly;
        private String tracePrincipal = "";
        private TraceMatchMode traceMatchMode = TraceMatchMode.CONTAINS;
        private int ldapPort = 389;
        private int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
        private int readTimeoutMs = DEFAULT_READ_TIMEOUT_MS;
        private int maxResults = DEFAULT_MAX_RESULTS;
    }

    private static final class LegacyTargetInput {
        private String target = "";
        private String username = "";
        private String password = "";
    }
}
