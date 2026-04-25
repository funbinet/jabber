package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.*;
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
 * AD Computer Enumerator.
 *
 * Real LDAP-backed computer object mapper that follows a strict mode pipeline:
 * mode selection -> input validation -> processing engine -> execution steps -> result normalization.
 *
 * Core objective:
 * Query (objectClass=computer) and normalize host inventory into actionable
 * infrastructure intelligence for lateral movement planning and target classification.
 */
@JRTSModule(
    id = "ad-computer-enumerator",
    name = "AD Computer Enumerator",
    description = "Enumerate AD computer objects over LDAP and extract hostnames, operating system data, logon recency, role flags, and optional DNS-resolved IP addresses.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.MEDIUM,
    sourceRef = "GetADComputers.py / LDAP computer object search",
    author = "JRTS"
)
public class ADComputerEnumeratorModule implements JRTSModuleInterface {

    private static final String MODULE_ID = "ad-computer-enumerator";

    private static final int UF_ACCOUNTDISABLE = 0x00000002;
    private static final int UF_WORKSTATION_TRUST_ACCOUNT = 0x00001000;
    private static final int UF_SERVER_TRUST_ACCOUNT = 0x00002000;
    private static final int UF_TRUSTED_FOR_DELEGATION = 0x00080000;

    private static final int DEFAULT_LDAP_PORT = 389;
    private static final int DEFAULT_LDAPS_PORT = 636;
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 10_000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 15_000;
    private static final int DEFAULT_MAX_RESULTS = 5_000;
    private static final int MAX_ALLOWED_RESULTS = 50_000;
    private static final int DEFAULT_STALE_DAYS_THRESHOLD = 90;

    private static final long AD_EPOCH_DIFF_SECONDS = 11_644_473_600L;
    private static final String[] COMPUTER_ATTRIBUTES = new String[] {
        "sAMAccountName",
        "dNSHostName",
        "operatingSystem",
        "operatingSystemVersion",
        "operatingSystemServicePack",
        "lastLogonTimestamp",
        "userAccountControl",
        "distinguishedName",
        "whenCreated",
        "whenChanged",
        "cn"
    };

    private static final DateTimeFormatter ISO_FMT = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of(
                    "inventory_map",
                    "target_classification",
                    "legacy_risk_audit",
                    "host_confirmation"
                ))
                .required()
                .defaultValue("inventory_map")
                .group("Mode")
                .helpText("Select the AD computer enumeration strategy and output perspective."),
            ModuleInputField.text("focus_host", "Focus Host")
                .placeholder("dc01.contoso.local or APP01$")
                .group("Mode")
                .modes("host_confirmation")
                .helpText("Required when mode=host_confirmation."),

            ModuleInputField.text("target", "Target Domain/DC")
                .required()
                .placeholder("contoso.local or dc01.contoso.local")
                .group("Target")
                .helpText("Domain FQDN or Domain Controller hostname/IP."),
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
                .helpText("Accepted as context; Java LDAP simple bind does not support hash-only auth."),
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

            ModuleInputField.checkbox("resolve_ips", "Resolve Host IP Addresses")
                .defaultValue("false")
                .group("Options"),
            ModuleInputField.checkbox("include_disabled", "Include Disabled Computer Accounts")
                .defaultValue("false")
                .group("Options"),
            ModuleInputField.text("os_filter", "OS Filter")
                .placeholder("Windows Server")
                .group("Options")
                .modes("inventory_map", "target_classification", "legacy_risk_audit")
                .helpText("Case-insensitive contains filter on operatingSystem."),
            ModuleInputField.text("hostname_filter", "Hostname Filter")
                .placeholder("dc* or *sql*")
                .group("Options")
                .modes("inventory_map", "target_classification", "legacy_risk_audit")
                .helpText("Wildcard filter matched against dNSHostName/sAMAccountName/CN."),
            ModuleInputField.text("stale_days_threshold", "Stale Logon Threshold (days)")
                .placeholder(String.valueOf(DEFAULT_STALE_DAYS_THRESHOLD))
                .group("Options")
                .helpText("Hosts older than threshold since lastLogonTimestamp are marked stale."),
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
                ctx.log("[*] Starting AD Computer Enumerator module");
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

                List<ComputerRecord> allRecords = fetchComputerRecords(ldap, baseDn, config, ctx);
                ctx.log("[*] LDAP computer objects returned: " + allRecords.size());
                ctx.reportProgress(62);

                List<ComputerRecord> filteredRecords = new ArrayList<>();
                for (ComputerRecord record : allRecords) {
                    if (matchesFilters(record, config)) {
                        if (config.resolveIps && !record.dnsHostName.isBlank()) {
                            record.ipAddresses = resolveIpAddresses(record.dnsHostName);
                        }
                        filteredRecords.add(record);
                    }
                }
                filteredRecords.sort(this::compareRecords);
                ctx.reportProgress(78);

                List<Map<String, Object>> findings = new ArrayList<>();
                for (ComputerRecord record : filteredRecords) {
                    Map<String, Object> finding = toFinding(record, config);
                    findings.add(finding);
                    result.addFinding(finding);
                }

                Map<String, Object> summary = buildSummary(allRecords, filteredRecords, config);
                Map<String, Object> modeResult = buildModeResult(filteredRecords, config);

                Map<String, Object> executionMetadata = new LinkedHashMap<>();
                executionMetadata.put("ldap_url", buildLdapUrl(config));
                executionMetadata.put("base_dn", baseDn);
                executionMetadata.put("ldap_filter", buildLdapFilter(config));
                executionMetadata.put("requested_attributes", Arrays.asList(COMPUTER_ATTRIBUTES));
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
                output.put("computers", findings);
                output.put("operational_stack", buildOperationalStack());
                output.put(config.mode.resultKey, modeResult);
                output.put("execution_metadata", executionMetadata);

                result.setNormalizedOutput(buildNormalizedOutput(summary, findings, config));

                result.complete(output);
                ctx.log("[+] AD Computer Enumeration completed with " + findings.size() + " host(s)");
                ctx.reportProgress(100);

            } catch (NamingException e) {
                result.fail("LDAP execution failed: " + e.getMessage());
                ctx.log("[!] LDAP execution failed: " + e.getMessage());
            } catch (Exception e) {
                result.fail("AD Computer Enumeration failed: " + e.getMessage());
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

    protected List<ComputerRecord> fetchComputerRecords(
            LdapContext ldap,
            String baseDn,
            ModuleConfig config,
            TaskContext ctx) throws NamingException {

        String filter = buildLdapFilter(config);
        ctx.log("[*] LDAP filter: " + filter);

        List<SearchResult> searchResults = ldapSearch(ldap, baseDn, filter, COMPUTER_ATTRIBUTES, config.maxResults);
        List<ComputerRecord> records = new ArrayList<>(searchResults.size());
        for (SearchResult result : searchResults) {
            ComputerRecord record = toComputerRecord(result);
            if (record != null) {
                records.add(record);
            }
        }
        return records;
    }

    protected List<String> resolveIpAddresses(String dnsHostName) {
        List<String> ips = new ArrayList<>();
        try {
            java.net.InetAddress[] addresses = java.net.InetAddress.getAllByName(dnsHostName);
            for (java.net.InetAddress address : addresses) {
                ips.add(address.getHostAddress());
            }
        } catch (Exception ignored) {
            // DNS resolution is best effort for optional infrastructure mapping.
        }
        return ips;
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
            // AD often emits partial results when referrals are disabled.
        } finally {
            if (results != null) {
                results.close();
            }
        }
        return collected;
    }

    private ComputerRecord toComputerRecord(SearchResult result) throws NamingException {
        Attributes attrs = result.getAttributes();
        if (attrs == null) {
            return null;
        }

        String samAccountName = stripTrailingDollar(firstNonBlank(
            getStringAttribute(attrs, "sAMAccountName"),
            getStringAttribute(attrs, "cn"),
            result.getName()
        ));

        String dnsHostName = firstNonBlank(
            getStringAttribute(attrs, "dNSHostName"),
            ""
        );

        String operatingSystem = getStringAttribute(attrs, "operatingSystem");
        String operatingSystemVersion = getStringAttribute(attrs, "operatingSystemVersion");
        String operatingSystemServicePack = getStringAttribute(attrs, "operatingSystemServicePack");
        String distinguishedName = firstNonBlank(
            getStringAttribute(attrs, "distinguishedName"),
            safeNameInNamespace(result),
            result.getName()
        );

        int userAccountControl = parseInteger(getStringAttribute(attrs, "userAccountControl"), 0);
        long lastLogonTimestampRaw = parseLong(getStringAttribute(attrs, "lastLogonTimestamp"), 0L);

        ComputerRecord record = new ComputerRecord();
        record.samAccountName = samAccountName;
        record.dnsHostName = dnsHostName;
        record.operatingSystem = operatingSystem;
        record.operatingSystemVersion = operatingSystemVersion;
        record.operatingSystemServicePack = operatingSystemServicePack;
        record.distinguishedName = distinguishedName;
        record.userAccountControl = userAccountControl;
        record.lastLogonTimestampRaw = lastLogonTimestampRaw;
        record.lastLogonTimestamp = fileTimeToIso(lastLogonTimestampRaw);
        record.lastLogonAgeDays = computeLastLogonAgeDays(lastLogonTimestampRaw);
        record.flags = decodeUacFlags(userAccountControl);
        record.disabled = hasUacFlag(userAccountControl, UF_ACCOUNTDISABLE);
        record.role = classifyRole(record);
        record.legacy = isLegacySystem(record);
        record.highValue = isHighValue(record);
        record.status = deriveStatus(record, DEFAULT_STALE_DAYS_THRESHOLD);

        return record;
    }

    private boolean matchesFilters(ComputerRecord record, ModuleConfig config) {
        if (!config.includeDisabled && record.disabled) {
            return false;
        }

        if (!config.osFilter.isBlank()) {
            String os = firstNonBlank(record.operatingSystem).toLowerCase(Locale.ROOT);
            if (!os.contains(config.osFilter.toLowerCase(Locale.ROOT))) {
                return false;
            }
        }

        if (!config.hostnameFilter.isBlank()) {
            if (!wildcardMatches(record.dnsHostName, config.hostnameFilter)
                    && !wildcardMatches(record.samAccountName, config.hostnameFilter)) {
                return false;
            }
        }

        if (config.mode == ModuleMode.HOST_CONFIRMATION) {
            if (config.focusHost.isBlank()) {
                return false;
            }
            String focus = normalizeFocus(config.focusHost);
            String host = normalizeFocus(record.dnsHostName);
            String account = normalizeFocus(record.samAccountName);
            return focus.equals(host) || focus.equals(account) || host.contains(focus) || account.contains(focus);
        }

        return true;
    }

    private Map<String, Object> toFinding(ComputerRecord record, ModuleConfig config) {
        String status = deriveStatus(record, config.staleDaysThreshold);

        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("computer_name", record.samAccountName);
        finding.put("dns_hostname", record.dnsHostName);
        finding.put("operating_system", record.operatingSystem);
        finding.put("operating_system_version", record.operatingSystemVersion);
        finding.put("operating_system_service_pack", record.operatingSystemServicePack);
        finding.put("last_logon_timestamp", record.lastLogonTimestamp);
        finding.put("last_logon_age_days", record.lastLogonAgeDays);
        finding.put("user_account_control", record.userAccountControl);
        finding.put("uac_flags", record.flags);
        finding.put("role", record.role.value);
        finding.put("high_value", record.highValue);
        finding.put("high_value_reasons", highValueReasons(record));
        finding.put("legacy", record.legacy);
        finding.put("legacy_reasons", legacyReasons(record));
        finding.put("status", status);
        finding.put("distinguished_name", record.distinguishedName);
        if (config.resolveIps) {
            finding.put("ip_addresses", record.ipAddresses);
        }
        return finding;
    }

    private Map<String, Object> buildSummary(
            List<ComputerRecord> allRecords,
            List<ComputerRecord> filteredRecords,
            ModuleConfig config) {

        long domainControllers = filteredRecords.stream().filter(r -> r.role == MachineRole.DOMAIN_CONTROLLER).count();
        long servers = filteredRecords.stream().filter(r -> r.role == MachineRole.SERVER).count();
        long workstations = filteredRecords.stream().filter(r -> r.role == MachineRole.WORKSTATION).count();
        long unknown = filteredRecords.stream().filter(r -> r.role == MachineRole.UNKNOWN).count();
        long legacy = filteredRecords.stream().filter(r -> r.legacy).count();
        long highValue = filteredRecords.stream().filter(r -> r.highValue).count();
        long disabled = filteredRecords.stream().filter(r -> r.disabled).count();
        long stale = filteredRecords.stream()
            .filter(r -> r.lastLogonAgeDays >= 0 && r.lastLogonAgeDays > config.staleDaysThreshold)
            .count();
        long resolvedIpHosts = filteredRecords.stream()
            .filter(r -> r.ipAddresses != null && !r.ipAddresses.isEmpty())
            .count();

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", config.mode.value);
        summary.put("total_ldap_objects", allRecords.size());
        summary.put("total_computers", filteredRecords.size());
        summary.put("domain_controller_count", domainControllers);
        summary.put("server_count", servers);
        summary.put("workstation_count", workstations);
        summary.put("unknown_role_count", unknown);
        summary.put("high_value_count", highValue);
        summary.put("legacy_count", legacy);
        summary.put("disabled_count", disabled);
        summary.put("stale_count", stale);
        summary.put("resolved_ip_count", resolvedIpHosts);
        summary.put("stale_days_threshold", config.staleDaysThreshold);
        return summary;
    }

    private Map<String, Object> buildModeResult(List<ComputerRecord> records, ModuleConfig config) {
        return switch (config.mode) {
            case INVENTORY_MAP -> buildInventoryResult(records, config);
            case TARGET_CLASSIFICATION -> buildTargetClassificationResult(records, config);
            case LEGACY_RISK_AUDIT -> buildLegacyRiskResult(records, config);
            case HOST_CONFIRMATION -> buildHostConfirmationResult(records, config);
        };
    }

    private Map<String, Object> buildInventoryResult(List<ComputerRecord> records, ModuleConfig config) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("inventory_size", records.size());
        result.put("fields", List.of(
            "computer_name",
            "dns_hostname",
            "operating_system",
            "operating_system_version",
            "last_logon_timestamp",
            "user_account_control",
            "role",
            "status"
        ));
        result.put("resolve_ips", config.resolveIps);
        return result;
    }

    private Map<String, Object> buildTargetClassificationResult(List<ComputerRecord> records, ModuleConfig config) {
        List<Map<String, Object>> domainControllers = new ArrayList<>();
        List<Map<String, Object>> servers = new ArrayList<>();
        List<Map<String, Object>> workstations = new ArrayList<>();
        List<Map<String, Object>> highValue = new ArrayList<>();

        for (ComputerRecord record : records) {
            Map<String, Object> view = hostView(record, config.resolveIps);
            switch (record.role) {
                case DOMAIN_CONTROLLER -> domainControllers.add(view);
                case SERVER -> servers.add(view);
                case WORKSTATION -> workstations.add(view);
                default -> {
                }
            }
            if (record.highValue) {
                highValue.add(view);
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("domain_controllers", domainControllers);
        result.put("servers", servers);
        result.put("workstations", workstations);
        result.put("high_value_targets", highValue);
        return result;
    }

    private Map<String, Object> buildLegacyRiskResult(List<ComputerRecord> records, ModuleConfig config) {
        List<Map<String, Object>> legacySystems = new ArrayList<>();
        List<Map<String, Object>> staleSystems = new ArrayList<>();

        for (ComputerRecord record : records) {
            if (record.legacy) {
                legacySystems.add(hostView(record, config.resolveIps));
            }
            if (record.lastLogonAgeDays >= 0 && record.lastLogonAgeDays > config.staleDaysThreshold) {
                staleSystems.add(hostView(record, config.resolveIps));
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("legacy_systems", legacySystems);
        result.put("stale_systems", staleSystems);
        result.put("legacy_reasons", List.of(
            "Older Windows release family",
            "Known end-of-life operating system lineage",
            "Potentially unsupported security baseline"
        ));
        return result;
    }

    private Map<String, Object> buildHostConfirmationResult(List<ComputerRecord> records, ModuleConfig config) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("focus_host", config.focusHost);
        result.put("confirmed", !records.isEmpty());
        result.put("match_count", records.size());
        result.put("matches", records.stream()
            .map(record -> hostView(record, config.resolveIps))
            .toList());
        return result;
    }

    private Map<String, Object> hostView(ComputerRecord record, boolean includeIps) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("computer_name", record.samAccountName);
        view.put("dns_hostname", record.dnsHostName);
        view.put("operating_system", record.operatingSystem);
        view.put("operating_system_version", record.operatingSystemVersion);
        view.put("role", record.role.value);
        view.put("high_value", record.highValue);
        view.put("legacy", record.legacy);
        if (includeIps) {
            view.put("ip_addresses", record.ipAddresses);
        }
        return view;
    }

    private List<Map<String, Object>> buildOperationalStack() {
        List<Map<String, Object>> stack = new ArrayList<>();
        stack.add(tool("PowerView", "Primary AD computer enumeration and object expansion", "https://github.com/PowerShellMafia/PowerSploit"));
        stack.add(tool("ActiveDirectory PowerShell Module", "Native AD object retrieval on Windows hosts", "https://learn.microsoft.com/en-us/powershell/module/activedirectory/"));
        stack.add(tool("LDAP Raw Query", "Directory-level retrieval of computer objects", "https://learn.microsoft.com/en-us/windows/win32/adsi/searching-with-ldap"));
        stack.add(tool("ldapsearch", "Linux-based LDAP query execution", "https://www.openldap.org/software/man.cgi?query=ldapsearch"));
        stack.add(tool("BloodHound", "Graph enrichment for host relationships and AD paths", "https://bloodhound.readthedocs.io/"));
        return stack;
    }

    private Map<String, Object> tool(String name, String purpose, String reference) {
        Map<String, Object> tool = new LinkedHashMap<>();
        tool.put("name", name);
        tool.put("purpose", purpose);
        tool.put("reference", reference);
        return tool;
    }

    private Map<String, Object> buildNormalizedOutput(
            Map<String, Object> summary,
            List<Map<String, Object>> findings,
            ModuleConfig config) {

        long legacyCount = ((Number) summary.getOrDefault("legacy_count", 0)).longValue();
        long highValueCount = ((Number) summary.getOrDefault("high_value_count", 0)).longValue();

        Map<String, Object> rawOutput = new LinkedHashMap<>();
        rawOutput.put("summary", summary);
        rawOutput.put("record_count", findings.size());

        Map<String, Object> parsedOutput = new LinkedHashMap<>();
        parsedOutput.put("status", legacyCount > 0
            ? "AD_COMPUTER_LEGACY_RISK_IDENTIFIED"
            : "AD_COMPUTER_INVENTORY_COMPLETED");
        parsedOutput.put("vulnerable", legacyCount > 0);
        parsedOutput.put("details", summary);
        parsedOutput.put("evidence", findings);
        parsedOutput.put("high_value_targets", highValueCount);

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
        StringBuilder filter = new StringBuilder("(&(objectClass=computer)");
        if (!config.includeDisabled) {
            filter.append("(!(userAccountControl:1.2.840.113556.1.4.803:=")
                .append(UF_ACCOUNTDISABLE)
                .append("))");
        }

        if (config.mode == ModuleMode.HOST_CONFIRMATION && !config.focusHost.isBlank()) {
            String escaped = escapeFilterValue(stripTrailingDollar(config.focusHost));
            filter.append("(|")
                .append("(dNSHostName=").append(escaped).append(")")
                .append("(sAMAccountName=").append(escaped).append("$)")
                .append("(cn=").append(escaped).append(")")
                .append(")");
        }

        filter.append(")");
        return filter.toString();
    }

    private ModuleConfig parseConfig(Map<String, String> input) {
        ModuleConfig config = new ModuleConfig();

        String legacyTarget = firstNonBlank(input.get("target"), "");
        LegacyTargetInput parsedLegacy = parseLegacyTarget(legacyTarget);

        config.mode = ModuleMode.fromInput(firstNonBlank(input.get("mode"), "inventory_map"));
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

        config.resolveIps = parseBoolean(input.get("resolve_ips"), false);
        config.includeDisabled = parseBoolean(input.get("include_disabled"), false);
        config.osFilter = trim(input.get("os_filter"));
        config.hostnameFilter = trim(input.get("hostname_filter"));
        config.focusHost = firstNonBlank(input.get("focus_host"), input.get("identify_target"));
        config.staleDaysThreshold = parseInteger(input.get("stale_days_threshold"), DEFAULT_STALE_DAYS_THRESHOLD);

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

        if (config.staleDaysThreshold < 0 || config.staleDaysThreshold > 3650) {
            errors.add("stale_days_threshold must be between 0 and 3650");
        }

        return errors;
    }

    private int compareRecords(ComputerRecord left, ComputerRecord right) {
        int byRole = left.role.value.compareTo(right.role.value);
        if (byRole != 0) {
            return byRole;
        }

        String leftHost = firstNonBlank(left.dnsHostName, left.samAccountName);
        String rightHost = firstNonBlank(right.dnsHostName, right.samAccountName);
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

    private List<String> decodeUacFlags(int userAccountControl) {
        List<String> flags = new ArrayList<>();
        if (hasUacFlag(userAccountControl, UF_ACCOUNTDISABLE)) {
            flags.add("ACCOUNTDISABLE");
        }
        if (hasUacFlag(userAccountControl, UF_WORKSTATION_TRUST_ACCOUNT)) {
            flags.add("WORKSTATION_TRUST_ACCOUNT");
        }
        if (hasUacFlag(userAccountControl, UF_SERVER_TRUST_ACCOUNT)) {
            flags.add("SERVER_TRUST_ACCOUNT");
        }
        if (hasUacFlag(userAccountControl, UF_TRUSTED_FOR_DELEGATION)) {
            flags.add("TRUSTED_FOR_DELEGATION");
        }
        return flags;
    }

    private boolean hasUacFlag(int uac, int flag) {
        return (uac & flag) == flag;
    }

    private MachineRole classifyRole(ComputerRecord record) {
        if (hasUacFlag(record.userAccountControl, UF_SERVER_TRUST_ACCOUNT)) {
            return MachineRole.DOMAIN_CONTROLLER;
        }

        String os = firstNonBlank(record.operatingSystem).toLowerCase(Locale.ROOT);
        if (os.contains("server")) {
            return MachineRole.SERVER;
        }
        if (hasUacFlag(record.userAccountControl, UF_WORKSTATION_TRUST_ACCOUNT)
                || os.contains("windows 10")
                || os.contains("windows 11")
                || os.contains("workstation")) {
            return MachineRole.WORKSTATION;
        }
        return MachineRole.UNKNOWN;
    }

    private boolean isHighValue(ComputerRecord record) {
        if (record.role == MachineRole.DOMAIN_CONTROLLER) {
            return true;
        }

        String os = firstNonBlank(record.operatingSystem).toLowerCase(Locale.ROOT);
        String host = firstNonBlank(record.dnsHostName, record.samAccountName).toLowerCase(Locale.ROOT);

        return os.contains("server")
            || host.contains("dc")
            || host.contains("sql")
            || host.contains("exchange")
            || host.contains("fs")
            || host.contains("file");
    }

    private List<String> highValueReasons(ComputerRecord record) {
        List<String> reasons = new ArrayList<>();
        if (record.role == MachineRole.DOMAIN_CONTROLLER) {
            reasons.add("Domain Controller trust account flag detected");
        }

        String os = firstNonBlank(record.operatingSystem).toLowerCase(Locale.ROOT);
        if (os.contains("server")) {
            reasons.add("Server-class operating system identified");
        }

        String host = firstNonBlank(record.dnsHostName, record.samAccountName).toLowerCase(Locale.ROOT);
        if (host.contains("sql") || host.contains("exchange") || host.contains("file") || host.contains("fs")) {
            reasons.add("Hostname indicates infrastructure or data-tier role");
        }
        return reasons;
    }

    private boolean isLegacySystem(ComputerRecord record) {
        String os = firstNonBlank(record.operatingSystem).toLowerCase(Locale.ROOT);
        String version = firstNonBlank(record.operatingSystemVersion).toLowerCase(Locale.ROOT);

        if (os.contains("2000") || os.contains("2003") || os.contains("2008")
                || os.contains("2012") || os.contains("xp") || os.contains("windows 7")
                || os.contains("windows 8")) {
            return true;
        }

        if (version.startsWith("5.") || version.startsWith("6.0") || version.startsWith("6.1")
                || version.startsWith("6.2") || version.startsWith("6.3")) {
            return true;
        }

        return false;
    }

    private List<String> legacyReasons(ComputerRecord record) {
        if (!record.legacy) {
            return List.of();
        }

        List<String> reasons = new ArrayList<>();
        String os = firstNonBlank(record.operatingSystem);
        String version = firstNonBlank(record.operatingSystemVersion);
        if (!os.isBlank()) {
            reasons.add("Legacy OS family detected: " + os);
        }
        if (!version.isBlank()) {
            reasons.add("Legacy version signal: " + version);
        }
        return reasons;
    }

    private String deriveStatus(ComputerRecord record, int staleDaysThreshold) {
        if (record.disabled) {
            return "disabled";
        }
        if (record.lastLogonAgeDays >= 0 && record.lastLogonAgeDays > staleDaysThreshold) {
            return "stale";
        }
        return "active";
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

    private long computeLastLogonAgeDays(long fileTime) {
        if (fileTime <= 0) {
            return -1;
        }
        try {
            long seconds = (fileTime / 10_000_000L) - AD_EPOCH_DIFF_SECONDS;
            if (seconds <= 0) {
                return -1;
            }
            long nowSeconds = Instant.now().getEpochSecond();
            return Math.max(0L, (nowSeconds - seconds) / 86_400L);
        } catch (Exception e) {
            return -1;
        }
    }

    private String getStringAttribute(Attributes attrs, String name) {
        try {
            Attribute attr = attrs.get(name);
            if (attr == null || attr.size() == 0) {
                return "";
            }
            Object value = attr.get();
            return value == null ? "" : String.valueOf(value).trim();
        } catch (NamingException e) {
            return "";
        }
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
        protected ModuleMode mode = ModuleMode.INVENTORY_MAP;
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

        protected boolean resolveIps;
        protected boolean includeDisabled;
        protected String osFilter = "";
        protected String hostnameFilter = "";
        protected String focusHost = "";
        protected int staleDaysThreshold = DEFAULT_STALE_DAYS_THRESHOLD;
    }

    protected enum ModuleMode {
        INVENTORY_MAP("inventory_map", "inventory_map_result"),
        TARGET_CLASSIFICATION("target_classification", "target_classification_result"),
        LEGACY_RISK_AUDIT("legacy_risk_audit", "legacy_risk_audit_result"),
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
                case "target_classification", "classification", "analysis" -> TARGET_CLASSIFICATION;
                case "legacy_risk_audit", "legacy", "risk_audit" -> LEGACY_RISK_AUDIT;
                case "host_confirmation", "identify", "identification" -> HOST_CONFIRMATION;
                default -> INVENTORY_MAP;
            };
        }
    }

    protected enum MachineRole {
        DOMAIN_CONTROLLER("domain_controller"),
        SERVER("server"),
        WORKSTATION("workstation"),
        UNKNOWN("unknown");

        private final String value;

        MachineRole(String value) {
            this.value = value;
        }
    }

    protected static class ComputerRecord {
        protected String samAccountName = "";
        protected String dnsHostName = "";
        protected String operatingSystem = "";
        protected String operatingSystemVersion = "";
        protected String operatingSystemServicePack = "";
        protected String distinguishedName = "";
        protected int userAccountControl;
        protected long lastLogonTimestampRaw;
        protected String lastLogonTimestamp = "";
        protected long lastLogonAgeDays = -1;
        protected List<String> flags = new ArrayList<>();
        protected MachineRole role = MachineRole.UNKNOWN;
        protected boolean disabled;
        protected boolean legacy;
        protected boolean highValue;
        protected String status = "unknown";
        protected List<String> ipAddresses = new ArrayList<>();
    }

    private static final class LegacyTargetInput {
        private String target = "";
        private String username = "";
        private String password = "";
    }
}
