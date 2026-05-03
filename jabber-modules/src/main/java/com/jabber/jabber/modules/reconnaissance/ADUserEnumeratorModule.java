package com.jabber.jabber.modules.reconnaissance;

import com.jabber.jabber.data.model.*;
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
 * AD User Enumerator.
 *
 * Real LDAP-backed identity inventory module for AD user objects.
 *
 * Execution pipeline:
 * mode selection -> input validation -> processing engine -> execution steps -> result normalization.
 *
 * Core objective:
 * Query (objectClass=user) while excluding computer objects by default,
 * then normalize identity-layer data for access analysis and attack-surface profiling.
 */
@JABBERModule(
    id = "ad-user-enumerator",
    name = "AD User Enumerator",
    description = "Query Active Directory user objects over LDAP and extract username, email, password age, logon activity, account status, and group membership intelligence.",
    category = Category.RECONNAISSANCE,
    riskLevel = RiskLevel.MEDIUM,
    sourceRef = "GetADUsers.py / LDAP user object search",
    author = "JABBER"
)
public class ADUserEnumeratorModule implements JABBERModuleInterface {

    private static final String MODULE_ID = "ad-user-enumerator";

    private static final int UF_ACCOUNTDISABLE = 0x00000002;
    private static final int UF_LOCKOUT = 0x00000010;
    private static final int UF_PASSWD_NOTREQD = 0x00000020;
    private static final int UF_DONT_EXPIRE_PASSWD = 0x00010000;
    private static final int UF_TRUSTED_FOR_DELEGATION = 0x00080000;
    private static final int UF_NOT_DELEGATED = 0x00100000;
    private static final int UF_DONT_REQUIRE_PREAUTH = 0x00400000;
    private static final int UF_PASSWORD_EXPIRED = 0x00800000;
    private static final int UF_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000;

    private static final int DEFAULT_LDAP_PORT = 389;
    private static final int DEFAULT_LDAPS_PORT = 636;
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 10_000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 15_000;
    private static final int DEFAULT_MAX_RESULTS = 7_500;
    private static final int MAX_ALLOWED_RESULTS = 75_000;

    private static final int DEFAULT_STALE_PASSWORD_DAYS = 365;
    private static final int DEFAULT_DORMANT_DAYS = 90;
    private static final int DEFAULT_RECENT_LOGIN_DAYS = 30;

    private static final long AD_EPOCH_DIFF_SECONDS = 11_644_473_600L;
    private static final DateTimeFormatter ISO_FMT = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

    private static final Set<String> PRIVILEGED_GROUP_KEYWORDS = Set.of(
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
        "account operators",
        "server operators",
        "backup operators"
    );

    private static final Set<String> SYSTEM_ACCOUNT_NAMES = Set.of(
        "krbtgt",
        "guest",
        "defaultaccount",
        "wdagutilityaccount"
    );

    private static final String[] USER_ATTRIBUTES = new String[] {
        "sAMAccountName",
        "userPrincipalName",
        "displayName",
        "givenName",
        "sn",
        "mail",
        "pwdLastSet",
        "lastLogonTimestamp",
        "userAccountControl",
        "memberOf",
        "adminCount",
        "servicePrincipalName",
        "distinguishedName",
        "whenCreated",
        "whenChanged"
    };

    @Override
    public List<ModuleInputField> getInputSchema() {
        return List.of(
            ModuleInputField.select("mode", "Execution Mode", List.of(
                    "identity_inventory",
                    "access_analysis",
                    "attack_surface_profile",
                    "user_confirmation"
                ))
                .required()
                .defaultValue("identity_inventory")
                .group("Mode")
                .helpText("Select identity inventory, access analysis, attack-surface profiling, or a single-user confirmation view."),
            ModuleInputField.text("focus_user", "Focus User")
                .placeholder("jdoe or jdoe@contoso.local")
                .group("Mode")
                .modes("user_confirmation")
                .helpText("Required when mode=user_confirmation."),

            ModuleInputField.text("target", "Target Domain/DC")
                .required().placeholder("contoso.local or dc01.contoso.local")
                .group("Target")
                .helpText("Domain FQDN or Domain Controller hostname/IP. Legacy domain/user:pass syntax is still accepted."),
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

            ModuleInputField.text("custom_ldap_filter", "Custom LDAP Filter")
                .placeholder("(&(sAMAccountName=*)(objectCategory=user))")
                .group("Options")
                .helpText("Optional raw LDAP filter. It is wrapped by additional module constraints."),
            ModuleInputField.checkbox("include_disabled", "Include Disabled Accounts")
                .defaultValue("false")
                .group("Options"),
            ModuleInputField.checkbox("include_system_accounts", "Include System/Built-in Accounts")
                .defaultValue("false")
                .group("Options"),
            ModuleInputField.checkbox("require_email", "Require Mail Attribute")
                .defaultValue("false")
                .group("Options"),
            ModuleInputField.text("group_keyword", "Group Keyword Filter")
                .placeholder("Domain Admins")
                .group("Options")
                .modes("access_analysis", "attack_surface_profile")
                .helpText("Case-insensitive keyword matched against memberOf/group names."),
            ModuleInputField.text("stale_password_days", "Stale Password Threshold (days)")
                .placeholder(String.valueOf(DEFAULT_STALE_PASSWORD_DAYS))
                .group("Options"),
            ModuleInputField.text("dormant_days", "Dormant Account Threshold (days)")
                .placeholder(String.valueOf(DEFAULT_DORMANT_DAYS))
                .group("Options"),
            ModuleInputField.text("recent_login_days", "Recent Login Window (days)")
                .placeholder(String.valueOf(DEFAULT_RECENT_LOGIN_DAYS))
                .group("Options"),
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
                ctx.log("[*] Starting AD User Enumerator module");
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

                List<UserRecord> allRecords = fetchUserRecords(ldap, baseDn, config, ctx);
                ctx.log("[*] LDAP user objects returned: " + allRecords.size());
                ctx.reportProgress(62);

                List<UserRecord> filteredRecords = new ArrayList<>();
                for (UserRecord record : allRecords) {
                    applyDynamicState(record, config);
                    if (matchesFilters(record, config)) {
                        filteredRecords.add(record);
                    }
                }
                filteredRecords.sort(this::compareRecords);
                ctx.reportProgress(78);

                List<Map<String, Object>> findings = new ArrayList<>();
                for (UserRecord record : filteredRecords) {
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
                executionMetadata.put("requested_attributes", Arrays.asList(USER_ATTRIBUTES));
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
                output.put("users", findings);
                output.put("operational_stack", buildOperationalStack());
                output.put(config.mode.resultKey, modeResult);
                output.put("execution_metadata", executionMetadata);

                result.setNormalizedOutput(buildNormalizedOutput(summary, findings, config));
                result.complete(output);

                ctx.log("[+] AD User Enumeration completed with " + findings.size() + " user(s)");
                ctx.reportProgress(100);

            } catch (NamingException e) {
                result.fail("LDAP execution failed: " + e.getMessage());
                ctx.log("[!] LDAP execution failed: " + e.getMessage());
            } catch (Exception e) {
                result.fail("AD User Enumeration failed: " + e.getMessage());
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

    protected List<UserRecord> fetchUserRecords(
            LdapContext ldap,
            String baseDn,
            ModuleConfig config,
            TaskContext ctx) throws NamingException {

        String filter = buildLdapFilter(config);
        ctx.log("[*] LDAP filter: " + filter);

        List<SearchResult> searchResults = ldapSearch(ldap, baseDn, filter, USER_ATTRIBUTES, config.maxResults);
        List<UserRecord> records = new ArrayList<>(searchResults.size());
        for (SearchResult result : searchResults) {
            UserRecord record = toUserRecord(result);
            if (record != null) {
                records.add(record);
            }
        }
        return records;
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

    private UserRecord toUserRecord(SearchResult result) {
        try {
            Attributes attrs = result.getAttributes();
            if (attrs == null) {
                return null;
            }

            UserRecord record = new UserRecord();
            record.samAccountName = firstNonBlank(
                getStringAttribute(attrs, "sAMAccountName"),
                getStringAttribute(attrs, "cn"),
                result.getName()
            );
            record.userPrincipalName = getStringAttribute(attrs, "userPrincipalName");
            record.displayName = firstNonBlank(
                getStringAttribute(attrs, "displayName"),
                record.samAccountName
            );
            record.givenName = getStringAttribute(attrs, "givenName");
            record.surname = getStringAttribute(attrs, "sn");
            record.mail = getStringAttribute(attrs, "mail");
            record.distinguishedName = firstNonBlank(
                getStringAttribute(attrs, "distinguishedName"),
                safeNameInNamespace(result),
                result.getName()
            );

            record.memberOf = getListAttribute(attrs, "memberOf");
            record.groupNames = new ArrayList<>();
            for (String groupDn : record.memberOf) {
                record.groupNames.add(extractGroupName(groupDn));
            }

            record.servicePrincipalNames = getListAttribute(attrs, "servicePrincipalName");
            record.userAccountControl = parseInteger(getStringAttribute(attrs, "userAccountControl"), 0);
            record.adminCount = parseInteger(getStringAttribute(attrs, "adminCount"), 0);
            record.pwdLastSetRaw = parseLong(getStringAttribute(attrs, "pwdLastSet"), 0L);
            record.lastLogonTimestampRaw = parseLong(getStringAttribute(attrs, "lastLogonTimestamp"), 0L);
            record.passwordLastSet = fileTimeToIso(record.pwdLastSetRaw);
            record.lastLogonTimestamp = fileTimeToIso(record.lastLogonTimestampRaw);
            record.passwordAgeDays = computeAgeDays(record.pwdLastSetRaw);
            record.lastLogonAgeDays = computeAgeDays(record.lastLogonTimestampRaw);

            record.flags = decodeUacFlags(record.userAccountControl);
            record.disabled = hasUacFlag(record.userAccountControl, UF_ACCOUNTDISABLE);
            record.locked = hasUacFlag(record.userAccountControl, UF_LOCKOUT);
            record.passwordNotRequired = hasUacFlag(record.userAccountControl, UF_PASSWD_NOTREQD);
            record.passwordNeverExpires = hasUacFlag(record.userAccountControl, UF_DONT_EXPIRE_PASSWD);
            record.passwordExpired = hasUacFlag(record.userAccountControl, UF_PASSWORD_EXPIRED);
            record.trustedForDelegation = hasUacFlag(record.userAccountControl, UF_TRUSTED_FOR_DELEGATION);
            record.trustedToAuthForDelegation = hasUacFlag(record.userAccountControl, UF_TRUSTED_TO_AUTH_FOR_DELEGATION);
            record.notDelegated = hasUacFlag(record.userAccountControl, UF_NOT_DELEGATED);
            record.preauthNotRequired = hasUacFlag(record.userAccountControl, UF_DONT_REQUIRE_PREAUTH);

            record.systemAccount = isSystemAccount(record.samAccountName);
            record.privileged = isPrivileged(record);
            record.serviceAccount = isServiceAccount(record);
            record.hasEmail = !record.mail.isBlank();
            record.status = record.disabled ? "disabled" : "active";
            return record;
        } catch (NamingException e) {
            return null;
        }
    }

    private void applyDynamicState(UserRecord record, ModuleConfig config) {
        record.passwordAgeDays = computeAgeDays(record.pwdLastSetRaw);
        record.lastLogonAgeDays = computeAgeDays(record.lastLogonTimestampRaw);

        record.stalePassword = record.passwordAgeDays >= 0 && record.passwordAgeDays > config.stalePasswordDays;
        record.dormant = record.lastLogonAgeDays >= 0 && record.lastLogonAgeDays > config.dormantDays;
        record.recentlyActive = record.lastLogonAgeDays >= 0 && record.lastLogonAgeDays <= config.recentLoginDays;

        record.status = deriveStatus(record);
        record.riskTags = buildRiskTags(record);
        record.riskScore = scoreRecord(record);
        record.riskLevel = riskLevel(record.riskScore);
    }

    private boolean matchesFilters(UserRecord record, ModuleConfig config) {
        if (!config.includeDisabled && record.disabled) {
            return false;
        }

        if (!config.includeSystemAccounts && record.systemAccount) {
            return false;
        }

        if (config.requireEmail && !record.hasEmail) {
            return false;
        }

        if (!config.groupKeyword.isBlank()) {
            String keyword = config.groupKeyword.toLowerCase(Locale.ROOT);
            boolean matched = false;
            for (String group : record.groupNames) {
                if (group.toLowerCase(Locale.ROOT).contains(keyword)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                for (String groupDn : record.memberOf) {
                    if (groupDn.toLowerCase(Locale.ROOT).contains(keyword)) {
                        matched = true;
                        break;
                    }
                }
            }
            if (!matched) {
                return false;
            }
        }

        if (config.mode == ModuleMode.USER_CONFIRMATION) {
            String focus = normalizeFocus(config.focusUser);
            String sam = normalizeFocus(record.samAccountName);
            String upn = normalizeFocus(record.userPrincipalName);
            String dn = normalizeFocus(record.distinguishedName);
            return focus.equals(sam) || focus.equals(upn) || focus.equals(dn)
                || sam.contains(focus) || upn.contains(focus) || dn.contains(focus);
        }

        return true;
    }

    private Map<String, Object> toFinding(UserRecord record) {
        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("username", record.samAccountName);
        finding.put("user_principal_name", record.userPrincipalName);
        finding.put("display_name", record.displayName);
        finding.put("given_name", record.givenName);
        finding.put("surname", record.surname);
        finding.put("email", record.mail);
        finding.put("password_last_set", record.passwordLastSet);
        finding.put("password_age_days", record.passwordAgeDays);
        finding.put("last_logon", record.lastLogonTimestamp);
        finding.put("last_logon_age_days", record.lastLogonAgeDays);
        finding.put("status", record.status);
        finding.put("disabled", record.disabled);
        finding.put("locked", record.locked);
        finding.put("password_never_expires", record.passwordNeverExpires);
        finding.put("password_not_required", record.passwordNotRequired);
        finding.put("password_expired", record.passwordExpired);
        finding.put("preauth_not_required", record.preauthNotRequired);
        finding.put("privileged", record.privileged);
        finding.put("service_account", record.serviceAccount);
        finding.put("system_account", record.systemAccount);
        finding.put("dormant", record.dormant);
        finding.put("stale_password", record.stalePassword);
        finding.put("recently_active", record.recentlyActive);
        finding.put("group_memberships", record.memberOf);
        finding.put("group_names", record.groupNames);
        finding.put("service_principal_names", record.servicePrincipalNames);
        finding.put("user_account_control", record.userAccountControl);
        finding.put("uac_flags", record.flags);
        finding.put("admin_count", record.adminCount);
        finding.put("delegation", Map.of(
            "trusted_for_delegation", record.trustedForDelegation,
            "trusted_to_auth_for_delegation", record.trustedToAuthForDelegation,
            "not_delegated", record.notDelegated
        ));
        finding.put("risk_score", record.riskScore);
        finding.put("risk_level", record.riskLevel);
        finding.put("risk_tags", record.riskTags);
        finding.put("distinguished_name", record.distinguishedName);
        return finding;
    }

    private Map<String, Object> buildSummary(
            List<UserRecord> allRecords,
            List<UserRecord> filteredRecords,
            ModuleConfig config) {

        long enabledCount = filteredRecords.stream().filter(r -> !r.disabled).count();
        long disabledCount = filteredRecords.stream().filter(r -> r.disabled).count();
        long privilegedCount = filteredRecords.stream().filter(r -> r.privileged).count();
        long serviceCount = filteredRecords.stream().filter(r -> r.serviceAccount).count();
        long stalePasswordCount = filteredRecords.stream().filter(r -> r.stalePassword).count();
        long dormantCount = filteredRecords.stream().filter(r -> r.dormant).count();
        long recentCount = filteredRecords.stream().filter(r -> r.recentlyActive).count();
        long pwdNeverExpiresCount = filteredRecords.stream().filter(r -> r.passwordNeverExpires).count();
        long delegationCount = filteredRecords.stream()
            .filter(r -> r.trustedForDelegation || r.trustedToAuthForDelegation)
            .count();
        long emailCount = filteredRecords.stream().filter(r -> r.hasEmail).count();
        long sprayCandidates = filteredRecords.stream()
            .filter(r -> !r.disabled && !r.privileged && !r.systemAccount)
            .count();

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("mode", config.mode.value);
        summary.put("total_ldap_objects", allRecords.size());
        summary.put("total_users", filteredRecords.size());
        summary.put("enabled_count", enabledCount);
        summary.put("disabled_count", disabledCount);
        summary.put("privileged_count", privilegedCount);
        summary.put("service_account_count", serviceCount);
        summary.put("stale_password_count", stalePasswordCount);
        summary.put("dormant_count", dormantCount);
        summary.put("recent_login_count", recentCount);
        summary.put("password_never_expires_count", pwdNeverExpiresCount);
        summary.put("delegation_enabled_count", delegationCount);
        summary.put("email_present_count", emailCount);
        summary.put("spray_candidate_count", sprayCandidates);
        summary.put("stale_password_days", config.stalePasswordDays);
        summary.put("dormant_days", config.dormantDays);
        summary.put("recent_login_days", config.recentLoginDays);
        return summary;
    }

    private Map<String, Object> buildModeResult(List<UserRecord> records, ModuleConfig config) {
        return switch (config.mode) {
            case IDENTITY_INVENTORY -> buildIdentityInventoryResult(records);
            case ACCESS_ANALYSIS -> buildAccessAnalysisResult(records);
            case ATTACK_SURFACE_PROFILE -> buildAttackSurfaceResult(records, config);
            case USER_CONFIRMATION -> buildUserConfirmationResult(records, config);
        };
    }

    private Map<String, Object> buildIdentityInventoryResult(List<UserRecord> records) {
        double mailCoverage = 0.0;
        if (!records.isEmpty()) {
            long withMail = records.stream().filter(r -> r.hasEmail).count();
            mailCoverage = Math.round(((withMail * 100.0) / records.size()) * 100.0) / 100.0;
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("inventory_size", records.size());
        result.put("fields", List.of(
            "username",
            "user_principal_name",
            "email",
            "password_last_set",
            "last_logon",
            "status",
            "group_memberships"
        ));
        result.put("mail_coverage_percent", mailCoverage);
        result.put("sample_usernames", records.stream()
            .map(r -> r.samAccountName)
            .limit(25)
            .toList());
        return result;
    }

    private Map<String, Object> buildAccessAnalysisResult(List<UserRecord> records) {
        List<Map<String, Object>> privilegedUsers = new ArrayList<>();
        List<Map<String, Object>> delegationCapable = new ArrayList<>();
        List<Map<String, Object>> noExpiryUsers = new ArrayList<>();

        Map<String, Integer> groupDistribution = new LinkedHashMap<>();

        for (UserRecord record : records) {
            for (String groupName : record.groupNames) {
                String key = groupName.toLowerCase(Locale.ROOT);
                groupDistribution.put(key, groupDistribution.getOrDefault(key, 0) + 1);
            }

            if (record.privileged) {
                privilegedUsers.add(accessView(record));
            }
            if (record.trustedForDelegation || record.trustedToAuthForDelegation) {
                delegationCapable.add(accessView(record));
            }
            if (record.passwordNeverExpires) {
                noExpiryUsers.add(accessView(record));
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("privileged_users", privilegedUsers);
        result.put("delegation_capable_users", delegationCapable);
        result.put("password_never_expires_users", noExpiryUsers);
        result.put("group_distribution", groupDistribution);
        return result;
    }

    private Map<String, Object> buildAttackSurfaceResult(List<UserRecord> records, ModuleConfig config) {
        List<Map<String, Object>> stalePasswordUsers = new ArrayList<>();
        List<Map<String, Object>> dormantUsers = new ArrayList<>();
        List<Map<String, Object>> serviceAccounts = new ArrayList<>();
        List<Map<String, Object>> recentActiveUsers = new ArrayList<>();
        List<Map<String, Object>> phishingTargets = new ArrayList<>();
        List<String> sprayCandidates = new ArrayList<>();

        for (UserRecord record : records) {
            if (record.stalePassword) {
                stalePasswordUsers.add(surfaceView(record));
            }
            if (record.dormant) {
                dormantUsers.add(surfaceView(record));
            }
            if (record.serviceAccount) {
                serviceAccounts.add(surfaceView(record));
            }
            if (record.recentlyActive) {
                recentActiveUsers.add(surfaceView(record));
            }
            if (record.hasEmail) {
                phishingTargets.add(surfaceView(record));
            }
            if (!record.disabled && !record.privileged && !record.systemAccount) {
                sprayCandidates.add(record.samAccountName);
            }
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("stale_password_users", stalePasswordUsers);
        result.put("dormant_users", dormantUsers);
        result.put("service_accounts", serviceAccounts);
        result.put("recently_active_users", recentActiveUsers);
        result.put("phishing_targets", phishingTargets);
        result.put("spray_candidate_usernames", sprayCandidates);
        result.put("thresholds", Map.of(
            "stale_password_days", config.stalePasswordDays,
            "dormant_days", config.dormantDays,
            "recent_login_days", config.recentLoginDays
        ));
        return result;
    }

    private Map<String, Object> buildUserConfirmationResult(List<UserRecord> records, ModuleConfig config) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("focus_user", config.focusUser);
        result.put("confirmed", !records.isEmpty());
        result.put("match_count", records.size());
        result.put("matches", records.stream().map(this::surfaceView).toList());
        return result;
    }

    private Map<String, Object> accessView(UserRecord record) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("username", record.samAccountName);
        out.put("email", record.mail);
        out.put("status", record.status);
        out.put("privileged", record.privileged);
        out.put("delegation_enabled", record.trustedForDelegation || record.trustedToAuthForDelegation);
        out.put("groups", record.groupNames);
        out.put("risk_level", record.riskLevel);
        return out;
    }

    private Map<String, Object> surfaceView(UserRecord record) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("username", record.samAccountName);
        out.put("email", record.mail);
        out.put("password_age_days", record.passwordAgeDays);
        out.put("last_logon_age_days", record.lastLogonAgeDays);
        out.put("status", record.status);
        out.put("service_account", record.serviceAccount);
        out.put("privileged", record.privileged);
        out.put("risk_score", record.riskScore);
        out.put("risk_level", record.riskLevel);
        return out;
    }

    private List<Map<String, Object>> buildOperationalStack() {
        List<Map<String, Object>> stack = new ArrayList<>();
        stack.add(tool("PowerView", "Primary AD user enumeration and property collection", "https://github.com/PowerShellMafia/PowerSploit"));
        stack.add(tool("ActiveDirectory PowerShell Module", "Native AD identity retrieval on Windows hosts", "https://learn.microsoft.com/en-us/powershell/module/activedirectory/"));
        stack.add(tool("ldapsearch", "Linux-based LDAP query execution for user objects", "https://www.openldap.org/software/man.cgi?query=ldapsearch"));
        stack.add(tool("LDAP Raw Query", "Direct RFC-compliant LDAP filtering over AD", "https://learn.microsoft.com/en-us/windows/win32/adsi/searching-with-ldap"));
        stack.add(tool("BloodHound", "Identity graph mapping and privilege path analysis", "https://bloodhound.readthedocs.io/"));
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

        long staleCount = ((Number) summary.getOrDefault("stale_password_count", 0)).longValue();
        long dormantCount = ((Number) summary.getOrDefault("dormant_count", 0)).longValue();
        long privilegedCount = ((Number) summary.getOrDefault("privileged_count", 0)).longValue();
        boolean riskSignals = staleCount > 0 || dormantCount > 0 || privilegedCount > 0;

        Map<String, Object> rawOutput = new LinkedHashMap<>();
        rawOutput.put("summary", summary);
        rawOutput.put("record_count", findings.size());

        Map<String, Object> parsedOutput = new LinkedHashMap<>();
        parsedOutput.put("status", riskSignals
            ? "AD_USER_ATTACK_SURFACE_PROFILED"
            : "AD_USER_INVENTORY_COMPLETED");
        parsedOutput.put("vulnerable", riskSignals);
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
        String baseFilter = config.customLdapFilter.isBlank()
            ? "(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))"
            : config.customLdapFilter;

        StringBuilder filter = new StringBuilder("(&");
        filter.append(baseFilter);

        if (!config.includeDisabled) {
            filter.append("(!(userAccountControl:1.2.840.113556.1.4.803:=")
                .append(UF_ACCOUNTDISABLE)
                .append("))");
        }

        if (config.requireEmail) {
            filter.append("(mail=*)");
        }

        if (config.mode == ModuleMode.USER_CONFIRMATION && !config.focusUser.isBlank()) {
            String escaped = escapeFilterValue(stripTrailingDollar(config.focusUser));
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

    private ModuleConfig parseConfig(Map<String, String> input) {
        ModuleConfig config = new ModuleConfig();

        LegacyTargetInput parsedLegacy = parseLegacyTarget(firstNonBlank(input.get("target"), ""));

        config.mode = ModuleMode.fromInput(firstNonBlank(input.get("mode"), "identity_inventory"));
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

        config.customLdapFilter = trim(input.get("custom_ldap_filter"));
        config.includeDisabled = parseBoolean(input.get("include_disabled"), false);
        config.includeSystemAccounts = parseBoolean(input.get("include_system_accounts"), false);
        config.requireEmail = parseBoolean(input.get("require_email"), false);
        config.groupKeyword = trim(input.get("group_keyword"));

        config.stalePasswordDays = parseInteger(input.get("stale_password_days"), DEFAULT_STALE_PASSWORD_DAYS);
        config.dormantDays = parseInteger(input.get("dormant_days"), DEFAULT_DORMANT_DAYS);
        config.recentLoginDays = parseInteger(input.get("recent_login_days"), DEFAULT_RECENT_LOGIN_DAYS);

        config.focusUser = firstNonBlank(input.get("focus_user"), input.get("identify_target"));
        return config;
    }

    private List<String> validateConfig(ModuleConfig config) {
        List<String> errors = new ArrayList<>();

        if (config.target.isBlank()) {
            errors.add("target is required");
        }

        if (config.mode == ModuleMode.USER_CONFIRMATION && config.focusUser.isBlank()) {
            errors.add("focus_user is required when mode=user_confirmation");
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

        if (config.stalePasswordDays < 0 || config.stalePasswordDays > 36500) {
            errors.add("stale_password_days must be between 0 and 36500");
        }

        if (config.dormantDays < 0 || config.dormantDays > 36500) {
            errors.add("dormant_days must be between 0 and 36500");
        }

        if (config.recentLoginDays < 0 || config.recentLoginDays > 36500) {
            errors.add("recent_login_days must be between 0 and 36500");
        }

        if (!config.customLdapFilter.isBlank() && !config.customLdapFilter.startsWith("(")) {
            errors.add("custom_ldap_filter must be a valid LDAP filter expression");
        }

        return errors;
    }

    private int compareRecords(UserRecord left, UserRecord right) {
        int scoreDiff = Integer.compare(right.riskScore, left.riskScore);
        if (scoreDiff != 0) {
            return scoreDiff;
        }
        return left.samAccountName.compareToIgnoreCase(right.samAccountName);
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

    private boolean isSystemAccount(String samAccountName) {
        String user = trim(samAccountName).toLowerCase(Locale.ROOT);
        return SYSTEM_ACCOUNT_NAMES.contains(user);
    }

    private boolean isPrivileged(UserRecord record) {
        if (record.adminCount > 0) {
            return true;
        }
        for (String group : record.groupNames) {
            String lowered = group.toLowerCase(Locale.ROOT);
            for (String keyword : PRIVILEGED_GROUP_KEYWORDS) {
                if (lowered.contains(keyword)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isServiceAccount(UserRecord record) {
        if (!record.servicePrincipalNames.isEmpty()) {
            return true;
        }

        String sam = record.samAccountName.toLowerCase(Locale.ROOT);
        return sam.startsWith("svc") || sam.startsWith("sql") || sam.startsWith("appsvc") || sam.startsWith("service_");
    }

    private String deriveStatus(UserRecord record) {
        if (record.disabled) {
            return "disabled";
        }
        if (record.dormant) {
            return "dormant";
        }
        if (record.locked) {
            return "locked";
        }
        return "active";
    }

    private List<String> buildRiskTags(UserRecord record) {
        List<String> tags = new ArrayList<>();
        if (record.privileged) {
            tags.add("privileged_account");
        }
        if (record.serviceAccount) {
            tags.add("service_account");
        }
        if (record.stalePassword) {
            tags.add("stale_password");
        }
        if (record.dormant) {
            tags.add("dormant_account");
        }
        if (record.passwordNeverExpires) {
            tags.add("password_never_expires");
        }
        if (record.preauthNotRequired) {
            tags.add("preauth_not_required");
        }
        if (record.trustedForDelegation || record.trustedToAuthForDelegation) {
            tags.add("delegation_enabled");
        }
        if (record.systemAccount) {
            tags.add("built_in_or_system");
        }
        return tags;
    }

    private int scoreRecord(UserRecord record) {
        int score = 20;

        if (record.privileged) {
            score += 35;
        }
        if (record.serviceAccount) {
            score += 15;
        }
        if (record.stalePassword) {
            score += 15;
        }
        if (record.dormant) {
            score += 10;
        }
        if (record.passwordNeverExpires) {
            score += 10;
        }
        if (record.preauthNotRequired) {
            score += 20;
        }
        if (record.trustedForDelegation) {
            score += 10;
        }
        if (record.trustedToAuthForDelegation) {
            score += 15;
        }
        if (record.disabled) {
            score -= 25;
        }
        if (record.systemAccount) {
            score -= 10;
        }

        return Math.max(0, Math.min(100, score));
    }

    private String riskLevel(int score) {
        if (score >= 80) {
            return "high";
        }
        if (score >= 55) {
            return "medium";
        }
        if (score >= 30) {
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

    private long computeAgeDays(long fileTime) {
        if (fileTime <= 0) {
            return -1;
        }
        try {
            long seconds = (fileTime / 10_000_000L) - AD_EPOCH_DIFF_SECONDS;
            if (seconds <= 0) {
                return -1;
            }
            long now = Instant.now().getEpochSecond();
            return Math.max(0L, (now - seconds) / 86_400L);
        } catch (Exception e) {
            return -1;
        }
    }

    private List<String> decodeUacFlags(int userAccountControl) {
        List<String> flags = new ArrayList<>();
        if (hasUacFlag(userAccountControl, UF_ACCOUNTDISABLE)) {
            flags.add("ACCOUNTDISABLE");
        }
        if (hasUacFlag(userAccountControl, UF_LOCKOUT)) {
            flags.add("LOCKOUT");
        }
        if (hasUacFlag(userAccountControl, UF_PASSWD_NOTREQD)) {
            flags.add("PASSWD_NOTREQD");
        }
        if (hasUacFlag(userAccountControl, UF_DONT_EXPIRE_PASSWD)) {
            flags.add("DONT_EXPIRE_PASSWD");
        }
        if (hasUacFlag(userAccountControl, UF_TRUSTED_FOR_DELEGATION)) {
            flags.add("TRUSTED_FOR_DELEGATION");
        }
        if (hasUacFlag(userAccountControl, UF_NOT_DELEGATED)) {
            flags.add("NOT_DELEGATED");
        }
        if (hasUacFlag(userAccountControl, UF_DONT_REQUIRE_PREAUTH)) {
            flags.add("DONT_REQUIRE_PREAUTH");
        }
        if (hasUacFlag(userAccountControl, UF_PASSWORD_EXPIRED)) {
            flags.add("PASSWORD_EXPIRED");
        }
        if (hasUacFlag(userAccountControl, UF_TRUSTED_TO_AUTH_FOR_DELEGATION)) {
            flags.add("TRUSTED_TO_AUTH_FOR_DELEGATION");
        }
        return flags;
    }

    private boolean hasUacFlag(int value, int flag) {
        return (value & flag) == flag;
    }

    private String extractGroupName(String groupDn) {
        String dn = trim(groupDn);
        if (dn.isBlank()) {
            return "";
        }
        for (String part : dn.split(",")) {
            String token = part.trim();
            if (token.regionMatches(true, 0, "CN=", 0, 3) && token.length() > 3) {
                return token.substring(3);
            }
        }
        return dn;
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
        protected ModuleMode mode = ModuleMode.IDENTITY_INVENTORY;

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

        protected String customLdapFilter = "";
        protected boolean includeDisabled;
        protected boolean includeSystemAccounts;
        protected boolean requireEmail;
        protected String groupKeyword = "";

        protected int stalePasswordDays = DEFAULT_STALE_PASSWORD_DAYS;
        protected int dormantDays = DEFAULT_DORMANT_DAYS;
        protected int recentLoginDays = DEFAULT_RECENT_LOGIN_DAYS;
        protected String focusUser = "";
    }

    protected enum ModuleMode {
        IDENTITY_INVENTORY("identity_inventory", "identity_inventory_result"),
        ACCESS_ANALYSIS("access_analysis", "access_analysis_result"),
        ATTACK_SURFACE_PROFILE("attack_surface_profile", "attack_surface_profile_result"),
        USER_CONFIRMATION("user_confirmation", "user_confirmation_result");

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
                case "access_analysis", "analysis", "access" -> ACCESS_ANALYSIS;
                case "attack_surface_profile", "attack_surface", "profile" -> ATTACK_SURFACE_PROFILE;
                case "user_confirmation", "identify", "identification" -> USER_CONFIRMATION;
                default -> IDENTITY_INVENTORY;
            };
        }
    }

    protected static class UserRecord {
        protected String samAccountName = "";
        protected String userPrincipalName = "";
        protected String displayName = "";
        protected String givenName = "";
        protected String surname = "";
        protected String mail = "";
        protected String distinguishedName = "";

        protected List<String> memberOf = new ArrayList<>();
        protected List<String> groupNames = new ArrayList<>();
        protected List<String> servicePrincipalNames = new ArrayList<>();

        protected int userAccountControl;
        protected int adminCount;

        protected long pwdLastSetRaw;
        protected long lastLogonTimestampRaw;
        protected String passwordLastSet = "";
        protected String lastLogonTimestamp = "";
        protected long passwordAgeDays = -1;
        protected long lastLogonAgeDays = -1;

        protected List<String> flags = new ArrayList<>();

        protected boolean disabled;
        protected boolean locked;
        protected boolean passwordNotRequired;
        protected boolean passwordNeverExpires;
        protected boolean passwordExpired;
        protected boolean trustedForDelegation;
        protected boolean trustedToAuthForDelegation;
        protected boolean notDelegated;
        protected boolean preauthNotRequired;

        protected boolean systemAccount;
        protected boolean privileged;
        protected boolean serviceAccount;
        protected boolean hasEmail;

        protected boolean stalePassword;
        protected boolean dormant;
        protected boolean recentlyActive;

        protected String status = "active";
        protected int riskScore;
        protected String riskLevel = "info";
        protected List<String> riskTags = new ArrayList<>();
    }

    private static final class LegacyTargetInput {
        private String target = "";
        private String username = "";
        private String password = "";
    }
}
