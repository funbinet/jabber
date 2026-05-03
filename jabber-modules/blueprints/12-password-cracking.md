# Password Cracking — Category Blueprint

**Category:** `PASSWORD_CRACKING` | **Slug:** `passcrack` | **Tools Dir:** `~/jabber/jabber-tools/passcrack/`
**Package:** `com.jabber.jabber.modules.credential` | **Group:** Privilege & Identity

---

## ToolManager: `passcrack/ToolManager.java`

| ID | Binary | Source | Version Check | Install Method |
|----|--------|--------|---------------|----------------|
| `hashcat` | `hashcat` | apt/github | `hashcat --version` | `apt_install` |
| `john` | `john` | apt (john) | `john --version` | `apt_install` |
| `hydra` | `hydra` | apt | `hydra -V` | `apt_install` |
| `ncrack` | `ncrack` | apt | `ncrack --version` | `apt_install` |
| `fcrackzip` | `fcrackzip` | apt | `fcrackzip --version` | `apt_install` |
| `hashid` | `hashid` | pip | `hashid --version` | `pip_install` |
| `python3` | `python3` | system | `python3 --version` | system |

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

Every module in the **Password Cracking** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between operations.
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for downloading results and logs.
4. **Live Terminal Stream**: A real-time stdout/stderr streaming component for operational transparency.
5. **Interactive Dashboard**: Real-time display of extracted data, payloads, or process progress.

---

---

## Modules

### 1. Hashcat Wrapper
**ID:** `crack-hashcat` | **Risk:** MEDIUM | **File:** `HashcatWrapModule.java`
**Tools:** `hashcat`, `john`, `hashid`, `python3`

#### Execution Modes:

- **`CRCK`** (Short Name: `CRCK`)
    - **Purpose**: High-performance recovery of password plaintexts from cryptographic hashes.
    - **Input Schema**: `{ hash_file: Path, mode: int, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `hashcat -m <mode> -a 0 <hash_file> <wordlist> --status` (Core Cracker)
        2. `john --wordlist=<wordlist> --format=... <hash_file>` (John Backup)
        3. `hashid <hash_file>` (Hash Identification)
        4. `python3 -c "import hashlib; ..."` (Integrity Check)
    - **Execution Flow**: Core Cracker -> John Backup -> Identification -> Integrity Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CRACK_[Timestamp]_cracked_passwords.txt`: List of recovered plaintexts and their associated hashes.
        - `reports/artifacts/CRACK_[Timestamp]_hashcat_session.log`: Full log of the Hashcat cracking session.
        - `reports/analysis/CRACK_[Timestamp]_hash_identification.json`: Analysis of the input hash types and formats.

- **`BNCH`** (Short Name: `BNCH`)
    - **Purpose**: Evaluate hardware performance for specific hashing algorithms.
    - **Input Schema**: `{ mode: int }`
    - **Multi-Tool Command Logic**:
        1. `hashcat -b -m <mode>` (Core Benchmark)
        2. `hashcat -I` (Device Inventory)
        3. `john --test` (John Benchmark)
        4. `python3 hardware_audit.py` (Environmental Audit)
    - **Execution Flow**: Core Benchmark -> Device Inventory -> John Benchmark -> Env Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/BENCH_[Timestamp]_performance_stats.json`: Hardware benchmarking results for the specified hash modes.
        - `reports/artifacts/BENCH_[Timestamp]_device_inventory.txt`: Detailed inventory of available CPU/GPU cracking devices.
        - `reports/analysis/BENCH_[Timestamp]_environment_audit.json`: Audit of drivers and hardware health during benchmark.

---

### 2. John The Ripper
**ID:** `crack-john` | **Risk:** MEDIUM | **File:** `JohnTheRipperModule.java`
**Tools:** `john`, `hashcat`, `hashid`, `python3`

#### Execution Modes:

- **`CRCK`** (Short Name: `CRCK`)
    - **Purpose**: Versatile password recovery using John the Ripper's extensive format support.
    - **Input Schema**: `{ hash_file: Path, format: String, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `john --format=<format> --wordlist=<wordlist> <hash_file>` (Core John Crack)
        2. `hashcat -m ... <hash_file> <wordlist>` (Hashcat Backup)
        3. `hashid <hash_file>` (Format Identification)
        4. `python3 -c "import hashlib; ..."` (Integrity Check)
    - **Execution Flow**: Core John -> Hashcat Backup -> Identification -> Integrity Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CRACK_[Timestamp]_john_results.txt`: Successfully recovered plaintexts from the John session.
        - `reports/artifacts/CRACK_[Timestamp]_john_log.txt`: Technical log of the John the Ripper execution.
        - `reports/analysis/CRACK_[Timestamp]_format_audit.json`: Audit of the utilized hash format and its security posture.


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

### 3. Hash Identifier
**ID:** `crack-hashid` | **Risk:** LOW | **File:** `HashIdentifierModule.java`
**Tools:** `hashid`, `python3`, `hashcat`, `john`

#### Execution Modes:

- **`IDNT`** (Short Name: `IDNT`)
    - **Purpose**: Automatically identify the type and format of a cryptographic hash.
    - **Input Schema**: `{ hash: String }`
    - **Multi-Tool Command Logic**:
        1. `hashid -m -j <hash>` (Core Identification)
        2. `python3 -c "import hashid; ..."` (Library Identification)
        3. `hashcat --help | grep -i "<hash_pattern>"` (Hashcat Mode Discovery)
        4. `john --list=formats | grep -i "<hash_pattern>"` (John Format Discovery)
    - **Execution Flow**: Core Identification -> Library Identification -> Hashcat Discovery -> John Discovery.
    - **Output Generation & Artifacts**:
        - `reports/outputs/IDENT_[Timestamp]_hash_report.json`: Comprehensive report on identified hash types and cracker modes.
        - `reports/artifacts/IDENT_[Timestamp]_id_matches.txt`: List of potential hash matches and their descriptions.
        - `reports/analysis/IDENT_[Timestamp]_ cracker_readiness.json**: Verification of cracker support for the identified formats.


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

### 4. Generic Password Cracker
**ID:** `crack-generic` | **Risk:** MEDIUM | **File:** `PasswordCrackerModule.java`
**Tools:** `hashcat`, `john`, `hashid`, `python3`

#### Execution Modes:

- **`AUTO`** (Short Name: `AUTO`)
    - **Purpose**: Automated end-to-end hash recovery using a multi-tool pipeline.
    - **Input Schema**: `{ hash_file: Path, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `hashid -m <hash_file>` (Step 1: Identify)
        2. `hashcat -m <id> <hash_file> <wordlist>` (Step 2: Hashcat Attack)
        3. `john <hash_file> --wordlist=<wordlist>` (Step 3: John Backup)
        4. `python3 stats.py <hash_file>` (Step 4: Stats)
    - **Execution Flow**: Identify -> Hashcat Attack -> John Backup -> Stats.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUTO_[Timestamp]_cracked_creds.json`: Consolidated list of recovered credentials from the auto-pipeline.
        - `reports/artifacts/AUTO_[Timestamp]_pipeline_log.txt`: Detailed log of the automated multi-tool execution flow.
        - `reports/analysis/AUTO_[Timestamp]_success_metrics.json`: Metrics on cracking speed, success rate, and tool effectiveness.


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

### 5. Kerberoast Cracker
**ID:** `crack-kerbroast` | **Risk:** HIGH | **File:** `KerbRoastCrackModule.java`
**Tools:** `hashcat`, `john`, `impacket`, `ldapsearch`, `nmap`

#### Execution Modes:

- **`CRCK`** (Short Name: `CRCK`)
    - **Purpose**: Crack Kerberos TGS-REP/AS-REP hashes to recover service account passwords.
    - **Input Schema**: `{ hash_file: Path, wordlist: Path, type: String }`
    - **Multi-Tool Command Logic**:
        1. `hashcat -m 13100 <hash_file> <wordlist>` (Core Kerberoast Crack)
        2. `john --format=krb5tgs <hash_file> --wordlist=<wordlist>` (John Kerberoast)
        3. `impacket-GetUserSPNs --help` (Binary Check)
        4. `ldapsearch -V` (Dependency Check)
        5. `nmap -V` (Dependency Check)
    - **Execution Flow**: Core Crack -> John Kerberoast -> Binary Check x3.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CRACK_[Timestamp]_kerberoast_plaintexts.txt`: Successfully recovered service account passwords.
        - `reports/artifacts/CRACK_[Timestamp]_john_session.log`: Log of the John the Ripper Kerberoasting session.
        - `reports/analysis/CRACK_[Timestamp]_binary_readiness.json`: Verification of all Kerberos-related cracking tools.

- **`EXTR`** (Short Name: `EXTR`)
    - **Purpose**: Enumerate and extract Kerberoastable tickets from a Domain Controller.
    - **Input Schema**: `{ target: String, user: String, pass: Password, domain: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-GetUserSPNs -request -dc-ip <target> <domain>/<user>:<pass>` (Core Extraction)
        2. `ldapsearch -h <target> -x -D "<user>@<domain>" -w "<pass>" -b "dc=...,dc=..." "(servicePrincipalName=*)"` (LDAP Discovery)
        3. `nmap -p 88 <target>` (KDC Port Probe)
        4. `john --version` (Binary Readiness)
        5. `hashcat --version` (Binary Readiness)
    - **Execution Flow**: Core Extraction -> LDAP Discovery -> KDC Probe -> Binary Readiness x2.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXTRACT_[Timestamp]_tgs_hashes.txt`: Kerberoastable TGS-REP hashes extracted from the DC.
        - `reports/artifacts/EXTRACT_[Timestamp]_ldap_discovery.json`: Map of SPNs and accounts discovered via LDAP.
        - `reports/analysis/EXTRACT_[Timestamp]_kdc_probe.xml`: Nmap audit of the Domain Controller's Kerberos service.

---

### 6. NTLM Cracker
**ID:** `crack-ntlm` | **Risk:** MEDIUM | **File:** `NTLMCrackModule.java`
**Tools:** `hashcat`, `john`, `rcracki_mt`, `ophcrack`, `hashid`

#### Execution Modes:

- **`CRCK`** (Short Name: `CRCK`)
    - **Purpose**: Recovery of Windows NTLM hashes using wordlists and hybrid attacks.
    - **Input Schema**: `{ hash_file: Path, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `hashcat -m 1000 -a 0 <hash_file> <wordlist>` (Core NTLM Crack)
        2. `john --format=nt <hash_file> --wordlist=<wordlist>` (John NTLM)
        3. `hashid <hash_file>` (Format Validation)
        4. `ophcrack -g -d tables/ -f <hash_file>` (Ophcrack Logic)
        5. `rcracki_mt -t 4 tables/ <hash_file>` (Rainbow Table Logic)
    - **Execution Flow**: Core NTLM -> John NTLM -> Format Validation -> Ophcrack -> Rainbow Tables.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CRACK_[Timestamp]_ntlm_plaintexts.txt`: Successfully recovered Windows NTLM passwords.
        - `reports/artifacts/CRACK_[Timestamp]_ophcrack_session.log`: Log of the Ophcrack execution and results.
        - `reports/analysis/CRACK_[Timestamp]_rainbow_audit.json`: Status and coverage report for available rainbow tables.

- **`RNBW`** (Short Name: `RNBW`)
    - **Purpose**: High-speed recovery of NTLM hashes using pre-computed rainbow tables.
    - **Input Schema**: `{ hash_file: Path, tables_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `rcracki_mt -t 4 <tables_path> <hash_file>` (Core Rainbow Crack)
        2. `ophcrack -g -d <tables_path> -f <hash_file>` (Alternative Rainbow)
        3. `hashcat -m 1000 --help` (Binary Check)
        4. `john --version` (Binary Check)
        5. `hashid <hash_file>` (Format Verification)
    - **Execution Flow**: Core Rainbow -> Alternative Rainbow -> Binary Check x2 -> Format Verify.
    - **Output Generation & Artifacts**:
        - `reports/outputs/RAINBW_[Timestamp]_recovered_passwords.txt`: NTLM plaintexts recovered via rainbow table lookup.
        - `reports/artifacts/RAINBW_[Timestamp]_rcracki_session.log`: Execution log of the rcracki engine.
        - `reports/analysis/RAINBW_[Timestamp]_table_inventory.json`: Inventory and verification of the utilized rainbow tables.

---

### 7. ZIP Cracker
**ID:** `crack-zip" | **Risk:** LOW | **File:** "ZIPCrackModule.java`
**Tools:** `fcrackzip`, `zip2john`, `john`, `hashcat`, `unzip`

#### Execution Modes:

- **`CRCK`** (Short Name: `CRCK`)
    - **Purpose**: Recover passwords for encrypted ZIP archives.
    - **Input Schema**: `{ zip_file: Path, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `fcrackzip -v -D -u -p <wordlist> <zip_file>` (Core ZIP Crack)
        2. `zip2john <zip_file> > hash.txt && john hash.txt --wordlist=<wordlist>` (John Extraction/Crack)
        3. `hashcat -m 17200 hash.txt <wordlist>` (Hashcat ZIP Logic)
        4. `unzip -l <zip_file>` (Archive Content Disclosure)
        5. `unzip -P "wrong_pass" <zip_file> 2>&1 | grep "incorrect"` (Pass-Check Audit)
    - **Execution Flow**: Core ZIP Crack -> John Extraction -> Hashcat Logic -> Content Disclosure -> Pass-Check Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CRACK_[Timestamp]_zip_password.txt`: Recovered password for the encrypted ZIP archive.
        - `reports/artifacts/CRACK_[Timestamp]_archive_inventory.json`: List of files and metadata contained within the ZIP.
        - `reports/analysis/CRACK_[Timestamp]_extraction_log.txt`: Technical log of the hash extraction from the archive.


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

### 8. MD5 Cracker
**ID:** `crack-md5` | **Risk:** LOW | **File:** `MD5CrackerModule.java`
**Tools:** `hashcat`, `john`, `hashid`, `python3`, `curl`

#### Execution Modes:

- **`DICT`** (Short Name: `DICT`)
    - **Purpose**: Recover MD5 plaintexts using dictionary-based attacks.
    - **Input Schema**: `{ hash_file: Path, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `hashcat -m 0 -a 0 <hash_file> <wordlist>` (Core MD5 Crack)
        2. `john --format=md5 <hash_file> --wordlist=<wordlist>` (John MD5)
        3. `hashid <hash_file>` (Format Validation)
        4. `curl -X POST -d "hash=$(cat <hash_file>)" https://crackstation.net/` (Online DB Query)
        5. `python3 -c "import hashlib; print(hashlib.md5(b'test').hexdigest())"` (Integrity Check)
    - **Execution Flow**: Core Crack -> John MD5 -> Validation -> Online Query -> Integrity Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DICT_[Timestamp]_md5_plaintexts.txt`: Recovered MD5 plaintexts from dictionary attacks.
        - `reports/artifacts/DICT_[Timestamp]_crackstation_results.html`: Captured results from the online database query.
        - `reports/analysis/DICT_[Timestamp]_hash_integrity.json`: Cryptographic verification of recovered plaintexts.


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

### 9. SHA1 Brute Force
**ID:** `crack-sha1` | **Risk:** LOW | **File:** `SHA1BruteModule.java`
**Tools:** `hashcat`, `john`, `hashid`, `python3`, `curl`

#### Execution Modes:

- **`BRTE`** (Short Name: `BRTE`)
    - **Purpose**: Exhaustive search for SHA1 plaintexts using mask-based character combinations.
    - **Input Schema**: `{ hash: String, mask: String }`
    - **Multi-Tool Command Logic**:
        1. `hashcat -m 100 -a 3 <hash> <mask>` (Core Brute)
        2. `john --format=sha1 <hash> --incremental` (John Incremental)
        3. `hashid <hash>` (Validation)
        4. `python3 stats.py` (Performance Profile)
        5. `curl -V` (Binary Audit)
    - **Execution Flow**: Core Brute -> John Incremental -> Validation -> Performance -> Binary Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/BRUTE_[Timestamp]_sha1_plaintexts.txt`: Recovered SHA1 plaintexts from mask-based attacks.
        - `reports/artifacts/BRUTE_[Timestamp]_session_telemetry.json`: Technical telemetry from the SHA1 cracking engine.
        - `reports/analysis/BRUTE_[Timestamp]_validation_report.json`: Verification of identified hash formats.


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

### 10. NTLM Rainbow Tables
**ID:** `crack-ntlm-rainbow` | **Risk:** MEDIUM | **File:** `NTLMRainbowModule.java`
**Tools:** `rtgen`, `rtsort`, `rcrack`, `python3`, `grep`

#### Execution Modes:

- **`CRCK`** (Short Name: `CRCK`)
    - **Purpose**: High-speed NTLM hash cracking using pre-computed rainbow tables.
    - **Input Schema**: `{ hash: String, table_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `rcrack <table_path> -h <hash>` (Core Rainbow Crack)
        2. `rtgen ntlm numeric 1 10 0 1000 1000 0` (Table Generation Engine)
        3. `rtsort <table_path>` (Table Optimization)
        4. `python3 verify_ntlm.py --hash <hash>` (Validation Logic)
        5. `grep --version` (Binary Check)
    - **Execution Flow**: Discovery -> Core Crack -> Table Gen -> Optimization -> Validation -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CRACK_[Timestamp]_ntlm_plaintext.txt`: Recovered plaintext for the NTLM hash.
        - `reports/artifacts/CRACK_[Timestamp]_table_status.json`: Report on rainbow table integrity and coverage.
        - `reports/analysis/CRACK_[Timestamp]_crack_telemetry.log`: Technical telemetry from the rainbow cracking engine.


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