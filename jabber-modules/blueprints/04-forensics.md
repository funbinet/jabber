# Forensics — Category Blueprint

**Category:** `FORENSICS` | **Slug:** `forensics` | **Tools Dir:** `~/jabber/jabber-tools/forensics/`
**Package:** `com.jabber.jabber.modules.credential` + `com.jabber.jabber.modules.utilities` | **Group:** Intelligence & Planning

---

## ToolManager: `forensics/ToolManager.java`

| ID | Binary | Source | Version Check | Install Method |
|----|--------|--------|---------------|----------------|
| `volatility3` | `vol` | pip (volatility3) | `vol --help` | `pip_install` |
| `exiftool` | `exiftool` | apt/brew | `exiftool -ver` | `apt_install` |
| `foremost` | `foremost` | apt | `foremost -V` | `apt_install` |
| `binwalk` | `binwalk` | pip/apt | `binwalk --help` | `pip_install` |
| `strings` | `strings` | apt (binutils) | `strings --version` | `apt_install` |
| `regipy` | `regipy-dump` | pip | `regipy-dump --help` | `pip_install` |

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

Every module in the **Forensics** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between processing strategies (e.g., `DUMP` vs `AUDIT`).
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for viewing carved files, hex dumps, and forensic timelines.
4. **Forensic Previewer**: A specialized viewer for common forensic formats (SQLite, EVTX, PCAP) directly within the module interface.

---

---

## Modules

### 1. Browser History Dump
**ID:** `forensics-browser-hist` | **Risk:** LOW | **File:** `BrowserHistDumpModule.java`
**Tools:** `sqlite3`, `strings`, `exiftool`, `find`, `foremost`

#### Execution Modes:

- **`DSCV`** (Short Name: `DSCV`)
    - **Purpose**: System-wide location and classification of browser artifacts.
    - **Input Schema**: `{ path: String }`
    - **Multi-Tool Command Logic**:
        1. `find <path> -name "History" -o -name "places.sqlite" -o -name "Login Data"` (Asset Search)
        2. `exiftool -T -FileName -FileSize -FileModifyDate history_files.txt` (Metadata Profile)
        3. `strings -n 10 <history_file> | grep -i "http"` (Quick URL Extraction)
        4. `foremost -i <history_file> -t sqlite -o forensic_out` (Carving Attempt)
        5. `sqlite3 <history_file> ".tables"` (Database Schema Check)
    - **Execution Flow**: Search -> Profile -> Quick Extraction -> Carving -> Schema Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DISCOV_[Timestamp]_found_assets.txt`: List of discovered browser database files.
        - `reports/analysis/DISCOV_[Timestamp]_file_profiles.json`: Metadata profiles for each history file.
        - `reports/artifacts/DISCOV_[Timestamp]_carved_sqls.db`: SQLite files recovered via carving.

- **`EXTR`** (Short Name: `EXTR`)
    - **Purpose**: High-fidelity extraction and reconstruction of user activity.
    - **Input Schema**: `{ db_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `sqlite3 <db_path> "SELECT url, title, last_visit_time FROM urls"` (URL History)
        2. `strings <db_path> | grep -aPo "(http|https)://[a-zA-Z0-9./?=_-]+"` (String Analysis)
        3. `exiftool -json <db_path>` (File Metadata)
        4. `foremost -v -i <db_path> -o carved_data` (Data Recovery)
        5. `sqlite3 <db_path> "PRAGMA integrity_check;"` (Consistency Audit)
    - **Execution Flow**: URL History -> String Analysis -> Metadata -> Recovery -> Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXTRACT_[Timestamp]_url_history.json`: Structured user browsing history.
        - `reports/artifacts/EXTRACT_[Timestamp]_carved_files/`: Directory of files recovered from the database.
        - `reports/analysis/EXTRACT_[Timestamp]_db_integrity.txt`: Database consistency and audit report.

---

### 2. EXIF Extractor
**ID:** `forensics-exif` | **Risk:** LOW | **File:** `EXIFExtractorModule.java`
**Tools:** `exiftool`, `identify`, `strings`, `binwalk`, `file`

#### Execution Modes:

- **`PROF`** (Short Name: `PROF`)
    - **Purpose**: Deep metadata and technical profiling of forensic images/files.
    - **Input Schema**: `{ input: Path }`
    - **Multi-Tool Command Logic**:
        1. `exiftool -all -G <input>` (Full Metadata)
        2. `identify -verbose <input>` (Image Specs)
        3. `file <input>` (Magic Signature)
        4. `strings -n 8 <input> | head -n 100` (Header Strings)
        5. `binwalk -E <input>` (Entropy Analysis)
    - **Execution Flow**: Metadata -> Specs -> Magic -> Strings -> Entropy.
    - **Output Generation & Artifacts**:
        - `reports/analysis/PROFILE_[Timestamp]_exif_metadata.json`: Full technical metadata profile.
        - `reports/artifacts/PROFILE_[Timestamp]_binary_entropy.txt`: Entropy analysis results.
        - `reports/outputs/PROFILE_[Timestamp]_file_info.txt`: Magic signature and technical specifications.

- **`RECV`** (Short Name: `RECV`)
    - **Purpose**: Forensic carving and hidden data detection within assets.
    - **Input Schema**: `{ input: Path }`
    - **Multi-Tool Command Logic**:
        1. `binwalk --extract --matryoshka <input>` (Embedded File Extraction)
        2. `exiftool -b -ThumbnailImage <input> > thumb.jpg` (Thumbnail Recovery)
        3. `strings <input> | grep -iE "password|api|key"` (Secret Search)
        4. `file -i <input>` (MIME Detection)
        5. `identify -list format` (Codec Verification)
    - **Execution Flow**: Embedded Extraction -> Thumbnail -> Secret Search -> MIME -> Codec.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/RECOVER_[Timestamp]_embedded_files/`: Directory of files extracted via binwalk.
        - `reports/payloads/RECOVER_[Timestamp]_extracted_thumb.jpg`: Recovered thumbnail image.
        - `reports/outputs/RECOVER_[Timestamp]_secret_matches.txt`: List of identified secrets and patterns.

---

### 3. Event Log Export
**ID:** `forensics-eventlog` | **Risk:** LOW | **File:** `EventLogExportModule.java`
**Tools:** `evtx_dump`, `strings`, `python3`, `grep`, `file`

#### Execution Modes:

- **`DUMP`** (Short Name: `DUMP`)
    - **Purpose**: Convert and normalize Windows Event Logs for analysis.
    - **Input Schema**: `{ evtx_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `evtx_dump -o json <evtx_path> > out.json` (JSON Conversion)
        2. `file <evtx_path>` (Log Format Verification)
        3. `strings -n 10 <evtx_path> | head -n 50` (Quick Strings)
        4. `python3 evtx_audit.py <evtx_path>` (Custom Logic Check)
        5. `grep -c "Event" out.json` (Entry Count)
    - **Execution Flow**: Conversion -> Verification -> Strings -> Logic Check -> Count.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DUMP_[Timestamp]_event_logs.json`: Normalized event data in JSON format.
        - `reports/artifacts/DUMP_[Timestamp]_raw_strings.txt`: String dump from the evtx file.
        - `reports/analysis/DUMP_[Timestamp]_audit_summary.json`: High-level summary of event counts and types.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Targeted forensic audit of logon and system events.
    - **Input Schema**: `{ evtx_path: Path, event_id: int }`
    - **Multi-Tool Command Logic**:
        1. `evtx_dump -o json <evtx_path> | grep "\"EventID\": <event_id>"` (Event Search)
        2. `python3 logon_analyzer.py out.json` (Logon Analysis)
        3. `strings <evtx_path> | grep -i "user"` (Identity Search)
        4. `file --mime-type <evtx_path>` (MIME Type)
        5. `grep -i "critical" out.json` (Severity Check)
    - **Execution Flow**: Event Search -> Logon Analysis -> Identity Search -> MIME -> Severity.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_logon_events.json`: Targeted extraction of authentication events.
        - `reports/artifacts/AUDIT_[Timestamp]_identity_matches.txt`: Discovered usernames and identities.
        - `reports/analysis/AUDIT_[Timestamp]_severity_profile.json`: Severity distribution and critical event report.

---

### 4. Memory Dump Sniff
**ID:** `forensics-memdump` | **Risk:** MEDIUM | **File:** `MemDumpSniffModule.java`
**Tools:** `volatility3`, `strings`, `foremost`, `binwalk`, `grep`

#### Execution Modes:

- **`PROC`** (Short Name: `PROC`)
    - **Purpose**: Comprehensive process and network state analysis from memory.
    - **Input Schema**: `{ dump_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `vol -f <dump_path> windows.pslist` (Process List)
        2. `vol -f <dump_path> windows.netscan` (Network Scan)
        3. `strings -n 10 <dump_path> | grep -i "http"` (Network Strings)
        4. `binwalk -E <dump_path>` (Kernel Entropy)
        5. `foremost -i <dump_path> -t exe -o recovered_exes` (Binary Recovery)
    - **Execution Flow**: Process List -> NetScan -> Strings -> Entropy -> Recovery.
    - **Output Generation & Artifacts**:
        - `reports/outputs/PROCESS_[Timestamp]_pslist.json`: Structured list of active processes.
        - `reports/outputs/PROCESS_[Timestamp]_netscan.json`: Active network connections and sockets.
        - `reports/artifacts/PROCESS_[Timestamp]_recovered_binaries/`: Directory of executables carved from memory.

- **`CRED`** (Short Name: `CRED`)
    - **Purpose**: Extraction of credentials and sensitive artifacts from memory.
    - **Input Schema**: `{ dump_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `vol -f <dump_path> windows.hashdump` (NTLM Hashes)
        2. `strings <dump_path> | grep -aPo "password[=:]\S+"` (Password Search)
        3. `foremost -i <dump_path> -t pdf,doc -o carved_docs` (Document Extraction)
        4. `vol -f <dump_path> windows.lsadump` (LSA Secrets)
        5. `binwalk -y <dump_path>` (Signature Search)
    - **Execution Flow**: Hashdump -> Password Search -> Document Extraction -> LSA Dump -> Signature Search.
    - **Output Generation & Artifacts**:
        - `reports/payloads/CRED_[Timestamp]_ntlm_hashes.txt`: Extracted NTLM password hashes.
        - `reports/artifacts/CRED_[Timestamp]_carved_documents/`: Recovered documents (PDF, DOC) from memory.
        - `reports/outputs/CRED_[Timestamp]_lsa_secrets.json`: Extracted LSA secrets and cached credentials.

---

### 5. Prefetch Reader
**ID:** `forensics-prefetch` | **Risk:** LOW | **File:** `PrefetchReaderModule.java`
**Tools:** `python3`, `strings`, `exiftool`, `foremost`, `file`

#### Execution Modes:

- **`PARS`** (Short Name: `PARS`)
    - **Purpose**: Full reconstruction of application execution history from Prefetch.
    - **Input Schema**: `{ pf_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `python3 prefetch_parser.py <pf_path> -o json` (Core Parse)
        2. `exiftool <pf_path>` (Metadata Timeline)
        3. `strings -n 8 <pf_path> | grep -i "\.exe"` (Direct String Check)
        4. `file <pf_path>` (Magic Check)
        5. `foremost -i <pf_path> -o carved_artifacts` (Artifact Recovery)
    - **Execution Flow**: Core Parse -> Metadata -> String Check -> Magic -> Recovery.
    - **Output Generation & Artifacts**:
        - `reports/outputs/PARSE_[Timestamp]_prefetch_data.json`: Normalized application execution history.
        - `reports/analysis/PARSE_[Timestamp]_execution_timeline.json`: Technical timeline of file activity.
        - `reports/artifacts/PARSE_[Timestamp]_carved_pf.txt`: Carved artifacts from prefetch data.

- **`TIME`** (Short Name: `TIME`)
    - **Purpose**: Correlate multiple Prefetch files into a high-fidelity execution timeline.
    - **Input Schema**: `{ pf_dir: String }`
    - **Multi-Tool Command Logic**:
        1. `python3 timeline_gen.py <pf_dir>` (Timeline Gen)
        2. `exiftool -csv <pf_dir>/*.pf > timeline.csv` (Metadata Aggregate)
        3. `strings <pf_dir>/*.pf | grep -i "Last Run"` (Status Extract)
        4. `file <pf_dir>/*` (Batch Verification)
        5. `foremost -i <pf_dir> -t all` (Batch Recovery)
    - **Execution Flow**: Timeline Gen -> Aggregate -> Status Extract -> Verification -> Recovery.

---

### 6. Registry Parser
**ID:** `forensics-regparse` | **Risk:** LOW | **File:** `RegParserModule.java`
**Tools:** `regipy-dump`, `strings`, `python3`, `foremost`, `file`

#### Execution Modes:

- **`DUMP`** (Short Name: `DUMP`)
    - **Purpose**: Exhaustive extraction and normalization of registry hive data.
    - **Input Schema**: `{ hive_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `regipy-dump <hive_path> -o out.json` (Full Hive Dump)
        2. `strings -n 12 <hive_path> | head -n 100` (String Sampling)
        3. `file <hive_path>` (Hive Verification)
        4. `python3 reg_audit.py <hive_path>` (Security Audit)
        5. `foremost -i <hive_path> -o carved_reg` (Sub-hive Recovery)
    - **Execution Flow**: Hive Dump -> String Sampling -> Verification -> Security Audit -> Recovery.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DUMP_[Timestamp]_registry_hive.json`: Complete normalized registry hive dump.
        - `reports/analysis/DUMP_[Timestamp]_security_audit.json`: Registry-based security configuration report.
        - `reports/artifacts/DUMP_[Timestamp]_carved_hives/`: Recovered sub-hives or registry fragments.

- **`SECR`** (Short Name: `SECR`)
    - **Purpose**: Targeted extraction of sensitive keys (SAM, SECURITY, SOFTWARE).
    - **Input Schema**: `{ hive_path: Path, key_path: String }`
    - **Multi-Tool Command Logic**:
        1. `regipy-dump <hive_path> -k <key_path>` (Key Extract)
        2. `python3 secret_finder.py <hive_path>` (Pattern Search)
        3. `strings <hive_path> | grep -iE "password|key|token"` (Secret Strings)
        4. `file --mime-type <hive_path>` (MIME Check)
        5. `foremost -v -i <hive_path>` (Data Carving)
    - **Execution Flow**: Key Extract -> Pattern Search -> Secret Strings -> MIME Check -> Data Carving.

---### 7. Network Forensics
**ID:** `forensics-network` | **Risk:** MEDIUM | **File:** `NetworkForensicsModule.java`
**Tools:** `tcpdump`, `wireshark` (tshark), `zeek`, `snort`, `network-miner`

#### Execution Modes:
- **`EXTR`** (Short Name: `EXTR`)
    - **Purpose**: Extract high-fidelity artifacts (files, credentials) from PCAP data.
    - **Input Schema**: `{ pcap_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `tshark -r <pcap_path> --export-objects http,files` (File Extraction)
        2. `zeek -r <pcap_path>` (Protocol Analysis)
        3. `tshark -r <pcap_path> -Y "http.authbasic" -T fields -e http.authbasic` (Cred Extraction)
        4. `snort -r <pcap_path> -c snort.conf` (IDS Audit)
        5. `capinfos <pcap_path>` (PCAP Metadata)
    - **Execution Flow**: File Extraction -> Protocol Analysis -> Cred Extraction -> IDS Audit -> Metadata.
- **`TIME`** (Short Name: `TIME`)
    - **Purpose**: Reconstruct a chronological timeline of network events.
    - **Input Schema**: `{ pcap_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `tshark -r <pcap_path> -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Info` (Chronology)
        2. `zeek-cut ts id.orig_h id.resp_h service < conn.log` (Conn Timeline)
        3. `tshark -r <pcap_path> -q -z io,phs` (Protocol Hierarchy)
        4. `snort -r <pcap_path> -A fast` (Alert Timeline)
        5. `tshark -r <pcap_path> -z follow,tcp,ascii,0` (Stream Reassembly)
    - **Execution Flow**: Chronology -> Conn Timeline -> Hierarchy -> Alert Timeline -> Stream Reassembly.

---

**© 2026 Funbinet Inc. — JABBER V 5.5.0.0**
