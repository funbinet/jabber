# Utilities — Category Blueprint

**Category:** `UTILITIES` | **Slug:** `util` | **Tools Dir:** `~/jabber/jabber-tools/util/`
**Package:** `com.jabber.jabber.modules.utilities` | **Group:** Data & Utilities

---

## ToolManager: `util/ToolManager.java`

| ID | Binary | Source | Version Check | Install Method |
|----|--------|--------|---------------|----------------|
| `xxd` | `xxd` | apt (xxd) | `xxd --version` | `apt_install` |
| `ipcalc` | `ipcalc` | apt | `ipcalc --version` | `apt_install` |
| `ntpdate` | `ntpdate` | apt | `ntpdate --version` | `apt_install` |
| `python3` | `python3` | system | `python3 --version` | system |
| `curl` | `curl` | system | `curl --version` | system |

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

Every module in the **Utilities** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between operations.
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for downloading results and logs.
4. **Live Terminal Stream**: A real-time stdout/stderr streaming component for operational transparency.
5. **Interactive Dashboard**: Real-time display of extracted data, payloads, or process progress.

---

---

## Modules

### 1. General Utilities Suite
**ID:** `util-suite` | **Risk:** LOW | **File:** `UtilitiesModule.java`
**Tools:** `xxd`, `ipcalc`, `ntpdate`, `python3`, `curl`

#### Execution Modes:

- **`HEX`** (Short Name: `HEX`)
    - **Purpose**: Perform high-fidelity binary-to-hexadecimal transformations for asset inspection.
    - **Input Schema**: `{ input: String, is_file: boolean }`
    - **Multi-Tool Command Logic**:
        1. `echo -n "<input>" | xxd` (Core Hex Dump)
        2. `python3 -c "import binascii; print(binascii.hexlify(b'<input>').decode())"` (Python Alternative)
        3. `curl --version` (Binary Audit)
        4. `ipcalc --version` (Binary Audit)
        5. `ntpdate --version` (Binary Audit)
    - **Execution Flow**: Core Hex -> Python Alt -> Binary Audit x3.
    - **Output Generation & Artifacts**:
        - `reports/outputs/HEX_[Timestamp]_hex_dump.txt`: Canonical hexadecimal representation of the input asset.
        - `reports/artifacts/HEX_[Timestamp]_python_hex.txt`: Alternative hex representation generated via the Python backend.
        - `reports/analysis/HEX_[Timestamp]_binary_status.json`: Verification of xxd, python3, and curl binary status.

- **`SUBN`** (Short Name: `SUBN`)
    - **Purpose**: Rapid calculation and validation of IPv4/IPv6 network boundaries.
    - **Input Schema**: `{ cidr: String }`
    - **Multi-Tool Command Logic**:
        1. `ipcalc <cidr>` (Core Subnet Calculation)
        2. `python3 -c "import ipaddress; n=ipaddress.ip_network('<cidr>'); print(n.netmask)"` (Python Validation)
        3. `curl -I http://ifconfig.me` (External IP Audit)
        4. `xxd --version` (Binary Check)
        5. `ntpdate -q pool.ntp.org` (Sync Audit)
    - **Execution Flow**: Core Calculation -> Python Validation -> External Audit -> Binary Check -> Sync Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SUBNET_[Timestamp]_subnet_calculation.json`: Detailed network boundaries and mask calculations.
        - `reports/artifacts/SUBNET_[Timestamp]_external_ip.txt`: Captured external IP address and HTTP header audit.
        - `reports/analysis/SUBNET_[Timestamp]_ntp_sync.json`: Verification of local system clock synchronization.

---

### 2. Binary Hex Dumper
**ID:** `util-hexdump` | **Risk:** LOW | **File:** `HexDumpModule.java`
**Tools:** `xxd`, `od`, `hexdump`, `python3`, `file`

#### Execution Modes:

- **`DUMP`** (Short Name: `DUMP`)
    - **Purpose**: Generate a canonical, multi-format binary representation of a target file.
    - **Input Schema**: `{ input: Path }`
    - **Multi-Tool Command Logic**:
        1. `hexdump -C <input>` (Core Canonical Dump)
        2. `od -tx1 <input>` (Octal Audit)
        3. `xxd <input>` (Alternative Dump)
        4. `file <input>` (Metadata Audit)
        5. `python3 -c "print(open('<input>', 'rb').read(16).hex())"` (Python Header Check)
    - **Execution Flow**: Core Dump -> Octal Audit -> Alternative Dump -> Metadata Audit -> Header Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DUMP_[Timestamp]_hexdump_canonical.txt`: Multi-format binary representation of the target file.
        - `reports/artifacts/DUMP_[Timestamp]_metadata_audit.json`: Detailed file metadata and magic number identification.
        - `reports/analysis/DUMP_[Timestamp]_octal_audit.txt`: Octal-based audit of the input stream for audit.

- **`REVR`** (Short Name: `REVR`)
    - **Purpose**: Reconstruct binary assets from hexadecimal ASCII representations.
    - **Input Schema**: `{ hex_input: Path }`
    - **Multi-Tool Command Logic**:
        1. `xxd -r <hex_input> out.bin` (Core Reconstruction)
        2. `file out.bin` (Format Audit)
        3. `hexdump -n 16 out.bin` (Re-verification)
        4. `od -V` (Binary Check)
        5. `python3 --version` (Binary Check)
    - **Execution Flow**: Core Reconstruction -> Format Audit -> Re-verification -> Binary Check x2.
    - **Output Generation & Artifacts**:
        - `reports/outputs/REVERSE_[Timestamp]_reconstructed_binary.bin`: Restored binary asset from hexadecimal ASCII input.
        - `reports/artifacts/REVERSE_[Timestamp]_reverification_dump.txt`: Canonical hex dump of the reconstructed asset for verification.
        - `reports/analysis/REVERSE_[Timestamp]_format_audit.json`: Detailed format identification and integrity check of the output.

---

### 3. Advanced Subnet Calculator
**ID:** `util-subnet` | **Risk:** LOW | **File:** `SubnetCalculator2Module.java`
**Tools:** `ipcalc`, `sipcalc`, `nmap`, `python3`, `dig`

#### Execution Modes:

- **`CALC`** (Short Name: `CALC`)
    - **Purpose**: Detailed network analysis including wildcard masks, broadcast limits, and host ranges.
    - **Input Schema**: `{ ip: String, mask: String }`
    - **Multi-Tool Command Logic**:
        1. `sipcalc <ip>/<mask1>` (Core Detailed Calc)
        2. `ipcalc <ip>/<mask1>` (Alternative Calc)
        3. `python3 -c "import ipaddress; print(ipaddress.ip_interface('<ip>/<mask1>').network)"` (Python Audit)
        4. `nmap -sL <ip>/<mask1>` (Host Inventory)
        5. `dig -x <ip> +short` (PTR Audit)
    - **Execution Flow**: Core Calc -> Alternative Calc -> Python Audit -> Host Inventory -> PTR Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CALC_[Timestamp]_network_analysis.json`: Comprehensive report on subnet masks, ranges, and boundaries.
        - `reports/artifacts/CALC_[Timestamp]_host_inventory.txt`: Resolved host inventory for the calculated network segment.
        - `reports/analysis/CALC_[Timestamp]_ptr_audit.json`: Reverse DNS (PTR) record inventory for the target IP.

- **`LIST`** (Short Name: `LIST`)
    - **Purpose**: Enumerate and resolve all possible host addresses within a specific network segment.
    - **Input Schema**: `{ cidr: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap -sL <cidr>` (Core Host Listing)
        2. `sipcalc <cidr> | grep "Host range"` (Range Audit)
        3. `ipcalc <cidr>` (Boundary Audit)
        4. `python3 -c "import ipaddress; [print(str(ip)) for ip in ipaddress.ip_network('<cidr>').hosts()]"` (Python List)
        5. `dig @8.8.8.8 -x <cidr>` (External Resolution Check)
    - **Execution Flow**: Core Listing -> Range Audit -> Boundary Audit -> Python List -> External Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/LIST_[Timestamp]_host_list.txt`: Recursive listing of all possible host addresses in the CIDR block.
        - `reports/artifacts/LIST_[Timestamp]_range_audit.json`: Technical audit of host ranges and boundary limits.
        - `reports/analysis/LIST_[Timestamp]_resolution_check.json`: Verification of external DNS resolution for the segment.

---

### 4. IP Format Converter
**ID:** `util-ipformat` | **Risk:** LOW | **File:** `IPFormatModule.java`
**Tools:** `ipcalc`, `python3`, `dig`, `host`, `curl`

#### Execution Modes:

- **`CONV`** (Short Name: `CONV`)
    - **Purpose**: Transform standard dot-decimal IP addresses into alternate numerical representations.
    - **Input Schema**: `{ ip: String }`
    - **Multi-Tool Command Logic**:
        1. `ipcalc <ip>` (Core Conversion)
        2. `python3 -c "import socket, struct; print(struct.unpack('!L', socket.inet_aton('<ip>'))[0])"` (Decimal Conv)
        3. `python3 -c "print(hex(struct.unpack('!L', socket.inet_aton('<ip>'))[0]))"` (Hex Conv)
        4. `host <ip>` (Native Name Lookup)
        5. `curl --version` (Binary Audit)
    - **Execution Flow**: Core Conversion -> Decimal Conv -> Hex Conv -> Native Lookup -> Binary Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CONVERT_[Timestamp]_ip_formats.json`: Map of the IP address in dot-decimal, decimal, and hex formats.
        - `reports/artifacts/CONVERT_[Timestamp]_host_lookup.txt`: Results of the native system name lookup for the IP.
        - `reports/analysis/CONVERT_[Timestamp]_binary_status.json`: Verification of ipcalc, python3, and dig tool status.

- **`PTR`** (Short Name: `PTR`)
    - **Purpose**: Resolve the reverse DNS records associated with a specific IP address.
    - **Input Schema**: `{ ip: String }`
    - **Multi-Tool Command Logic**:
        1. `dig -x <ip> +short` (Core Dig Lookup)
        2. `host <ip>` (Native Host Lookup)
        3. `python3 -c "import socket; print(socket.gethostbyaddr('<ip>'))"` (Python Lookup)
        4. `ipcalc <ip>` (Boundary Audit)
        5. `curl -v http://ifconfig.me` (External IP Check)
    - **Execution Flow**: Core Dig -> Native Host -> Python Lookup -> Boundary Audit -> External Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/PTR_[Timestamp]_reverse_dns.json`: Inventory of all identified reverse DNS records and hostnames.
        - `reports/artifacts/PTR_[Timestamp]_external_posture.txt`: Results of the external IP liveness and posture check.
        - `reports/analysis/PTR_[Timestamp]_boundary_audit.json`: Verification of IP boundary limits and subnet metadata.

---

### 5. URL Decode Tool
**ID:** `util-urldecode` | **Risk:** LOW | **File:** `URLDecodeModule.java`
**Tools:** `python3`, `curl`, `php`, `perl`, `sed`

#### Execution Modes:

- **`DECD`** (Short Name: `DECD`)
    - **Purpose**: Revert percent-encoded URL strings to their original character representations.
    - **Input Schema**: `{ input: String }`
    - **Multi-Tool Command Logic**:
        1. `python3 -c "import urllib.parse; print(urllib.parse.unquote('<input>'))"` (Core Python Decode)
        2. `php -r "echo urldecode('<input>');"` (PHP Alternative)
        3. `perl -MURI::Escape -e 'print uri_unescape("<input>")'` (Perl Alternative)
        4. `echo "<input>" | sed 's/%\([0-9A-F][0-9A-F]\)/\\\\x\1/g' | xargs -0 printf` (SED/Printf Backup)
        5. `curl --version` (Binary Audit)
    - **Execution Flow**: Core Python -> PHP Alt -> Perl Alt -> SED Backup -> Binary Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DECODE_[Timestamp]_decoded_string.txt`: Percent-encoded string restored to original characters.
        - `reports/artifacts/DECODE_[Timestamp]_perl_audit.txt`: Verification of characters handled by the Perl URI escape engine.
        - `reports/analysis/DECODE_[Timestamp]_binary_readiness.json`: Verification of python3, php, perl, and sed availability.

- **`ENCD`** (Short Name: `ENCD`)
    - **Purpose**: Transform strings into percent-encoded format for safe inclusion in URLs.
    - **Input Schema**: `{ input: String }`
    - **Multi-Tool Command Logic**:
        1. `python3 -c "import urllib.parse; print(urllib.parse.quote('<input>'))"` (Core Python Encode)
        2. `php -r "echo urlencode('<input>');"` (PHP Alternative)
        3. `perl -MURI::Escape -e 'print uri_escape("<input>")'` (Perl Alternative)
        4. `curl -Gso /dev/null --data-urlencode "x=<input>" http://localhost` (Curl Logic)
        5. `sed --version` (Binary Check)
    - **Execution Flow**: Core Python -> PHP Alt -> Perl Alt -> Curl Logic -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ENCODE_[Timestamp]_encoded_url.txt`: Input string transformed into safe percent-encoded URL format.
        - `reports/artifacts/ENCODE_[Timestamp]_curl_logic.log`: Technical log of the curl-based URL encoding validation.
        - `reports/analysis/ENCODE_[Timestamp]_php_status.json`: Verification of the PHP runtime and urlencode function.

---

### 6. Time Sync Auditor
**ID:** `util-timesync` | **Risk:** LOW | **File:** `TimeSyncCheckModule.java`
**Tools:** `ntpdate`, `timedatectl`, `date`, `chronyc`, `curl`

#### Execution Modes:

- **`CHCK`** (Short Name: `CHCK`)
    - **Purpose**: Query remote NTP stratums to calculate local clock drift and synchronization offset.
    - **Input Schema**: `{ server: String }`
    - **Multi-Tool Command Logic**:
        1. `ntpdate -q <server>` (Core NTP Query)
        2. `chronyc sources -v` (Chrony Status Audit)
        3. `curl -I <server>` (HTTP Header Time Check)
        4. `date -u` (Local UTC Audit)
        5. `timedatectl status` (Systemd Time Audit)
    - **Execution Flow**: Core NTP -> Chrony Status -> HTTP Check -> Local UTC -> Systemd Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CHECK_[Timestamp]_ntp_drift_audit.json`: Detailed report on clock drift, offset, and sync status.
        - `reports/artifacts/CHECK_[Timestamp]_http_time_check.txt`: Captured HTTP Date header for external time reference.
        - `reports/analysis/CHECK_[Timestamp]_chrony_status.json`: Performance and synchronization audit from the chrony agent.

- **`STAT`** (Short Name: `STAT`)
    - **Purpose**: Comprehensive audit of local system time configuration and synchronization state.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `timedatectl status` (Core Systemd Status)
        2. `chronyc tracking` (Chrony Performance Audit)
        3. `ntpdate --version` (Binary Check)
        4. `date --version` (Binary Check)
        5. `curl -s http://worldtimeapi.org/api/ip | jq` (External Reference Check)
    - **Execution Flow**: Systemd Status -> Chrony Audit -> Binary Check x2 -> External Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/STATUS_[Timestamp]_time_configuration.json`: Comprehensive report on local time and sync state.
        - `reports/artifacts/STATUS_[Timestamp]_worldtime_api.json`: Reference time data from an external world-time API.
        - `reports/analysis/STATUS_[Timestamp]_binary_versions.json`: Version inventory for ntpdate, chronyc, and timedatectl.

---

### 7. String Metrics Calculator
**ID:** `util-strlen` | **Risk:** LOW | **File:** `StrLenModule.java`
**Tools:** `wc`, `python3`, `awk`, `xxd`, `perl`

#### Execution Modes:

- **`CONT`** (Short Name: `CONT`)
    - **Purpose**: Calculate precise character, word, and line metrics for target strings or data payloads.
    - **Input Schema**: `{ input: String }`
    - **Multi-Tool Command Logic**:
        1. `echo -n "<input>" | wc -c -w -l` (Core WC Metrics)
        2. `python3 -c "print(len('<input>'))"` (Python Char Count)
        3. `awk '{print length}'` (AWK Char Count)
        4. `perl -e 'print length("<input>")'` (Perl Char Count)
        5. `xxd -p | wc -c` (Raw Byte Density)
    - **Execution Flow**: Core WC -> Python -> AWK -> Perl -> Byte Density.
    - **Output Generation & Artifacts**:
        - `reports/outputs/COUNT_[Timestamp]_string_metrics.json`: Detailed count of characters, words, and lines.
        - `reports/artifacts/COUNT_[Timestamp]_raw_byte_density.txt`: Hex-based audit of data density and non-printable bytes.
        - `reports/analysis/COUNT_[Timestamp]_python_audit.json`: Verification of the Python char counting and length logic.

- **`ANAL`** (Short Name: `ANAL`)
    - **Purpose**: Perform deep byte-level analysis and entropy calculation for target strings.
    - **Input Schema**: `{ input: String }`
    - **Multi-Tool Command Logic**:
        1. `echo -n "<input>" | xxd` (Core Hex Analysis)
        2. `python3 -c "import math; ..."` (Entropy Calculation)
        3. `awk 'BEGIN{...}'` (Byte Distribution)
        4. `perl -e 'print unpack("B*", "<input>")'` (Binary Bitstream)
        5. `wc --version` (Binary Check)
    - **Execution Flow**: Core Hex -> Entropy -> Distribution -> Bitstream -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ANALYZE_[Timestamp]_entropy_report.json`: Mathematical calculation of data entropy and randomness.
        - `reports/artifacts/ANALYZE_[Timestamp]_byte_distribution.txt`: Frequency analysis of byte distribution in the input.
        - `reports/analysis/ANALYZE_[Timestamp]_bitstream_audit.bin`: Captured binary bitstream for low-level cryptographic audit.

---

### 8. EXIF Data Extractor
**ID:** `util-exif` | **Risk:** LOW | **File:** `EXIFExtractorModule.java`
**Tools:** `exiftool`, `file`, `strings`, `grep`, `jq`

#### Execution Modes:

- **`EXTR`** (Short Name: `EXTR`)
    - **Purpose**: Extract high-fidelity metadata and GPS coordinates from image/video assets.
    - **Input Schema**: `{ file: Path }`
    - **Multi-Tool Command Logic**:
        1. `exiftool -j <file>` (Core Metadata Extraction)
        2. `exiftool -gps:all <file>` (GPS Data Extraction)
        3. `file <file>` (Format Verification)
        4. `strings <file> | head -n 100` (Header Audit)
        5. `jq --version` (Binary Check)
    - **Execution Flow**: Format Verify -> Core Extraction -> GPS Data -> Header Audit -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXTRACT_[Timestamp]_metadata.json`: Complete JSON-formatted metadata export.
        - `reports/artifacts/EXTRACT_[Timestamp]_gps_map.txt`: Extracted GPS coordinates and location metadata.
        - `reports/analysis/EXTRACT_[Timestamp]_header_audit.txt`: Technical audit of file headers and magic numbers.


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

### 9. Event Log Exporter
**ID:** `util-eventlog` | **Risk:** MEDIUM | **File:** `EventLogExportModule.java`
**Tools:** `powershell`, `wevtutil`, `find`, `grep`, `cat`

#### Execution Modes:

- **`EXPR`** (Short Name: `EXPR`)
    - **Purpose**: Export and filter system event logs for forensic analysis.
    - **Input Schema**: `{ log_name: String, count: int }`
    - **Multi-Tool Command Logic**:
        1. `wevtutil qe <log_name> /c:<count> /f:text` (Core Windows Export)
        2. `powershell -Command "Get-WinEvent -LogName <log_name> -MaxEvents <count>"` (Alternative PS Export)
        3. `find /var/log/ -name "*.log"` (Linux Discovery)
        4. `grep -ri "error" /var/log/` (Error Audit)
        5. `cat --version` (Binary Check)
    - **Execution Flow**: Discovery -> Core Export -> PS Alternative -> Error Audit -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXPORT_[Timestamp]_event_logs.txt`: Filtered export of system event logs.
        - `reports/artifacts/EXPORT_[Timestamp]_error_audit.log`: Log of identified error and warning events.
        - `reports/analysis/EXPORT_[Timestamp]_log_inventory.json`: Inventory of available log sources and statuses.


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

### 10. File Hex Dumper
**ID:** `util-hexdump` | **Risk:** LOW | **File:** `HexDumpModule.java`
**Tools:** `xxd`, `hexdump`, `od`, `strings`, `file`

#### Execution Modes:

- **`DUMP`** (Short Name: `DUMP`)
    - **Purpose**: Generate high-fidelity hex dumps of binary files for analysis.
    - **Input Schema**: `{ file: Path, length: int }`
    - **Multi-Tool Command Logic**:
        1. `xxd -l <length> <file>` (Core Hex Dump)
        2. `hexdump -C -n <length> <file>` (Alternative Canonical Dump)
        3. `od -t x1 -N <length> <file>` (Octal Dump Alternative)
        4. `strings -n 4 <file> | head -n 20` (String Extraction)
        5. `file <file>` (Format Verification)
    - **Execution Flow**: Format Verify -> Core Dump -> Alternative -> String Extraction -> Octal Dump.


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

### 11. IP Address Formatter
**ID:** `util-ipformat` | **Risk:** LOW | **File:** `IPFormatModule.java`
**Tools:** `python3`, `awk`, `sed`, `grep`, `cat`

#### Execution Modes:

- **`CONV`** (Short Name: `CONV`)
    - **Purpose**: Convert IP addresses between various formats (Decimal, Hex, Binary, CIDR).
    - **Input Schema**: `{ ip: String, format: String }`
    - **Multi-Tool Command Logic**:
        1. `python3 -c "import socket, struct; ..."` (Core Conversion)
        2. `echo <ip> | awk -F. '{...}'` (Awk Logic)
        3. `sed 's/\./ /g' <<< "<ip>"` (Sed Formatting)
        4. `grep -E "[0-9]{1,3}" <<< "<ip>"` (Validation)
        5. `cat --version` (Binary Check)
    - **Execution Flow**: Validation -> Core Conversion -> Awk Logic -> Sed Formatting -> Binary Check.


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

### 12. Memory Sniffing Tool
**ID:** `util-memsniff` | **Risk:** HIGH | **File:** `MemDumpSniffModule.java`
**Tools:** `gcore`, `strings`, `grep`, `awk`, `cat`

#### Execution Modes:

- **`SNIF`** (Short Name: `SNIF`)
    - **Purpose**: Capture and sniff process memory for sensitive strings and credentials.
    - **Input Schema**: `{ pid: int, keyword: String }`
    - **Multi-Tool Command Logic**:
        1. `gcore -o dump <pid>` (Core Memory Dump)
        2. `strings dump.<pid> | grep -i "<keyword>"` (String Search)
        3. `awk '/<keyword>/{print $0}' dump.<pid>` (Pattern Extraction)
        4. `cat /proc/<pid>/maps` (Memory Map Audit)
        5. `grep --version` (Binary Check)
    - **Execution Flow**: Map Audit -> Core Dump -> String Search -> Pattern Extraction -> Binary Check.


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

### 13. Prefetch History Reader
**ID:** `util-prefetch` | **Risk:** LOW | **File:** `PrefetchReaderModule.java`
**Tools:** `python3`, `strings`, `file`, `find`, `cat`

#### Execution Modes:

- **`READ`** (Short Name: `READ`)
    - **Purpose**: Parse Windows Prefetch files to identify application execution history.
    - **Input Schema**: `{ file: Path }`
    - **Multi-Tool Command Logic**:
        1. `python3 prefetch_parser.py <file>` (Core Parsing)
        2. `strings <file> | head -n 50` (Metadata Extraction)
        3. `file <file>` (Format Verification)
        4. `find C:/Windows/Prefetch/ -name "*.pf"` (Discovery)
        5. `cat --version` (Binary Check)
    - **Execution Flow**: Discovery -> Format Verify -> Core Parsing -> Metadata -> Binary Check.


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

### 14. Registry Hive Parser
**ID:** `util-regparser` | **Risk:** MEDIUM | **File:** `RegParserModule.java`
**Tools:** `reg`, `python3`, `strings`, `file`, `grep`

#### Execution Modes:

- **`QUER`** (Short Name: `QUER`)
    - **Purpose**: Query and parse Windows Registry keys for configuration data.
    - **Input Schema**: `{ key: String }`
    - **Multi-Tool Command Logic**:
        1. `reg query "<key>" /s` (Core Registry Query)
        2. `python3 reg_parser.py --key "<key>"` (Custom Logic)
        3. `strings NTUSER.DAT | grep -i "user"` (Hive Audit)
        4. `file NTUSER.DAT` (Hive Verification)
        5. `grep --version` (Binary Check)
    - **Execution Flow**: Hive Verify -> Core Query -> Custom Logic -> Hive Audit -> Binary Check.


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

### 15. Simple String Counter
**ID:** `util-strlen` | **Risk:** LOW | **File:** `StrLenModule.java`
**Tools:** `wc`, `awk`, `python3`, `sed`, `cat`

#### Execution Modes:

- **`CONT`** (Short Name: `CONT`)
    - **Purpose**: Calculate the exact length and entropy of input strings.
    - **Input Schema**: `{ input: String }`
    - **Multi-Tool Command Logic**:
        1. `echo -n "<input>" | wc -m` (Core Char Count)
        2. `echo -n "<input>" | awk '{print length}'` (Awk Length)
        3. `python3 -c "print(len('<input>'))"` (Python Length)
        4. `sed 's/./& /g' <<< "<input>" | wc -w` (Token Count)
        5. `cat --version` (Binary Check)
    - **Execution Flow**: Core Count -> Awk Length -> Python Length -> Token Count -> Binary Check.


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

### 16. Subnet Analysis Tool
**ID:** `util-subnet-v2` | **Risk:** LOW | **File:** `SubnetCalculator2Module.java`
**Tools:** `ipcalc`, `python3`, `awk`, `grep`, `cat`

#### Execution Modes:

- **`CALC`** (Short Name: `CALC`)
    - **Purpose**: Advanced IPv4/IPv6 subnet calculation and range expansion.
    - **Input Schema**: `{ network: String }`
    - **Multi-Tool Command Logic**:
        1. `ipcalc <network>` (Core Subnet Calc)
        2. `python3 -c "import ipaddress; ..."` (Python Logic)
        3. `awk -F/ '{...}' <<< "<network>"` (Prefix Logic)
        4. `grep -E "[0-9/]+" <<< "<network>"` (Validation)
        5. `cat --version` (Binary Check)
    - **Execution Flow**: Validation -> Core Calc -> Python Logic -> Prefix Logic -> Binary Check.


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

### 17. Time Synchronization Auditor
**ID:** `util-timesync` | **Risk:** LOW | **File:** `TimeSyncCheckModule.java`
**Tools:** `ntpdate`, `date`, `timedatectl`, `hwclock`, `curl`

#### Execution Modes:

- **`CHCK`** (Short Name: `CHCK`)
    - **Purpose**: Audit system clock synchronization and drift against remote NTP servers.
    - **Input Schema**: `{ ntp_server: String }`
    - **Multi-Tool Command Logic**:
        1. `ntpdate -q <ntp_server>` (Core Drift Check)
        2. `date` (Local Time Audit)
        3. `timedatectl status` (Systemd Context)
        4. `hwclock -r` (Hardware Clock Audit)
        5. `curl -sI https://google.com | grep Date` (HTTP Time Audit)
    - **Execution Flow**: Local Audit -> HTTP Audit -> Core Drift -> Systemd Context -> Hardware Audit.


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

### 18. Obfuscation URL Decoder
**ID:** `util-urldecode` | **Risk:** LOW | **File:** `URLDecodeModule.java`
**Tools:** `python3`, `sed`, `awk`, `curl`, `cat`

#### Execution Modes:

- **`DECD`** (Short Name: `DECD`)
    - **Purpose**: Decode URL-encoded strings and identify potential obfuscation.
    - **Input Schema**: `{ input: String }`
    - **Multi-Tool Command Logic**:
        1. `python3 -c "import urllib.parse; print(urllib.parse.unquote('<input>'))"` (Core Decoding)
        2. `sed 's/%\([0-9A-F]\{2\}\)/\\\x\1/g' <<< "<input>"` (Sed Transform)
        3. `awk 'BEGIN {for(i=0;i<256;i++) hex[sprintf("%02X",i)]=sprintf("%c",i); ...}'` (Awk Decode)
        4. `curl -G --data-urlencode "q=<input>" http://localhost` (Curl Logic)
        5. `cat --version` (Binary Check)
    - **Execution Flow**: Core Decoding -> Sed Transform -> Awk Decode -> Curl Logic -> Binary Check.


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

### 19. Browser History V2
**ID:** `util-history-v2` | **Risk:** LOW | **File:** `BrowserHistDump2Module.java`
**Tools:** `sqlite3`, `find`, `strings`, `grep`, `jq`

#### Execution Modes:

- **`DUMP`** (Short Name: `DUMP`)
    - **Purpose**: Extraction of browser history with advanced pattern matching and JSON export.
    - **Input Schema**: `{ search_root: String, pattern: String }`
    - **Multi-Tool Command Logic**:
        1. `find <search_root> -name "History" -exec sqlite3 {} "SELECT url FROM urls WHERE url LIKE '%<pattern>%'" \;` (Core Extraction)
        2. `strings <search_root>/*History* | grep -i "<pattern>"` (Raw String Search)
        3. `jq --version` (Binary Check)
        4. `sqlite3 --version` (Binary Check)
        5. `grep --version` (Binary Check)
    - **Execution Flow**: Discovery -> Core Extraction -> Raw Search -> Binary Check x3.


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