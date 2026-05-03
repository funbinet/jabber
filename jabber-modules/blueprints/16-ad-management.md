# AD Management — Category Blueprint

**Category:** `AD_MANAGEMENT` | **Slug:** `admanage` | **Tools Dir:** `~/jabber/jabber-tools/admanage/`
**Package:** `com.jabber.jabber.modules.credential` | **Group:** Operations & Assets

---

## ToolManager: `admanage/ToolManager.java`

| ID | Binary | Source | Version Check | Install Method |
|----|--------|--------|---------------|----------------|
| `ldapsearch` | `ldapsearch` | apt (ldap-utils) | `ldapsearch -V` | `apt_install` |
| `ldapmodify` | `ldapmodify` | apt (ldap-utils) | `ldapmodify -V` | `apt_install` |
| `rpcclient` | `rpcclient` | apt (smbclient) | `rpcclient --version` | `apt_install` |
| `net` | `net` | apt (samba-common-bin) | `net help` | `apt_install` |
| `adidnsdump` | `adidnsdump` | pip | `adidnsdump --help` | `pip_install` |
| `crackmapexec` | `crackmapexec` | pip | `crackmapexec --version` | `pip_install` |
| `impacket` | `impacket-addcomputer` | pip | `impacket-addcomputer --help` | `pip_install` |
| `dig` | `dig` | apt (dnsutils) | `dig -v` | `apt_install` |
| `whois` | `whois` | apt/pkg | `whois --version` | `apt_install` |

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

Every module in the **AD Management** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between operations.
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for downloading results and logs.
4. **Live Terminal Stream**: A real-time stdout/stderr streaming component for operational transparency.
5. **Interactive Dashboard**: Real-time display of extracted data, payloads, or process progress.

---

---

## Modules

### 1. AD User Creator
**ID:** `ad-user-create` | **Risk:** HIGH | **File:** `UserCreateModule.java`
**Tools:** `ldapmodify`, `rpcclient`, `net`, `impacket`, `ldapsearch`

#### Execution Modes:

- **`CREA`** (Short Name: `CREA`)
    - **Purpose**: Provision a new user object in Active Directory via RPC and LDAP interfaces.
    - **Input Schema**: `{ username: String, pass: Password, dc: String, domain: String }`
    - **Multi-Tool Command Logic**:
        1. `rpcclient -U <admin>%<pass> <dc> -c "createdomuser <username>"` (Core RPC User Create)
        2. `ldapmodify -x -H ldap://<dc> -D <dn> -w <pass> -f user.ldif` (LDAP Object Gen)
        3. `net ads user add <username> -S <dc> -U <admin>%<pass>` (Samba Native Add)
        4. `impacket-addcomputer -dc-ip <dc> -handle <username> <domain>/<admin>:<pass>` (Computer-Account Alternative)
        5. `ldapsearch -H ldap://<dc> -x -b "dc=...,dc=..." "(sAMAccountName=<username>)"` (Creation Audit)
    - **Execution Flow**: Core RPC -> LDAP Object -> Samba Native -> Computer Alt -> Creation Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CREATE_[Timestamp]_creation_audit.json`: Detailed report on the success and attributes of the new AD user.
        - `reports/artifacts/CREATE_[Timestamp]_user.ldif`: Generated LDIF file used for the user creation object.
        - `reports/analysis/CREATE_[Timestamp]_rpc_output.txt`: Raw console output from the RPC user creation command.

- **`VRFY`** (Short Name: `VRFY`)
    - **Purpose**: Perform multi-protocol validation of user account existence and attributes.
    - **Input Schema**: `{ username: String, dc: String }`
    - **Multi-Tool Command Logic**:
        1. `ldapsearch -x -H ldap://<dc> "(sAMAccountName=<username>)"` (Core LDAP Query)
        2. `rpcclient -U "" <dc> -c "lookupnames <username>"` (RPC Name Lookup)
        3. `net ads user info <username> -S <dc>` (Samba Info Audit)
        4. `impacket-lookupsid <domain>/<user>@<dc>` (SID Extraction)
        5. `dig -t SRV _ldap._tcp.dc._msdcs.<domain>` (DC Discovery Audit)
    - **Execution Flow**: Core LDAP -> RPC Lookup -> Samba Info -> SID Extraction -> DC Discovery.
    - **Output Generation & Artifacts**:
        - `reports/outputs/VERIFY_[Timestamp]_user_attributes.json`: Comprehensive report on identified user attributes and SID.
        - `reports/artifacts/VERIFY_[Timestamp]_ldap_query.xml`: Raw LDAP query results for the targeted user.
        - `reports/analysis/VERIFY_[Timestamp]_dc_discovery.xml`: Nmap SRV record discovery results for the Domain Controller.

---

### 2. Group Membership Manager
**ID:** `ad-group-add` | **Risk:** HIGH | **File:** `GroupAddModule.java`
**Tools:** `ldapmodify`, `rpcclient`, `net`, `ldapsearch`, `crackmapexec`

#### Execution Modes:

- **`ADD`** (Short Name: `ADD`)
    - **Purpose**: Escalate privileges or organize assets by adding users to AD security groups.
    - **Input Schema**: `{ username: String, group: String, dc: String }`
    - **Multi-Tool Command Logic**:
        1. `rpcclient -U <admin>%<pass> <dc> -c "addmember <group> <username>"` (Core RPC Membership)
        2. `ldapmodify -x -H ldap://<dc> -D <dn> -w <pass> -f group.ldif` (LDAP Membership Gen)
        3. `net ads group addmem <group> <username> -S <dc>` (Samba Native Membership)
        4. `crackmapexec smb <dc> -u <admin> -p <pass> --groups` (Group Permission Audit)
        5. `ldapsearch -H ldap://<dc> -x "(cn=<group>)" member` (Membership Audit)
    - **Execution Flow**: Core RPC -> LDAP Gen -> Samba Native -> Permission Audit -> Membership Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ADD_[Timestamp]_membership_audit.json`: Verification of the user's new group membership and permissions.
        - `reports/artifacts/ADD_[Timestamp]_group.ldif`: Generated LDIF file used for the group membership modification.
        - `reports/analysis/ADD_[Timestamp]_permission_stats.json`: CrackMapExec group permission audit results.

- **`LIST`** (Short Name: `LIST`)
    - **Purpose**: Enumerate group memberships to identify high-value targets and nested permissions.
    - **Input Schema**: `{ group: String, dc: String }`
    - **Multi-Tool Command Logic**:
        1. `ldapsearch -x -H ldap://<dc> "(cn=<group>)" member` (Core Membership List)
        2. `rpcclient -U "" <dc> -c "enumdomgroups"` (Group Inventory)
        3. `net ads group -S <dc> -U <admin>%<pass>` (Samba Group Audit)
        4. `crackmapexec smb <dc> -u <admin> -p <pass> --groups` (Automated Enumeration)
        5. `ldapmodify --help` (Binary Check)
    - **Execution Flow**: Core List -> Group Inventory -> Samba Audit -> Automated Enum -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/LIST_[Timestamp]_group_members.json`: Comprehensive list of group members and nested accounts.
        - `reports/artifacts/LIST_[Timestamp]_inventory_audit.txt`: Inventory of domain groups discovered via RPC.
        - `reports/analysis/LIST_[Timestamp]_binary_status.json`: Verification of ldapsearch and rpcclient binary status.

---

### 3. GPO Modification Tool
**ID:** `ad-gpo-modify` | **Risk:** CRITICAL | **File:** `GPOModifyModule.java`
**Tools:** `ldapmodify`, `smbclient`, `rpcclient`, `ldapsearch`, `crackmapexec`

#### Execution Modes:

- **`MOD`** (Short Name: `MOD`)
    - **Purpose**: Modify Group Policy Objects to enforce security policies or maintain persistence.
    - **Input Schema**: `{ gpo_dn: String, attr: String, value: String, dc: String }`
    - **Multi-Tool Command Logic**:
        1. `ldapmodify -x -H ldap://<dc> -D <dn> -w <pass> -f gpo.ldif` (Core LDAP Modification)
        2. `smbclient //<dc>/SYSVOL -c "put gpt.ini"` (SYSVOL Template Update)
        3. `rpcclient -U <admin>%<pass> <dc> -c "getusername"` (Session Audit)
        4. `crackmapexec smb <dc> -u <admin> -p <pass> --gpo` (GPO State Audit)
        5. `ldapsearch -H ldap://<dc> -x "(distinguishedName=<gpo_dn>)"` (Post-Mod Audit)
    - **Execution Flow**: Core LDAP -> SYSVOL Update -> Session Audit -> GPO State -> Post-Mod Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/MOD_[Timestamp]_gpo_audit.json`: Detailed report on the GPO modification and SYSVOL update.
        - `reports/artifacts/MOD_[Timestamp]_gpt.ini`: Modified GPT.INI file uploaded to the DC's SYSVOL share.
        - `reports/analysis/MOD_[Timestamp]_gpo_state.json`: CrackMapExec GPO state and security audit results.

- **`LIST`** (Short Name: `LIST`)
    - **Purpose**: Enumerate all GPOs and their associated containers in the domain.
    - **Input Schema**: `{ dc: String }`
    - **Multi-Tool Command Logic**:
        1. `ldapsearch -x -H ldap://<dc> "(objectClass=groupPolicyContainer)"` (Core GPO List)
        2. `smbclient //<dc>/SYSVOL -c "ls"` (SYSVOL Structure Audit)
        3. `crackmapexec smb <dc> -u <admin> -p <pass> --gpo` (Automated GPO Discovery)
        4. `rpcclient -U "" <dc> -c "dsenum"` (DS Enumeration)
        5. `ldapmodify -V` (Binary Check)
    - **Execution Flow**: Core List -> SYSVOL Audit -> Automated Discovery -> DS Enum -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/LIST_[Timestamp]_gpo_inventory.json`: Catalog of all identified GPOs and their associated containers.
        - `reports/artifacts/LIST_[Timestamp]_sysvol_structure.txt`: Recursive listing of the SYSVOL directory structure.
        - `reports/analysis/LIST_[Timestamp]_ds_enum.xml`: Results of the Active Directory DS enumeration.

---

### 4. SPN Management Tool
**ID:** `ad-spn-add` | **Risk:** HIGH | **File:** `SPNAddModule.java`
**Tools:** `ldapmodify`, `rpcclient`, `ldapsearch`, `crackmapexec`, `net`

#### Execution Modes:

- **`ADD`** (Short Name: `ADD`)
    - **Purpose**: Register Service Principal Names to facilitate Kerberoasting or service masquerading.
    - **Input Schema**: `{ target: String, spn: String, dc: String }`
    - **Multi-Tool Command Logic**:
        1. `ldapmodify -x -H ldap://<dc> -D <dn> -w <pass> -f spn.ldif` (Core LDAP SPN Gen)
        2. `rpcclient -U <admin>%<pass> <dc> -c "setspn <target> <spn>"` (RPC SPN Mapping)
        3. `net ads spn add <spn> <target> -S <dc>` (Samba Native SPN)
        4. `crackmapexec smb <dc> -u <admin> -p <pass> --users` (Target Audit)
        5. `ldapsearch -H ldap://<dc> -x "(servicePrincipalName=<spn>)"` (SPN Audit)
    - **Execution Flow**: Core LDAP -> RPC Mapping -> Samba Native -> Target Audit -> SPN Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ADD_[Timestamp]_spn_audit.json`: Verification of the new SPN registration and mapping.
        - `reports/artifacts/ADD_[Timestamp]_spn.ldif`: Generated LDIF file used for the SPN attribute modification.
        - `reports/analysis/ADD_[Timestamp]_target_profile.json`: Technical profile of the target account for SPN registration.

- **`QUER`** (Short Name: `QUER`)
    - **Purpose**: Identify existing SPNs to discover high-value service accounts and potential attack vectors.
    - **Input Schema**: `{ target: String, dc: String }`
    - **Multi-Tool Command Logic**:
        1. `ldapsearch -x -H ldap://<dc> "(sAMAccountName=<target>)" servicePrincipalName` (Core SPN Query)
        2. `rpcclient -U "" <dc> -c "getusername"` (Session Check)
        3. `net ads spn list <target> -S <dc>` (Samba SPN List)
        4. `crackmapexec smb <dc> -u <admin> -p <pass> --kerberoasting` (Automated SPN Audit)
        5. `ldapmodify --version` (Binary Check)
    - **Execution Flow**: Core Query -> Session Check -> Samba List -> Automated Audit -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/QUERY_[Timestamp]_spn_results.json`: Inventory of identified SPNs and potential Kerberoasting targets.
        - `reports/artifacts/QUERY_[Timestamp]_samba_spns.txt`: List of SPNs enumerated via the Samba native interface.
        - `reports/analysis/QUERY_[Timestamp]_kerberoast_audit.json`: CrackMapExec automated SPN and Kerberoasting audit.

---

### 5. Kerberos TGT Resetter
**ID:** `ad-krbtgt-reset` | **Risk:** CRITICAL | **File:** `KerbTGTResetModule.java`
**Tools:** `ldapmodify`, `rpcclient`, `ldapsearch`, `crackmapexec`, `impacket`

#### Execution Modes:

- **`RSET`** (Short Name: `RSET`)
    - **Purpose**: Force a KRBTGT password reset to invalidate all existing Kerberos tickets across the domain.
    - **Input Schema**: `{ dc: String, admin: String, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `rpcclient -U <admin>%<pass> <dc> -c "setuserinfo2 krbtgt 23 <pass>"` (Core RPC Reset)
        2. `impacket-secretsdump -ntds ntds.dit LOCAL` (Offline NTDS Audit)
        3. `crackmapexec smb <dc> -u <admin> -p <pass> --lsass` (LSASS Flush Audit)
        4. `ldapmodify -x -H ldap://<dc> -D <dn> -w <pass> -f reset.ldif` (LDAP Property Update)
        5. `ldapsearch -H ldap://<dc> -x "(sAMAccountName=krbtgt)" pwdLastSet` (Validation)
    - **Execution Flow**: Core RPC Reset -> NTDS Audit -> LSASS Flush -> LDAP Property -> Validation.
    - **Output Generation & Artifacts**:
        - `reports/outputs/RESET_[Timestamp]_krbtgt_audit.json`: Verification of the KRBTGT password reset and ticket invalidation.
        - `reports/artifacts/RESET_[Timestamp]_ntds_hashes.txt`: Extracted hashes from the NTDS audit for verification.
        - `reports/analysis/RESET_[Timestamp]_lsass_telemetry.json`: Log of the LSASS flush audit for ticket clearing.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify the current state and password history of the KRBTGT account.
    - **Input Schema**: `{ dc: String }`
    - **Multi-Tool Command Logic**:
        1. `ldapsearch -x -H ldap://<dc> "(sAMAccountName=krbtgt)"` (Core Account Audit)
        2. `rpcclient -U "" <dc> -c "queryuser krbtgt"` (RPC User Audit)
        3. `crackmapexec smb <dc> -u <admin> -p <pass> --pass-pol` (Policy Audit)
        4. `impacket-secretsdump --version` (Binary Check)
        5. `ldapmodify -V` (Binary Check)
    - **Execution Flow**: Core Account Audit -> RPC User Audit -> Policy Audit -> Binary Check x2.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_krbtgt_history.json`: Detailed report on the KRBTGT account state and password history.
        - `reports/artifacts/AUDIT_[Timestamp]_policy_disclosure.txt`: Captured domain password policy and KRBTGT settings.
        - `reports/analysis/AUDIT_[Timestamp]_tool_readiness.json`: Verification of impacket-secretsdump and ldapmodify status.

---

### 6. DSRM Password Syncer
**ID:** `ad-dsrm-sync` | **Risk:** HIGH | **File:** `DSRMSyncModule.java`
**Tools:** `ldapmodify`, `rpcclient`, `reg`, `ldapsearch`, `crackmapexec`

#### Execution Modes:

- **`SYNC`** (Short Name: `SYNC`)
    - **Purpose**: Synchronize the Directory Services Restore Mode (DSRM) password with a domain account for persistence.
    - **Input Schema**: `{ user: String, dc: String }`
    - **Multi-Tool Command Logic**:
        1. `net rpc dsrm passsync -U <admin>%<pass> -S <dc>` (Core Samba Sync)
        2. `reg add HKLM\System\CurrentControlSet\Control\Lsa /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f` (Registry Bypass)
        3. `rpcclient -U <admin>%<pass> <dc> -c "getusername"` (Session Audit)
        4. `crackmapexec smb <dc> -u <admin> -p <pass> --lsa` (LSA Secret Audit)
        5. `ldapsearch -H ldap://<dc> -x "(sAMAccountName=<user>)"` (Account Audit)
    - **Execution Flow**: Core Sync -> Registry Bypass -> Session Audit -> LSA Audit -> Account Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SYNC_[Timestamp]_dsrm_audit.json`: Verification of the DSRM password synchronization and bypass.
        - `reports/artifacts/SYNC_[Timestamp]_lsa_secrets.txt`: Captured LSA secrets related to the DSRM configuration.
        - `reports/analysis/SYNC_[Timestamp]_registry_bypass.reg`: Export of the registry keys modified for DSRM logon behavior.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify DSRM logon behavior and registry configurations.
    - **Input Schema**: `{ dc: String }`
    - **Multi-Tool Command Logic**:
        1. `reg query HKLM\System\CurrentControlSet\Control\Lsa /v DsrmAdminLogonBehavior` (Core Registry Audit)
        2. `rpcclient -U "" <dc> -c "dsenum"` (DS Enumeration)
        3. `crackmapexec smb <dc> -u <admin> -p <pass> --shares` (Access Audit)
        4. `ldapsearch -V` (Binary Check)
        5. `ldapmodify --version` (Binary Check)
    - **Execution Flow**: Core Registry Audit -> DS Enum -> Access Audit -> Binary Check x2.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_dsrm_status.json`: Comprehensive report on DSRM logon behavior and registry state.
        - `reports/artifacts/AUDIT_[Timestamp]_access_verification.txt`: Log of filesystem and share access audits for DSRM.
        - `reports/analysis/AUDIT_[Timestamp]_binary_status.json`: Verification of ldapsearch and rpcclient readiness.

---
