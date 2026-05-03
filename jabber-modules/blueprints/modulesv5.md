# JABBER Modules V5.5 Blueprint: Universal Upgrade Guide

This document serves as the authoritative implementation plan for upgrading the remaining modules in the JABBER from a demo/dummy state to full-fidelity, live execution status.

## 1. Objective
The goal is to transition all modules across all 20 categories (`/home/bane/jabber/jabber-modules/src/main/java/com/jabber/jabber/modules/`) to use real external security tools. Modules must be orchestrated dynamically via Java's `ProcessBuilder`, entirely eliminating any reliance on placeholder data or simulated outputs.

## 2. Directory & Package Reorganization
Every module should be isolated into its own sub-package within its category to maintain cleanliness and separation of concerns.
**Pattern:** `com.jabber.jabber.modules.<category>.<module_slug>`

## 3. Per-Module Infrastructure Isolation (CRITICAL)
To ensure that each module only displays and manages its relevant tools in the UI, and to maintain strict modularity, each module sub-package MUST contain its own copy of the following infrastructure files:

1.  **`[ModuleName]Module.java`**: Controller defining dynamic input schemas and metadata.
2.  **`[ModuleName]Engine.java`**: Core orchestrator implementing the 8-step execution loop.
3.  **`ToolManager.java`**: Registry for the 5+ required tools. Handles tool status checks, versioning, and automatic dependency installation via OS-specific package managers (apt, pip, github_release).
4.  **`InputSanitizer.java`**: Mode-aware validation logic that ensures all inputs (IPs, domains, file paths) are sanitized and conform to security best practices before process execution.
5.  **`ProcessExecutor.java`**: A thread-safe, low-level process runner that manages `ProcessBuilder` lifecycles, real-time stdout/stderr streaming, and timeout enforcement.
6.  **`CommandRecord.java`**: A structured data container that captures full telemetry for every command executed (CLI strings, exit codes, durations, and output previews) for the final report.
7.  **`ReportGenerator.java`**: The findings aggregator that transforms raw tool output and `CommandRecord` data into high-fidelity, structured reports in JSON, Markdown, and HTML formats. It is strictly responsible for capturing, organizing, and physically saving all generated outputs (files, payloads, artifacts) into the reporting structure.

**Why?** This prevents the "category-wide tool bleed" where the UI shows unrelated tools. Each module should feel like an independent, self-contained unit.

## 4. Real-World Execution Standards (NEW)
To ensure high fidelity and production-grade reliability, all modules must adhere to the following standards:

### A. Strict Input Validation
Modules must use `InputSanitizer` to validate all user inputs (URLs, hostnames, IPs, port specs) before starting any execution. Any invalid input must result in an immediate validation failure in the `ModuleResult`.

### B. Target Intelligence & Asset Fusion (MANDATORY - SOPHISTICATED)
Every module MUST perform a deep "Target Intelligence" phase using the **Sophisticated Discovery Toolkit**. "Mere" tools like `dig` and `whois` are fallbacks; production-grade modules MUST use advanced orchestrators:

- **DNS & Record Classification (via `dnsx`)**:
    - **Full Spectrum**: Resolve `A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, `TXT`, and `SRV` records in a single pass.
    - **Classification**: Identify the Authoritative Name Servers and DNS providers (e.g., Cloudflare, Route53).
    - **Validation**: Use `dnsx -resp` to get the actual server IPs and valid response codes.
- **Domain/Subdomain Mapping (via `subfinder` / `passive discovery`)**:
    - Identify subdomains and related domains to build a full asset map.
- **Infrastructure Fingerprinting (via `httpx`)**:
    - Identify the server type (Nginx, Apache, IIS), Title, and Content-Length to classify the asset (e.g., "Login Portal", "API Endpoint", "Static Storage").
- **Ownership & Routing (via `whois`)**:
    - Extract Organization, ASN, NetRange, and CIDR.
- **Asset Fusion logic**:
    - **If IP**: Find ALL hostnames sharing that IP (Reverse Mapping).
    - **If Domain**: Find ALL IPs associated (Multi-homed resolution).
- **Report Persistence**: This data MUST be stored in `ModuleResult` and rendered as high-fidelity "Infrastructure Asset" findings.

### E. Execution Mode System (THE SURGICAL DOCTRINE)
Every module MUST implement a functional "Execution Mode System" where modes are first-class execution units.
- **Naming**: Mode names MUST be short, descriptive, and exactly four (4) characters (e.g., `SRVY`, `DEEP`, `STLH`, `FSN`).
- **Minimum Modes**: Every module MUST define at least two (2) distinct execution modes.
- **Surgical Tool-Selection (MANDATORY)**: Once an execution mode is selected, the UI MUST render a tool selection table.
    - The user MUST explicitly select tools using toggle buttons.
    - **NO DEFAULT TOOLS**: If no tools are selected, the module MUST fail immediately with the error: `[Must select a tool for execution]`.
    - **NO DUMMY EXECUTION**: If a tool is not selected, it MUST NOT execute, even if it is part of the mode's standard pipeline.
    - **Execution Logic**: If one tool is selected, only its command logic runs. If multiple tools are selected, only those tools' commands run sequentially. If all are selected, the full multi-tool pipeline executes.
- **Multi-Tool Orchestration**: Every execution mode MUST define a full pipeline that orchestrates and executes **ALL tools** defined within that module (minimum five tools).
- **Command Pipelines**: Every mode MUST design a full pipeline that executes **at least five (5) commands**. The `Engine` must dynamically filter this pipeline based on the `selectedTools` payload.
- **Logic Mapping**: The `Engine` must branch its execution logic based on the `ModuleMode` AND the explicitly `selectedTools` to build the correct command sequences.

### F. Standardized Infrastructure
To ensure strict separation of concerns and portability, every module sub-package MUST contain:
1.  **`[ModuleName]Module.java`**: Controller defining dynamic input schemas and metadata.
2.  **`[ModuleName]Engine.java`**: Core orchestrator implementing the 8-step execution loop.
3.  **`ToolManager.java`**: Self-contained registry of the module's tools (minimum 5 tools).
4.  **`InputSanitizer.java`**: Mode-aware validation logic.
5.  **`ProcessExecutor.java`**: High-level utility for running `ProcessBuilder` commands safely.
6.  **`CommandRecord.java`**: DTO for capturing command telemetry (CLI, exit code, stdout, stderr, duration).
7.  **`ReportGenerator.java`**: Transforms `CommandRecord`s and raw data into structured findings (JSON/HTML/MD).

### G. The "No Generalization" Rule
Blueprint files MUST NOT use "Remaining Modules" tables. Every module MUST be fully documented with its ID, tools, modes, and command logic. 

### H. Multi-Environment & Architecture Support
Tooling and command construction must be aware of the environment:
- **Environments**: Native Linux, Android (Termux), Android (chroot).
- **Architectures**: `amd64`, `arm64`, `armv7`.
- **Logic**: Use `ToolPlatform` detection to select the correct binary or command flags (e.g., `masscan` is often unavailable on pure Android/Termux).

### I. 8-Step Execution Doctrine (MANDATORY)
Every module MUST implement the following 8-step execution loop in its `[ModuleName]Engine.java`:

1.  **Validate Mode**: Verify that the selected `ModuleMode` is supported and available.
2.  **Sanitize Schema**: Validate and sanitize all user-provided inputs against the mode-specific schema using `InputSanitizer`.
3.  **Target Intelligence**: Perform mandatory infrastructure discovery (DNS resolution, WHOIS lookup, server fingerprinting via `dnsx`, `subfinder`, `httpx`).
4.  **Tool Readiness & Verification**: Resolve binary paths via `ToolManager` AND verify the specific tools explicitly selected by the user for this execution.
5.  **Dynamic Command Orchestration**: Build the exact command strings and arguments ONLY for the external tools that were explicitly selected by the user via the frontend toggles.
6.  **Real-Time Streaming**: Execute selected tools sequentially via `ProcessExecutor` and stream live stdout/stderr logs to the `TaskContext` for UI visibility.
7.  **Findings Extraction**: Parse raw tool output using `ReportGenerator` to identify and extract high-fidelity security findings.
8.  **Full Telemetry**: Aggregate all `CommandRecord` data into the final `ModuleResult` for complete auditability.

### J. Artifact & Output Generation Standard (MANDATORY)

Every module that generates physical data (files, binaries, handshakes, capture files, etc.) MUST adhere to the following output lifecycle:

1.  **Physical Generation**: All outputs must be real, functional files produced by tools. Simulated or placeholder content is strictly forbidden.
2.  **Classification & Storage**: Outputs must be classified into one of the following directories within the module's execution workspace:
    - `reports/artifacts/`: General forensic data, screenshots, handshakes (e.g., `.cap`, `.pcap`, `.hccapx`).
    - `reports/payloads/`: Generated binaries, scripts, or weaponized files (e.g., `.exe`, `.elf`, `.msi`, `.ps1`).
    - `reports/outputs/`: Structured data exports (e.g., `.csv`, `.json`, `.xml`, `.txt`).
    - `reports/analysis/`: Technical fingerprints or environment dumps (e.g., `.xml`, `.html`).
3.  **Naming Convention**: Files must be named using the pattern: `[Mode]_[Timestamp]_[OriginalName].[Ext]` (e.g., `GEN_1714442400_beacon.exe`).
4.  **Multi-Format Profiling**:
    - The profiling engine MUST generate outputs in **five concurrent formats**: HTML (Primary/Detailed), JSON, Markdown, TXT, and RAW.
    - HTML is the default and most detailed representation for the user.
5.  **Reporting Integration**:
    - The `ReportGenerator` must detect all files in these directories.
    - Each file must be hashed (SHA256) and linked in the final report.
    - Reports must provide a "Download" or "View" reference for every artifact.
6.  **Preservation**: Original tool outputs must be preserved exactly as generated. No modification or "prettification" that could alter forensic integrity is allowed.

### K. Anti-Pollution & Reporting Excellence (MANDATORY - V 5.5)

To maintain the premium, high-fidelity aesthetic of JABBER, all modules MUST adhere to the Anti-Pollution Doctrine to eliminate visual "junk" and raw JSON blocks in reports:

1.  **Summary Hygiene**: The `ModuleResult.output` map MUST only contain high-level metrics and executive summaries (e.g., `findings_count`, `elapsed_ms`, `target_identity`). 
2.  **Telemetry Isolation**: Technical telemetry (CLI strings, exit codes, durations, raw command output previews) MUST NOT be stored in the main finding objects. These findings must be flat and audit-ready.
3.  **Recursive Table Structure**: All findings (especially OSINT profiles and breach data) MUST be structured as a `List<Map<String, Object>>`. The JABBER Report Engine is optimized to recursively render these into professional, nested HTML tables.
4.  **Dossier Overrides**: For complex modules, the `ReportGenerator` MUST produce a pre-rendered HTML dossier and store it in `parsed_output.html_report`. This dossier will serve as the primary visual interface for the operation.
5.  **Target Metadata Integrity**: Engines MUST explicitly set the `target` field on the `ModuleResult`. Reports showing "Target: unknown" are considered failures.

### L. Failure State Doctrine (MANDATORY)

Engines MUST return explicit, bracketed error tags to facilitate consistent frontend feedback and prevent UI hang-ups:

1.  **Tool Selection Failure**: If `selectedTools` is empty, return `[Must select a tool for execution]`.
2.  **Input Validation Failure**: If mandatory inputs (e.g., domain, IP, CIDR) are missing, return `[Input required for execution]`.
3.  **Critical Failures**: Use `[FATAL]` for unrecoverable engine errors.

### L. Tool Installation Standards (Kali/Debian Compatibility)

To ensure "seamless" execution on security-focused distributions (Kali Linux, Debian 12+) where Python environments are externally managed (PEP 668):

1.  **PIP Breakout**: All `ToolManager` implementations involving Python tools MUST append the `--break-system-packages` flag to their `pip install` commands.
2.  **OS-Aware Installers**: Install commands should prioritize `apt` for system utilities and `pip --break-system-packages` for Python-based offensive tools.

---

## 6. Elevated Privilege Workflow (Sudo Support) (NEW)

Certain high-fidelity tools (e.g., `masscan`, `arp-scan`, `bettercap`) require root or elevated privileges to interact with raw sockets and network interfaces. Every module must handle this gracefully.

### A. Sudo Password Prompting
- **Identification**: Modules must identify tools that require elevated privileges in their `ToolManager`.
- **UI Interaction**: When a user clicks "Execute Module," the frontend must check if any selected tools require `sudo`. If so, it must display a secure **Sudo Password Modal**.
- **Persistence**: The password should be stored in the frontend's `localStorage` (session-based) to avoid repeated prompts.
- **Backend Transmission**: The `sudoPassword` must be passed as an optional field in the `executeModule` API payload.

### B. Execution Logic
- **ProcessExecutor Integration**: The `ProcessExecutor` must support wrapping commands with `sudo -S`.
- **Command Construction**: `echo "[password]" | sudo -S [command]`.
- **Security**: Passwords must never be logged in `CommandRecord` or `TaskContext`. The `ProcessExecutor` must proactively scrub the password from any telemetry.

---

## 5. Universal JABBER v5 Module Upgrade Prompt

Use this prompt when implementing or upgrading any module to the V5 standard. It enforces all architectural and execution requirements.

```markdown
Role: Senior Security Automation Architect
Task: Upgrade/Implement [ModuleName] to JABBER V5 Standard

Context:
The JABBER (JABBER) V5 architecture mandates high-fidelity, tool-based execution, strict infrastructure isolation, and an 8-step execution doctrine.

Requirements:
1. Infrastructure Isolation: Create a self-contained package (com.jabber.jabber.modules.<category>.<slug>) containing [ModuleName]Module.java, [ModuleName]Engine.java, ToolManager.java, InputSanitizer.java, ProcessExecutor.java, CommandRecord.java, and ReportGenerator.java.
2. Execution Modes: Define at least two (2) distinct ModuleModes (e.g., QUICK, DEEP). Each mode MUST orchestrate at least five (5) tools/commands.
3. 8-Step Doctrine: Implement the engine loop: Validate Mode -> Sanitize Schema -> Target Intelligence (DNS/Whois) -> Tool Readiness -> Command Orchestration -> Real-Time Streaming -> Findings Extraction -> Full Telemetry.
4. Artifact Standards: Automatically save all outputs to reports/artifacts/, reports/payloads/, reports/outputs/, or reports/analysis/ using the [Mode]_[Timestamp]_[Name].[Ext] pattern with SHA256 hashing.
5. Profiling: Generate profiles in HTML (primary), JSON, MD, TXT, and RAW formats.
6. Frontend: Reference the Execution Mode Toggle and the Artifact Gallery in the module's documentation.

No placeholders. No simulated data. Real tools only.
```
