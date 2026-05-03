<!-- 
# THE UNIVERSAL JABBER v5 MODULE UPGRADE PROMPT (ELITE ARCHITECT EDITION)

You are an elite Senior Security Automation Architect and Lead Offensive Engineer. Your mission is to perform a surgical, production-grade refactor of the JABBER module provided below. You must transform it from a legacy "dummy/generic" state into a high-fidelity, isolated execution engine that uses real-world security tools and adheres to the **JABBER v5 Multi-Tool Doctrine with Dynamic Tool-Selection Layer**.

## THE CORE MISSION
Eliminate all simulated data. Enforce absolute package isolation. Every execution mode MUST be a powerful multi-tool orchestrator, and its execution must dynamically adapt to the user's specific tool selections from the frontend. Think like a hacker: a single tool is a probe; a multi-tool pipeline is an operation.

## MANDATORY ARCHITECTURAL REQUIREMENTS

### 1. Package Isolation & Infrastructure Duplicate
- **Sub-package**: `com.jabber.jabber.modules.<category>.<module_slug>`.
- **Self-Contained Infrastructure**: Every module MUST have its own local copy:
    - `[ModuleName]Module.java`: Controller & Metadata (Input Schemas).
    - `[ModuleName]Engine.java`: Orchestrator (The Execution Brain).
    - `ToolManager.java`: Dependency Registry (Minimum 5 tools, Tailored to this module). MUST expose endpoints to return the tool list for the active mode.
    - `InputSanitizer.java`: Security validation.
    - `ProcessExecutor.java`: Low-level thread-safe executor.
    - `CommandRecord.java`: DTO for execution telemetry.
    - `ReportGenerator.java`: Profiling and artifact export logic.

### 2. The 8-Step Execution Doctrine (MANDATORY)
In the `[ModuleName]Engine.java`, you MUST implement the following loop:
1. **Validate Mode**: Verify the selected `ModuleMode`.
2. **Sanitize Schema**: Validate user inputs via `InputSanitizer`.
3. **Target Intelligence (SOPHISTICATED)**: Perform mandatory infrastructure discovery (dnsx, subfinder, httpx, whois).
4. **Tool Readiness & Selection Verification**: Resolve binary paths via `ToolManager` AND verify which tools the user has explicitly selected for execution in this run.
5. **Dynamic Command Pipeline Orchestration**: Build the command sequence *dynamically*. **CRITICAL**: The execution behavior must directly reflect the frontend tool selection. 
    - If one tool is selected, only its command logic runs.
    - If multiple tools are selected, only those tools’ commands run sequentially (or as defined).
    - If all are selected, the full 5+ multi-tool pipeline executes.
6. **Real-Time Streaming**: Execute via `ProcessExecutor` and stream logs.
7. **Findings Extraction & Aggregation**: Parse and aggregate outputs from ALL executed tools into a normalized result set via `ReportGenerator`.
8. **Intelligence-Grade Reporting**: Export structured findings and telemetry. **CRITICAL**: The `ModuleResult` must be optimized for the JABBER Report Engine. High-fidelity dossiers MUST be pre-rendered in `parsed_output.html_report` to override generic layouts.

### 3. Execution Mode System
- **Min 2-3 Modes**: Each with a clear offensive purpose.
- **Short Names**: < 10 chars.
- **Mode-Specific Schemas**: Dynamic input fields per mode.
- **Multi-Tool Command Logic**: Documentation must define the full multi-tool flow and input-to-command mapping.

### 4. High-Fidelity & Error Handling
- **No Phantom Findings**: Results must be verified by real data.
- **Resilient Execution**: Failure of one tool does not stop the pipeline. Deeply explain failures in reports.
- **Selective Consumption**: Commands only use the inputs they need.
- **Cross-Platform**: Support Linux, Android (Termux/chroot) across amd64, arm64, armv7.

### 5. Anti-Pollution Doctrine (Reporting)
- **No Raw JSON Pollution**: The "Processing Results" section of the report MUST remain a clean executive summary. 
- **Mandatory Key Filtering**: The `ModuleResult.output` map should only contain high-level metrics. Technical blobs (like raw tool outputs or duplicate findings lists) MUST be excluded or stored in `parsed_output` to prevent visual junk in the final dossier.
- **Recursive Table Support**: All intelligence findings (e.g., account lists, emails, profile maps) must be structured as `List<Map<String, Object>>` to allow the Report Engine to render professional nested tables.

## UI / FRONTEND MODIFICATION REQUIREMENTS (CRITICAL)
As the architect, you must also upgrade the frontend components to support the **Dynamic Tool-Selection Layer**:
1. **`ModuleExecutor.jsx` (and related components)**:
    - **Before rendering input fields**, you must introduce a horizontal tool-selection interface (e.g., a table or a grid of toggle buttons).
    - Fetch the available tools for the active mode from the backend (`ToolManager` exposed endpoint).
    - Display each tool with a toggle and a short name.
    - The user MUST be able to select one, multiple, or all tools.
    - The `executeModule` API call must be updated to pass the `selectedTools` array along with the `formData` and `mode`.
2. **Artifact Gallery Integration**: Ensure the UI prominently features links to the centralized **Artifacts (Category 21)** system to view outputs (JSON/HTML/Raw) and payloads.
3. **`api.js`**: Update API routes to include the new tool selection payloads.

## EXECUTION WORKFLOW
1. **Analyze Category Blueprint**: Study `blueprints/<category>.md` for tool requirements and mode logic.
2. **Scaffold Infrastructure**: Create the 7 core Java classes.
3. **Update Frontend UI**: Implement the horizontal tool-selection table in `ModuleExecutor.jsx` for dynamic control.
4. **Design Pipelines**: Map the mode's objective to a 5+ command orchestration.
5. **Implement Dynamic Engine Brain**: Build the `switch(mode)` logic and `ProcessBuilder` sequences that adapt dynamically based on `selectedTools`.
6. **Standardize Reporting**: Aggregating normalized results from all selected tools.
7. **Verify Build**: `JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 ./gradlew clean compileJava -x test`.

---
**MODULE TO UPGRADE**: [INSERT MODULE NAME/PATH HERE]
MODULE CATEGORY BLUEPRINT: [INSERT RELEVANT BLUEPRINT SECTION HERE]
MODULES ADDITIONAL REF: modulesv5.md
-->

## ARTIFACTS CATEGORY UPGRADE PROMPT

You are an elite Senior Security Automation Architect. Refactor the Artifacts system to enforce absolute naming, hashing, and integration with every module. Ensure that all generated files are automatically saved to the correct directories, and that the UI provides direct links and integrity badges.

### Requirements
1. **Universal Naming**: `[Mode]_[Timestamp]_[OriginalName].[Ext]` enforced in all modules.
2. **SHA256 Integrity**: Every artifact must be hashed and the hash displayed in the UI.
3. **Centralized Indexing**: `ReportGenerator` must register each artifact in the Artifacts catalog.
4. **Frontend Gallery**: Update the Artifacts Gallery to show preview, download, and integrity badge for each file.
5. **Tool Registry Sync**: `ToolManager` must expose artifact-related tools and ensure they are installed.

## PHONE ENUMERATION CATEGORY UPGRADE PROMPT

You are an elite Senior Security Automation Architect. Enhance the Phone Enumeration blueprint to provide deep, high-fidelity mobile forensics while maintaining the unified execution doctrine.

### Requirements
1. **Single Exhaustive Flow**: Preserve the no‑mode design but add explicit steps for device credential extraction, app data dumping, and secure storage.
2. **Artifact Capture**: All extracted databases, binaries, and screenshots must be saved in `reports/artifacts/` with proper naming and SHA256 hashing.
3. **Dynamic Tool Checks**: `ToolManager` must verify availability of `adb`, `frida`, `objection`, `drozer`, `ideviceinfo` before execution.
4. **Frontend Enhancements**: Add a device selector UI, live log streaming, and direct links to the Artifacts Gallery for each extracted file.
5. **Error Resilience**: Failure of any single tool must not abort the entire enumeration; partial results are still saved and reported.
