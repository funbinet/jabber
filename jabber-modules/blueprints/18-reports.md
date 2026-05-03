# Reporting — Category Blueprint

**Category:** `REPORTING` | **Slug:** `reports` | **Tools Dir:** `~/jabber/jabber-tools/reports/`
**Package:** `com.jabber.jabber.modules.reporting` | **Group:** Data & Utilities

---

## ToolManager: `reports/ToolManager.java`

| ID | Binary | Source | Version Check | Install Method |
|----|--------|--------|---------------|----------------|
| `wkhtmltopdf` | `wkhtmltopdf` | apt/github | `wkhtmltopdf --version` | `apt_install` |
| `pandoc` | `pandoc` | apt/github | `pandoc --version` | `apt_install` |
| `jq` | `jq` | apt | `jq --version` | `apt_install` |
| `python3` | `python3` | system | `python3 --version` | system |
| `xmllint` | `xmllint` | apt (libxml2-utils) | `xmllint --version` | `apt_install` |

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

Every module in the **Reporting** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between operations.
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for downloading results and logs.
4. **Live Terminal Stream**: A real-time stdout/stderr streaming component for operational transparency.
5. **Interactive Dashboard**: Real-time display of extracted data, payloads, or process progress.

---

---

## Modules

### 1. Assessment Report Manager
**ID:** `report-manager` | **Risk:** LOW | **File:** `ReportsModule.java`
**Tools:** `jq`, `pandoc`, `wkhtmltopdf`, `python3`, `find`

#### Execution Modes:

- **`LIST`** (Short Name: `LIST`)
    - **Purpose**: Perform a deep inventory and structural audit of all generated JABBER assessment reports.
    - **Input Schema**: `{ path: String }`
    - **Multi-Tool Command Logic**:
        1. `find <path> -maxdepth 3 -name "*.json" -o -name "*.md" -o -name "*.html"` (Core Discovery)
        2. `jq -r '.metadata.id' *.json` (ID Inventory)
        3. `python3 stats.py <path>` (Volume Analysis)
        4. `pandoc --version` (Binary Check)
        5. `wkhtmltopdf --version` (Binary Check)
    - **Execution Flow**: Core Discovery -> ID Inventory -> Volume Analysis -> Binary Check x2.
    - **Output Generation & Artifacts**:
        - `reports/outputs/LIST_[Timestamp]_report_inventory.json`: Comprehensive catalog of all identified assessment reports.
        - `reports/artifacts/LIST_[Timestamp]_volume_analysis.json`: Statistical analysis of the volume and types of findings.
        - `reports/analysis/LIST_[Timestamp]_discovery_log.txt`: Technical log of the report discovery process.

- **`MRGE`** (Short Name: `MRGE`)
    - **Purpose**: Aggregation of heterogeneous module results into a unified master security assessment report.
    - **Input Schema**: `{ reports: List<Path> }`
    - **Multi-Tool Command Logic**:
        1. `jq -s '.[0].findings += (.[1:] | map(.findings) | flatten) | .[0]' <reports>` (Core JSON Merge)
        2. `python3 merge_metadata.py <reports>` (Metadata Normalization)
        3. `pandoc -s merged.json -o master_report.md` (Format Conversion)
        4. `wkhtmltopdf master_report.html master.pdf` (PDF Archiving)
        5. `find . -name "merged.json"` (Final Presence Audit)
    - **Execution Flow**: Core Merge -> Normalization -> Conversion -> Archiving -> Presence Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/MERGE_[Timestamp]_master_report.pdf`: Unified master security assessment report in PDF format.
        - `reports/artifacts/MERGE_[Timestamp]_merged.json`: Aggregated JSON dataset containing all module findings.
        - `reports/analysis/MERGE_[Timestamp]_metadata_normalization.json`: Audit of metadata normalization across merged reports.

---

### 2. JSON Report Exporter
**ID:** `report-json` | **Risk:** LOW | **File:** `JSONExportModule.java`
**Tools:** `jq`, `python3`, `diff`, `sed`, `grep`

#### Execution Modes:

- **`FRMT`** (Short Name: `FRMT`)
    - **Purpose**: Pretty-print, lint, and structurally validate machine-readable JSON reports.
    - **Input Schema**: `{ input: Path }`
    - **Multi-Tool Command Logic**:
        1. `jq '.' <input>` (Core Prettify)
        2. `python3 -m json.tool <input>` (Alternative Lint)
        3. `sed -i 's/\t/    /g' <input>` (Whitespace Normalization)
        4. `grep -c "finding" <input>` (Integrity Count)
        5. `diff <input> <input>.bak` (Change Audit)
    - **Execution Flow**: Core Prettify -> Alternative Lint -> Whitespace Norm -> Integrity Count -> Change Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/FORMAT_[Timestamp]_formatted_report.json`: Structurally validated and pretty-printed JSON report.
        - `reports/artifacts/FORMAT_[Timestamp]_whitespace_audit.txt`: Log of whitespace and tab normalization changes.
        - `reports/analysis/FORMAT_[Timestamp]_lint_report.json`: Results of the JSON linting and syntax validation.

- **`FLTR`** (Short Name: `FLTR`)
    - **Purpose**: Extract high-fidelity security findings from raw assessment data based on severity thresholds.
    - **Input Schema**: `{ input: Path, severity: String }`
    - **Multi-Tool Command Logic**:
        1. `jq '.findings | map(select(.severity == "<severity>"))' <input>` (Core Severity Filter)
        2. `grep -i "<severity>" <input>` (String Search Backup)
        3. `python3 filter_logic.py --in <input> --sev <severity>` (Advanced Logic Filter)
        4. `sed -n '/<severity>/p' <input>` (Stream Extraction)
        5. `jq --version` (Binary Check)
    - **Execution Flow**: Core Filter -> String Backup -> Advanced Logic -> Stream Extraction -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/FILTER_[Timestamp]_severity_filtered.json`: JSON report containing only findings matching the severity threshold.
        - `reports/artifacts/FILTER_[Timestamp]_filter_logic.log`: Detailed log of the filtering logic and excluded items.
        - `reports/analysis/FILTER_[Timestamp]_integrity_count.json`: Verification of finding counts before and after filtering.

---

### 3. HTML Report Generator
**ID:** `report-html` | **Risk:** LOW | **File:** `HTMLGenModule.java`
**Tools:** `pandoc`, `wkhtmltopdf`, `python3`, `tidy`, `curl`

#### Execution Modes:

- **`GEN`** (Short Name: `GEN`)
    - **Purpose**: Transform raw markdown documentation into high-fidelity, interactive HTML presentation reports.
    - **Input Schema**: `{ input_md: Path, theme: String }`
    - **Multi-Tool Command Logic**:
        1. `pandoc -f markdown -t html --standalone <input_md> -o report.html` (Core HTML Gen)
        2. `tidy -m -i report.html` (HTML Cleanup)
        3. `python3 -m http.server 8080 --directory . & sleep 2 && curl http://localhost:8080/report.html` (Render Test)
        4. `wkhtmltopdf report.html report.pdf` (PDF Generation)
        5. `pandoc --version` (Binary Check)
    - **Execution Flow**: Core Gen -> Cleanup -> Render Test -> PDF Gen -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/GEN_[Timestamp]_interactive_report.html`: High-fidelity, interactive HTML presentation report.
        - `reports/artifacts/GEN_[Timestamp]_cleaned_source.html`: Sanitized and cleaned HTML source code.
        - `reports/analysis/GEN_[Timestamp]_render_test.log`: Results of the automated HTML rendering and accessibility test.

- **`VALD`** (Short Name: `VALD`)
    - **Purpose**: Automated syntax and accessibility validation of generated HTML assets.
    - **Input Schema**: `{ input_html: Path }`
    - **Multi-Tool Command Logic**:
        1. `tidy -errors <input_html>` (Core Syntax Check)
        2. `python3 accessibility_audit.py <input_html>` (Accessibility Audit)
        3. `curl --version` (Binary Check)
        4. `pandoc -v` (Binary Check)
        5. `wkhtmltopdf -V` (Binary Check)
    - **Execution Flow**: Syntax Check -> Accessibility Audit -> Binary Check x3.
    - **Output Generation & Artifacts**:
        - `reports/outputs/VALID_[Timestamp]_accessibility_audit.json`: Detailed report on HTML accessibility and compliance.
        - `reports/artifacts/VALID_[Timestamp]_syntax_errors.txt`: Captured syntax and structural errors from the tidy audit.
        - `reports/analysis/VALID_[Timestamp]_tool_versions.json`: Version inventory for tidy, pandoc, and wkhtmltopdf.

---

### 4. Markdown Report Exporter
**ID:** `report-md` | **Risk:** LOW | **File:** `MDExportModule.java`
**Tools:** `pandoc`, `jq`, `python3`, `sed`, `awk`

#### Execution Modes:

- **`GEN`** (Short Name: `GEN`)
    - **Purpose**: Convert machine-readable JSON assessment data into human-readable Markdown documentation.
    - **Input Schema**: `{ input_json: Path }`
    - **Multi-Tool Command Logic**:
        1. `pandoc -f json -t markdown <input_json> -o report.md` (Core MD Gen)
        2. `jq -r '.findings[] | "# " + .title + "\n" + .description' <input_json>` (Template Extraction)
        3. `sed -i 's/\\//g' report.md` (Escape Character Cleanup)
        4. `awk '/#/{print $0}' report.md` (Header Inventory)
        5. `python3 --version` (Binary Check)
    - **Execution Flow**: Core Gen -> Template Extraction -> Cleanup -> Header Inventory -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/GEN_[Timestamp]_assessment_doc.md`: Human-readable Markdown version of the assessment findings.
        - `reports/artifacts/GEN_[Timestamp]_template_extraction.json`: Extracted markdown templates used for generation.
        - `reports/analysis/GEN_[Timestamp]_header_inventory.txt`: Inventory of headers and sections for document structure audit.

- **`AUDIT`** (Short Name: `AUDIT`)
    - **Purpose**: Verify the structural integrity and link validity of generated Markdown reports.
    - **Input Schema**: `{ report_md: Path }`
    - **Multi-Tool Command Logic**:
        1. `pandoc --from markdown --to native <report_md>` (AST Structural Audit)
        2. `grep -c "\[.*\](.*)" <report_md>` (Link Count)
        3. `jq --version` (Binary Check)
        4. `sed --version` (Binary Check)
        5. `awk --version` (Binary Check)
    - **Execution Flow**: AST Audit -> Link Count -> Binary Check x3.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_markdown_ast.json`: Structural AST audit of the generated markdown document.
        - `reports/artifacts/AUDIT_[Timestamp]_link_verification.txt`: Results of the link validity and structural integrity check.
        - `reports/analysis/AUDIT_[Timestamp]_binary_status.json`: Verification of pandoc, sed, and awk status.

---

### 5. CSV Report Exporter
**ID:** `report-csv` | **Risk:** LOW | **File:** `CSVExportModule.java`
**Tools:** `jq`, `python3`, `awk`, `csvtool`, `sed`

#### Execution Modes:

- **`EXPR`** (Short Name: `EXPR`)
    - **Purpose**: Flatten complex JSON findings into CSV format for spreadsheet analysis and SIEM ingestion.
    - **Input Schema**: `{ input_json: Path }`
    - **Multi-Tool Command Logic**:
        1. `jq -r '.findings[] | [.id, .title, .severity] | @csv' <input_json>` (Core CSV Flattening)
        2. `csvtool col 1-3 report.csv` (Column Audit)
        3. `python3 csv_normalize.py report.csv` (Header Injection)
        4. `awk -F, '{print $2}' report.csv` (Title Verification)
        5. `sed -i 's/"//g' report.csv` (Quote Sanitization)
    - **Execution Flow**: Core Flatten -> Column Audit -> Header Injection -> Title Verify -> Quote Sanitization.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXPORT_[Timestamp]_assessment_data.csv`: Flattened findings data in CSV format for analysis.
        - `reports/artifacts/EXPORT_[Timestamp]_normalized_headers.csv`: CSV file with standardized headers and quote sanitization.
        - `reports/analysis/EXPORT_[Timestamp]_column_mapping.json`: Mapping of JSON fields to CSV columns for audit.

- **`VALD`** (Short Name: `VALD`)
    - **Purpose**: Verify CSV data alignment and character encoding for import readiness.
    - **Input Schema**: `{ input_csv: Path }`
    - **Multi-Tool Command Logic**:
        1. `csvtool readable <input_csv>` (Core Alignment Check)
        2. `awk -F, 'END {print NR}' <input_csv>` (Row Count Audit)
        3. `jq --version` (Binary Check)
        4. `python3 --version` (Binary Check)
        5. `sed --version` (Binary Check)
    - **Execution Flow**: Alignment Check -> Row Count -> Binary Check x3.
    - **Output Generation & Artifacts**:
        - `reports/outputs/VALID_[Timestamp]_csv_alignment.json`: Results of the data alignment and character encoding check.
        - `reports/artifacts/VALID_[Timestamp]_row_count_audit.txt`: Audit of row counts and data consistency for the CSV.
        - `reports/analysis/VALID_[Timestamp]_binary_readiness.json`: Verification of csvtool, awk, and sed readiness.

---

### 6. XML Report Exporter
**ID:** `report-xml` | **Risk:** LOW | **File:** `XMLExportModule.java`
**Tools:** `xmllint`, `jq`, `pandoc`, `python3`, `sed`

#### Execution Modes:

- **`EXPR`** (Short Name: `EXPR`)
    - **Purpose**: Export security findings to XML/DocBook format for legacy system integration.
    - **Input Schema**: `{ input_json: Path }`
    - **Multi-Tool Command Logic**:
        1. `pandoc -f json -t docbook <input_json> -o report.xml` (Core XML/DocBook Gen)
        2. `xmllint --format report.xml -o report.xml` (XML Prettify)
        3. `sed -i 's/UTF-16/UTF-8/g' report.xml` (Encoding Fix)
        4. `python3 xml_audit.py report.xml` (Schema Validation)
        5. `jq --version` (Binary Check)
    - **Execution Flow**: Core Gen -> XML Prettify -> Encoding Fix -> Schema Audit -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXPORT_[Timestamp]_docbook_report.xml`: Findings exported to XML/DocBook format.
        - `reports/artifacts/EXPORT_[Timestamp]_prettified.xml`: Human-readable, pretty-printed version of the XML export.
        - `reports/analysis/EXPORT_[Timestamp]_schema_validation.json`: Results of the XML schema and encoding audit.

- **`VALD`** (Short Name: `VALD`)
    - **Purpose**: Perform deep XSD/DTD validation of generated XML report assets.
    - **Input Schema**: `{ input_xml: Path }`
    - **Multi-Tool Command Logic**:
        1. `xmllint --noout --valid <input_xml>` (Core DTD Validation)
        2. `sed -n '1p' <input_xml>` (Prologue Audit)
        3. `python3 --version` (Binary Check)
        4. `pandoc -v` (Binary Check)
        5. `jq -V` (Binary Check)
    - **Execution Flow**: DTD Validation -> Prologue Audit -> Binary Check x3.
    - **Output Generation & Artifacts**:
        - `reports/outputs/VALID_[Timestamp]_dtd_validation.json`: Detailed report on DTD/XSD schema compliance.
        - `reports/artifacts/VALID_[Timestamp]_xml_prologue.txt**: Audit of the XML prologue and encoding declarations.
        - `reports/analysis/VALID_[Timestamp]_binary_status.json`: Verification of xmllint, pandoc, and jq status.

---

### 7. PDF Report Wrapper
**ID:** `report-pdf` | **Risk:** LOW | **File:** `PDFWrapModule.java`
**Tools:** `wkhtmltopdf`, `pandoc`, `python3`, `weasyprint`, `jq`

#### Execution Modes:

- **`WRAP`** (Short Name: `WRAP`)
    - **Purpose**: Compile finalized HTML/Markdown reports into professional, printable PDF documents.
    - **Input Schema**: `{ input: Path, format: String }`
    - **Multi-Tool Command Logic**:
        1. `wkhtmltopdf <input> report.pdf` (Core PDF Gen)
        2. `pandoc <input> -o report_alt.pdf --pdf-engine=weasyprint` (WeasyPrint Backup)
        3. `python3 pdf_metadata.py report.pdf` (Metadata Injection)
        4. `jq '.' <input>.json` (Data Context Check)
        5. `wkhtmltopdf --version` (Binary Check)
    - **Execution Flow**: Core PDF -> WeasyPrint Backup -> Metadata Injection -> Context Check -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/WRAP_[Timestamp]_final_assessment.pdf`: Professional, printable PDF report document.
        - `reports/artifacts/WRAP_[Timestamp]_pdf_metadata.json`: Captured and injected PDF metadata (author, subject, etc.).
        - `reports/analysis/WRAP_[Timestamp]_pdf_engine_audit.txt`: Performance and compatibility audit for the PDF engine.

- **`OPTM`** (Short Name: `OPTM`)
    - **Purpose**: Compress and linearize PDF reports for web delivery and email attachment compatibility.
    - **Input Schema**: `{ input_pdf: Path }`
    - **Multi-Tool Command Logic**:
        1. `python3 compress_pdf.py <input_pdf>` (Core Compression)
        2. `wkhtmltopdf --quiet <input_pdf> out.pdf` (Quiet Re-render)
        3. `pandoc -v` (Binary Check)
        4. `weasyprint --version` (Binary Check)
        5. `jq -V` (Binary Check)
    - **Execution Flow**: Core Compression -> Quiet Re-render -> Binary Check x3.
    - **Output Generation & Artifacts**:
        - `reports/outputs/OPTIM_[Timestamp]_web_optimized.pdf`: Compressed and linearized PDF for web delivery.
        - `reports/artifacts/OPTIM_[Timestamp]_compression_stats.json`: Results of the PDF compression and size reduction.
        - `reports/analysis/OPTIM_[Timestamp]_binary_versions.json`: Version inventory for weasyprint, wkhtmltopdf, and pandoc.

---
