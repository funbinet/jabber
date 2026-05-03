# JABBER Module System — Blueprint Documentation

> **Authoritative implementation reference for all 209 JABBER modules across 20 attack categories.**
> Each category file enumerates every module, defines required tools, and provides detailed implementation guidance.

## Directory Structure

```
~/jabber/jabber-tools/                 ← Global tool storage root
├── recon/                         ← Reconnaissance tools
├── vulnscan/                      ← Vulnerability scanning tools
├── social/                        ← Social engineering tools
├── forensics/                     ← Forensics tools
├── exploit/                       ← Exploitation tools
├── webapp/                        ← Web assessment tools
├── wireless/                      ← Wireless hacking tools
├── network/                       ← Network attack tools
├── privesc/                       ← Privilege escalation tools
├── lateral/                       ← Lateral movement tools
├── credaccess/                    ← Credential access tools
├── passcrack/                     ← Password cracking tools
├── payload/                       ← Payload creation tools
├── crypto/                        ← Cryptographic tools
├── c2/                            ← C2 & persistence tools
├── admanage/                      ← AD management tools
├── savedcreds/                    ← Saved credentials tools
├── reports/                       ← Reporting tools
├── util/                          ← Utility tools
└── phoneenum/                     ← Phone enumeration tools
```

## Category Blueprints

| # | Category | Slug | File | Modules |
|---|----------|------|------|---------|
| 1 | Reconnaissance | `recon` | [01-reconnaissance.md](01-reconnaissance.md) | 19 |
| 2 | Vulnerability Scanning | `vulnscan` | [02-vulnerability-scanning.md](02-vulnerability-scanning.md) | 12 |
| 3 | Social Engineering | `social` | [03-social-engineering.md](03-social-engineering.md) | 9 |
| 4 | Forensics | `forensics` | [04-forensics.md](04-forensics.md) | 7 |
| 5 | Exploitation | `exploit` | [05-exploitation.md](05-exploitation.md) | 30 |
| 6 | Web Assessment | `webapp` | [06-web-assessment.md](06-web-assessment.md) | 12 |
| 7 | Wireless Hacking | `wireless` | [07-wireless-hacking.md](07-wireless-hacking.md) | 11 |
| 8 | Network Attack & Defense | `network` | [08-network-attack-defense.md](08-network-attack-defense.md) | 11 |
| 9 | Privilege Escalation | `privesc` | [09-privilege-escalation.md](09-privilege-escalation.md) | 12 |
| 10 | Lateral Movement | `lateral` | [10-lateral-movement.md](10-lateral-movement.md) | 16 |
| 11 | Credential Access | `credaccess` | [11-credential-access.md](11-credential-access.md) | 13 |
| 12 | Password Cracking | `passcrack` | [12-password-cracking.md](12-password-cracking.md) | 6 |
| 13 | Payload Creation | `payload` | [13-payload-creation.md](13-payload-creation.md) | 23 |
| 14 | Cryptographic Operations | `crypto` | [14-crypto-operations.md](14-crypto-operations.md) | 8 |
| 15 | C2 Server & Persistence | `c2` | [15-c2-persistence.md](15-c2-persistence.md) | 11 |
| 16 | AD Management | `admanage` | [16-ad-management.md](16-ad-management.md) | 6 |
| 17 | Saved Credentials | `savedcreds` | [17-saved-credentials.md](17-saved-credentials.md) | 6 |
| 18 | Reporting | `reports` | [18-reports.md](18-reports.md) | 7 |
| 19 | Utilities | `util` | [19-utilities.md](19-utilities.md) | 19 |
| 20 | Phone Enumeration | `phoneenum` | [20-phone-enumeration.md](20-phone-enumeration.md) | 2 |
| 21 | Artifacts | `artifacts` | [21-artifacts.md](21-artifacts.md) | System Hub |

## Shared Architecture (Modules v5 Standard)

As of V5, all modules utilize a strictly isolated, per-module infrastructure to ensure zero "tool bleed" and maximum fidelity:

1. **ToolManager** (Sub-package Local) — Manages module-specific binaries (e.g., `dig`, `whois`, `nmap`).
2. **ProcessExecutor** (Sub-package Local) — Orchestrates real `ProcessBuilder` execution with telemetry.
3. **InputSanitizer** (Sub-package Local) — Enforces strict validation of targets and parameters.
4. **ReportGenerator** (Sub-package Local) — Consolidates raw tool outputs into structured JSON/HTML/Markdown reports.
5. **Target Intelligence Phase** (MANDATORY) — Every module MUST perform automated DNS discovery (`dig`) and hosting identification (`whois`) before its core operation.
6. **Universal ToolManager API**: A unified `ToolManager` class pattern handles resolving tool paths, verifying dependencies, and installing missing binaries using `PackageManager` integration.
- **Dynamic Tool-Selection Layer**: The V5 UI renders a horizontal table for every execution mode, allowing users to dynamically toggle which tools run. The `ProcessBuilder` execution automatically adapts to run only the specific logic mapped to the user-selected tools.
7. **Artifact System Integration** — Automated classification and SHA256 hashing of all generated files via the `Artifacts` system (Category 21).

## Frontend & UI Requirements

To ensure the frontend aligns with the V5 architecture, every module UI MUST implement:

1. **Execution Mode Toggle**: A dynamic selector to switch between `QUICK`, `DEEP`, and `STEALTH` modes.
2. **Artifact Gallery**: A centralized viewer for logs, captures, and payloads, linked directly to the `Artifacts` system.
3. **Live Terminal Stream**: A real-time stdout/stderr streaming component for operational transparency.
4. **Tool Management Dashboard**: A global interface (managed by Category 21) for alphabetical tool inventory and control.

### Platform Support Matrix

| Platform | OS Token | Arch Tokens | Binary Suffix | Notes |
|----------|----------|-------------|---------------|-------|
| Linux x86_64 | `linux` | `amd64`, `x86_64`, `x64` | (none) | Primary target |
| Linux ARM64 | `linux` | `arm64`, `aarch64` | (none) | Raspberry Pi, ARM servers |
| Linux ARMv7 | `linux` | `armv7`, `armv6`, `arm` | (none) | Older ARM boards |
| Android/Termux | `linux` | `arm64`, `aarch64` | (none) | `TERMUX_VERSION` env detected |
| Android/chroot | `linux` | `arm64`, `aarch64` | (none) | `ANDROID_ROOT` env detected |

### Tool Installation Methods

| Method | Description | Used When |
|--------|-------------|-----------|
| `github_release` | Download from GitHub Releases API | Go/Rust single-binary tools |
| `pip_install` | `pip install --user <pkg>` | Python-based tools |
| `apt_install` | `apt install <pkg>` (Linux only) | System packages (nmap, etc.) |
| `pkg_install` | `pkg install <pkg>` (Termux only) | Android/Termux packages |
| `go_install` | `go install <pkg>@latest` | Go tools without releases |
| `brew_install` | `brew install <pkg>` (macOS only) | macOS Homebrew packages |
| `manual` | Requires manual setup | Complex tools (Metasploit, etc.) |

---

**© 2026 Funbinet Inc. — JABBER V 5.5.0.0**
