<div align="center">

# JABBER Red Teaming Suite (JRTS)

### V3 — Production-Grade • Modular • Enterprise-Ready

![JABBER Logo](jabber.png)

**Created by [Funbinet](https://dancan.tech)** · [GitHub](https://github.com/funbinet) · [Codeberg](https://codeberg.org/funbinet)

---

![Dashboard Overview](screenshots/01_dashboard_overview.png)

</div>

## Overview

JABBER Red Teaming Suite (JRTS) is a **production-grade modular offensive security platform** integrating **209 native security modules** across **19 attack categories** into a unified Java/Spring Boot backend with a premium **React/Electron** dual-mode frontend. V3 introduces unified output management, target profiling, and 30 exploitation modules.

## Quick Start

```bash
# Clone and start (web mode — auto-opens browser)
cd /home/bane/jrts
./run.sh web

# Desktop mode (Electron window)
./run.sh desk

# Stop all services
./stop.sh
```

After installation via `.deb` package:

```bash
jabber          # Desktop mode
jabber web      # Browser mode
jabber stop     # Stop all services
jabber status   # Check service status
```

## Commands

| Goal | Command | Port |
|------|---------|------|
| **Desktop Mode** | `./run.sh desk` | Electron |
| **Browser Mode** | `./run.sh web` | 5173 → 8314 |
| **Stop All** | `./stop.sh` | — |
| **Service Status** | `./run.sh status` | — |
| **Build Backend** | `./gradlew :jrts-core:bootJar` | — |
| **Build Frontend** | `cd jrts-ui && npm run build` | — |
| **Build .deb** | `./packaging/build-deb.sh` | — |

## Dashboard

The dashboard provides a real-time overview of all loaded modules, categories, and risk-level statistics.

![Dashboard Overview](screenshots/01_dashboard_overview.png)

Scrolling reveals every category grouped by attack lifecycle phase:

![Dashboard Categories](screenshots/02_dashboard_categories.png)
![Dashboard Bottom](screenshots/03_dashboard_bottom.png)

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    JABBER V3 Architecture                     │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌──────────┐    REST API     ┌──────────────────────┐     │
│   │  React   │ ◄─────────────► │   Spring Boot 3      │     │
│   │  Frontend│   port 5173     │   Backend (port 8314) │     │
│   │  (Vite)  │                 │                      │     │
│   └──────────┘                 │  ┌────────────────┐  │     │
│        │                       │  │ PluginRegistry │  │     │
│   ┌──────────┐                 │  │ TaskEngine     │  │     │
│   │ Electron │                 │  │ ReportEngine   │  │     │
│   │ Desktop  │                 │  │ ProfileEngine  │  │     │
│   └──────────┘                 │  │ StorageService │  │     │
│                                │  └────────────────┘  │     │
│                                └──────────┬───────────┘     │
│                                           │                  │
│                                ┌──────────▼───────────┐     │
│                                │   209 Modules         │     │
│                                │   (16 packages)       │     │
│                                │   jrts-modules/       │     │
│                                └──────────────────────┘     │
└──────────────────────────────────────────────────────────────┘
```

### Component Breakdown

| Component | Technology | Location |
|-----------|-----------|----------|
| Backend | Java 21, Spring Boot 3 | `jrts-core/` |
| Modules | Java plugins, 16 category packages | `jrts-modules/` |
| Data Layer | H2 database, JPA entities | `jrts-data/` |
| Frontend | React 19, Vite 8, Lucide icons | `jrts-ui/` |
| Desktop | Electron 41 | `jrts-ui/electron/` |
| Startup | Bash (run.sh / stop.sh) | Project root |
| Packaging | Debian .deb builder | `packaging/` |
| Reports | JSON, HTML, multi-format | `reports/` |

## Module Categories

All **209 modules** are organized across **19 categories** in 5 lifecycle groups:

### Intelligence & Planning

| Category | Modules | Screenshot |
|----------|---------|------------|
| Reconnaissance | 16 | ![Recon](screenshots/04_category_reconnaissance.png) |
| Vulnerability Scanning | 12 | ![VulnScan](screenshots/21_category_vuln_scanning.png) |
| Social Engineering | 9 | ![SocEng](screenshots/12_category_social_engineering.png) |
| Forensics | 7 | ![Forensics](screenshots/22_category_forensics.png) |

### Access & Penetration

| Category | Modules | Screenshot |
|----------|---------|------------|
| Exploitation | 30 | ![Exploit](screenshots/05_category_exploitation.png) |
| Web Assessment | 12 | ![WebAssess](screenshots/23_category_web_assessment.png) |
| Wireless Hacking | 11 | ![Wireless](screenshots/07_category_wireless_hacking.png) |
| Network Attack & Defense | 11 | ![Network](screenshots/20_category_network_attack.png) |

### Privilege & Identity

| Category | Modules | Screenshot |
|----------|---------|------------|
| Privilege Escalation | 12 | ![PrivEsc](screenshots/13_category_privilege_escalation.png) |
| Lateral Movement | 16 | ![Lateral](screenshots/14_category_lateral_movement.png) |
| Credential Access | 20 | ![Cred](screenshots/06_category_credential_access.png) |
| Password Cracking | 6 | ![PassCrack](screenshots/15_category_password_cracking.png) |

### Operations & Assets

| Category | Modules | Screenshot |
|----------|---------|------------|
| Payload Creation & Injection | 9 | ![Payload](screenshots/18_category_payload_creation.png) |
| Cryptographic Operations | 6 | ![Crypto](screenshots/19_category_crypto_operations.png) |
| C2 Server & Persistence | 8 | ![C2](screenshots/16_category_c2_persistence.png) |
| AD Management | 6 | ![AD](screenshots/17_category_ad_management.png) |

### Data & Utilities

| Category | Modules | Screenshot |
|----------|---------|------------|
| Saved Credentials | 6 | ![SavedCred](screenshots/24_category_saved_credentials.png) |
| Reports | 6 | — |
| Utilities | 6 | ![Utilities](screenshots/08_category_utilities.png) |

## Module Executor

Click any module card to open the executor panel with parameter forms, real-time terminal output, and execution controls:

![Module Executor](screenshots/09_module_executor.png)

## Report Manager

The V3 Report Manager provides browsing, filtering, editing, and export of all module outputs:

![Report Manager](screenshots/11_report_manager.png)

## API Reference

All API endpoints are served on port **8314**:

```bash
# System info
curl http://localhost:8314/api/info

# List all modules
curl http://localhost:8314/api/modules

# Modules by category
curl http://localhost:8314/api/modules/category/RECONNAISSANCE

# Execute a module
curl -X POST http://localhost:8314/api/modules/execute \
  -H "Content-Type: application/json" \
  -d '{"moduleId":"util-system-info"}'

# Module parameter schema
curl http://localhost:8314/api/modules/{id}/schema

# Task status
curl http://localhost:8314/api/tasks/{taskId}

# Reports
curl http://localhost:8314/api/reports
```

## Project Structure

```
jrts/
├── jrts-core/           # Spring Boot backend
│   └── src/main/java/com/jabber/jrts/core/
│       ├── api/         # REST controllers
│       ├── engine/      # TaskEngine
│       ├── plugin/      # PluginRegistry
│       ├── report/      # ReportEngine
│       ├── profiling/   # TargetProfileEngine
│       └── storage/     # ReportStorageService
├── jrts-modules/        # 209 modules (16 packages)
│   └── src/main/java/com/jabber/jrts/modules/
│       ├── reconnaissance/
│       ├── exploitation/
│       ├── credential/
│       ├── wireless/
│       ├── network/
│       ├── privesc/
│       ├── lateral/
│       ├── social/
│       ├── vulnscan/
│       ├── webapp/
│       ├── payload/
│       ├── crypto/
│       ├── c2/
│       ├── persistence/
│       ├── reporting/
│       └── utilities/
├── jrts-data/           # H2 database + JPA entities
├── jrts-ui/             # React/Electron frontend
│   ├── src/
│   │   ├── components/  # 9 React components
│   │   ├── api.js       # Backend API client
│   │   ├── App.jsx      # Main app + routing
│   │   └── index.css    # Full design system
│   └── electron/        # Electron main process
├── screenshots/         # 806×806 UI screenshots
├── reports/             # Module output artifacts
├── logs/                # Runtime logs (backend, frontend)
├── packaging/           # .deb package builder
├── frags/               # Impacket tool collection
├── run.sh               # Unified launcher (desk/web)
├── stop.sh              # Graceful shutdown
├── jabber.png           # Brand logo (1080×1080)
└── jabber-dashboard.png # Reference dashboard image
```

## Module Source Structure

All modules are located in:
```
jrts-modules/src/main/java/com/jabber/jrts/modules/
```

Each category directory contains Java classes implementing `JRTSModuleInterface`.

## Documentation

| Document | Purpose |
|----------|---------|
| [README.md](README.md) | Getting started, architecture, screenshots |
| [MODULES.md](MODULES.md) | Complete 209-module catalog |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture deep-dive |
| [LICENSE.md](LICENSE.md) | Proprietary license agreement |
| [packaging/README_DEB.md](packaging/README_DEB.md) | Debian package guide |

## Production Features

- ✅ 209 native security modules across 19 categories
- ✅ Spring Boot 3 backend on port 8314
- ✅ React 19 / Vite 8 frontend
- ✅ Electron 41 desktop wrapper
- ✅ Unified output management (V3)
- ✅ Target profiling engine (V3)
- ✅ 30 exploitation modules (V3)
- ✅ Report storage with filesystem persistence
- ✅ Multi-format export (JSON, HTML, CSV, XML, Markdown)
- ✅ `.deb` package installer with `jabber` CLI command
- ✅ Structured logging (logs/ directory)
- ✅ PID-based process management

## License

See [LICENSE.md](LICENSE.md)

## Contact

- **Website**: [dancan.tech](https://dancan.tech)
- **GitHub**: [github.com/funbinet](https://github.com/funbinet)
- **Codeberg**: [codeberg.org/funbinet](https://codeberg.org/funbinet)
- **Email**: funbinet@gmail.com

---

<div align="center">

**JABBER Red Teaming Suite V3** · All Systems Ready ✅  
**© 2026 Funbinet Inc. All Rights Reserved.**

</div>
