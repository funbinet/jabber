<div align="center">
  <img src="https://raw.githubusercontent.com/funbinet/jabber-framework/main/jabber-logo.png" width="120" alt="JABBER Logo">
  <h1><b>JABBER+</b></h1>
  <h3>THE OFFENSIVE SECURITY FRAMEWORK</h3>
  <p><b>Version 5.5.0</b></p>
  <p>Created by <b>Funbinet</b> · <a href="https://github.com/funbinet/jabber-framework">GitHub</a> · <a href="https://codeberg.org/funbinet/jabber-framework">Codeberg</a></p>
</div>

---

## Overview

JABBER is a **production-grade modular offensive security platform** integrating **209 native security modules** across **19 attack categories** into a unified Java/Spring Boot backend with a premium **React/Electron** dual-mode frontend.

![JABBER Dashboard](file:///home/bane/.gemini/antigravity/brain/920f970e-2933-4a85-8206-1325488e7cc3/dashboard_screenshot_1777788212891.png)

Version 5.5.0 introduces unified output management, target profiling, and enhanced artifact management with a state-of-the-art responsive UI.

## Quick Start

```bash
# Clone and start (web mode — auto-opens browser)
cd /home/bane/jabber
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
| **Build Backend** | `./gradlew :jabber-core:bootJar` | — |
| **Build Frontend** | `cd jabber-ui && npm run build` | — |
| **Build .deb** | `./packaging/build-deb.sh` | — |

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  JABBER V 5.5.0 Architecture                     │
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
│                                │   jabber-modules/       │     │
│                                └──────────────────────┘     │
└──────────────────────────────────────────────────────────────┘
```

### Component Breakdown

| Component | Technology | Location |
|-----------|-----------|----------|
| Backend | Java 21, Spring Boot 3 | `jabber-core/` |
| Modules | Java plugins, 16 category packages | `jabber-modules/` |
| Data Layer | H2 database, JPA entities | `jabber-data/` |
| Frontend | React 19, Vite 8, Lucide icons | `jabber-ui/` |
| Desktop | Electron 41 | `jabber-ui/electron/` |
| Startup | Bash (run.sh / stop.sh) | Project root |
| Packaging | Debian .deb builder | `packaging/` |
| Reports | JSON, HTML, multi-format | `reports/` |

## Module Categories

All **209 modules** are organized across **19 categories** in 5 lifecycle groups:

### Intelligence & Planning
- Reconnaissance (16 modules)
- Vulnerability Scanning (12 modules)
- Social Engineering (9 modules)
- Forensics (7 modules)

### Access & Penetration
- Exploitation (30 modules)
- Web Assessment (12 modules)
- Wireless Hacking (11 modules)
- Network Attack & Defense (11 modules)

### Privilege & Identity
- Privilege Escalation (12 modules)
- Lateral Movement (16 modules)
- Credential Access (20 modules)
- Password Cracking (6 modules)

### Operations & Assets
- Payload Creation & Injection (9 modules)
- Cryptographic Operations (6 modules)
- C2 Server & Persistence (8 modules)
- AD Management (6 modules)

### Data & Utilities
- Saved Credentials (6 modules)
- Reports (6 modules)
- Utilities (6 modules)

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
```

## Project Structure

```
jabber/
├── jabber-core/           # Spring Boot backend
├── jabber-modules/        # 209 modules (16 packages)
├── jabber-data/           # H2 database + JPA entities
├── jabber-ui/             # React/Electron frontend
├── reports/             # Module output artifacts
├── logs/                # Runtime logs (backend, frontend)
├── packaging/           # .deb package builder
├── frags/               # Impacket tool collection
├── run.sh               # Unified launcher (desk/web)
├── stop.sh              # Graceful shutdown
└── https://raw.githubusercontent.com/funbinet/jabber-framework/main/jabber-logo.png      # Brand logo
```

## Documentation

| Document | Purpose |
|----------|---------|
| [README.md](README.md) | Getting started, architecture |
| [MODULES.md](MODULES.md) | Complete 209-module catalog |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture deep-dive |
| [LICENSE.md](LICENSE.md) | Proprietary license agreement |
| [packaging/README_DEB.md](packaging/README_DEB.md) | Debian package guide |

## Production Features

- ✅ 209 native security modules across 19 categories
- ✅ Spring Boot 3 backend on port 8314
- ✅ React 19 / Vite 8 frontend
- ✅ Electron 41 desktop wrapper
- ✅ Unified output management (V5.5)
- ✅ Target profiling engine (V5.5)
- ✅ 30 exploitation modules (V5.5)
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

**JABBER V 5.5.0** · All Systems Ready ✅  
**© 2026 Funbinet Inc. All Rights Reserved.**

</div>
