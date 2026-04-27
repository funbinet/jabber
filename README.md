<div align="center">
  <img src="jabber-logo.png" width="150" alt="JABBER Logo">
  <h1>JABBER RED TEAMING SUITE</h1>
  <br>
  <h3>V4.0.0 — Production-Grade • Modular • Enterprise-Ready</h3>
  <p>Created by <b>Funbinet</b> · <a href="https://github.com/funbinet/jabber">GitHub</a> · <a href="https://codeberg.org/funbinet/jabber">Codeberg</a></p>
</div>

---

## Overview

JABBER Red Teaming Suite (JRTS) is a **production-grade modular offensive security platform** integrating **209 native security modules** across **19 attack categories** into a unified Java/Spring Boot backend with a premium **React/Electron** dual-mode frontend. V4.0.0 introduces unified output management, target profiling, and 30 exploitation modules with an optimized responsive layout.

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

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  JABBER V4.0 Architecture                     │
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
jrts/
├── jrts-core/           # Spring Boot backend
├── jrts-modules/        # 209 modules (16 packages)
├── jrts-data/           # H2 database + JPA entities
├── jrts-ui/             # React/Electron frontend
├── reports/             # Module output artifacts
├── logs/                # Runtime logs (backend, frontend)
├── packaging/           # .deb package builder
├── frags/               # Impacket tool collection
├── run.sh               # Unified launcher (desk/web)
├── stop.sh              # Graceful shutdown
└── jabber-logo.png      # Brand logo
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
- ✅ Unified output management (V4.0)
- ✅ Target profiling engine (V4.0)
- ✅ 30 exploitation modules (V4.0)
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

**JABBER Red Teaming Suite V4.0.0** · All Systems Ready ✅  
**© 2026 Funbinet Inc. All Rights Reserved.**

</div>
