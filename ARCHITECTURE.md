# JABBER Architecture

## Overview

JABBER Red Teaming Suite (JRTS) V3 is a production-grade, modular offensive security platform integrating 209 native security modules across 19 attack categories into a unified Java/Spring Boot backend with a dual-mode React/Electron frontend.

![Dashboard](screenshots/01_dashboard_overview.png)

## System Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      JABBER V3 Platform                        │
├─────────────┬──────────────────────────┬───────────────────────┤
│   Frontend  │       Backend            │     Modules           │
│   (React)   │    (Spring Boot 3)       │  (Java Plugins)       │
│   Port 5173 │       Port 8314          │                       │
├─────────────┤                          │  reconnaissance/      │
│  Electron   │  ┌────────────────────┐  │  exploitation/        │
│  Desktop    │  │  JRTSApiController │  │  credential/          │
│  (optional) │  │  PluginRegistry    │  │  wireless/            │
│             │  │  TaskEngine        │  │  network/             │
│             │  │  ReportEngine      │  │  privesc/             │
│             │  │  ProfileEngine     │  │  lateral/             │
│             │  │  StorageService    │  │  social/...           │
│             │  └────────────────────┘  │  (16 packages total)  │
├─────────────┴──────────────────────────┴───────────────────────┤
│                        Data Layer (H2)                          │
│                        jrts-data/                               │
└────────────────────────────────────────────────────────────────┘
```

## Components

### Backend (`jrts-core/`)

- **JRTSApplication.java** — Spring Boot entry point
- **JRTSApiController.java** — Single REST controller handling all `/api/*` endpoints
- **PluginRegistry.java** — Discovers and loads modules from `jrts-modules/`
- **TaskEngine.java** — Asynchronous module execution with progress tracking
- **ReportEngine.java** — Multi-format report generation (JSON, HTML, CSV, XML, Markdown)
- **TargetProfileEngine.java** — Cross-report data correlation and risk scoring
- **ReportStorageService.java** — Filesystem persistence with structured metadata

### Modules (`jrts-modules/`)

209 Java modules implementing `JRTSModuleInterface`, organized into 16 packages by attack category. Each module defines its parameter schema, risk level, and execution logic.

### Frontend (`jrts-ui/`)

9 React components providing the full UI:

| Component | Purpose |
|-----------|---------|
| `App.jsx` | Root application, state management, routing |
| `Header.jsx` | Top bar with logo, title, connection status |
| `SideNav.jsx` | Category sidebar with module counts |
| `Workspace.jsx` | Main content router (dashboard/category/executor/reports) |
| `DashboardHome.jsx` | Hero overview with statistics and category cards |
| `ModuleGrid.jsx` | Category module card layout |
| `ModuleExecutor.jsx` | Parameter forms, execution, terminal output |
| `ReportManager.jsx` | Report browsing, filtering, editing, export |
| `TargetProfiler.jsx` | Cross-report correlation and profiling |
| `StatusBar.jsx` | Footer with social links and system status |

### Desktop (`jrts-ui/electron/`)

Electron wrapper (`main.cjs`) that loads the React frontend in a native window. Supports both dev mode (Vite URL) and production mode (built artifacts).

## Data Flow

```
User Action → React Component → api.js → REST API (port 8314)
                                              ↓
                                     PluginRegistry.lookup()
                                              ↓
                                     TaskEngine.execute()
                                              ↓
                                     Module.execute(params)
                                              ↓
                                     Result → ReportStorageService
                                              ↓
                                     Response → React → Terminal Output
```

## Module Executor

![Module Executor](screenshots/09_module_executor.png)

The executor panel provides:
- **Parameter form** — Dynamically generated from module schema
- **Terminal output** — Real-time execution logs
- **Progress tracking** — Percentage-based progress bar
- **Report generation** — Automatic artifact persistence

## Report Manager

![Report Manager](screenshots/11_report_manager.png)

V3 Report Manager capabilities:
- Browse, filter, and search reports by target, type, or category
- View report contents in editor or preview mode
- Export individual reports or bulk selections
- Launch Target Profiler from selected reports

## Build & Deployment

- **Build System**: Gradle 8 (multi-project: jrts-core, jrts-data, jrts-modules)
- **Backend**: Java 21, Spring Boot 3.4.4, port 8314
- **Frontend**: React 19, Vite 8, port 5173
- **Desktop**: Electron 41
- **Package**: Debian `.deb` via `packaging/build-deb.sh`
- **Install path**: `/opt/jabber` (packaged), project root (development)

## Startup Scripts

| Script | Purpose |
|--------|---------|
| `run.sh desk` | Start backend + frontend + Electron |
| `run.sh web` | Start backend + frontend + auto-open browser |
| `stop.sh` | Graceful shutdown of all services |

---

**© 2026 Funbinet Inc. All Rights Reserved.**
