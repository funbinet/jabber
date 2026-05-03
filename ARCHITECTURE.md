<div align="center">
  <img src="https://raw.githubusercontent.com/funbinet/jabber-framework/main/jabber-logo.png" width="120" alt="JABBER Logo">
  <h1><b>JABBER+</b></h1>
  <h3>THE OFFENSIVE SECURITY FRAMEWORK</h3>
  <p><b>Version 5.5.0</b></p>
</div>

JABBER V 5.5.0 is a production-grade, modular offensive security platform integrating 209 native security modules across 19 attack categories into a unified Java/Spring Boot backend with a dual-mode React/Electron frontend.

## System Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    JABBER V 5.5.0 Platform                        │
├─────────────┬──────────────────────────┬───────────────────────┤
│   Frontend  │       Backend            │     Modules           │
│   (React)   │    (Spring Boot 3)       │  (Java Plugins)       │
│   Port 5173 │       Port 8314          │                       │
├─────────────┤                          │  reconnaissance/      │
│  Electron   │  ┌────────────────────┐  │  exploitation/        │
│  Desktop    │  │  JABBERApiController │  │  credential/          │
│  (optional) │  │  PluginRegistry    │  │  wireless/            │
│             │  │  TaskEngine        │  │  network/             │
│             │  │  ReportEngine      │  │  privesc/             │
│             │  │  ProfileEngine     │  │  lateral/             │
│             │  │  StorageService    │  │  social/...           │
│             │  └────────────────────┘  │  (16 packages total)  │
├─────────────┴──────────────────────────┴───────────────────────┤
│                        Data Layer (H2)                          │
│                        jabber-data/                               │
└────────────────────────────────────────────────────────────────┘
```

## Components

### Backend (`jabber-core/`)

- **JABBERApplication.java** — Spring Boot entry point
- **JABBERApiController.java** — Single REST controller handling all `/api/*` endpoints
- **PluginRegistry.java** — Discovers and loads modules from `jabber-modules/`
- **TaskEngine.java** — Asynchronous module execution with progress tracking
- **ReportEngine.java** — Multi-format report generation (JSON, HTML, CSV, XML, Markdown)
- **TargetProfileEngine.java** — Cross-report data correlation and risk scoring
- **ReportStorageService.java** — Filesystem persistence with structured metadata

### Modules (`jabber-modules/`)

209 Java modules implementing `JABBERModuleInterface`, organized into 16 packages by attack category. Each module defines its parameter schema, risk level, and execution logic.

### Frontend (`jabber-ui/`)

The React-based UI handles all user interactions and communicates with the backend via REST.

| Component | Purpose |
|-----------|---------|
| `App.jsx` | Root application, state management, routing |
| `Header.jsx` | Top bar with logo, title, connection status |
| `SideNav.jsx` | Category sidebar with module counts |
| `Workspace.jsx` | Main content router (dashboard/category/executor/reports) |
| `DashboardHome.jsx` | Hero overview with statistics and category cards |
| `ModuleExecutor.jsx` | Parameter forms, execution, terminal output |
| `ReportManager.jsx` | Report browsing, filtering, editing, export |
| `TargetProfiler.jsx` | Cross-report correlation and profiling |

### Desktop (`jabber-ui/electron/`)

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

The executor panel provides:
- **Parameter form** — Dynamically generated from module schema
- **Terminal output** — Real-time execution logs
- **Progress tracking** — Percentage-based progress bar
- **Report generation** — Automatic artifact persistence

## Report Manager

V5.5 Report Manager capabilities:
- Browse, filter, and search reports by target, type, or category
- View report contents in editor or preview mode
- Export individual reports or bulk selections
- Launch Target Profiler from selected reports

## Build & Deployment

- **Build System**: Gradle 8 (multi-project: jabber-core, jabber-data, jabber-modules)
- **Backend**: Java 21, Spring Boot 3, port 8314
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

<div align="center">

**JABBER V 5.5.0** · All Systems Ready ✅  
**© 2026 Funbinet Inc. All Rights Reserved.**

</div>
