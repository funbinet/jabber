<div align="center">
  <img src="jabber-logo.png" width="150" alt="JABBER Logo">
  <h1>JABBER RED TEAMING SUITE</h1>
  <br>
  <h3>RUNTIME DEPENDENCIES</h3>
</div>

---

## Overview

This document lists the required tools, packages, and environment conditions needed to start JABBER using `run.sh` in a clean environment.

The launcher starts:
- Backend (Spring Boot via Gradle) on port `8314`
- Frontend (Vite) on port `5173`
- Optional Electron desktop shell in `desk` mode

---

## Core Requirements (All Modes)

### System and Shell Utilities

| Tool | Required | Why |
|------|----------|-----|
| `bash` | Yes | Script interpreter for `run.sh` and `stop.sh` |
| `curl` | Yes | Health checks to verify backend/frontend readiness |
| `lsof` | Yes | Detect and clear occupied service ports |
| `xargs` | Yes | Used in process cleanup pipelines |
| `pgrep` / `pkill` | Yes | Residual process cleanup during shutdown |
| `nohup` | Yes | Launch background services |
| `kill` | Yes | Process termination |

### Java Runtime/Build

| Tool | Required Version | Why |
|------|------------------|-----|
| `java` / `javac` | JDK 21 | Backend Gradle toolchain is set to Java 21 |
| `gradlew` | Included in repo | Starts backend with `:jrts-core:bootRun` |

### Node.js Runtime

| Tool | Required Version | Why |
|------|------------------|-----|
| `node` | 18+ (20 LTS recommended) | Required for Vite/Electron toolchain |
| `npm` | Bundled with Node | Install frontend dependencies |
| `npx` | Bundled with npm | Runs `vite` and `electron` from local packages |

---

## Mode-Specific Requirements

### Web Mode (`./run.sh web`)

| Requirement | Required | Notes |
|-------------|----------|-------|
| Web browser | Yes | Access UI at `http://localhost:5173` |
| `xdg-open` | Optional | Enables auto-open of browser from launcher |

### Desktop Mode (`./run.sh desk`)

| Requirement | Required | Notes |
|-------------|----------|-------|
| Electron package | Yes | Installed via `npm ci` in `jrts-ui` |
| Linux GUI session | Yes | X11/Wayland required |
| Electron runtime libraries | Yes | Common desktop libs required on minimal distros |

Suggested Debian/Ubuntu Electron runtime libraries:

```bash
sudo apt install -y libgtk-3-0 libnss3 libasound2t64 libxss1 libxtst6 libgbm1
```

---

## One-Time Bootstrap on a Clean Clone

1. Install system prerequisites (Java, Node, shell utilities).
2. Install frontend dependencies:

```bash
cd /home/bane/jrts/jrts-ui
npm ci
```

3. Return to project root and run:

```bash
cd /home/bane/jrts
./run.sh web
# or
./run.sh desk
```

---

## Network and Environment Requirements

| Item | Required | Why |
|------|----------|-----|
| Internet access (first run) | Yes | Downloads Gradle distribution + Maven/npm dependencies |
| Port `8314` free | Yes | Backend service bind |
| Port `5173` free | Yes | Frontend dev server bind |
| Write access to home directory | Yes | Gradle cache defaults to `~/.gradle_jrts` |

---

## Minimal Package Install (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y openjdk-21-jdk nodejs npm curl lsof procps xdg-utils
```

---

## Important Scope Note

This dependency list covers only what is needed to start JABBER through `run.sh`.

Individual offensive modules may require additional external tools (for example: network scanners, cracking tools, or Python security utilities). Those are module-specific dependencies and are not required for base platform startup.

---

<div align="center">

**JABBER Red Teaming Suite V4.0.0** · Baseline Baseline Ready ✅  
**© 2026 Funbinet Inc. All Rights Reserved.**

</div>