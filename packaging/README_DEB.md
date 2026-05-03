<div align="center">
  <img src="https://raw.githubusercontent.com/funbinet/jabber-framework/main/jabber-logo.png" width="120" alt="JABBER Logo">
  <h1><b>JABBER+</b></h1>
  <h3>THE OFFENSIVE SECURITY FRAMEWORK</h3>
  <p><b>Version 5.5.0</b></p>
</div>

---

## Overview

This directory contains the Debian packaging pipeline for JABBER V 5.5.0.  
The build script produces two `.deb` packages (AMD64 and ARM64) that install the complete platform with the `jabber` command.

## Build the .deb Package

```bash
cd /home/bane/jabber/packaging
./build-deb.sh
```

Output:
- `build-deb/jabber_5.5.0_amd64.deb`
- `build-deb/jabber_5.5.0_arm64.deb`

## Package Contents

| Installed Path | Purpose |
|----------------|---------|
| `/opt/jabber/` | Application root |
| `/opt/jabber/lib/jabber-server.jar` | Backend JAR |
| `/opt/jabber/ui/` | Built frontend + Electron |
| `/opt/jabber/run.sh` | Launcher script |
| `/opt/jabber/stop.sh` | Shutdown script |
| `/opt/jabber/logs/` | Runtime logs |
| `/usr/bin/jabber` | Global CLI command |
| `/usr/share/applications/jabber.desktop` | Desktop entry |
| `/usr/share/pixmaps/jabber.png` | App icon |

## Installation

```bash
sudo dpkg -i jabber_5.5.0_amd64.deb
```

## Usage

```bash
jabber          # Launch desktop mode (Electron + backend)
jabber web      # Launch browser mode (auto-opens localhost)
jabber stop     # Stop all services
jabber status   # Check service status
```

## Dependencies

- `openjdk-21-jre`
- `nodejs` (>= 18)

## Uninstallation

```bash
jabber stop
sudo dpkg -r jabber
sudo rm -rf /opt/jabber
```

## Build Script Details

The `build-deb.sh` script performs 8 phases:
1. Clean previous build artifacts
2. Build backend JAR (`gradlew :jabber-core:bootJar`)
3. Build frontend (`npm ci && npm run build`)
4. Assemble package structure under `/opt/jabber`
5. Create DEBIAN control files
6. Generate CLI wrapper, .desktop entry, maintainer scripts
7. Generate architecture-specific metadata and maintainer scripts
8. Build both `.deb` files with `dpkg-deb`

---

<div align="center">

**JABBER V 5.5.0** · Packaging Systems Ready ✅  
**© 2026 Funbinet Inc. All Rights Reserved.**

</div>
