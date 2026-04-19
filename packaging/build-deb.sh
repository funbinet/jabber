#!/bin/bash
# ============================================================
# JABBER Debian Package Builder — v3.2
# Builds a production-ready .deb for the JABBER Red Teaming Suite
# Usage: ./build-deb.sh [version]
# Created by Funbinet (dancan.tech)
# ============================================================
set -e

VERSION="${1:-3.2.0}"
PACKAGE="jabber"
ARCH="amd64"
MAINTAINER="Funbinet <admin@dancan.tech>"
DESCRIPTION="JABBER — Red Teaming Suite"
INSTALL_DIR="/opt/jabber"

# Working directories
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${SCRIPT_DIR}/build-deb"
PKG_DIR="${BUILD_DIR}/${PACKAGE}_${VERSION}"

# Colours
R='\033[0;31m' G='\033[0;32m' B='\033[0;34m' Y='\033[1;33m'
W='\033[1;37m' NC='\033[0m'

echo ""
echo -e "${R}╔══════════════════════════════════════════╗${NC}"
echo -e "${R}║${W}   JABBER .deb Package Builder v3.2       ${R}║${NC}"
echo -e "${R}║${B}   Version: ${VERSION}                        ${R}║${NC}"
echo -e "${R}╚══════════════════════════════════════════╝${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════
# Phase 1: Clean
# ═══════════════════════════════════════════════════════════════
echo -e "${B}[1/8] Cleaning previous builds...${NC}"
rm -rf "${BUILD_DIR}"
mkdir -p "${PKG_DIR}"
echo -e "${G}  ✓ Clean${NC}"

# ═══════════════════════════════════════════════════════════════
# Phase 2: Build Backend
# ═══════════════════════════════════════════════════════════════
echo -e "${B}[2/8] Building backend (Spring Boot JAR)...${NC}"
cd "${PROJECT_ROOT}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-/home/$(whoami)/.gradle_jrts}"
./gradlew --project-cache-dir "${GRADLE_USER_HOME}/project_cache" \
  :jrts-core:bootJar -x test --no-daemon -q 2>&1

BOOT_JAR=$(find . -name "*.jar" -path "*/jrts-core/*" -not -name "*-plain*" | head -1)
if [ -z "$BOOT_JAR" ]; then
    echo -e "${R}Error: bootJar not found!${NC}"
    exit 1
fi
echo -e "${G}  ✓ Backend: ${BOOT_JAR}${NC}"

# ═══════════════════════════════════════════════════════════════
# Phase 3: Build Frontend
# ═══════════════════════════════════════════════════════════════
echo -e "${B}[3/8] Building frontend (Vite production)...${NC}"
cd "${PROJECT_ROOT}/jrts-ui"
npm ci --silent 2>&1
npm run build 2>&1
if [ ! -d "dist" ]; then
    echo -e "${R}Error: Frontend build failed!${NC}"
    exit 1
fi
echo -e "${G}  ✓ Frontend built${NC}"

# ═══════════════════════════════════════════════════════════════
# Phase 4: Bundle Electron (Option A — instant desktop launch)
# ═══════════════════════════════════════════════════════════════
echo -e "${B}[4/8] Bundling Electron for instant desktop launch...${NC}"
cd "${PROJECT_ROOT}/jrts-ui"

# Create a minimal package.json for the installed electron
ELECTRON_VERSION=$(node -e "console.log(require('./package.json').devDependencies.electron.replace('^',''))")
echo -e "${B}  Electron version: ${ELECTRON_VERSION}${NC}"

# We'll install electron into a staging area
ELECTRON_STAGING="${BUILD_DIR}/electron-staging"
mkdir -p "${ELECTRON_STAGING}"
cd "${ELECTRON_STAGING}"
cat > package.json << EPKG
{
  "name": "jabber-electron",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "electron": "${ELECTRON_VERSION}"
  }
}
EPKG
npm install --production 2>&1
echo -e "${G}  ✓ Electron bundled${NC}"

# ═══════════════════════════════════════════════════════════════
# Phase 5: Assemble
# ═══════════════════════════════════════════════════════════════
echo -e "${B}[5/8] Assembling package...${NC}"
cd "${PROJECT_ROOT}"

mkdir -p "${PKG_DIR}${INSTALL_DIR}"
mkdir -p "${PKG_DIR}${INSTALL_DIR}/lib"
mkdir -p "${PKG_DIR}${INSTALL_DIR}/ui/dist"
mkdir -p "${PKG_DIR}${INSTALL_DIR}/ui/electron"
mkdir -p "${PKG_DIR}${INSTALL_DIR}/logs"
mkdir -p "${PKG_DIR}/usr/local/bin"
mkdir -p "${PKG_DIR}/usr/share/applications"
mkdir -p "${PKG_DIR}/usr/share/pixmaps"
mkdir -p "${PKG_DIR}/DEBIAN"

# Backend JAR
cp "${BOOT_JAR}" "${PKG_DIR}${INSTALL_DIR}/lib/jrts-server.jar"

# Frontend build → /opt/jabber/ui/dist/ (preserves path Electron expects)
cp -r jrts-ui/dist/* "${PKG_DIR}${INSTALL_DIR}/ui/dist/"

# Electron main process
cp jrts-ui/electron/main.cjs "${PKG_DIR}${INSTALL_DIR}/ui/electron/"

# Minimal package.json for Electron (tells it where main is)
cat > "${PKG_DIR}${INSTALL_DIR}/ui/package.json" << 'PKGJSON'
{
  "name": "jabber",
  "version": "3.2.0",
  "main": "electron/main.cjs",
  "description": "JABBER Red Teaming Suite"
}
PKGJSON

# Bundled Electron node_modules (for instant launch)
cp -r "${ELECTRON_STAGING}/node_modules" "${PKG_DIR}${INSTALL_DIR}/ui/"

# Icon / logo
if [ -f "jrts-ui/public/jabber.png" ]; then
    cp jrts-ui/public/jabber.png "${PKG_DIR}/usr/share/pixmaps/jabber.png"
    cp jrts-ui/public/jabber.png "${PKG_DIR}${INSTALL_DIR}/jabber.png"
    cp jrts-ui/public/jabber.png "${PKG_DIR}${INSTALL_DIR}/ui/jabber.png"
elif [ -f "jabber.png" ]; then
    cp jabber.png "${PKG_DIR}/usr/share/pixmaps/jabber.png"
    cp jabber.png "${PKG_DIR}${INSTALL_DIR}/jabber.png"
    cp jabber.png "${PKG_DIR}${INSTALL_DIR}/ui/jabber.png"
fi

# ── Installed run.sh ─────────────────────────────────────────
cat > "${PKG_DIR}${INSTALL_DIR}/run.sh" << 'RUNEOF'
#!/bin/bash
# ============================================================
# JABBER Red Teaming Suite — Unified Launcher v3.2 (installed)
# ============================================================
set -euo pipefail

JABBER_HOME="/opt/jabber"
APP_DATA="${HOME}/.jabber"
LOG_DIR="${APP_DATA}/logs"
BACKEND_PORT=8314

R='\033[0;31m' G='\033[0;32m' B='\033[0;34m' Y='\033[1;33m'
C='\033[0;36m' W='\033[1;37m' NC='\033[0m'

banner() {
  echo ""
  echo -e "${R}     ╦╔═╗╔╗ ╔╗ ╔═╗╦═╗${NC}"
  echo -e "${R}     ║╠═╣╠╩╗╠╩╗║╣ ╠╦╝${NC}"
  echo -e "${R}    ╚╝╩ ╩╚═╝╚═╝╚═╝╩╚═${NC}"
  echo -e "${W}    Red Teaming Suite V3.2${NC}"
  echo -e "${C}    Created by Funbinet${NC}"
  echo ""
}

log()  { echo -e "${B}[$(date +%H:%M:%S)]${NC} $1"; }
ok()   { echo -e "${G}[$(date +%H:%M:%S)] ✓${NC} $1"; }
warn() { echo -e "${Y}[$(date +%H:%M:%S)] ⚠${NC} $1"; }
fail() { echo -e "${R}[$(date +%H:%M:%S)] ✗${NC} $1"; }
die()  { fail "$1"; exit 1; }

pid_running() { [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; }

port_in_use() { lsof -i :"$1" -sTCP:LISTEN &>/dev/null 2>&1; }

start_backend() {
  if port_in_use ${BACKEND_PORT}; then
    if curl -sf "http://localhost:${BACKEND_PORT}/api/info" > /dev/null 2>&1; then
      [ "${QUIET:-0}" != "1" ] && ok "Backend already online — port ${BACKEND_PORT}"
      return 0
    fi
  fi

  [ "${QUIET:-0}" != "1" ] && log "Starting backend on port ${BACKEND_PORT}..."

  cd "${JABBER_HOME}"
  nohup java -jar "${JABBER_HOME}/lib/jrts-server.jar" \
    --spring.datasource.url="jdbc:h2:file:${APP_DATA}/jrts-data/jrts-db;DB_CLOSE_ON_EXIT=FALSE" \
    --jrts.reports.base-dir="${APP_DATA}/reports" \
    --spring.web.resources.static-locations="file:${JABBER_HOME}/ui/dist/" \
    > "${LOG_DIR}/backend.log" 2>&1 &
  local PID=$!
  echo "$PID" > "${LOG_DIR}/backend.pid"

  local max=90 i=0
  while [ $i -lt $max ]; do
    if curl -sf "http://localhost:${BACKEND_PORT}/api/info" > /dev/null 2>&1; then
      [ "${QUIET:-0}" != "1" ] && ok "Backend online — port ${BACKEND_PORT}"
      return 0
    fi
    if ! pid_running "$PID"; then
      [ "${QUIET:-0}" != "1" ] && fail "Backend died. Check ${LOG_DIR}/backend.log"
      return 1
    fi
    sleep 1
    i=$((i + 1))
  done
  [ "${QUIET:-0}" != "1" ] && fail "Backend timeout after ${max}s"
  return 1
}

launch_desktop() {
  cd "${JABBER_HOME}/ui"

  local ELECTRON_BIN="${JABBER_HOME}/ui/node_modules/.bin/electron"
  if [ ! -x "$ELECTRON_BIN" ]; then
    ELECTRON_BIN="${JABBER_HOME}/ui/node_modules/electron/dist/electron"
  fi

  if [ ! -f "$ELECTRON_BIN" ] && ! command -v electron &>/dev/null; then
    die "Electron not found. Reinstall jabber package."
  fi

  nohup "$ELECTRON_BIN" . > "${LOG_DIR}/desktop.log" 2>&1 &
  local PID=$!
  echo "$PID" > "${LOG_DIR}/desktop.pid"
}

open_browser() {
  local url="http://localhost:${BACKEND_PORT}"
  if command -v xdg-open &>/dev/null; then
    nohup xdg-open "$url" > /dev/null 2>&1 &
  elif command -v sensible-browser &>/dev/null; then
    nohup sensible-browser "$url" > /dev/null 2>&1 &
  elif command -v firefox &>/dev/null; then
    nohup firefox "$url" > /dev/null 2>&1 &
  elif command -v chromium-browser &>/dev/null; then
    nohup chromium-browser "$url" > /dev/null 2>&1 &
  else
    warn "No browser found. Open manually: ${url}"
  fi
}

cleanup() {
  echo ""
  warn "Shutting down..."
  "${JABBER_HOME}/stop.sh" 2>/dev/null || true
  exit 0
}
trap cleanup SIGINT SIGTERM

mkdir -p "${LOG_DIR}"

MODE="${1:-desk}"

case "$MODE" in
  desk|desktop)
    # === DESKTOP MODE ===
    # Completely silent when launched via CLI wrapper
    # Backend starts in background, Electron loads file:// directly
    QUIET=1
    start_backend || die "Backend failed"
    launch_desktop

    # Wait for desktop window to close, then clean up
    local_pid=$(cat "${LOG_DIR}/desktop.pid" 2>/dev/null || echo "")
    if [ -n "$local_pid" ] && pid_running "$local_pid"; then
      wait "$local_pid" 2>/dev/null || true
      "${JABBER_HOME}/stop.sh" > /dev/null 2>&1 || true
    fi
    ;;

  web|browser)
    # === WEB BROWSER MODE ===
    # Shows status output, opens browser to backend URL
    banner
    log "Mode: ${W}WEB BROWSER${NC}"

    start_backend || die "Backend failed to start"

    # No separate frontend server needed!
    # Backend serves both API and static files on port 8314
    ok "Frontend ready — served by backend on port ${BACKEND_PORT}"

    open_browser
    echo ""
    ok "JABBER running in browser mode"
    log "Dashboard → http://localhost:${BACKEND_PORT}"
    log "API       → http://localhost:${BACKEND_PORT}/api/info"
    echo ""
    log "Press Ctrl+C to stop, or run: ${W}jabber stop${NC}"
    echo ""

    # Keep script alive for Ctrl+C cleanup
    while true; do sleep 3600; done &
    wait
    ;;

  status)
    echo ""
    echo -e "${W}JABBER Service Status${NC}"
    echo "─────────────────────────────────────"
    if [ -f "${LOG_DIR}/backend.pid" ] && pid_running "$(cat "${LOG_DIR}/backend.pid" 2>/dev/null)"; then
      ok "Backend: running (PID $(cat "${LOG_DIR}/backend.pid"))"
      if curl -sf "http://localhost:${BACKEND_PORT}/api/info" > /dev/null 2>&1; then
        ok "API: healthy"
      fi
    else
      fail "Backend: not running"
    fi
    if [ -f "${LOG_DIR}/desktop.pid" ] && pid_running "$(cat "${LOG_DIR}/desktop.pid" 2>/dev/null)"; then
      ok "Desktop: running (PID $(cat "${LOG_DIR}/desktop.pid"))"
    else
      echo "   Desktop: not running"
    fi
    echo ""
    ;;

  *)
    echo ""
    echo -e "${W}JABBER${NC} — Red Teaming Suite V3.2"
    echo ""
    echo "Usage: jabber [command]"
    echo ""
    echo "  (none)     Launch desktop mode (Electron)"
    echo "  web        Launch browser mode"
    echo "  stop       Stop all services"
    echo "  status     Show service status"
    echo ""
    ;;
esac
RUNEOF
chmod +x "${PKG_DIR}${INSTALL_DIR}/run.sh"

# ── Installed stop.sh ────────────────────────────────────────
cat > "${PKG_DIR}${INSTALL_DIR}/stop.sh" << 'STOPEOF'
#!/bin/bash
# ============================================================
# JABBER Red Teaming Suite — Graceful Shutdown v3.2
# Created by Funbinet (dancan.tech)
# ============================================================

JABBER_HOME="/opt/jabber"
APP_DATA="${HOME}/.jabber"
LOG_DIR="${APP_DATA}/logs"
BACKEND_PORT=8314

R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' W='\033[1;37m' NC='\033[0m'

ok()   { echo -e "${G}[$(date +%H:%M:%S)] ✓${NC} $1"; }
warn() { echo -e "${Y}[$(date +%H:%M:%S)] ⚠${NC} $1"; }
log()  { echo -e "${W}[$(date +%H:%M:%S)]${NC} $1"; }

kill_service() {
  local name="$1"
  local pidfile="${LOG_DIR}/${name}.pid"
  [ ! -f "$pidfile" ] && return 0
  local PID
  PID=$(cat "$pidfile" 2>/dev/null)
  [ -z "$PID" ] && { rm -f "$pidfile"; return 0; }

  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null
    # Wait up to 5 seconds for graceful shutdown
    local i=0
    while [ $i -lt 50 ]; do
      if ! kill -0 "$PID" 2>/dev/null; then
        ok "Stopped ${name} (PID ${PID})"
        rm -f "$pidfile"
        return 0
      fi
      sleep 0.1
      i=$((i + 1))
    done
    # Force kill if still alive
    kill -9 "$PID" 2>/dev/null || true
    ok "Force-stopped ${name} (PID ${PID})"
  else
    log "${name} already stopped"
  fi
  rm -f "$pidfile"
}

echo ""
echo -e "${R}Stopping JABBER...${NC}"
echo "─────────────────────────────────────"

# Phase 1: Stop by PID files
kill_service "desktop"
kill_service "frontend"
kill_service "backend"

# Phase 2: Kill residual Java processes
if pgrep -f "jrts-server" > /dev/null 2>&1; then
  pkill -f "jrts-server" 2>/dev/null || true
  sleep 1
  pgrep -f "jrts-server" > /dev/null 2>&1 && pkill -9 -f "jrts-server" 2>/dev/null
  ok "Terminated residual Java processes"
fi

# Phase 3: Final port sweep
for port in ${BACKEND_PORT}; do
  if lsof -ti :"$port" -sTCP:LISTEN 2>/dev/null > /dev/null; then
    lsof -ti :"$port" -sTCP:LISTEN | xargs kill -9 2>/dev/null || true
    ok "Cleared port ${port}"
  fi
done

echo ""
ok "All JABBER services stopped."
echo ""
STOPEOF
chmod +x "${PKG_DIR}${INSTALL_DIR}/stop.sh"

echo -e "${G}  ✓ Package assembled${NC}"

# ═══════════════════════════════════════════════════════════════
# Phase 6: DEBIAN control files
# ═══════════════════════════════════════════════════════════════
echo -e "${B}[6/8] Creating DEBIAN metadata...${NC}"

cat > "${PKG_DIR}/DEBIAN/control" << EOF
Package: ${PACKAGE}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Depends: openjdk-21-jre | openjdk-17-jre
Recommends: nodejs (>= 18), npm, lsof
Maintainer: ${MAINTAINER}
Description: ${DESCRIPTION}
 JABBER is a production-grade offensive security platform featuring
 modular security tools across 19+ attack categories including
 reconnaissance, exploitation, wireless hacking, C2, and more.
 .
 V3.2 — stabilized desktop launch, eliminated frontend timeouts,
 unified backend+frontend serving, instant Electron startup.
 Created by Funbinet (dancan.tech).
EOF

echo -e "${G}  ✓ DEBIAN/control${NC}"

# ═══════════════════════════════════════════════════════════════
# Phase 7: CLI wrapper + .desktop entry + maintainer scripts
# ═══════════════════════════════════════════════════════════════
echo -e "${B}[7/8] Creating CLI wrapper and desktop entry...${NC}"

# /usr/local/bin/jabber — the main CLI command
cat > "${PKG_DIR}/usr/local/bin/jabber" << 'CLIEOF'
#!/bin/bash
# ============================================================
# JABBER — CLI Command v3.2
# Usage:
#   jabber          → Desktop mode (silent, GUI-only, instant)
#   jabber web      → Browser mode (auto-opens localhost)
#   jabber stop     → Stop all services
#   jabber status   → Show service status
# Created by Funbinet (dancan.tech)
# ============================================================

JABBER_HOME="/opt/jabber"

case "${1:-}" in
  stop)
    exec "${JABBER_HOME}/stop.sh"
    ;;
  web|browser)
    exec "${JABBER_HOME}/run.sh" web
    ;;
  status)
    exec "${JABBER_HOME}/run.sh" status
    ;;
  -h|--help|help)
    echo ""
    echo "JABBER — Red Teaming Suite V3.2"
    echo "Created by Funbinet (dancan.tech)"
    echo ""
    echo "Usage:"
    echo "  jabber            Launch desktop mode (silent, instant)"
    echo "  jabber web        Launch browser mode (auto-opens localhost)"
    echo "  jabber stop       Stop all running services"
    echo "  jabber status     Show service status"
    echo ""
    ;;
  ""|desk|desktop)
    # DESKTOP MODE: completely silent, GUI-only
    # Launch in background, detach from terminal entirely
    nohup "${JABBER_HOME}/run.sh" desk > /dev/null 2>&1 &
    disown
    # Exit immediately — terminal is free
    exit 0
    ;;
  *)
    echo "Unknown command: $1"
    echo "Run 'jabber --help' for usage"
    exit 1
    ;;
esac
CLIEOF
chmod +x "${PKG_DIR}/usr/local/bin/jabber"

# .desktop entry for application menu launcher
cat > "${PKG_DIR}/usr/share/applications/jabber.desktop" << 'DESKTOPEOF'
[Desktop Entry]
Name=JABBER
Comment=JABBER Red Teaming Suite V3.2
Exec=/opt/jabber/run.sh desk
Icon=jabber
Terminal=false
Type=Application
Categories=Utility;Security;System;
Keywords=security;pentesting;hacking;red-team;offensive;
StartupNotify=true
StartupWMClass=jabber
DESKTOPEOF

# postinst
cat > "${PKG_DIR}/DEBIAN/postinst" << 'POSTEOF'
#!/bin/bash
set -e

# Ensure permissions
chown -R root:root /opt/jabber
chmod -R 755 /opt/jabber
chmod +x /opt/jabber/run.sh /opt/jabber/stop.sh
mkdir -p /opt/jabber/logs
chmod 777 /opt/jabber/logs

# Make electron binary executable
if [ -f "/opt/jabber/ui/node_modules/electron/dist/electron" ]; then
    chmod +x /opt/jabber/ui/node_modules/electron/dist/electron
fi

# Update desktop database
if command -v update-desktop-database &>/dev/null; then
    update-desktop-database /usr/share/applications/ 2>/dev/null || true
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   JABBER v3.2 installed successfully!    ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "  Commands:"
echo "    jabber          Desktop mode (instant, silent)"
echo "    jabber web      Browser mode (auto-opens)"
echo "    jabber stop     Stop all services"
echo "    jabber status   Check service status"
echo ""
echo "  Created by Funbinet (dancan.tech)"
echo ""
POSTEOF
chmod +x "${PKG_DIR}/DEBIAN/postinst"

# prerm
cat > "${PKG_DIR}/DEBIAN/prerm" << 'PRERMEOF'
#!/bin/bash
set -e

# Stop services before removal
if [ -x "/opt/jabber/stop.sh" ]; then
    /opt/jabber/stop.sh 2>/dev/null || true
fi
PRERMEOF
chmod +x "${PKG_DIR}/DEBIAN/prerm"

# postrm
cat > "${PKG_DIR}/DEBIAN/postrm" << 'POSTRMEOF'
#!/bin/bash
set -e

if [ "$1" = "purge" ] || [ "$1" = "remove" ]; then
    rm -rf /opt/jabber/logs
    # Clean up desktop entry cache
    if command -v update-desktop-database &>/dev/null; then
        update-desktop-database /usr/share/applications/ 2>/dev/null || true
    fi
fi
POSTRMEOF
chmod +x "${PKG_DIR}/DEBIAN/postrm"

echo -e "${G}  ✓ CLI wrapper, .desktop entry, and maintainer scripts${NC}"

# ═══════════════════════════════════════════════════════════════
# Phase 8: Build .deb
# ═══════════════════════════════════════════════════════════════
echo -e "${B}[8/8] Building .deb package...${NC}"
DEB_FILE="${BUILD_DIR}/${PACKAGE}_v${VERSION}.deb"
dpkg-deb --build "${PKG_DIR}" "${DEB_FILE}" 2>&1

if [ -f "${DEB_FILE}" ]; then
    SIZE=$(du -h "${DEB_FILE}" | cut -f1)
    echo ""
    echo -e "${G}╔══════════════════════════════════════════╗${NC}"
    echo -e "${G}║   Build Complete!                        ║${NC}"
    echo -e "${G}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Package:  ${W}${DEB_FILE}${NC}"
    echo -e "  Size:     ${W}${SIZE}${NC}"
    echo ""
    echo -e "  Install:  ${Y}sudo dpkg -i ${DEB_FILE}${NC}"
    echo -e "  Run:      ${Y}jabber${NC}  or  ${Y}jabber web${NC}"
    echo ""
else
    echo -e "${R}Build failed!${NC}"
    exit 1
fi
