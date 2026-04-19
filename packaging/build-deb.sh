#!/bin/bash
# ============================================================
# JABBER Debian Package Builder
# Builds a production-ready .deb for the JABBER Red Teaming Suite
# Usage: ./build-deb.sh [version]
# Created by Funbinet (dancan.tech)
# ============================================================
set -e

VERSION="${1:-3.0.0}"
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
echo -e "${R}║${W}   JABBER .deb Package Builder             ${R}║${NC}"
echo -e "${R}║${B}   Version: ${VERSION}                          ${R}║${NC}"
echo -e "${R}╚══════════════════════════════════════════╝${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════
# Phase 1: Clean
# ═══════════════════════════════════════════════════════════════
echo -e "${B}[1/7] Cleaning previous builds...${NC}"
rm -rf "${BUILD_DIR}"
mkdir -p "${PKG_DIR}"
echo -e "${G}  ✓ Clean${NC}"

# ═══════════════════════════════════════════════════════════════
# Phase 2: Build Backend
# ═══════════════════════════════════════════════════════════════
echo -e "${B}[2/7] Building backend (Spring Boot JAR)...${NC}"
cd "${PROJECT_ROOT}"
GRADLE_USER_HOME=${GRADLE_USER_HOME:-/home/$(whoami)/.gradle_jrts} \
  ./gradlew :jrts-core:bootJar -x test --no-daemon -q 2>&1

BOOT_JAR=$(find . -name "*.jar" -path "*/jrts-core/*" -not -name "*-plain*" | head -1)
if [ -z "$BOOT_JAR" ]; then
    echo -e "${R}Error: bootJar not found!${NC}"
    exit 1
fi
echo -e "${G}  ✓ Backend: ${BOOT_JAR}${NC}"

# ═══════════════════════════════════════════════════════════════
# Phase 3: Build Frontend
# ═══════════════════════════════════════════════════════════════
echo -e "${B}[3/7] Building frontend (Vite production)...${NC}"
cd "${PROJECT_ROOT}/jrts-ui"
npm ci --silent 2>&1
npm run build 2>&1
if [ ! -d "dist" ]; then
    echo -e "${R}Error: Frontend build failed!${NC}"
    exit 1
fi
echo -e "${G}  ✓ Frontend built${NC}"

# ═══════════════════════════════════════════════════════════════
# Phase 4: Assemble
# ═══════════════════════════════════════════════════════════════
echo -e "${B}[4/7] Assembling package...${NC}"
cd "${PROJECT_ROOT}"

mkdir -p "${PKG_DIR}${INSTALL_DIR}"
mkdir -p "${PKG_DIR}${INSTALL_DIR}/lib"
mkdir -p "${PKG_DIR}${INSTALL_DIR}/ui"
mkdir -p "${PKG_DIR}${INSTALL_DIR}/ui/electron"
mkdir -p "${PKG_DIR}${INSTALL_DIR}/logs"
mkdir -p "${PKG_DIR}/usr/local/bin"
mkdir -p "${PKG_DIR}/usr/share/applications"
mkdir -p "${PKG_DIR}/usr/share/pixmaps"
mkdir -p "${PKG_DIR}/DEBIAN"

# Backend JAR
cp "${BOOT_JAR}" "${PKG_DIR}${INSTALL_DIR}/lib/jrts-server.jar"

# Frontend build
cp -r jrts-ui/dist/* "${PKG_DIR}${INSTALL_DIR}/ui/"
cp -r jrts-ui/electron "${PKG_DIR}${INSTALL_DIR}/ui/"
cp jrts-ui/package.json "${PKG_DIR}${INSTALL_DIR}/ui/"

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

# Startup scripts (adjusted for installed paths)
cat > "${PKG_DIR}${INSTALL_DIR}/run.sh" << 'RUNEOF'
#!/bin/bash
# JABBER — Unified Launcher (installed version)
set -euo pipefail

JABBER_HOME="/opt/jabber"
LOG_DIR="${JABBER_HOME}/logs"
BACKEND_PORT=8314
FRONTEND_PORT=5173
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-/root/.gradle_jrts}"

R='\033[0;31m' G='\033[0;32m' B='\033[0;34m' Y='\033[1;33m'
C='\033[0;36m' W='\033[1;37m' NC='\033[0m'

banner() {
  echo ""
  echo -e "${R}     ╦╔═╗╔╗ ╔╗ ╔═╗╦═╗${NC}"
  echo -e "${R}     ║╠═╣╠╩╗╠╩╗║╣ ╠╦╝${NC}"
  echo -e "${R}    ╚╝╩ ╩╚═╝╚═╝╚═╝╩╚═${NC}"
  echo -e "${W}    Red Teaming Suite V3${NC}"
  echo -e "${C}    Created by Funbinet${NC}"
  echo ""
}

log()  { echo -e "${B}[$(date +%H:%M:%S)]${NC} $1"; }
ok()   { echo -e "${G}[$(date +%H:%M:%S)] ✓${NC} $1"; }
warn() { echo -e "${Y}[$(date +%H:%M:%S)] ⚠${NC} $1"; }
fail() { echo -e "${R}[$(date +%H:%M:%S)] ✗${NC} $1"; }
die()  { fail "$1"; exit 1; }

pid_running() { [ -n "$1" ] && kill -0 "$1" 2>/dev/null; }

ensure_dirs() { mkdir -p "${LOG_DIR}"; }

port_in_use() { lsof -i :"$1" -sTCP:LISTEN &>/dev/null 2>&1; }

start_backend() {
  log "Starting backend on port ${BACKEND_PORT}..."
  if port_in_use ${BACKEND_PORT}; then
    warn "Port ${BACKEND_PORT} occupied — backend may be running."
    return 0
  fi
  cd "${JABBER_HOME}"
  nohup java -jar "${JABBER_HOME}/lib/jrts-server.jar" \
    > "${LOG_DIR}/backend.log" 2>&1 &
  local PID=$!
  echo "$PID" > "${LOG_DIR}/backend.pid"
  local max=90 i=0
  while [ $i -lt $max ]; do
    if curl -sf "http://localhost:${BACKEND_PORT}/api/info" > /dev/null 2>&1; then
      ok "Backend online — port ${BACKEND_PORT}"
      return 0
    fi
    if ! pid_running "$PID"; then
      fail "Backend died. Check ${LOG_DIR}/backend.log"
      return 1
    fi
    sleep 1; i=$((i + 1))
  done
  fail "Backend timeout after ${max}s"
  return 1
}

start_frontend() {
  log "Starting frontend on port ${FRONTEND_PORT}..."
  if port_in_use ${FRONTEND_PORT}; then
    warn "Port ${FRONTEND_PORT} occupied — frontend may be running."
    return 0
  fi
  cd "${JABBER_HOME}/ui"
  nohup npx vite preview --port ${FRONTEND_PORT} \
    > "${LOG_DIR}/frontend.log" 2>&1 &
  local PID=$!
  echo "$PID" > "${LOG_DIR}/frontend.pid"
  local max=30 i=0
  while [ $i -lt $max ]; do
    if curl -sf "http://localhost:${FRONTEND_PORT}" > /dev/null 2>&1; then
      ok "Frontend online — http://localhost:${FRONTEND_PORT}"
      return 0
    fi
    if ! pid_running "$PID"; then
      fail "Frontend died. Check ${LOG_DIR}/frontend.log"
      return 1
    fi
    sleep 1; i=$((i + 1))
  done
  fail "Frontend timeout after ${max}s"
  return 1
}

launch_desktop() {
  log "Launching desktop..."
  cd "${JABBER_HOME}/ui"
  nohup npx electron . > "${LOG_DIR}/desktop.log" 2>&1 &
  echo $! > "${LOG_DIR}/desktop.pid"
  ok "Desktop launched (PID $(cat "${LOG_DIR}/desktop.pid"))"
}

open_browser() {
  local url="http://localhost:${FRONTEND_PORT}"
  log "Opening browser → ${url}"
  if command -v xdg-open &>/dev/null; then
    nohup xdg-open "$url" > /dev/null 2>&1 &
  elif command -v firefox &>/dev/null; then
    nohup firefox "$url" > /dev/null 2>&1 &
  else
    warn "Open manually: ${url}"
  fi
}

cleanup() {
  echo ""
  warn "Shutting down..."
  "${JABBER_HOME}/stop.sh" 2>/dev/null || true
  exit 0
}
trap cleanup SIGINT SIGTERM

MODE="${1:-desk}"

case "$MODE" in
  desk|desktop)
    banner
    log "Mode: ${W}DESKTOP${NC}"
    ensure_dirs
    start_backend || die "Backend failed"
    start_frontend || die "Frontend failed"
    launch_desktop
    echo ""
    ok "JABBER running in desktop mode"
    log "Ctrl+C or 'jabber stop' to shutdown"
    echo ""
    DESK_PID=$(cat "${LOG_DIR}/desktop.pid" 2>/dev/null || echo "")
    if [ -n "$DESK_PID" ] && pid_running "$DESK_PID"; then
      wait "$DESK_PID" 2>/dev/null || true
      "${JABBER_HOME}/stop.sh" 2>/dev/null || true
    else
      wait
    fi
    ;;
  web|browser)
    banner
    log "Mode: ${W}WEB BROWSER${NC}"
    ensure_dirs
    start_backend || die "Backend failed"
    start_frontend || die "Frontend failed"
    open_browser
    echo ""
    ok "JABBER running in browser mode"
    log "Ctrl+C or 'jabber stop' to shutdown"
    echo ""
    wait
    ;;
  status)
    echo ""
    echo -e "${W}JABBER Service Status${NC}"
    if [ -f "${LOG_DIR}/backend.pid" ] && pid_running "$(cat "${LOG_DIR}/backend.pid" 2>/dev/null)"; then
      ok "Backend: running"
    else fail "Backend: not running"; fi
    if [ -f "${LOG_DIR}/frontend.pid" ] && pid_running "$(cat "${LOG_DIR}/frontend.pid" 2>/dev/null)"; then
      ok "Frontend: running"
    else fail "Frontend: not running"; fi
    echo ""
    ;;
  *)
    echo "JABBER — Red Teaming Suite V3"
    echo ""
    echo "Usage: jabber [desk|web|stop|status]"
    echo ""
    ;;
esac
RUNEOF
chmod +x "${PKG_DIR}${INSTALL_DIR}/run.sh"

# Stop script for installed version
cat > "${PKG_DIR}${INSTALL_DIR}/stop.sh" << 'STOPEOF'
#!/bin/bash
# JABBER — Graceful Shutdown (installed version)

JABBER_HOME="/opt/jabber"
LOG_DIR="${JABBER_HOME}/logs"
BACKEND_PORT=8314
FRONTEND_PORT=5173

R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' W='\033[1;37m' NC='\033[0m'
ok()   { echo -e "${G}[$(date +%H:%M:%S)] ✓${NC} $1"; }
log()  { echo -e "${W}[$(date +%H:%M:%S)]${NC} $1"; }

kill_service() {
  local name="$1" pidfile="${LOG_DIR}/${name}.pid"
  [ ! -f "$pidfile" ] && return 0
  local PID; PID=$(cat "$pidfile" 2>/dev/null)
  [ -z "$PID" ] && { rm -f "$pidfile"; return 0; }
  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null
    local i=0
    while [ $i -lt 50 ]; do
      kill -0 "$PID" 2>/dev/null || break
      sleep 0.1; i=$((i + 1))
    done
    kill -0 "$PID" 2>/dev/null && kill -9 "$PID" 2>/dev/null
    ok "Stopped ${name} (PID ${PID})"
  else
    log "${name} already stopped"
  fi
  rm -f "$pidfile"
}

echo ""
echo -e "${R}Stopping JABBER...${NC}"
kill_service "desktop"
kill_service "frontend"
kill_service "backend"

# Kill residual Java
pgrep -f "jrts-server" > /dev/null 2>&1 && { pkill -f "jrts-server" 2>/dev/null; sleep 1; pkill -9 -f "jrts-server" 2>/dev/null; ok "Killed residual Java"; }

# Port sweep
for port in ${BACKEND_PORT} ${FRONTEND_PORT}; do
  lsof -ti :"$port" -sTCP:LISTEN 2>/dev/null | xargs kill -9 2>/dev/null || true
done

echo ""
ok "All JABBER services stopped."
echo ""
STOPEOF
chmod +x "${PKG_DIR}${INSTALL_DIR}/stop.sh"

echo -e "${G}  ✓ Package assembled${NC}"

# ═══════════════════════════════════════════════════════════════
# Phase 5: DEBIAN control files
# ═══════════════════════════════════════════════════════════════
echo -e "${B}[5/7] Creating DEBIAN metadata...${NC}"

cat > "${PKG_DIR}/DEBIAN/control" << EOF
Package: ${PACKAGE}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Depends: openjdk-21-jre | openjdk-17-jre
Recommends: nodejs (>= 18), npm
Maintainer: ${MAINTAINER}
Description: ${DESCRIPTION}
 JABBER is a production-grade offensive security platform featuring
 modular security tools across 19+ attack categories including
 reconnaissance, exploitation, wireless hacking, C2, and more.
 .
 V3 — unified output management, target profiling, and 30 exploitation modules.
 Created by Funbinet (dancan.tech).
EOF

echo -e "${G}  ✓ DEBIAN/control${NC}"

# ═══════════════════════════════════════════════════════════════
# Phase 6: CLI wrapper + .desktop entry + maintainer scripts
# ═══════════════════════════════════════════════════════════════
echo -e "${B}[6/7] Creating CLI wrapper and desktop entry...${NC}"

# /usr/local/bin/jabber
cat > "${PKG_DIR}/usr/local/bin/jabber" << 'EOF'
#!/bin/bash
# JABBER — CLI Command
# Usage:
#   jabber          → Desktop mode (Electron + backend)
#   jabber web      → Browser mode (auto-opens localhost)
#   jabber stop     → Stop all services
#   jabber status   → Show service status

JABBER_HOME="/opt/jabber"

case "${1:-desk}" in
  stop)
    exec "${JABBER_HOME}/stop.sh"
    ;;
  desk|desktop|web|browser|status)
    exec "${JABBER_HOME}/run.sh" "$@"
    ;;
  -h|--help|help)
    echo ""
    echo "JABBER — Red Teaming Suite V3"
    echo "Created by Funbinet (dancan.tech)"
    echo ""
    echo "Usage:"
    echo "  jabber            Launch desktop mode (Electron)"
    echo "  jabber web        Launch browser mode (auto-opens localhost)"
    echo "  jabber stop       Stop all running services"
    echo "  jabber status     Show service status"
    echo ""
    ;;
  *)
    exec "${JABBER_HOME}/run.sh" "$@"
    ;;
esac
EOF
chmod +x "${PKG_DIR}/usr/local/bin/jabber"

# .desktop entry
cat > "${PKG_DIR}/usr/share/applications/jabber.desktop" << EOF
[Desktop Entry]
Name=JABBER
Comment=JABBER Red Teaming Suite V3
Exec=jabber
Icon=jabber
Terminal=true
Type=Application
Categories=Utility;Security;System;
Keywords=security;pentesting;hacking;red-team;offensive;
StartupNotify=true
EOF

# postinst
cat > "${PKG_DIR}/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

# Ensure permissions
chown -R root:root /opt/jabber
chmod -R 755 /opt/jabber
chmod +x /opt/jabber/run.sh /opt/jabber/stop.sh
mkdir -p /opt/jabber/logs

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   JABBER installed successfully!         ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "  Commands:"
echo "    jabber          Desktop mode"
echo "    jabber web      Browser mode"
echo "    jabber stop     Stop services"
echo "    jabber status   Check status"
echo ""
echo "  Created by Funbinet (dancan.tech)"
echo ""
EOF
chmod +x "${PKG_DIR}/DEBIAN/postinst"

# prerm
cat > "${PKG_DIR}/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e

# Stop services before removal
if [ -x "/opt/jabber/stop.sh" ]; then
    /opt/jabber/stop.sh 2>/dev/null || true
fi
EOF
chmod +x "${PKG_DIR}/DEBIAN/prerm"

# postrm
cat > "${PKG_DIR}/DEBIAN/postrm" << 'EOF'
#!/bin/bash
set -e

if [ "$1" = "purge" ]; then
    rm -rf /opt/jabber/logs
fi
EOF
chmod +x "${PKG_DIR}/DEBIAN/postrm"

echo -e "${G}  ✓ CLI wrapper, .desktop entry, and maintainer scripts created${NC}"

# ═══════════════════════════════════════════════════════════════
# Phase 7: Build .deb
# ═══════════════════════════════════════════════════════════════
echo -e "${B}[7/7] Building .deb package...${NC}"
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
