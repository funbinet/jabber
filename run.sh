#!/bin/bash
# ============================================================
# JABBER — Unified Launcher V5.5 (production)
# Modes:  desk (default)  |  web  |  status
# Created by Funbinet (dancan.tech)
# ============================================================
set -euo pipefail

# ── Paths ────────────────────────────────────────────────────
JABBER_HOME="${JABBER_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
LOG_DIR="${JABBER_HOME}/logs"
BACKEND_PORT=8314
FRONTEND_PORT=5173
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-/home/$(whoami)/.gradle_jabber}"
CACHE_DIR="${GRADLE_USER_HOME}/project_cache"
export JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64"

# ── Colours ──────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' B='\033[0;34m' Y='\033[1;33m'
C='\033[0;36m' W='\033[1;37m' NC='\033[0m'

# ── Helpers ──────────────────────────────────────────────────
banner() {
  echo ""
  echo -e "${R}     ╦╔═╗╔╗ ╔╗ ╔═╗╦═╗${NC}"
  echo -e "${R}     ║╠═╣╠╩╗╠╩╗║╣ ╠╦╝${NC}"
  echo -e "${R}    ╚╝╩ ╩╚═╝╚═╝╚═╝╩╚═${NC}"
  echo -e "${W}    JABBER V 5.5.0${NC}"
  echo -e "${C}    Created by Funbinet${NC}"
  echo ""
}


log()     { echo -e "${B}[$(date +%H:%M:%S)]${NC} $1"; }
ok()      { echo -e "${G}[$(date +%H:%M:%S)] ✓${NC} $1"; }
warn()    { echo -e "${Y}[$(date +%H:%M:%S)] ⚠${NC} $1"; }
fail()    { echo -e "${R}[$(date +%H:%M:%S)] ✗${NC} $1"; }
die()     { fail "$1"; exit 1; }

pid_running() { [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; }

ensure_dirs() {
  mkdir -p "${LOG_DIR}"
}

# ── Pre-flight checks ───────────────────────────────────────
preflight() {
  if ! command -v java &>/dev/null; then
    die "Java not found. Install openjdk-21-jre or openjdk-17-jre."
  fi
  if ! command -v node &>/dev/null; then
    die "Node.js not found. Install nodejs >= 18."
  fi
  if [ ! -f "${JABBER_HOME}/gradlew" ]; then
    die "Gradle wrapper not found at ${JABBER_HOME}/gradlew"
  fi
}

# ── Port checks ──────────────────────────────────────────────
port_in_use() {
  lsof -i :"$1" -sTCP:LISTEN &>/dev/null 2>&1
}

# ── Start Backend (Gradle bootRun for dev) ───────────────────
start_backend() {
  log "Starting backend on port ${BACKEND_PORT}..."

  if port_in_use ${BACKEND_PORT}; then
    if curl --noproxy "*" -sf "http://127.0.0.1:${BACKEND_PORT}/api/info" > /dev/null 2>&1; then
      ok "Backend already online — port ${BACKEND_PORT}"
      return 0
    fi
    warn "Port ${BACKEND_PORT} in use but not responding — clearing..."
    lsof -ti :${BACKEND_PORT} -sTCP:LISTEN | xargs kill -9 2>/dev/null || true
    sleep 1
  fi

  cd "${JABBER_HOME}"
  nohup ./gradlew --project-cache-dir "${CACHE_DIR}" :jabber-core:bootRun --no-daemon \
    > "${LOG_DIR}/backend.log" 2>&1 &
  local PID=$!
  echo "$PID" > "${LOG_DIR}/backend.pid"

  # Wait for health endpoint
  local max=180 i=0
  while [ $i -lt $max ]; do
    if curl --noproxy "*" -sf "http://127.0.0.1:${BACKEND_PORT}/api/info" > /dev/null 2>&1; then
      ok "Backend online — port ${BACKEND_PORT}"
      return 0
    fi
    if ! pid_running "$PID"; then
      fail "Backend process died. Check ${LOG_DIR}/backend.log"
      tail -n 20 "${LOG_DIR}/backend.log" 2>/dev/null
      return 1
    fi
    sleep 1
    i=$((i + 1))
  done
  fail "Backend did not respond after ${max}s. Check ${LOG_DIR}/backend.log"
  warn "Last 20 lines of ${LOG_DIR}/backend.log:"
  tail -n 20 "${LOG_DIR}/backend.log" 2>/dev/null
  return 1
}

# ── Start Frontend (Vite dev server — dev only) ──────────────
start_frontend() {
  log "Starting frontend dev server on port ${FRONTEND_PORT}..."

  if port_in_use ${FRONTEND_PORT}; then
    if curl --noproxy "*" -sf "http://127.0.0.1:${FRONTEND_PORT}" > /dev/null 2>&1; then
      ok "Frontend already online — port ${FRONTEND_PORT}"
      return 0
    fi
    warn "Port ${FRONTEND_PORT} in use but not responding — clearing..."
    lsof -ti :${FRONTEND_PORT} -sTCP:LISTEN | xargs kill -9 2>/dev/null || true
    sleep 1
  fi

  cd "${JABBER_HOME}/jabber-ui"
  nohup npx vite --port ${FRONTEND_PORT} \
    > "${LOG_DIR}/frontend.log" 2>&1 &
  local PID=$!
  echo "$PID" > "${LOG_DIR}/frontend.pid"

  # Wait for vite to bind
  local max=60 i=0
  while [ $i -lt $max ]; do
    if curl --noproxy "*" -sf "http://127.0.0.1:${FRONTEND_PORT}" > /dev/null 2>&1; then
      ok "Frontend online — http://127.0.0.1:${FRONTEND_PORT}"
      return 0
    fi
    if ! pid_running "$PID"; then
      fail "Frontend process died. Check ${LOG_DIR}/frontend.log"
      tail -5 "${LOG_DIR}/frontend.log" 2>/dev/null
      return 1
    fi
    sleep 1
    i=$((i + 1))
  done
  fail "Frontend did not respond after ${max}s. Check ${LOG_DIR}/frontend.log"
  return 1
}

# ── Launch Electron Desktop ─────────────────────────────────
launch_desktop() {
  cd "${JABBER_HOME}/jabber-ui"

  if ! npx electron --version &>/dev/null 2>&1; then
    die "Electron not found. Run: cd jabber-ui && npm install"
  fi

  nohup npx electron . --dev \
    > "${LOG_DIR}/desktop.log" 2>&1 &
  local PID=$!
  echo "$PID" > "${LOG_DIR}/desktop.pid"
  ok "Desktop launched (PID ${PID})"
}

# ── Open Browser ─────────────────────────────────────────────
open_browser() {
  local url="http://127.0.0.1:${FRONTEND_PORT}"
  log "Opening browser → ${url}"
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

# ── Trap: cleanup on Ctrl+C ─────────────────────────────────
cleanup() {
  echo ""
  warn "Interrupt received — shutting down..."
  "${JABBER_HOME}/stop.sh" 2>/dev/null || true
  exit 0
}
trap cleanup SIGINT SIGTERM

# ── Entry Point ──────────────────────────────────────────────
MODE="${1:-desk}"

case "$MODE" in
  desk|desktop)
    banner
    log "Mode: ${W}DESKTOP (dev)${NC}"
    ensure_dirs
    preflight
    start_backend || die "Backend failed to start"
    start_frontend || die "Frontend failed to start"
    launch_desktop
    echo ""
    ok "JABBER running in desktop mode (dev)"
    log "Backend  → http://localhost:${BACKEND_PORT}"
    log "Frontend → http://localhost:${FRONTEND_PORT}"
    echo ""
    log "Press Ctrl+C to stop, or run: ${W}./stop.sh${NC}"
    echo ""
    DESK_PID=$(cat "${LOG_DIR}/desktop.pid" 2>/dev/null || echo "")
    if [ -n "$DESK_PID" ] && pid_running "$DESK_PID"; then
      wait "$DESK_PID" 2>/dev/null || true
      log "Desktop closed. Stopping services..."
      "${JABBER_HOME}/stop.sh" 2>/dev/null || true
    else
      wait
    fi
    ;;

  web|browser)
    banner
    log "Mode: ${W}WEB BROWSER (dev)${NC}"
    ensure_dirs
    preflight
    start_backend || die "Backend failed to start"
    start_frontend || die "Frontend failed to start"
    open_browser
    echo ""
    ok "JABBER running in browser mode (dev)"
    log "Backend  → http://localhost:${BACKEND_PORT}"
    log "Frontend → http://localhost:${FRONTEND_PORT}"
    echo ""
    log "Press Ctrl+C to stop, or run: ${W}./stop.sh${NC}"
    echo ""
    wait
    ;;

  status)
    echo ""
    echo -e "${W}JABBER Service Status${NC}"
    echo "─────────────────────────────────────"
    if [ -f "${LOG_DIR}/backend.pid" ] && pid_running "$(cat "${LOG_DIR}/backend.pid" 2>/dev/null)"; then
      ok "Backend: running (PID $(cat "${LOG_DIR}/backend.pid"))"
    else
      fail "Backend: not running"
    fi
    if [ -f "${LOG_DIR}/frontend.pid" ] && pid_running "$(cat "${LOG_DIR}/frontend.pid" 2>/dev/null)"; then
      ok "Frontend: running (PID $(cat "${LOG_DIR}/frontend.pid"))"
    else
      fail "Frontend: not running"
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
    echo -e "${W}JABBER${NC} V5.5"
    echo ""
    echo "Usage: $0 [mode]"
    echo ""
    echo "  desk     Launch desktop mode (Electron)  [default]"
    echo "  web      Launch browser mode (auto-opens localhost)"
    echo "  status   Show running services"
    echo ""
    ;;
esac
