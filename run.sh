#!/bin/bash
# ============================================================
# JABBER Red Teaming Suite — Unified Launcher (run.sh)
# Modes:  desk (default)  |  web
# Created by Funbinet (dancan.tech)
# ============================================================
set -euo pipefail

# ── Paths ────────────────────────────────────────────────────
JABBER_HOME="${JABBER_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
LOG_DIR="${JABBER_HOME}/logs"
BACKEND_PORT=8314
FRONTEND_PORT=5173
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-/home/$(whoami)/.gradle_jrts}"
CACHE_DIR="${GRADLE_USER_HOME}/project_cache"

# ── Colours ──────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' B='\033[0;34m' Y='\033[1;33m'
C='\033[0;36m' W='\033[1;37m' NC='\033[0m'

# ── Helpers ──────────────────────────────────────────────────
banner() {
  echo ""
  echo -e "${R}     ╦╔═╗╔╗ ╔╗ ╔═╗╦═╗${NC}"
  echo -e "${R}     ║╠═╣╠╩╗╠╩╗║╣ ╠╦╝${NC}"
  echo -e "${R}    ╚╝╩ ╩╚═╝╚═╝╚═╝╩╚═${NC}"
  echo -e "${W}    Red Teaming Suite V3${NC}"
  echo -e "${C}    Created by Funbinet${NC}"
  echo ""
}

log()     { echo -e "${B}[$(date +%H:%M:%S)]${NC} $1"; }
ok()      { echo -e "${G}[$(date +%H:%M:%S)] ✓${NC} $1"; }
warn()    { echo -e "${Y}[$(date +%H:%M:%S)] ⚠${NC} $1"; }
fail()    { echo -e "${R}[$(date +%H:%M:%S)] ✗${NC} $1"; }
die()     { fail "$1"; exit 1; }

pid_running() { [ -n "$1" ] && kill -0 "$1" 2>/dev/null; }

ensure_dirs() {
  mkdir -p "${LOG_DIR}"
}

# ── Pre-flight checks ───────────────────────────────────────
preflight() {
  # Java
  if ! command -v java &>/dev/null; then
    die "Java not found. Install openjdk-21-jre or openjdk-17-jre."
  fi
  # Node
  if ! command -v node &>/dev/null; then
    die "Node.js not found. Install nodejs >= 18."
  fi
  # Gradle wrapper
  if [ ! -f "${JABBER_HOME}/gradlew" ]; then
    die "Gradle wrapper not found at ${JABBER_HOME}/gradlew"
  fi
}

# ── Port checks ──────────────────────────────────────────────
port_in_use() {
  lsof -i :"$1" -sTCP:LISTEN &>/dev/null 2>&1
}

check_already_running() {
  local running=0
  if [ -f "${LOG_DIR}/backend.pid" ] && pid_running "$(cat "${LOG_DIR}/backend.pid" 2>/dev/null)"; then
    warn "Backend already running (PID $(cat "${LOG_DIR}/backend.pid"))"
    running=1
  fi
  if [ -f "${LOG_DIR}/frontend.pid" ] && pid_running "$(cat "${LOG_DIR}/frontend.pid" 2>/dev/null)"; then
    warn "Frontend already running (PID $(cat "${LOG_DIR}/frontend.pid"))"
    running=1
  fi
  if [ "$running" -eq 1 ]; then
    warn "Services already running. Run ./stop.sh first, or use --force."
    if [ "${FORCE:-0}" != "1" ]; then
      exit 0
    fi
    # Force mode: stop first
    "${JABBER_HOME}/stop.sh" 2>/dev/null || true
    sleep 1
  fi
}

# ── Start Backend ────────────────────────────────────────────
start_backend() {
  log "Starting backend engine on port ${BACKEND_PORT}..."

  if port_in_use ${BACKEND_PORT}; then
    warn "Port ${BACKEND_PORT} already in use — assuming backend is running."
    return 0
  fi

  cd "${JABBER_HOME}"
  nohup ./gradlew --project-cache-dir "${CACHE_DIR}" :jrts-core:bootRun --no-daemon \
    > "${LOG_DIR}/backend.log" 2>&1 &
  local PID=$!
  echo "$PID" > "${LOG_DIR}/backend.pid"
  log "Backend process started (PID ${PID})"

  # Wait for health endpoint
  local max=90 i=0
  while [ $i -lt $max ]; do
    if curl -sf "http://localhost:${BACKEND_PORT}/api/info" > /dev/null 2>&1; then
      ok "Backend online — port ${BACKEND_PORT}"
      return 0
    fi
    # Check process is still alive
    if ! pid_running "$PID"; then
      fail "Backend process died. Check ${LOG_DIR}/backend.log"
      tail -5 "${LOG_DIR}/backend.log" 2>/dev/null
      return 1
    fi
    sleep 1
    i=$((i + 1))
  done
  fail "Backend did not respond after ${max}s. Check ${LOG_DIR}/backend.log"
  return 1
}

# ── Start Frontend (Vite dev server) ─────────────────────────
start_frontend() {
  log "Starting frontend on port ${FRONTEND_PORT}..."

  if port_in_use ${FRONTEND_PORT}; then
    warn "Port ${FRONTEND_PORT} already in use — assuming frontend is running."
    return 0
  fi

  cd "${JABBER_HOME}/jrts-ui"
  nohup npx vite --port ${FRONTEND_PORT} \
    > "${LOG_DIR}/frontend.log" 2>&1 &
  local PID=$!
  echo "$PID" > "${LOG_DIR}/frontend.pid"

  # Wait for vite to bind
  local max=30 i=0
  while [ $i -lt $max ]; do
    if curl -sf "http://localhost:${FRONTEND_PORT}" > /dev/null 2>&1; then
      ok "Frontend online — http://localhost:${FRONTEND_PORT}"
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
  log "Launching JABBER desktop window..."

  cd "${JABBER_HOME}/jrts-ui"

  # Ensure electron is available
  if ! npx electron --version &>/dev/null 2>&1; then
    die "Electron not found. Run: cd jrts-ui && npm install"
  fi

  nohup npx electron . --dev \
    > "${LOG_DIR}/desktop.log" 2>&1 &
  local PID=$!
  echo "$PID" > "${LOG_DIR}/desktop.pid"
  ok "Desktop launched (PID ${PID})"
}

# ── Open Browser ─────────────────────────────────────────────
open_browser() {
  local url="http://localhost:${FRONTEND_PORT}"
  log "Opening browser → ${url}"
  # Try common openers
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

# ── Mode: desk ───────────────────────────────────────────────
mode_desk() {
  banner
  log "Mode: ${W}DESKTOP${NC}"
  log "─────────────────────────────────────"
  ensure_dirs
  preflight
  check_already_running

  start_backend || die "Backend failed to start"
  start_frontend || die "Frontend failed to start"
  launch_desktop

  echo ""
  ok "JABBER is running in desktop mode"
  log "Backend  → http://localhost:${BACKEND_PORT}"
  log "Frontend → http://localhost:${FRONTEND_PORT}"
  log "Logs     → ${LOG_DIR}/"
  echo ""
  log "Press Ctrl+C to stop all services, or run: ${W}./stop.sh${NC}"
  echo ""

  # Wait for desktop to close
  local DESK_PID
  DESK_PID=$(cat "${LOG_DIR}/desktop.pid" 2>/dev/null || echo "")
  if [ -n "$DESK_PID" ] && pid_running "$DESK_PID"; then
    wait "$DESK_PID" 2>/dev/null || true
    log "Desktop window closed. Stopping services..."
    "${JABBER_HOME}/stop.sh" 2>/dev/null || true
  else
    # Keep alive
    wait
  fi
}

# ── Mode: web ────────────────────────────────────────────────
mode_web() {
  banner
  log "Mode: ${W}WEB BROWSER${NC}"
  log "─────────────────────────────────────"
  ensure_dirs
  preflight
  check_already_running

  start_backend || die "Backend failed to start"
  start_frontend || die "Frontend failed to start"
  open_browser

  echo ""
  ok "JABBER is running in browser mode"
  log "Backend  → http://localhost:${BACKEND_PORT}"
  log "Frontend → http://localhost:${FRONTEND_PORT}"
  log "Logs     → ${LOG_DIR}/"
  echo ""
  log "Press Ctrl+C to stop all services, or run: ${W}./stop.sh${NC}"
  echo ""

  # Keep script alive so Ctrl+C cleanup works
  wait
}

# ── Mode: status ─────────────────────────────────────────────
mode_status() {
  echo ""
  echo -e "${W}JABBER Service Status${NC}"
  echo "─────────────────────────────────────"

  # Backend
  if [ -f "${LOG_DIR}/backend.pid" ] && pid_running "$(cat "${LOG_DIR}/backend.pid" 2>/dev/null)"; then
    ok "Backend: running (PID $(cat "${LOG_DIR}/backend.pid"))"
    if curl -sf "http://localhost:${BACKEND_PORT}/api/info" > /dev/null 2>&1; then
      curl -s "http://localhost:${BACKEND_PORT}/api/info" 2>/dev/null | python3 -m json.tool 2>/dev/null || true
    fi
  else
    fail "Backend: not running"
  fi

  # Frontend
  if [ -f "${LOG_DIR}/frontend.pid" ] && pid_running "$(cat "${LOG_DIR}/frontend.pid" 2>/dev/null)"; then
    ok "Frontend: running (PID $(cat "${LOG_DIR}/frontend.pid"))"
  else
    fail "Frontend: not running"
  fi

  # Desktop
  if [ -f "${LOG_DIR}/desktop.pid" ] && pid_running "$(cat "${LOG_DIR}/desktop.pid" 2>/dev/null)"; then
    ok "Desktop: running (PID $(cat "${LOG_DIR}/desktop.pid"))"
  else
    echo -e "   Desktop: not running"
  fi
  echo ""
}

# ── Entry Point ──────────────────────────────────────────────
MODE="${1:-desk}"
[ "$MODE" = "--force" ] && { FORCE=1; MODE="${2:-desk}"; }

case "$MODE" in
  desk|desktop)   mode_desk ;;
  web|browser)    mode_web ;;
  status)         mode_status ;;
  *)
    echo ""
    echo -e "${W}JABBER${NC} — Red Teaming Suite V3"
    echo ""
    echo "Usage: $0 [mode]"
    echo ""
    echo "  desk     Launch desktop mode (Electron)  [default]"
    echo "  web      Launch browser mode (auto-opens localhost)"
    echo "  status   Show running services"
    echo ""
    echo "Examples:"
    echo "  ./run.sh            # Desktop mode"
    echo "  ./run.sh web        # Browser mode"
    echo "  jabber              # Desktop mode (after install)"
    echo "  jabber web          # Browser mode (after install)"
    echo "  jabber stop         # Stop all services"
    echo ""
    ;;
esac
