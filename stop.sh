#!/bin/bash
# ============================================================
# JABBER Red Teaming Suite — Graceful Shutdown v4.0.0
# Created by Funbinet (dancan.tech)
# ============================================================

JABBER_HOME="${JABBER_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
LOG_DIR="${JABBER_HOME}/logs"
BACKEND_PORT=8314
FRONTEND_PORT=5173

# ── Colours ──────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' W='\033[1;37m' NC='\033[0m'

ok()   { echo -e "${G}[$(date +%H:%M:%S)] ✓${NC} $1"; }
warn() { echo -e "${Y}[$(date +%H:%M:%S)] ⚠${NC} $1"; }
log()  { echo -e "${W}[$(date +%H:%M:%S)]${NC} $1"; }

# ── Kill by PID file ────────────────────────────────────────
kill_service() {
  local name="$1"
  local pidfile="${LOG_DIR}/${name}.pid"

  if [ ! -f "$pidfile" ]; then
    return 0
  fi

  local PID
  PID=$(cat "$pidfile" 2>/dev/null)
  if [ -z "$PID" ]; then
    rm -f "$pidfile"
    return 0
  fi

  if kill -0 "$PID" 2>/dev/null; then
    # Graceful SIGTERM
    kill "$PID" 2>/dev/null
    # Wait up to 5 seconds
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
    # Force kill
    kill -9 "$PID" 2>/dev/null || true
    ok "Force-stopped ${name} (PID ${PID})"
  else
    log "${name} already stopped"
  fi
  rm -f "$pidfile"
}

# ── Kill Java backend processes ──────────────────────────────
kill_java_residuals() {
  if pgrep -f "jrts-core\|jrts-server" > /dev/null 2>&1; then
    pkill -f "jrts-core\|jrts-server" 2>/dev/null || true
    sleep 1
    if pgrep -f "jrts-core\|jrts-server" > /dev/null 2>&1; then
      pkill -9 -f "jrts-core\|jrts-server" 2>/dev/null || true
    fi
    ok "Terminated residual Java processes"
  fi
}

# ── Clear ports ──────────────────────────────────────────────
clear_ports() {
  local cleared=0
  for port in ${BACKEND_PORT} ${FRONTEND_PORT}; do
    if lsof -i :"$port" -sTCP:LISTEN > /dev/null 2>&1; then
      lsof -ti :"$port" -sTCP:LISTEN | xargs kill -9 2>/dev/null || true
      cleared=1
    fi
  done
  if [ "$cleared" -eq 1 ]; then
    ok "Cleared ports ${BACKEND_PORT}, ${FRONTEND_PORT}"
  fi
}

# ── Main ─────────────────────────────────────────────────────
echo ""
echo -e "${R}Stopping JABBER...${NC}"
echo "─────────────────────────────────────"

# Phase 1: Stop by PID files
kill_service "desktop"
kill_service "frontend"
kill_service "backend"

# Phase 2: Kill residual Java processes
kill_java_residuals

# Phase 3: Final port sweep
clear_ports

echo ""
ok "All JABBER services stopped."
echo ""
