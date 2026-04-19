#!/usr/bin/env bash
# ============================================================
# JRTS V2 Startup Script - Production-Grade Initialization
# ============================================================
# Purpose: Validates environment, installs missing deps,
#          initializes services, and launches JRTS reliably.
# Usage: ./start-jrts.sh [--background|--foreground]
# ============================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────
JRTS_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_JAR="${JRTS_HOME}/jrts-core/build/libs/jrts-server-1.0.0.jar"
UI_DIR="${JRTS_HOME}/jrts-ui"
REQUIRED_JAVA_VERSION=21
BACKGROUND_FLAG="${1:---background}"

# ── Colors & Logging ───────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ── Pre-flight Checks ──────────────────────────────────────
log_info "Running pre-flight checks..."

check_command() {
    if ! command -v "$1" &>/dev/null; then
        log_error "Missing command: $1"
        return 1
    fi
    return 0
}

check_file() {
    if [[ ! -f "$1" ]]; then
        log_error "Missing file: $1"
        return 1
    fi
    return 0
}

check_java_version() {
    if ! check_command java; then
        return 1
    fi
    local java_version
    java_version=$(java -version 2>&1 | head -1 | grep -oP '"\K[0-9]+' || echo "0")
    if (( java_version < REQUIRED_JAVA_VERSION )); then
        log_error "Java version ${java_version} found, but ${REQUIRED_JAVA_VERSION}+ is required."
        return 1
    fi
    log_success "Java ${java_version} is available."
    return 0
}

check_javac() {
    if ! check_command javac; then
        return 1
    fi
    log_success "javac is available."
    return 0
}

check_gradle() {
    if ! check_command gradle; then
        log_warn "gradle not found; will attempt to use wrapper."
        if [[ ! -f "${JRTS_HOME}/gradlew" ]]; then
            log_error "Gradle wrapper not found. Please install gradle or ensure ./gradlew exists."
            return 1
        fi
        return 0
    fi
    log_success "gradle is available."
    return 0
}

check_dependencies() {
    local missing=0
    check_command curl    || { log_error "curl is required for auto-install."; ((missing++)); }
    check_command wget    || { log_error "wget is required for auto-install."; ((missing++)); }
    check_command apt-get || { log_error "apt-get is required (Debian/Ubuntu/Kali)."; ((missing++)); }
    check_command dpkg    || { log_error "dpkg is required (Debian/Ubuntu/Kali)."; ((missing++)); }
    if (( missing > 0 )); then
        log_error "Missing ${missing} dependency(ies) needed for auto-install."
        return 1
    fi
    log_success "All dependency checkers are available."
    return 0
}

# ── Auto-install Missing Dependencies ───────────────────────
install_dependencies() {
    log_info "Attempting to install missing dependencies automatically..."
    local packages=""
    local missing_pkgs=()

    # Java JDK
    if ! check_java_version; then
        log_info "Installing Java ${REQUIRED_JAVA_VERSION}+..."
        if command -v apt-get &>/dev/null; then
            packages="openjdk-21-jdk"
        elif command -v dnf &>/dev/null; then
            packages="java-21-openjdk-devel"
        elif command -v yum &>/dev/null; then
            packages="java-21-openjdk-devel"
        else
            log_error "Unsupported package manager. Install Java ${REQUIRED_JAVA_VERSION}+ manually."
            missing_pkgs+=("openjdk-21-jdk")
        fi
    fi

    # Build tools
    if ! check_gradle; then
        if command -v apt-get &>/dev/null; then
            packages="${packages} gradle" 2>/dev/null || true
        fi
    fi

    # System utilities
    if ! check_dependencies; then
        if command -v apt-get &>/dev/null; then
            packages="${packages} curl wget apt-utils dpkg" 2>/dev/null || true
        fi
    fi

    if [[ -n "$packages" ]]; then
        log_info "Running: apt-get update && apt-get install -y $packages"
        if apt-get update && apt-get install -y $packages; then
            log_success "Auto-installed packages: $packages"
        else
            log_error "Failed to install packages via apt. Please install manually."
        fi
    fi

    # Verify post-install
    local still_missing=()
    check_java_version || still_missing+=("java-${REQUIRED_JAVA_VERSION}-jdk")
    check_gradle || still_missing+=("gradle")
    check_dependencies || still_missing+=("curl wget apt dpkg")

    if (( ${#still_missing[@]} > 0 )); then
        log_error "The following packages must be installed manually:"
        printf '  - %s\n' "${still_missing[@]}"
        log_error "On Debian/Ubuntu/Kali, run: sudo apt-get install ${still_missing[*]}"
        return 1
    fi
    log_success "All required dependencies are now satisfied."
    return 0
}

# ── Build Application (if needed) ──────────────────────────
build_application() {
    log_info "Ensuring application is built..."
    if [[ ! -f "$BACKEND_JAR" ]]; then
        log_info "Building backend with Gradle wrapper..."
        cd "$JRTS_HOME"
        if [[ -f "./gradlew" ]]; then
            ./gradlew :jrts-core:build -x test --quiet 2>/dev/null || {
                log_warn "Gradle build had warnings; attempting without --quiet..."
                ./gradlew :jrts-core:build -x test
            }
        else
            log_error "Gradle wrapper not found. Please run: cd $JRTS_HOME && ./gradlew :jrts-core:build"
            return 1
        fi
        log_success "Backend built successfully."
    else
        log_success "Backend JAR already exists."
    fi
}

# ── Launch Services ─────────────────────────────────────────
launch_backend() {
    log_info "Starting JRTS backend on port 8080..."
    cd "$JRTS_HOME"
    nohup java -jar "$BACKEND_JAR" > /tmp/jrts-backend.log 2>&1 &
    echo $! > /tmp/jrts-backend.pid
    log_success "Backend started (PID: $(cat /tmp/jrts-backend.pid))."
    # Wait for startup
    local max_tries=30
    for i in $(seq 1 $max_tries); do
        if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/actuator/health 2>/dev/null | grep -q "200\|UP"; then
            log_success "Backend is healthy."
            return 0
        fi
        log_info "Waiting for backend to start... ($i/$max_tries)"
        sleep 2
    done
    log_error "Backend failed to become healthy within ${max_tries} attempts. Check /tmp/jrts-backend.log"
    return 1
}

launch_ui() {
    if [[ "$BACKGROUND_FLAG" == "--background" ]]; then
        log_info "Starting UI in background (detached)..."
        cd "$UI_DIR"
        nohup npm run electron:dev > /tmp/jrts-ui.log 2>&1 &
        echo $! > /tmp/jrts-ui.pid
        log_success "UI launched in background (PID: $(cat /tmp/jrts-ui.pid))."
    else
        log_info "Starting UI in foreground (Ctrl+C to stop)..."
        cd "$UI_DIR"
        npm run electron:dev
    fi
}

# ── Main Flow ────────────────────────────────────────────────
echo "============================================"
echo "  JRTS V2 Startup Sequence"
echo "============================================"

# Step 1: Check essential commands
log_info "Checking system readiness..."
check_dependencies

# Step 2: Auto-install if possible
install_dependencies

# Step 3: Verify Java
check_java_version
check_javac

# Step 4: Build
build_application

# Step 5: Launch backend
launch_backend

# Step 6: Launch UI
launch_ui

echo "============================================"
log_success "JRTS V2 is running."
echo "  Backend API: http://localhost:8080/api/info"
echo "  Web UI:      http://localhost:5173"
echo "  Stop with:   kill \$(cat /tmp/jrts-backend.pid) or pkill -f jrts-server"
echo "============================================"
