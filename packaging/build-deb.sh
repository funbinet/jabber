#!/usr/bin/env bash
# ============================================================
# JABBER Debian Package Builder - V5.5
# Builds production-ready .deb packages for amd64 and arm64.
# Usage: ./build-deb.sh [version]
# ============================================================
set -euo pipefail

VERSION="${1:-5.5.0}"
PACKAGE="jabber"
MAINTAINER="Funbinet <admin@dancan.tech>"
DESCRIPTION="JABBER"
INSTALL_DIR="/opt/jabber"
ARCHES=("amd64" "arm64")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
BUILD_DIR="${SCRIPT_DIR}/build-deb"
DIST_DIR="${BUILD_DIR}/dist"

R='\033[0;31m'
G='\033[0;32m'
B='\033[0;34m'
Y='\033[1;33m'
W='\033[1;37m'
NC='\033[0m'

log()  { echo -e "${B}[build]${NC} $1" >&2; }
ok()   { echo -e "${G}[ ok ]${NC} $1" >&2; }
warn() { echo -e "${Y}[warn]${NC} $1" >&2; }
die()  { echo -e "${R}[fail]${NC} $1" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

write_installed_run_sh() {
  local target="$1"
  cat > "$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail

JABBER_HOME="/opt/jabber"
APP_DATA="\${HOME}/.jabber"
LOG_DIR="\${APP_DATA}/logs"
BACKEND_PORT=8314

R='\\033[0;31m'
G='\\033[0;32m'
B='\\033[0;34m'
Y='\\033[1;33m'
W='\\033[1;37m'
NC='\\033[0m'

log()  { echo -e "\${B}[\$(date +%H:%M:%S)]\${NC} \$1"; }
ok()   { echo -e "\${G}[\$(date +%H:%M:%S)] OK\${NC} \$1"; }
warn() { echo -e "\${Y}[\$(date +%H:%M:%S)] WARN\${NC} \$1"; }
fail() { echo -e "\${R}[\$(date +%H:%M:%S)] FAIL\${NC} \$1"; }
die()  { fail "\$1"; exit 1; }

pid_running() {
  [ -n "\${1:-}" ] && kill -0 "\$1" 2>/dev/null
}

port_in_use() {
  lsof -i :"\$1" -sTCP:LISTEN >/dev/null 2>&1
}

start_backend() {
  mkdir -p "\${APP_DATA}/jabber-data" "\${APP_DATA}/reports" "\${LOG_DIR}"

  if port_in_use "\${BACKEND_PORT}"; then
    if curl -sf "http://localhost:\${BACKEND_PORT}/api/info" >/dev/null 2>&1; then
      ok "Backend already online on port \${BACKEND_PORT}"
      return 0
    fi
    warn "Port \${BACKEND_PORT} in use by non-JABBER process"
    return 1
  fi

  cd "\${JABBER_HOME}"
  nohup java -jar "\${JABBER_HOME}/lib/jabber-server.jar" \\
    --spring.datasource.url="jdbc:h2:file:\${APP_DATA}/jabber-data/jabber-db;DB_CLOSE_ON_EXIT=FALSE" \\
    --jabber.reports.base-dir="\${APP_DATA}/reports" \\
    --spring.web.resources.static-locations="file:\${JABBER_HOME}/ui/dist/" \\
    > "\${LOG_DIR}/backend.log" 2>&1 &

  local pid=\$!
  echo "\${pid}" > "\${LOG_DIR}/backend.pid"

  local max=90 i=0
  while [ \$i -lt \$max ]; do
    if curl -sf "http://localhost:\${BACKEND_PORT}/api/info" >/dev/null 2>&1; then
      ok "Backend online on port \${BACKEND_PORT}"
      return 0
    fi
    if ! pid_running "\${pid}"; then
      fail "Backend exited early. See \${LOG_DIR}/backend.log"
      return 1
    fi
    sleep 1
    i=\$((i + 1))
  done

  fail "Backend health check timed out"
  return 1
}

launch_desktop() {
  local electron_bin="\${JABBER_HOME}/ui/node_modules/electron/dist/electron"
  if [ ! -x "\${electron_bin}" ]; then
    die "Electron runtime missing. Reinstall package."
  fi

  nohup "\${electron_bin}" "\${JABBER_HOME}/ui" > "\${LOG_DIR}/desktop.log" 2>&1 &
  local pid=\$!
  echo "\${pid}" > "\${LOG_DIR}/desktop.pid"
  ok "Desktop launched (PID \${pid})"
}

open_browser() {
  local url="http://localhost:\${BACKEND_PORT}"
  if command -v xdg-open >/dev/null 2>&1; then
    nohup xdg-open "\${url}" >/dev/null 2>&1 &
  elif command -v sensible-browser >/dev/null 2>&1; then
    nohup sensible-browser "\${url}" >/dev/null 2>&1 &
  elif command -v firefox >/dev/null 2>&1; then
    nohup firefox "\${url}" >/dev/null 2>&1 &
  elif command -v chromium-browser >/dev/null 2>&1; then
    nohup chromium-browser "\${url}" >/dev/null 2>&1 &
  else
    warn "No browser launcher found. Open manually: \${url}"
  fi
}

cleanup() {
  "\${JABBER_HOME}/stop.sh" >/dev/null 2>&1 || true
}
trap cleanup SIGINT SIGTERM

mode="\${1:-desk}"

case "\${mode}" in
  desk|desktop)
    start_backend || die "Backend failed to start"
    launch_desktop
    desktop_pid="\$(cat "\${LOG_DIR}/desktop.pid" 2>/dev/null || true)"
    if [ -n "\${desktop_pid}" ] && pid_running "\${desktop_pid}"; then
      wait "\${desktop_pid}" || true
      "\${JABBER_HOME}/stop.sh" >/dev/null 2>&1 || true
    fi
    ;;
  web|browser)
    start_backend || die "Backend failed to start"
    ok "Web mode available at http://localhost:\${BACKEND_PORT}"
    open_browser
    while true; do sleep 3600; done
    ;;
  status)
    if [ -f "\${LOG_DIR}/backend.pid" ] && pid_running "\$(cat "\${LOG_DIR}/backend.pid" 2>/dev/null)"; then
      ok "Backend running"
    else
      warn "Backend not running"
    fi
    if [ -f "\${LOG_DIR}/desktop.pid" ] && pid_running "\$(cat "\${LOG_DIR}/desktop.pid" 2>/dev/null)"; then
      ok "Desktop running"
    else
      warn "Desktop not running"
    fi
    ;;
  *)
    echo "Usage: jabber [desk|web|status|stop]"
    ;;
esac
EOF
}

write_installed_stop_sh() {
  local target="$1"
  cat > "$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

JABBER_HOME="/opt/jabber"
APP_DATA="${HOME}/.jabber"
LOG_DIR="${APP_DATA}/logs"
BACKEND_PORT=8314

pid_running() {
  [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null
}

stop_by_pidfile() {
  local name="$1"
  local pidfile="${LOG_DIR}/${name}.pid"

  [ -f "$pidfile" ] || return 0
  local pid
  pid="$(cat "$pidfile" 2>/dev/null || true)"

  if [ -n "$pid" ] && pid_running "$pid"; then
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do
      pid_running "$pid" || break
      sleep 0.1
    done
    pid_running "$pid" && kill -9 "$pid" 2>/dev/null || true
  fi

  rm -f "$pidfile"
}

stop_by_pidfile backend
stop_by_pidfile frontend
stop_by_pidfile desktop

if pgrep -f "jabber-server|jabber-core" >/dev/null 2>&1; then
  pkill -f "jabber-server|jabber-core" 2>/dev/null || true
  sleep 1
  pkill -9 -f "jabber-server|jabber-core" 2>/dev/null || true
fi

if lsof -i :"${BACKEND_PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
  lsof -ti :"${BACKEND_PORT}" -sTCP:LISTEN | xargs kill -9 2>/dev/null || true
fi

echo "JABBER services stopped."
EOF
}

write_control_file() {
  local pkg_root="$1"
  local arch="$2"
  cat > "${pkg_root}/DEBIAN/control" <<EOF
Package: ${PACKAGE}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${arch}
Maintainer: ${MAINTAINER}
Depends: bash, curl, lsof, procps, xdg-utils, openjdk-21-jre | openjdk-17-jre, nodejs (>= 18), npm
Recommends: libgtk-3-0, libnss3, libxss1, libxtst6, libgbm1
Description: ${DESCRIPTION}
 JABBER is a modular offensive security platform with a Spring Boot
 backend, React UI, and Electron desktop shell.
 .
 Release ${VERSION} includes normalized versioning, terminal improvements,
 cleaned production layout, and dual-architecture packaging.
EOF
}

write_postinst() {
  local target="$1"
  cat > "$target" <<'EOF'
#!/usr/bin/env bash
set -e

chmod -R 755 /opt/jabber || true
chmod +x /opt/jabber/run.sh /opt/jabber/stop.sh || true
chmod +x /usr/bin/jabber || true
mkdir -p /opt/jabber/logs || true

if [ -x /opt/jabber/ui/node_modules/electron/dist/electron ]; then
  chmod +x /opt/jabber/ui/node_modules/electron/dist/electron || true
fi

MISSING=()
command -v java >/dev/null 2>&1 || MISSING+=(openjdk-21-jre)
command -v node >/dev/null 2>&1 || MISSING+=(nodejs)
command -v npm >/dev/null 2>&1 || MISSING+=(npm)
command -v curl >/dev/null 2>&1 || MISSING+=(curl)
command -v lsof >/dev/null 2>&1 || MISSING+=(lsof)
command -v pgrep >/dev/null 2>&1 || MISSING+=(procps)
command -v xdg-open >/dev/null 2>&1 || MISSING+=(xdg-utils)

if [ ${#MISSING[@]} -gt 0 ] && command -v apt-get >/dev/null 2>&1; then
  apt-get update || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${MISSING[@]}" || true
fi

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database /usr/share/applications/ >/dev/null 2>&1 || true
fi

echo "JABBER ${VERSION:-5.0.0} installed."
EOF
}

write_prerm() {
  local target="$1"
  cat > "$target" <<'EOF'
#!/usr/bin/env bash
set -e

if [ -x /opt/jabber/stop.sh ]; then
  /opt/jabber/stop.sh >/dev/null 2>&1 || true
fi
EOF
}

write_postrm() {
  local target="$1"
  cat > "$target" <<'EOF'
#!/usr/bin/env bash
set -e

if [ "$1" = "purge" ]; then
  rm -rf /opt/jabber/logs || true
fi

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database /usr/share/applications/ >/dev/null 2>&1 || true
fi
EOF
}

write_cli_wrapper() {
  local target="$1"
  cat > "$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

JABBER_HOME="/opt/jabber"
mode="${1:-desk}"

case "$mode" in
  stop)
    exec "${JABBER_HOME}/stop.sh"
    ;;
  status)
    exec "${JABBER_HOME}/run.sh" status
    ;;
  web|browser)
    exec "${JABBER_HOME}/run.sh" web
    ;;
  desk|desktop|"")
    nohup "${JABBER_HOME}/run.sh" desk >/dev/null 2>&1 &
    disown || true
    ;;
  -h|--help|help)
    echo "Usage: jabber [desk|web|status|stop]"
    ;;
  *)
    echo "Unknown command: $mode"
    exit 1
    ;;
esac
EOF
}

write_desktop_entry() {
  local target="$1"
  cat > "$target" <<EOF
[Desktop Entry]
Name=JABBER
Comment=JABBER V 5.5.0
Exec=/usr/bin/jabber
Icon=jabber
Terminal=false
Type=Application
Categories=Utility;Security;System;
Keywords=security;red-team;offensive;
StartupNotify=true
EOF
}

build_backend_and_frontend() {
  log "Building backend bootJar"
  export GRADLE_USER_HOME="${GRADLE_USER_HOME:-/home/$(whoami)/.gradle_jabber}"
  rm -rf "${PROJECT_ROOT}/jabber-core/build/libs/"*
  ./gradlew --project-cache-dir "${GRADLE_USER_HOME}/project_cache" :jabber-core:bootJar -x test --no-daemon

  BOOT_JAR="$(find "${PROJECT_ROOT}/jabber-core/build/libs" -maxdepth 1 -type f -name '*.jar' ! -name '*-plain*' | head -n 1)"
  [ -n "${BOOT_JAR}" ] || die "Backend JAR not found after build"
  ok "Backend built: ${BOOT_JAR}"

  log "Building frontend dist"
  (
    cd "${PROJECT_ROOT}/jabber-ui"
    npm ci
    npm run build
  )
  [ -d "${PROJECT_ROOT}/jabber-ui/dist" ] || die "Frontend dist directory missing"
  ok "Frontend built"
}

bundle_electron_for_arch() {
  local arch="$1"
  local staging_dir="${BUILD_DIR}/electron-${arch}"
  local electron_version
  local npm_arch

  # Map architecture names
  case "${arch}" in
    amd64) npm_arch="x64" ;;
    arm64) npm_arch="arm64" ;;
    *) die "Unsupported architecture: ${arch}" ;;
  esac

  electron_version="$(node -e "console.log(require('${PROJECT_ROOT}/jabber-ui/package.json').devDependencies.electron.replace('^',''))")"
  rm -rf "${staging_dir}"
  mkdir -p "${staging_dir}"

  cat > "${staging_dir}/package.json" <<EOF
{
  "name": "jabber-electron-${arch}",
  "version": "${VERSION}",
  "private": true,
  "dependencies": {
    "electron": "${electron_version}"
  }
}
EOF

  log "Installing Electron ${electron_version} for ${arch} (npm arch: ${npm_arch})"
  (
    cd "${staging_dir}"
    npm_config_platform=linux npm_config_arch="${npm_arch}" npm install --omit=dev 2>&1 | tail -5 >&2
  )

  # Wait a moment for npm to finish writing files
  sleep 1

  if [ ! -d "${staging_dir}/node_modules/electron" ]; then
    die "Electron bundle missing for ${arch} at ${staging_dir}/node_modules/electron"
  fi
  ok "Electron bundled for ${arch}"

  # Return only the path
  echo "${staging_dir}"
}

assemble_package_for_arch() {
  local arch="$1"
  local electron_stage="$2"
  local pkg_root="${BUILD_DIR}/${PACKAGE}_${VERSION}_${arch}"
  local out_file="${DIST_DIR}/${PACKAGE}_${VERSION}_${arch}.deb"

  rm -rf "${pkg_root}"
  mkdir -p "${pkg_root}${INSTALL_DIR}/lib"
  mkdir -p "${pkg_root}${INSTALL_DIR}/ui/dist"
  mkdir -p "${pkg_root}${INSTALL_DIR}/ui/electron"
  mkdir -p "${pkg_root}${INSTALL_DIR}/logs"
  mkdir -p "${pkg_root}/usr/bin"
  mkdir -p "${pkg_root}/usr/share/applications"
  mkdir -p "${pkg_root}/usr/share/pixmaps"
  mkdir -p "${pkg_root}/DEBIAN"

  cp "${BOOT_JAR}" "${pkg_root}${INSTALL_DIR}/lib/jabber-server.jar"
  cp -r "${PROJECT_ROOT}/jabber-ui/dist/." "${pkg_root}${INSTALL_DIR}/ui/dist/"
  cp "${PROJECT_ROOT}/jabber-ui/electron/main.cjs" "${pkg_root}${INSTALL_DIR}/ui/electron/main.cjs"

  cat > "${pkg_root}${INSTALL_DIR}/ui/package.json" <<EOF
{
  "name": "jabber",
  "version": "${VERSION}",
  "main": "electron/main.cjs",
  "description": "JABBER"
}
EOF

  cp -r "${electron_stage}/node_modules" "${pkg_root}${INSTALL_DIR}/ui/"

  # Copy Logo
  if [ -f "${PROJECT_ROOT}/jabber-logo.png" ]; then
    cp "${PROJECT_ROOT}/jabber-logo.png" "${pkg_root}/usr/share/pixmaps/jabber.png"
    cp "${PROJECT_ROOT}/jabber-logo.png" "${pkg_root}${INSTALL_DIR}/jabber-logo.png"
  fi

  write_installed_run_sh "${pkg_root}${INSTALL_DIR}/run.sh"
  write_installed_stop_sh "${pkg_root}${INSTALL_DIR}/stop.sh"
  write_cli_wrapper "${pkg_root}/usr/bin/jabber"
  write_desktop_entry "${pkg_root}/usr/share/applications/jabber.desktop"
  write_control_file "${pkg_root}" "${arch}"
  write_postinst "${pkg_root}/DEBIAN/postinst"
  write_prerm "${pkg_root}/DEBIAN/prerm"
  write_postrm "${pkg_root}/DEBIAN/postrm"

  chmod +x "${pkg_root}${INSTALL_DIR}/run.sh"
  chmod +x "${pkg_root}${INSTALL_DIR}/stop.sh"
  chmod +x "${pkg_root}/usr/bin/jabber"
  chmod +x "${pkg_root}/DEBIAN/postinst" "${pkg_root}/DEBIAN/prerm" "${pkg_root}/DEBIAN/postrm"

  dpkg-deb --build "${pkg_root}" "${out_file}" >/dev/null
  ok "Built ${out_file}"
}

main() {
  require_cmd dpkg-deb
  require_cmd node
  require_cmd npm
  require_cmd java

  echo ""
  echo -e "${R}============================================================${NC}"
  echo -e "${W} JABBER Debian Builder V5.5${NC}"
  echo -e "${W} Version: ${VERSION}${NC}"
  echo -e "${R}============================================================${NC}"
  echo ""

  rm -rf "${BUILD_DIR}"
  mkdir -p "${DIST_DIR}"

  cd "${PROJECT_ROOT}"
  build_backend_and_frontend

  for arch in "${ARCHES[@]}"; do
    log "Preparing package for ${arch}"
    stage="$(bundle_electron_for_arch "${arch}")"
    assemble_package_for_arch "${arch}" "${stage}"
  done

  echo ""
  ok "Debian build complete"
  ls -lh "${DIST_DIR}"/*.deb
  echo ""
  echo "Install examples:"
  echo "  sudo dpkg -i ${DIST_DIR}/${PACKAGE}_${VERSION}_amd64.deb"
  echo "  sudo dpkg -i ${DIST_DIR}/${PACKAGE}_${VERSION}_arm64.deb"
}

main "$@"
