#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# NeonScan — Termux (Android) prerequisites installer + smoke test.
#
#   Run it INSIDE Termux:
#       bash setup-termux.sh
#
#   Or bootstrap from scratch (clones the repo, then sets it up):
#       pkg install -y git && \
#       git clone https://github.com/angel-clobi/neonscan && \
#       cd neonscan && bash setup-termux.sh
#
# It installs Python + the tools NeonScan's recon half needs, extracts the
# vendored `rich`, and runs a quick smoke test. Missing optional packages are
# reported but never abort the script.
# ---------------------------------------------------------------------------

set -u

# --- pretty output (degrades if no colour) ---------------------------------
if [ -t 1 ]; then
  B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; C=$'\033[36m'; Z=$'\033[0m'
else
  B=""; G=""; Y=""; R=""; C=""; Z=""
fi
say()  { printf '%s\n' "${C}${B}::${Z} $*"; }
ok()   { printf '%s\n' "  ${G}OK${Z}   $*"; }
warn() { printf '%s\n' "  ${Y}WARN${Z} $*"; }
err()  { printf '%s\n' "  ${R}FAIL${Z} $*"; }

# --- 0. Sanity: are we in Termux? ------------------------------------------
if [ -z "${PREFIX:-}" ] || ! printf '%s' "$PREFIX" | grep -q "com.termux"; then
  if [ ! -d /data/data/com.termux/files ]; then
    err "This script is for Termux (Android). On desktop Linux use your package"
    err "manager (apt/dnf/pacman) instead, e.g. 'apt install python3 iproute2 iputils-ping'."
    exit 1
  fi
fi
say "Termux detected (PREFIX=${PREFIX:-?})"

# --- helper: install a group of packages, never fatal ----------------------
install_group() {
  local label="$1"; shift
  say "Installing ${label}: $*"
  # shellcheck disable=SC2068
  pkg install -y $@ >/dev/null 2>&1 || warn "some of '$*' could not be installed (continuing)"
}

have() { command -v "$1" >/dev/null 2>&1; }

# --- 1. Refresh the package index ------------------------------------------
say "Updating package lists (pkg update)…"
yes | pkg update >/dev/null 2>&1 || warn "pkg update reported an issue (continuing)"

# --- 2. Install prerequisites ----------------------------------------------
install_group "Python (required)"      python
install_group "recon tools"            iproute2 traceroute openssl-tool
# ping lives in different packages across Termux revisions — try both.
install_group "ping"                   iputils inetutils
install_group "extras (optional)"      git lsof nmap netcat-openbsd dnsutils
install_group "Wi-Fi bridge (optional)" termux-api

# --- 3. Report what actually landed ----------------------------------------
say "Tool availability on this device:"
report_tool() { if have "$1"; then ok "$1 ($(command -v "$1"))"; else warn "$1 not found ($2)"; fi; }
report_tool python  "REQUIRED — install with: pkg install python"
report_tool ip      "routes/connections fall back to /proc, but 'ip' is better (pkg install iproute2)"
report_tool ss      "connections need this (pkg install iproute2)"
report_tool ping    "host discovery/ping (pkg install iputils; Android's /system/bin/ping may also work)"
report_tool traceroute "traceroute/mtr (pkg install traceroute)"
report_tool openssl "tls cert verification (pkg install openssl-tool)"
report_tool dig     "dns 'dig' fast path (pkg install dnsutils) — a raw-UDP fallback is built in"
report_tool termux-wifi-connectioninfo "wifi/aps need the Termux:API app + 'pkg install termux-api'"

if ! have python; then
  err "Python is required and is missing — cannot continue. Run: pkg install python"
  exit 1
fi
PYVER="$(python --version 2>&1)"
ok "Python: ${PYVER}"

# --- 4. Locate the NeonScan project ----------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
if [ -f "${SCRIPT_DIR}/neonscan.py" ]; then
  REPO="${SCRIPT_DIR}"
elif [ -f "./neonscan.py" ]; then
  REPO="$(pwd)"
else
  say "NeonScan not found next to this script — cloning it into \$HOME/neonscan…"
  if ! have git; then
    err "git is needed to clone. Run: pkg install git"
    exit 1
  fi
  if [ ! -d "${HOME}/neonscan" ]; then
    git clone https://github.com/angel-clobi/neonscan "${HOME}/neonscan" || {
      err "clone failed (no network?)"; exit 1; }
  fi
  REPO="${HOME}/neonscan"
fi
ok "Project: ${REPO}"

# --- 5. Bootstrap the vendored 'rich' (offline) + smoke test ---------------
say "Bootstrapping vendored dependencies (first run extracts vendor/wheels)…"
cd "${REPO}" || { err "cannot cd into ${REPO}"; exit 1; }
if python neonscan.py --no-banner --offline routes >/tmp/neonscan_boot.txt 2>&1; then
  ok "neonscan runs. 'routes' output:"
  sed 's/^/       /' /tmp/neonscan_boot.txt | head -8
else
  warn "first run returned non-zero — output:"
  sed 's/^/       /' /tmp/neonscan_boot.txt | head -12
fi

# --- 6. Optional shared-storage access -------------------------------------
if have termux-setup-storage && [ ! -d "${HOME}/storage" ]; then
  say "Tip: run 'termux-setup-storage' once to let NeonScan write reports to shared storage."
fi

# --- 7. Done ---------------------------------------------------------------
echo
say "${G}Setup complete.${Z} Try:"
cat <<EOF
    cd ${REPO}
    python neonscan.py --offline            # interactive
    python neonscan.py dns
    python neonscan.py ping 8.8.8.8 -c 4
    python neonscan.py net                  # parallel /24 host discovery
    python neonscan.py tls github.com
    python neonscan.py wifi                 # needs Termux:API app + 'pkg install termux-api'
    python neonscan.py full --out report.md
EOF
