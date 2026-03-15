#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Murari MacControl — Setup & Launcher
#
# First run  : creates your PIN, generates a local TLS certificate, starts server
# Subsequent : just starts the server
#
# Usage: bash setup.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║   🍎  Murari MacControl                   ║"
echo "  ╚═══════════════════════════════════════════╝"
echo ""

# ── Python 3 check ────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo "  ✗ Python 3 not found."
  echo "    Install it from https://python.org or via Homebrew: brew install python3"
  exit 1
fi
echo "  ✓ Python 3 — $(python3 --version)"

# ── macOS check ───────────────────────────────────────────────────────────────
if [[ "$(uname)" != "Darwin" ]]; then
  echo "  ✗ This tool only works on macOS (it uses AppleScript and macOS system tools)."
  exit 1
fi
MACOS_VER="$(sw_vers -productVersion)"
echo "  ✓ macOS ${MACOS_VER}"

# ── openssl check (needed for TLS cert generation) ───────────────────────────
if ! command -v openssl &>/dev/null; then
  echo "  ✗ openssl not found — needed for HTTPS cert generation."
  echo "    Install Xcode Command Line Tools: xcode-select --install"
  exit 1
fi
echo "  ✓ openssl — $(openssl version)"

# ── First-run notice ─────────────────────────────────────────────────────────
CONFIG="$DIR/config.json"
if [[ ! -f "$CONFIG" ]]; then
  echo ""
  echo "  ┌──────────────────────────────────────────────────────────────────┐"
  echo "  │  First run! You'll be asked to create a PIN.                     │"
  echo "  │  This PIN protects access to your Mac from your iPhone.          │"
  echo "  │  Choose 4–12 digits. It's stored as a secure hash — never plain. │"
  echo "  └──────────────────────────────────────────────────────────────────┘"
fi

# ── Permissions reminder ──────────────────────────────────────────────────────
echo ""
echo "  ┌─ Recommended permissions ──────────────────────────────────────────┐"
echo "  │                                                                     │"
echo "  │  For Wake & Unlock to work, grant two permissions:                 │"
echo "  │                                                                     │"
echo "  │  ① System Settings → Privacy & Security → Accessibility            │"
echo "  │    → Add this terminal app (Terminal / iTerm2 / etc.)               │"
echo "  │                                                                     │"
echo "  │  ② System Settings → Privacy & Security → Automation               │"
echo "  │    → Terminal → enable System Events                                │"
echo "  │                                                                     │"
echo "  │  All other features (media, apps, Bluetooth, etc.) work without    │"
echo "  │  any permissions.                                                   │"
echo "  │                                                                     │"
echo "  └─────────────────────────────────────────────────────────────────────┘"
echo ""

# ── Launch ────────────────────────────────────────────────────────────────────
echo "  Starting server…"
echo "  (Press Ctrl+C to stop)"
echo ""
cd "$DIR"
python3 server.py
