#!/usr/bin/env python3
"""
Murari WinControl — Interactive Setup
Lets the user pick which features to enable, checks dependencies,
then launches server_windows.py.

Run via:  setup.bat   (Windows)
      or: python setup_windows.py
"""

import os, sys, json, subprocess, socket, platform

# ── Windows check ─────────────────────────────────────────────────────────────
if platform.system() != "Windows":
    print("\n  ✗ This setup is for Windows only.")
    print("  For macOS use: bash setup.sh\n")
    sys.exit(1)

import msvcrt  # stdlib, Windows only

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

# ── Feature definitions ───────────────────────────────────────────────────────
FEATURES = [
    {
        "id":      "media",
        "name":    "Media Control",
        "desc":    "Play/Pause, Next, Previous, Volume, Mute",
        "default": True,
    },
    {
        "id":      "apps",
        "name":    "App Management",
        "desc":    "Launch, switch, kill & force-kill apps",
        "default": True,
    },
    {
        "id":      "system",
        "name":    "System Controls",
        "desc":    "Lock screen, Sleep, Screenshot, Dark Mode",
        "default": True,
    },
    {
        "id":      "clipboard",
        "name":    "Clipboard",
        "desc":    "Read & push clipboard between phone and PC",
        "default": True,
    },
    {
        "id":      "notifications",
        "name":    "Notifications",
        "desc":    "Send Windows toast notifications (Windows 10+)",
        "default": True,
    },
    {
        "id":      "brightness",
        "name":    "Brightness Control",
        "desc":    "Adjust monitor brightness (WMI / laptop panels only)",
        "default": False,
    },
    {
        "id":      "terminal",
        "name":    "Terminal / PowerShell",
        "desc":    "Run shell commands silently or in a new PS window",
        "default": True,
    },
]

DEP_OPTIONS = [
    {
        "id":   "none",
        "name": "Zero dependencies",
        "desc": "stdlib + PowerShell only — no pip install needed",
    },
    {
        "id":   "minimal",
        "name": "Minimal (recommended)",
        "desc": "pip install pillow pycaw  — better screenshots & precise volume",
    },
]

# ── Terminal helpers ──────────────────────────────────────────────────────────
def cls():
    os.system("cls")

def getch():
    """Read one keypress (no Enter needed)."""
    ch = msvcrt.getch()
    try:
        return ch.decode("utf-8")
    except Exception:
        return ""

def banner(title=""):
    cls()
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║   🪟  Murari WinControl — Setup              ║")
    if title:
        pad = 44 - len(title) - 2
        print(f"  ║   {title}{' ' * pad}║")
    print("  ╚══════════════════════════════════════════════╝")
    print()

# ── Step 1: Feature selection ─────────────────────────────────────────────────
def select_features():
    enabled = {f["id"]: f["default"] for f in FEATURES}

    while True:
        banner("Step 1 of 3 — Choose features")
        print("  Press the number to toggle ON/OFF.")
        print("  Press A = all on   N = all off   Enter = confirm")
        print()

        for i, f in enumerate(FEATURES, 1):
            tick  = "✓" if enabled[f["id"]] else "✗"
            color_on  = "\033[92m" if enabled[f["id"]] else "\033[90m"
            color_off = "\033[0m"
            print(f"  [{i}] {color_on}{tick}  {f['name']:<22}{color_off}  {f['desc']}")

        print()
        print("  ─────────────────────────────────────────────────")
        active = sum(1 for v in enabled.values() if v)
        print(f"  {active} of {len(FEATURES)} features selected")
        print()

        ch = getch().lower()

        if ch == "\r" or ch == "\n":          # Enter — confirm
            break
        elif ch == "a":
            for f in FEATURES: enabled[f["id"]] = True
        elif ch == "n":
            for f in FEATURES: enabled[f["id"]] = False
        elif ch.isdigit():
            idx = int(ch) - 1
            if 0 <= idx < len(FEATURES):
                fid = FEATURES[idx]["id"]
                enabled[fid] = not enabled[fid]

    return [fid for fid, on in enabled.items() if on]

# ── Step 2: Dependency level ──────────────────────────────────────────────────
def select_deps():
    selected = 0   # index into DEP_OPTIONS

    while True:
        banner("Step 2 of 3 — Dependencies")
        print("  Use ↑↓ arrow keys or 1/2, then press Enter.")
        print()

        for i, d in enumerate(DEP_OPTIONS):
            marker = "●" if i == selected else "○"
            bold   = "\033[1m" if i == selected else ""
            reset  = "\033[0m"
            print(f"  [{i+1}] {bold}{marker}  {d['name']}{reset}")
            print(f"       {d['desc']}")
            print()

        ch = getch()

        if ch == "\r" or ch == "\n":
            break
        elif ch in ("1", "2"):
            selected = int(ch) - 1
        elif ch == "\xe0":           # special key prefix on Windows
            arrow = getch()
            if arrow == "H" and selected > 0:                selected -= 1
            elif arrow == "P" and selected < len(DEP_OPTIONS)-1: selected += 1

    return DEP_OPTIONS[selected]["id"]

# ── Step 3: Confirm + install deps ────────────────────────────────────────────
def confirm_and_install(features, dep_level):
    banner("Step 3 of 3 — Confirm")

    print("  Selected features:")
    for f in FEATURES:
        tick = "\033[92m✓\033[0m" if f["id"] in features else "\033[90m✗\033[0m"
        print(f"    {tick}  {f['name']}")

    print()
    print(f"  Dependencies : {DEP_OPTIONS[0]['name'] if dep_level == 'none' else DEP_OPTIONS[1]['name']}")
    print()
    print("  Press Enter to continue or Esc to go back.")
    print()

    ch = getch()
    if ch == "\x1b":   # Esc
        return False

    # Install pip packages if requested
    if dep_level == "minimal":
        pkgs = ["pillow", "pycaw", "comtypes"]
        print()
        print("  Installing packages…")
        for pkg in pkgs:
            print(f"    pip install {pkg}  ", end="", flush=True)
            r = subprocess.run(
                [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
                capture_output=True
            )
            print("✓" if r.returncode == 0 else "✗ (skipped)")
        print()

    return True

# ── Save config ───────────────────────────────────────────────────────────────
def save_feature_config(features, dep_level):
    cfg = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}

    cfg["features"]  = features
    cfg["dep_level"] = dep_level

    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

# ── Python version check ──────────────────────────────────────────────────────
def check_python():
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 8):
        print(f"\n  ✗ Python 3.8+ required. You have {major}.{minor}.")
        print("  Download from https://python.org\n")
        sys.exit(1)
    print(f"  ✓ Python {major}.{minor}")

# ── PowerShell check ──────────────────────────────────────────────────────────
def check_powershell():
    r = subprocess.run(
        ["powershell", "-Command", "$PSVersionTable.PSVersion.Major"],
        capture_output=True, text=True, timeout=10
    )
    if r.returncode != 0:
        print("  ✗ PowerShell not found — required for most features.")
        sys.exit(1)
    ver = r.stdout.strip()
    print(f"  ✓ PowerShell {ver}")

# ── Launch server ─────────────────────────────────────────────────────────────
def launch_server():
    server_path = os.path.join(BASE_DIR, "server_windows.py")
    if not os.path.exists(server_path):
        print(f"\n  ✗ server_windows.py not found at {server_path}")
        sys.exit(1)

    banner()
    print("  ✓ Configuration saved.")
    print("  Starting Murari WinControl server…")
    print("  (Press Ctrl+C to stop)")
    print()
    os.execv(sys.executable, [sys.executable, server_path])

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    banner("System check")
    print("  Checking requirements…")
    print()
    check_python()
    check_powershell()
    print()
    input("  Press Enter to continue to feature selection…")

    features  = select_features()
    dep_level = select_deps()
    ok        = confirm_and_install(features, dep_level)

    if not ok:
        # User went back — restart
        main()
        return

    save_feature_config(features, dep_level)
    launch_server()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Cancelled.\n")
        sys.exit(0)
