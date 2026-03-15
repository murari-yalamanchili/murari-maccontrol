#!/usr/bin/env python3
"""
MS Mac Remote — server.py v5
HTTPS · PBKDF2 PIN auth · Session tokens · Battery · Bluetooth · Spotify art
Clipboard · Notifications · Screenshot · Dark Mode
Run: python3 server.py
"""

import subprocess, json, socket, os, time, ssl, hashlib, secrets, re, urllib.request, base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
CERT_FILE   = os.path.join(BASE_DIR, "cert.pem")
KEY_FILE    = os.path.join(BASE_DIR, "key.pem")
CNF_FILE    = os.path.join(BASE_DIR, "ssl.cnf")

# ─── Helpers ─────────────────────────────────────────────────────────────────

def run_script(s: str, timeout: int = 10) -> dict:
    try:
        r = subprocess.run(["osascript", "-e", s],
                           capture_output=True, text=True, timeout=timeout)
        return {"ok": True, "output": r.stdout.strip(), "error": r.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def run_shell(cmd: list, timeout: int = 10) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"ok": r.returncode == 0,
                "output": r.stdout.strip(), "error": r.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "output": ""}
    except Exception as e:
        return {"ok": False, "error": str(e), "output": ""}

def run_shell_str(cmd: str, timeout: int = 30) -> dict:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return {"ok": r.returncode == 0, "output": r.stdout.strip(),
                "error": r.stderr.strip(), "returncode": r.returncode}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "output": "", "returncode": -1}
    except Exception as e:
        return {"ok": False, "error": str(e), "output": "", "returncode": -1}

# ─── Crypto & Auth ────────────────────────────────────────────────────────────

def hash_pin(pin: str, salt: str = None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 200_000)
    return salt, h.hex()

def verify_pin(pin: str, salt: str, stored: str) -> bool:
    _, computed = hash_pin(pin, salt)
    return secrets.compare_digest(computed, stored)

_sessions: dict = {}
_attempts: dict = {}

def create_session() -> str:
    token = secrets.token_hex(32)
    _sessions[token] = time.time() + 86_400
    now = time.time()
    for t in [k for k, v in _sessions.items() if v < now]:
        _sessions.pop(t, None)
    return token

def valid_session(token: str) -> bool:
    """Validate and touch (extend) session expiry on every authenticated request."""
    if not token or token not in _sessions:
        return False
    if time.time() > _sessions[token]:
        _sessions.pop(token, None)
        return False
    # Touch: extend 24 h from now on every valid use
    _sessions[token] = time.time() + 86_400
    return True

def rate_ok(ip: str) -> bool:
    rec = _attempts.get(ip)
    if not rec:
        return True
    count, since = rec
    if count >= 5 and time.time() - since < 300:
        return False
    if time.time() - since >= 300:
        _attempts.pop(ip, None)
    return True

def record_fail(ip: str):
    rec = _attempts.get(ip)
    if rec:
        rec[0] += 1
    else:
        _attempts[ip] = [1, time.time()]

def clear_fail(ip: str):
    _attempts.pop(ip, None)

# ─── Config ───────────────────────────────────────────────────────────────────

_cfg: dict = {}

def load_config():
    global _cfg
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            _cfg = json.load(f)
    return _cfg

def save_config():
    with open(CONFIG_FILE, "w") as f:
        json.dump(_cfg, f, indent=2)

def setup_required() -> bool:
    return "pin_hash" not in _cfg

def interactive_setup():
    print("\n  ┌──────────────────────────────────────┐")
    print("  │  First Run — Create your access PIN  │")
    print("  └──────────────────────────────────────┘")
    while True:
        pin = input("  PIN (4–12 digits): ").strip()
        if pin.isdigit() and 4 <= len(pin) <= 12:
            if input("  Confirm PIN: ").strip() == pin:
                break
            print("  Mismatch.")
        else:
            print("  Must be 4–12 digits.")
    salt, h = hash_pin(pin)
    _cfg["pin_salt"] = salt
    _cfg["pin_hash"] = h
    _cfg["pin_length"] = len(pin)
    save_config()
    print("  ✓ PIN saved (PBKDF2-SHA256, 200k rounds)\n")

# ─── TLS ─────────────────────────────────────────────────────────────────────

def generate_cert(ip: str) -> bool:
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return True
    print("  Generating TLS cert (RSA-2048)…")
    cnf = f"""[req]
distinguished_name=dn
x509_extensions=san
prompt=no
[dn]
CN=MSMacRemote
O=Local
[san]
subjectAltName=IP:{ip},IP:127.0.0.1,DNS:localhost
"""
    with open(CNF_FILE, "w") as f:
        f.write(cnf)
    r = subprocess.run(
        ["openssl","req","-x509","-newkey","rsa:2048",
         "-keyout",KEY_FILE,"-out",CERT_FILE,"-days","730",
         "-nodes","-config",CNF_FILE],
        capture_output=True, timeout=45)
    if r.returncode != 0:
        subprocess.run(
            ["openssl","req","-x509","-newkey","rsa:2048",
             "-keyout",KEY_FILE,"-out",CERT_FILE,"-days","730",
             "-nodes","-subj","/CN=MSMacRemote"],
            capture_output=True, timeout=45)
    ok = os.path.exists(CERT_FILE)
    if ok:
        print("  ✓ TLS cert ready")
    return ok

def get_fingerprint() -> str:
    if not os.path.exists(CERT_FILE):
        return ""
    r = subprocess.run(
        ["openssl","x509","-noout","-fingerprint","-sha256","-in",CERT_FILE],
        capture_output=True, text=True)
    fp = r.stdout.strip()
    for pfx in ["SHA256 Fingerprint=","sha256 Fingerprint="]:
        fp = fp.replace(pfx, "")
    return fp

# ─── Wake & Unlock ───────────────────────────────────────────────────────────

def wake_display() -> dict:
    try:
        subprocess.Popen(["caffeinate", "-u", "-t", "5"])
        time.sleep(0.5)
        run_script('tell application "System Events" to key code 126', timeout=3)
        return {"ok": True, "output": "Display wake signal sent"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def unlock_mac(password: str) -> dict:
    if not password:
        return {"ok": False, "error": "No password provided"}

    safe = password.replace("\\", "\\\\").replace('"', '\\"')

    # Aggressively wake the display with extra hold time
    subprocess.Popen(["caffeinate", "-u", "-t", "15"])
    time.sleep(2.0)   # give display extra time to fully power on

    # Multi-phase sequence:
    # – up-arrow (126) wakes screensaver / display
    # – space (49)     triggers password field on macOS lock screen
    # – keystroke      types the password
    # – return (36)    submits
    script = f'''
tell application "System Events"
    key code 126
    delay 1.8
    key code 49
    delay 1.2
    keystroke "{safe}"
    delay 0.5
    key code 36
end tell
'''
    result = run_script(script, timeout=20)
    err = result.get("error", "")
    if ("assistive" in err.lower() or "accessibility" in err.lower()
            or "-1719" in err or "-25211" in err
            or "not allowed" in err.lower()):
        result["permission_error"] = True
        result["hint"] = (
            "Two permissions are required in System Settings → Privacy & Security:\n"
            "① Accessibility → enable Terminal (or iTerm2 / your shell)\n"
            "② Automation → Terminal → enable System Events\n"
            "After granting both, restart the server and try again.\n"
            "Note: macOS hard-locks the login screen — this works best "
            "for display-sleep (not a full logout)."
        )
    return result

# ─── Spotify ─────────────────────────────────────────────────────────────────

def get_spotify_status() -> dict:
    """Single AppleScript call for all track info (was 4 separate calls)."""
    r = run_script('''
tell application "Spotify"
    if it is running then
        try
            return (name of current track) & "|||" & (artist of current track) & "|||" & (album of current track) & "|||" & (player state as string) & "|||" & (spotify url of current track)
        end try
    end if
    return "||||"
end tell''')

    parts = r.get("output", "||||").split("|||", 4)
    while len(parts) < 5:
        parts.append("")
    track_name, artist_name, album_name, state_val, spotify_url = [p.strip() for p in parts]

    art_url = ""
    if spotify_url and ":" in spotify_url:
        try:
            oembed_url = f"https://open.spotify.com/oembed?url={spotify_url}"
            req = urllib.request.Request(oembed_url, headers={"User-Agent": "MSMacRemote/5.0"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read())
                art_url = data.get("thumbnail_url", "")
        except Exception:
            pass

    return {
        "ok":     True,
        "track":  track_name,
        "artist": artist_name,
        "album":  album_name,
        "state":  state_val,
        "art":    art_url,
        "url":    spotify_url,
    }

# ─── Battery ─────────────────────────────────────────────────────────────────

def get_battery() -> dict:
    r = run_shell(["pmset", "-g", "batt"])
    out = r.get("output", "")
    m_pct     = re.search(r"(\d+)%", out)
    # FIX: use word-boundary to avoid "charging" matching inside "discharging"
    charging  = bool(re.search(r"\bcharging\b", out, re.IGNORECASE))
    plugged   = "AC Power" in out
    m_rem     = re.search(r"(\d+:\d+) remaining", out)
    return {
        "ok":        True,
        "percent":   int(m_pct.group(1)) if m_pct else None,
        "charging":  charging,
        "plugged":   plugged,
        "remaining": m_rem.group(1) if m_rem else "",
    }

# ─── Bluetooth ───────────────────────────────────────────────────────────────

BT_EMOJI = {
    "headphone":"🎧","earphone":"🎧","airpod":"🎧","earbud":"🎧",
    "speaker":"🔊","homepod":"🔊",
    "mouse":"🖱️","trackpad":"🖱️",
    "keyboard":"⌨️",
    "phone":"📱","iphone":"📱",
    "watch":"⌚","apple watch":"⌚",
    "controller":"🎮","gamepad":"🎮","joystick":"🎮",
    "headset":"🎧",
}

def bt_emoji(name: str, type_str: str = "") -> str:
    combo = (name + " " + type_str).lower()
    for k, v in BT_EMOJI.items():
        if k in combo:
            return v
    return "🔵"

def get_bluetooth() -> dict:
    r = run_shell(["system_profiler", "SPBluetoothDataType", "-json"], timeout=15)
    if not r["ok"] and not r["output"]:
        return {"ok": False, "error": "Bluetooth query failed", "connected": [], "available": []}
    try:
        data = json.loads(r["output"])
        bt = (data.get("SPBluetoothDataType") or [{}])[0]

        def parse_list(raw) -> list:
            out = []
            if not isinstance(raw, list):
                return out
            for item in raw:
                if not isinstance(item, dict):
                    continue
                for name, info in item.items():
                    if not isinstance(info, dict):
                        continue
                    addr = info.get("device_address") or info.get("BDAddress") or ""
                    typ  = info.get("device_minorType") or info.get("Minor Type") or ""
                    out.append({"name": name, "address": addr,
                                "type": typ, "emoji": bt_emoji(name, typ)})
            return out

        connected, available = [], []
        for key in ["device_connected","devices_connected"]:
            if key in bt:
                connected = parse_list(bt[key]); break
        for key in ["device_not_connected","devices_not_connected"]:
            if key in bt:
                available = parse_list(bt[key]); break

        return {"ok": True, "connected": connected, "available": available}
    except Exception as e:
        return {"ok": False, "error": str(e), "connected": [], "available": []}

# Bluetooth TTL cache — system_profiler blocks for 3–15s; cache 30s server-side
_bt_cache: dict = {"data": None, "ts": 0.0}
_BT_TTL = 30.0

def get_bluetooth_cached() -> dict:
    now = time.time()
    if _bt_cache["data"] and now - _bt_cache["ts"] < _BT_TTL:
        return _bt_cache["data"]
    result = get_bluetooth()
    _bt_cache["data"] = result
    _bt_cache["ts"] = now
    return result

def _blueutil() -> Optional[str]:
    for p in ["/opt/homebrew/bin/blueutil", "/usr/local/bin/blueutil"]:
        if os.path.exists(p):
            return p
    r = run_shell(["which", "blueutil"])
    return r["output"].strip() or None

def bluetooth_toggle(address: str, connect: bool) -> dict:
    bu = _blueutil()
    if not bu:
        return {"ok": False, "needs_blueutil": True,
                "error": "blueutil not installed — run: brew install blueutil"}
    return run_shell([bu, "--connect" if connect else "--disconnect", address])

# ─── Apps ────────────────────────────────────────────────────────────────────

APP_EMOJI = {
    "safari":"🌐","finder":"📁","terminal":"⌨️","iterm":"⌨️","iterm2":"⌨️",
    "warp":"⌨️","ghostty":"👻",
    "spotify":"🎵","music":"🎶","garageband":"🎸","logic pro":"🎧",
    "visual studio code":"💻","vs code":"💻","vscode":"💻","code":"💻",
    "cursor":"🖱️","windsurf":"🏄","xcode":"🛠️","simulator":"📱",
    "notes":"📝","messages":"💬","mail":"📧","calendar":"📅","reminders":"✅",
    "photos":"🖼️","facetime":"📹","maps":"🗺️","contacts":"👤",
    "calculator":"🔢","preview":"👁️","textedit":"📄",
    "pages":"📰","numbers":"📊","keynote":"📊",
    "system preferences":"⚙️","system settings":"⚙️",
    "activity monitor":"📊","disk utility":"💾","console":"🖥️",
    "app store":"🛍️",
    "chrome":"🌐","google chrome":"🌐","firefox":"🦊","arc":"🌐",
    "brave":"🦁","opera":"🌐","edge":"🌐",
    "slack":"💬","zoom":"📹","discord":"💬","teams":"💬",
    "telegram":"✈️","whatsapp":"💬","signal":"🔒",
    "figma":"🎨","sketch":"✏️","affinity":"🎨",
    "photoshop":"🎨","illustrator":"✒️","lightroom":"📷",
    "final cut":"🎬","imovie":"🎬",
    "vlc":"▶️","iina":"▶️","infuse":"▶️",
    "1password":"🔑","bitwarden":"🔑",
    "notion":"📋","obsidian":"🪨","bear":"🐻","craft":"✍️",
    "tableplus":"🗄️","sequel pro":"🗄️","postico":"🗄️",
    "docker":"🐳","proxyman":"🔬","charles":"🔬",
    "postman":"📮","insomnia":"😴",
    "raycast":"🚀","alfred":"🔍",
    "magnet":"🧲","rectangle":"🟦",
    "dropbox":"📦","google drive":"☁️","onedrive":"☁️",
    "default":"📱",
}

VSCODE_PATHS = [
    "/Applications/Visual Studio Code.app",
    "/Applications/VSCode.app",
    "/usr/local/bin/code",
    os.path.expanduser("~/Applications/Visual Studio Code.app"),
]

def emoji_for(name: str) -> str:
    lo = name.lower()
    for k, v in APP_EMOJI.items():
        if k in lo:
            return v
    return APP_EMOJI["default"]

def get_running_apps() -> dict:
    r = run_script('''
tell application "System Events"
    set procs to every application process whose background only is false
    set out to {}
    repeat with p in procs
        set end of out to name of p
    end repeat
    return out
end tell''')
    names = [n.strip() for n in r.get("output","").split(",") if n.strip()]
    return {"ok": True,
            "apps": sorted([{"name": n, "emoji": emoji_for(n)} for n in names],
                           key=lambda x: x["name"].lower())}

def get_installed_apps() -> dict:
    dirs = [
        "/Applications",
        os.path.expanduser("~/Applications"),
        "/Applications/Utilities",
        "/System/Applications",
        "/System/Applications/Utilities",
    ]
    seen, apps = set(), []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            for e in sorted(os.listdir(d)):
                if not e.endswith(".app"):
                    continue
                name = e[:-4]
                if name.lower() in seen:
                    continue
                seen.add(name.lower())
                apps.append({"name": name, "emoji": emoji_for(name),
                             "path": os.path.join(d, e)})
        except PermissionError:
            pass

    for vp in VSCODE_PATHS:
        if os.path.exists(vp) and vp.endswith(".app"):
            name = os.path.basename(vp)[:-4]
            if name.lower() not in seen:
                seen.add(name.lower())
                apps.append({"name": name, "emoji": "💻", "path": vp})

    return {"ok": True, "apps": sorted(apps, key=lambda x: x["name"].lower())}

# ─── Safari ──────────────────────────────────────────────────────────────────

SAFARI_ACTS = {
    "back":       'tell application "Safari" to do JavaScript "history.back()" in front document',
    "forward":    'tell application "Safari" to do JavaScript "history.forward()" in front document',
    "reload":     'tell application "Safari" to do JavaScript "location.reload()" in front document',
    "new_tab":    'tell application "Safari" to make new document',
    "close_tab":  'tell application "System Events" to keystroke "w" using command down',
    "focus":      'tell application "Safari" to activate',
    "scroll_top": 'tell application "Safari" to do JavaScript "window.scrollTo(0,0)" in front document',
    "scroll_bot": 'tell application "Safari" to do JavaScript "window.scrollTo(0,document.body.scrollHeight)" in front document',
}

def safari_info() -> dict:
    r = run_script('''
tell application "Safari"
    if it is running then
        try
            return (name of front document) & "|||" & (URL of front document)
        end try
    end if
    return "|||"
end tell''')
    p = r.get("output", "|||").split("|||", 1)
    return {"ok": True, "title": p[0], "url": p[1] if len(p) > 1 else ""}

def safari_navigate(url: str) -> dict:
    if url and not url.startswith("http"):
        url = "https://" + url
    safe = url.replace('"', '\\"')
    return run_script(f'tell application "Safari" to set URL of front document to "{safe}"')

def safari_new_tab(url: str = "") -> dict:
    if url and not url.startswith("http"):
        url = "https://" + url
    safe = url.replace('"', '\\"')
    return run_script(f'''
tell application "Safari"
    activate
    make new document
    if "{safe}" is not "" then set URL of front document to "{safe}"
end tell''')

def safari_js(js: str) -> dict:
    safe = js.replace("\\","\\\\").replace('"','\\"')
    return run_script(f'tell application "Safari" to do JavaScript "{safe}" in front document')

# ─── System status ────────────────────────────────────────────────────────────

def get_status() -> dict:
    """Parallel fetch of all status data — was serial (2–4 s), now concurrent."""
    with ThreadPoolExecutor(max_workers=6) as ex:
        fvol   = ex.submit(run_script, "output volume of (get volume settings)")
        fmuted = ex.submit(run_script, "output muted of (get volume settings)")
        ffront = ex.submit(run_script,
                           'tell application "System Events" to name of first application process whose frontmost is true')
        fsaf   = ex.submit(safari_info)
        fbatt  = ex.submit(get_battery)
        fsp    = ex.submit(get_spotify_status)

    vol   = fvol.result()
    muted = fmuted.result()
    front = ffront.result()
    saf   = fsaf.result()
    batt  = fbatt.result()
    sp    = fsp.result()

    return {
        "volume":       vol.get("output", "?"),
        "muted":        muted.get("output","false") == "true",
        "spotify":      sp,
        "front_app":    front.get("output",""),
        "safari_title": saf.get("title",""),
        "safari_url":   saf.get("url",""),
        "battery":      batt,
    }

def set_volume(level: int) -> dict:
    return run_script(f"set volume output volume {max(0,min(100,level))}")

def type_text(text: str) -> dict:
    safe = text.replace("\\","\\\\").replace('"','\\"')
    return run_script(f'tell application "System Events" to keystroke "{safe}"')

def open_url_mac(url: str) -> dict:
    safe = url.replace('"','\\"')
    return run_script(f'open location "{safe}"')

def terminal_run_silent(cmd: str) -> dict:
    return run_shell_str(cmd, timeout=30)

def terminal_run_visible(cmd: str) -> dict:
    safe = cmd.replace("\\","\\\\").replace('"','\\"')
    return run_script(f'''
tell application "Terminal"
    activate
    do script "{safe}"
end tell''')

def terminal_get_output() -> dict:
    return run_script('''
tell application "Terminal"
    if it is running then
        try
            return contents of front window
        end try
    end if
    return ""
end tell''', timeout=5)

# ─── Clipboard ───────────────────────────────────────────────────────────────

def get_clipboard() -> dict:
    r = run_shell(["pbpaste"])
    return {"ok": True, "text": r.get("output", "")}

def set_clipboard(text: str) -> dict:
    try:
        proc = subprocess.run(["pbcopy"], input=text, text=True, timeout=5)
        return {"ok": proc.returncode == 0}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ─── Notifications ────────────────────────────────────────────────────────────

def send_notification(title: str, message: str, subtitle: str = "") -> dict:
    def _esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')
    sub_part = f' subtitle "{_esc(subtitle)}"' if subtitle.strip() else ""
    script = f'display notification "{_esc(message)}"{sub_part} with title "{_esc(title)}"'
    return run_script(script)

# ─── Screenshot to base64 ────────────────────────────────────────────────────

def screenshot_b64() -> dict:
    """Capture screen as JPEG, resize to max 1280 px, return base64."""
    path = "/tmp/msmr_ss.jpg"
    try:
        r = run_shell(["screencapture", "-x", "-t", "jpg", path])
        if not os.path.exists(path):
            return {"ok": False, "error": r.get("error", "Capture failed — is screen locked?")}
        # Resize to max 1280px (keeps aspect ratio), reduces transfer size significantly
        run_shell(["sips", "-Z", "1280", path])
        with open(path, "rb") as f:
            data = base64.b64encode(f.read()).decode()
        os.unlink(path)
        return {"ok": True, "data": data, "mime": "image/jpeg"}
    except Exception as e:
        if os.path.exists(path):
            try: os.unlink(path)
            except: pass
        return {"ok": False, "error": str(e)}

# ─── Dark Mode ───────────────────────────────────────────────────────────────

def get_darkmode() -> dict:
    r = run_script('''
tell application "System Events"
    tell appearance preferences
        return dark mode
    end tell
end tell''')
    return {"ok": True, "dark_mode": r.get("output", "").strip().lower() == "true"}

def toggle_darkmode() -> dict:
    r = run_script('''
tell application "System Events"
    tell appearance preferences
        set dark mode to not dark mode
        return dark mode
    end tell
end tell''')
    state = r.get("output", "").strip().lower() == "true"
    r["dark_mode"] = state
    return r

# ─── Empty Trash (non-blocking) ──────────────────────────────────────────────

def _empty_trash_bg() -> dict:
    """Fire-and-forget trash empty — avoids HTTP timeout on large files."""
    try:
        subprocess.Popen(
            ["osascript", "-e", 'tell application "Finder" to empty trash'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return {"ok": True, "output": "Emptying trash in background…"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ─── App Icon ─────────────────────────────────────────────────────────────────

def get_app_icon_b64(app_name: str) -> dict:
    """Return the macOS app icon as a base64-encoded PNG (60×60)."""
    search_dirs = [
        "/Applications",
        os.path.expanduser("~/Applications"),
        "/System/Applications",
        "/System/Applications/Utilities",
        "/Applications/Utilities",
    ]
    app_path = None
    for d in search_dirs:
        p = os.path.join(d, f"{app_name}.app")
        if os.path.exists(p):
            app_path = p
            break
    if not app_path:
        return {"ok": False, "error": "App not found"}
    try:
        info_plist = os.path.join(app_path, "Contents", "Info.plist")
        r = run_shell(["defaults", "read", info_plist, "CFBundleIconFile"], timeout=5)
        icon_name = r.get("output", "").strip() or "AppIcon"
        if not icon_name.endswith(".icns"):
            icon_name += ".icns"
        icon_path = os.path.join(app_path, "Contents", "Resources", icon_name)
        if not os.path.exists(icon_path):
            for fb in ["AppIcon.icns", "Application.icns", "app.icns"]:
                fp = os.path.join(app_path, "Contents", "Resources", fb)
                if os.path.exists(fp):
                    icon_path = fp
                    break
        if not os.path.exists(icon_path):
            return {"ok": False, "error": "Icon file not found"}
        safe_name = app_name.replace(" ", "_").replace("/", "_")
        tmp = f"/tmp/msmr_ico_{safe_name}.png"
        run_shell(["sips", "-s", "format", "png", "--resampleWidth", "60",
                   icon_path, "--out", tmp], timeout=10)
        if not os.path.exists(tmp):
            return {"ok": False, "error": "sips conversion failed"}
        with open(tmp, "rb") as f:
            data = base64.b64encode(f.read()).decode()
        try:
            os.unlink(tmp)
        except Exception:
            pass
        return {"ok": True, "data": data, "mime": "image/png"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ─── Force Quit ───────────────────────────────────────────────────────────────

def force_quit_app(name: str) -> dict:
    """Kill -9 via shell (instant), fallback to AppleScript quit."""
    r = run_shell(["killall", "-9", name], timeout=5)
    if not r["ok"]:
        safe = name.replace('"', '\\"')
        r = run_script(f'tell application "{safe}" to quit saving no', timeout=6)
    return r

# ─── Controls dict ────────────────────────────────────────────────────────────

CONTROLS = {
    "play_pause":       lambda: run_script('tell application "Spotify" to playpause'),
    "next_track":       lambda: run_script('tell application "Spotify" to next track'),
    "prev_track":       lambda: run_script('tell application "Spotify" to previous track'),
    "vol_up":           lambda: run_script('set volume output volume (output volume of (get volume settings) + 10)'),
    "vol_down":         lambda: run_script('set volume output volume (output volume of (get volume settings) - 10)'),
    "mute":             lambda: run_script("set volume with output muted"),
    "unmute":           lambda: run_script("set volume without output muted"),
    "sleep":            lambda: run_script('tell application "System Events" to sleep'),
    "lock":             lambda: run_shell(["pmset","displaysleepnow"]),
    "screenshot":       lambda: run_shell(["screencapture","-x",
                                           os.path.expanduser("~/Desktop/iphone_capture.png")]),
    "empty_trash":      lambda: _empty_trash_bg(),
    "show_desktop":     lambda: run_script('tell application "System Events" to keystroke "d" using {command down, mission control key down}'),
    "bright_up":        lambda: run_script('tell application "System Events" to key code 144'),
    "bright_down":      lambda: run_script('tell application "System Events" to key code 145'),
    "mission_control":  lambda: run_script('tell application "System Events" to key code 160'),
    "launchpad":        lambda: run_script('tell application "System Events" to key code 131'),
    "dark_mode_toggle": lambda: toggle_darkmode(),
    "force_quit_front": lambda: run_script('''
tell application "System Events"
    set fa to name of first application process whose frontmost is true
    tell process fa to keystroke "q" using command down
end tell'''),
}

# ─── HTTP Handler ─────────────────────────────────────────────────────────────

PUBLIC_PATHS = {"/","/index.html","/cert.pem",
                "/api/ping","/api/auth/status",
                "/api/auth/login","/api/auth/setup"}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"  {self.address_string()} → {fmt % args}")

    def ip(self): return self.client_address[0]
    def token(self): return (self.headers.get("X-Session-Token") or "").strip()
    def authed(self): return valid_session(self.token())

    def _security_headers(self, is_https: bool = False):
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                         "font-src https://fonts.gstatic.com; img-src 'self' data: https://i.scdn.co https://mosaic.scdn.co https://*.spotifycdn.com; "
                         "script-src 'self' 'unsafe-inline'")
        if is_https:
            self.send_header("Strict-Transport-Security", "max-age=31536000")

    def send_json(self, data: dict, code: int = 200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",len(body))
        self.send_header("Access-Control-Allow-Origin","*")
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path: str, mime: str):
        with open(path,"rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type",mime)
        self.send_header("Content-Length",len(body))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def body(self) -> dict:
        n = int(self.headers.get("Content-Length",0))
        raw = self.rfile.read(n)
        try: return json.loads(raw) if raw else {}
        except: return {}

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type,X-Session-Token")
        self.end_headers()

    def guard(self) -> bool:
        if urlparse(self.path).path in PUBLIC_PATHS:
            return True
        if not self.authed():
            self.send_json({"ok":False,"error":"Unauthorized"},401)
            return False
        return True

    def do_GET(self):
        if not self.guard(): return
        parsed = urlparse(self.path)
        path, params = parsed.path, parse_qs(parsed.query)

        if path in ("/","/index.html"):
            self.send_file(os.path.join(BASE_DIR,"index.html"),"text/html;charset=utf-8")
        elif path == "/cert.pem" and os.path.exists(CERT_FILE):
            self.send_file(CERT_FILE,"application/x-pem-file")
        elif path == "/api/ping":
            self.send_json({"ok":True,"ts":time.time()})
        elif path == "/api/auth/status":
            self.send_json({"ok":True,"setup_required":setup_required(),
                            "authenticated":self.authed(),"fingerprint":get_fingerprint(),
                            "pin_length":_cfg.get("pin_length", 6)})
        elif path == "/api/status":       self.send_json(get_status())
        elif path == "/api/battery":      self.send_json(get_battery())
        elif path == "/api/bluetooth":    self.send_json(get_bluetooth_cached())
        elif path == "/api/spotify":      self.send_json(get_spotify_status())
        elif path == "/api/apps/running": self.send_json(get_running_apps())
        elif path == "/api/apps/installed": self.send_json(get_installed_apps())
        elif path == "/api/apps/icon":
            name = params.get("name",[""])[0]
            if name: self.send_json(get_app_icon_b64(name))
            else: self.send_json({"ok":False,"error":"No name"},400)
        elif path == "/api/terminal/output": self.send_json(terminal_get_output())
        elif path == "/api/safari/info":  self.send_json(safari_info())
        elif path == "/api/clipboard":    self.send_json(get_clipboard())
        elif path == "/api/screenshot":   self.send_json(screenshot_b64())
        elif path == "/api/darkmode":     self.send_json(get_darkmode())
        elif path == "/api/safari/action":
            a = params.get("action",[""])[0]
            if a in SAFARI_ACTS: self.send_json(run_script(SAFARI_ACTS[a]))
            else: self.send_json({"ok":False,"error":f"Unknown: {a}"},400)
        elif path == "/api/control":
            a = params.get("action",[""])[0]
            if a in CONTROLS: self.send_json(CONTROLS[a]())
            else: self.send_json({"ok":False,"error":f"Unknown: {a}"},400)
        elif path == "/api/volume":
            try: self.send_json(set_volume(int(params.get("level",["50"])[0])))
            except: self.send_json({"ok":False,"error":"Invalid"},400)
        else:
            self.send_json({"ok":False,"error":"Not found"},404)

    def do_POST(self):
        path = urlparse(self.path).path
        data = self.body()

        # ── Auth endpoints (no token required) ──
        if path == "/api/auth/login":
            ip = self.ip()
            if not rate_ok(ip):
                self.send_json({"ok":False,"error":"Too many attempts. Wait 5 minutes."},429)
                return
            if setup_required():
                self.send_json({"ok":False,"error":"Server not set up"},400)
                return
            pin = data.get("pin","")
            if verify_pin(pin, _cfg["pin_salt"], _cfg["pin_hash"]):
                clear_fail(ip)
                self.send_json({"ok":True,"token":create_session()})
            else:
                record_fail(ip)
                left = max(0, 5 - _attempts.get(ip,[0,0])[0])
                self.send_json({"ok":False,"error":f"Wrong PIN. {left} attempt(s) left."},401)
            return

        if path == "/api/auth/setup":
            if not setup_required():
                self.send_json({"ok":False,"error":"Already configured"},400)
                return
            pin = data.get("pin","")
            if not (pin.isdigit() and 4 <= len(pin) <= 12):
                self.send_json({"ok":False,"error":"PIN must be 4–12 digits"},400)
                return
            salt, h = hash_pin(pin)
            _cfg["pin_salt"] = salt; _cfg["pin_hash"] = h
            _cfg["pin_length"] = len(pin)
            save_config()
            self.send_json({"ok":True,"token":create_session()})
            return

        # ── Authenticated routes ──
        if not self.guard(): return

        if path == "/api/unlock/wake":
            self.send_json(wake_display())
        elif path == "/api/unlock":
            self.send_json(unlock_mac(data.get("password","")))
        elif path == "/api/type":
            self.send_json(type_text(data.get("text","")))
        elif path == "/api/url":
            self.send_json(open_url_mac(data.get("url","")))
        elif path == "/api/custom":
            self.send_json(run_script(data.get("script","")))
        elif path == "/api/terminal/run":
            cmd = data.get("command","")
            self.send_json(terminal_run_visible(cmd) if data.get("visible") else terminal_run_silent(cmd))
        elif path == "/api/safari/navigate":
            self.send_json(safari_navigate(data.get("url","")))
        elif path == "/api/safari/newtab":
            self.send_json(safari_new_tab(data.get("url","")))
        elif path == "/api/safari/js":
            self.send_json(safari_js(data.get("js","")))
        elif path == "/api/apps/focus":
            name = data.get("name","").replace('"','\\"')
            self.send_json(run_script(f'tell application "{name}" to activate'))
        elif path == "/api/apps/launch":
            p = data.get("path","")
            n = data.get("name","")
            if p.startswith("/"):
                self.send_json(run_shell(["open", p]))
            else:
                self.send_json(run_script(f'tell application "{n}" to activate'))
        elif path == "/api/apps/quit":
            n = data.get("name","").replace('"','\\"')
            self.send_json(run_script(f'tell application "{n}" to quit'))
        elif path == "/api/apps/force_quit":
            self.send_json(force_quit_app(data.get("name","")))
        elif path == "/api/bluetooth/connect":
            self.send_json(bluetooth_toggle(data.get("address",""), True))
        elif path == "/api/bluetooth/disconnect":
            self.send_json(bluetooth_toggle(data.get("address",""), False))
        # ── Clipboard ──
        elif path == "/api/clipboard":
            self.send_json(set_clipboard(data.get("text","")))
        # ── Notifications ──
        elif path == "/api/notify":
            self.send_json(send_notification(
                data.get("title","Mac Remote"),
                data.get("message",""),
                data.get("subtitle","")
            ))
        # ── Dark mode ──
        elif path == "/api/darkmode/toggle":
            self.send_json(toggle_darkmode())
        # ── Auth management ──
        elif path == "/api/auth/change_pin":
            op = data.get("old_pin",""); np = data.get("new_pin","")
            if not verify_pin(op, _cfg["pin_salt"], _cfg["pin_hash"]):
                self.send_json({"ok":False,"error":"Current PIN incorrect"})
            elif not (np.isdigit() and 4 <= len(np) <= 12):
                self.send_json({"ok":False,"error":"New PIN: 4–12 digits"})
            else:
                salt, h = hash_pin(np)
                _cfg["pin_salt"] = salt; _cfg["pin_hash"] = h
                save_config()
                self.send_json({"ok":True})
        elif path == "/api/auth/logout":
            _sessions.pop(self.token(), None)
            self.send_json({"ok":True})
        else:
            self.send_json({"ok":False,"error":"Not found"},404)

# ─── Entry point ─────────────────────────────────────────────────────────────

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8",80))
        return s.getsockname()[0]
    finally:
        s.close()

if __name__ == "__main__":
    PORT = 5001
    ip = get_local_ip()
    load_config()
    if setup_required():
        interactive_setup()
    use_https = generate_cert(ip)

    server = HTTPServer(("0.0.0.0", PORT), Handler)
    proto = "http"
    if use_https:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(CERT_FILE, KEY_FILE)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            proto = "https"
        except Exception as e:
            print(f"  ⚠ TLS failed ({e}) — falling back to HTTP")

    fp = get_fingerprint()
    print("\n" + "═"*56)
    print("  🍎  MS Mac Remote v5")
    print("═"*56)
    print(f"  Protocol : {'HTTPS (TLS 1.2+)' if proto=='https' else 'HTTP'}")
    print(f"\n  📱  iPhone URL:  {proto}://{ip}:{PORT}")
    if proto == "https":
        print(f"\n  🔒  Cert fingerprint (SHA-256):")
        print(f"      {fp}")
        print(f"\n  ⚠   First visit: Safari → Show Details → Visit This Website")
        print(f"      To permanently trust: open {proto}://{ip}:{PORT}/cert.pem")
    print("\n  Ctrl+C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
