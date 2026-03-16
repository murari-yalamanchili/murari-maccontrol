#!/usr/bin/env python3
"""
Murari WinControl — server_windows.py
Windows remote control server (Android / iPhone → Windows PC)

Backend  : PowerShell + ctypes (zero pip) or Pillow + pycaw (minimal pip)
Auth     : PBKDF2-SHA256 PIN, session tokens, rate limiting
Transport: HTTPS (self-signed cert) or HTTP fallback

Run via setup.bat  or  python setup_windows.py
"""

import subprocess, json, socket, os, time, ssl, hashlib, secrets
import re, base64, ctypes, winreg, platform
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
CERT_FILE   = os.path.join(BASE_DIR, "cert.pem")
KEY_FILE    = os.path.join(BASE_DIR, "key.pem")
CNF_FILE    = os.path.join(BASE_DIR, "ssl.cnf")

# ── Optional deps ─────────────────────────────────────────────────────────────
try:
    from PIL import ImageGrab
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False

try:
    from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
    from comtypes import CLSCTX_ALL
    HAS_PYCAW = True
except ImportError:
    HAS_PYCAW = False

# ── Windows virtual key codes ─────────────────────────────────────────────────
VK_MEDIA_NEXT_TRACK  = 0xB0
VK_MEDIA_PREV_TRACK  = 0xB1
VK_MEDIA_STOP        = 0xB2
VK_MEDIA_PLAY_PAUSE  = 0xB3
VK_VOLUME_MUTE       = 0xAD
VK_VOLUME_DOWN       = 0xAE
VK_VOLUME_UP         = 0xAF

# ── Helpers ───────────────────────────────────────────────────────────────────

def run_ps(script: str, timeout: int = 10) -> dict:
    """Run a PowerShell script string and return stdout/stderr."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=timeout
        )
        return {
            "ok":     r.returncode == 0,
            "output": r.stdout.strip(),
            "error":  r.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "output": ""}
    except Exception as e:
        return {"ok": False, "error": str(e), "output": ""}

def run_shell(cmd: list, timeout: int = 10) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"ok": r.returncode == 0,
                "output": r.stdout.strip(), "error": r.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "output": ""}
    except Exception as e:
        return {"ok": False, "error": str(e), "output": ""}

def send_vk(vk: int):
    """Simulate a virtual key press via keybd_event."""
    ctypes.windll.user32.keybd_event(vk, 0, 0, 0)
    ctypes.windll.user32.keybd_event(vk, 0, 2, 0)  # KEYEVENTF_KEYUP

def feature_enabled(feat: str) -> bool:
    return feat in _cfg.get("features", [
        "media","apps","system","clipboard","notifications","terminal","brightness"
    ])

# ── Auth / Crypto ─────────────────────────────────────────────────────────────

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
    if not token or token not in _sessions:
        return False
    if time.time() > _sessions[token]:
        _sessions.pop(token, None)
        return False
    _sessions[token] = time.time() + 86_400
    return True

def rate_ok(ip: str) -> bool:
    rec = _attempts.get(ip)
    if not rec: return True
    count, since = rec
    if count >= 5 and time.time() - since < 300: return False
    if time.time() - since >= 300: _attempts.pop(ip, None)
    return True

def record_fail(ip: str):
    rec = _attempts.get(ip)
    if rec: rec[0] += 1
    else: _attempts[ip] = [1, time.time()]

def clear_fail(ip: str):
    _attempts.pop(ip, None)

# ── Config ────────────────────────────────────────────────────────────────────

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
    import getpass
    while True:
        pin = input("  PIN (4–12 digits): ").strip()
        if pin.isdigit() and 4 <= len(pin) <= 12:
            if input("  Confirm PIN: ").strip() == pin:
                break
            print("  Mismatch — try again.")
        else:
            print("  Must be 4–12 digits.")
    salt, h = hash_pin(pin)
    _cfg["pin_salt"]   = salt
    _cfg["pin_hash"]   = h
    _cfg["pin_length"] = len(pin)
    save_config()
    print("  ✓ PIN saved (PBKDF2-SHA256, 200k rounds)\n")

# ── TLS cert ─────────────────────────────────────────────────────────────────

def generate_cert(ip: str) -> bool:
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return True
    print("  Generating TLS cert (RSA-2048)…")
    cnf = (f"[req]\ndistinguished_name=dn\nx509_extensions=san\nprompt=no\n"
           f"[dn]\nCN=MurariWinCtrl\nO=Local\n"
           f"[san]\nsubjectAltName=IP:{ip},IP:127.0.0.1,DNS:localhost\n")
    with open(CNF_FILE, "w") as f:
        f.write(cnf)
    r = subprocess.run(
        ["openssl","req","-x509","-newkey","rsa:2048",
         "-keyout",KEY_FILE,"-out",CERT_FILE,"-days","730",
         "-nodes","-config",CNF_FILE],
        capture_output=True, timeout=45
    )
    if r.returncode != 0:
        subprocess.run(
            ["openssl","req","-x509","-newkey","rsa:2048",
             "-keyout",KEY_FILE,"-out",CERT_FILE,"-days","730",
             "-nodes","-subj","/CN=MurariWinCtrl"],
            capture_output=True, timeout=45
        )
    ok = os.path.exists(CERT_FILE)
    if ok: print("  ✓ TLS cert ready")
    return ok

def get_fingerprint() -> str:
    if not os.path.exists(CERT_FILE): return ""
    r = subprocess.run(
        ["openssl","x509","-noout","-fingerprint","-sha256","-in",CERT_FILE],
        capture_output=True, text=True
    )
    fp = r.stdout.strip()
    for pfx in ["SHA256 Fingerprint=","sha256 Fingerprint="]:
        fp = fp.replace(pfx, "")
    return fp

# ── Media ─────────────────────────────────────────────────────────────────────

def media_play_pause() -> dict:
    send_vk(VK_MEDIA_PLAY_PAUSE)
    return {"ok": True, "output": "play/pause"}

def media_next() -> dict:
    send_vk(VK_MEDIA_NEXT_TRACK)
    return {"ok": True, "output": "next track"}

def media_prev() -> dict:
    send_vk(VK_MEDIA_PREV_TRACK)
    return {"ok": True, "output": "previous track"}

def media_stop() -> dict:
    send_vk(VK_MEDIA_STOP)
    return {"ok": True, "output": "stop"}

# ── Volume ────────────────────────────────────────────────────────────────────

def _pycaw_volume_interface():
    devices = AudioUtilities.GetSpeakers()
    interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
    return interface.QueryInterface(IAudioEndpointVolume)

def get_volume() -> dict:
    try:
        if HAS_PYCAW:
            vol = _pycaw_volume_interface()
            pct = round(vol.GetMasterVolumeLevelScalar() * 100)
            muted = bool(vol.GetMute())
        else:
            # waveout fallback (left channel)
            v = ctypes.c_uint32()
            ctypes.windll.winmm.waveOutGetVolume(None, ctypes.byref(v))
            pct = round((v.value & 0xFFFF) * 100 / 65535)
            muted = False
        return {"ok": True, "volume": pct, "muted": muted}
    except Exception as e:
        return {"ok": False, "error": str(e), "volume": 0, "muted": False}

def set_volume(level: int) -> dict:
    level = max(0, min(100, level))
    try:
        if HAS_PYCAW:
            vol = _pycaw_volume_interface()
            vol.SetMasterVolumeLevelScalar(level / 100.0, None)
        else:
            val = int(level * 65535 / 100)
            packed = val | (val << 16)
            ctypes.windll.winmm.waveOutSetVolume(None, packed)
        return {"ok": True, "volume": level}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def vol_up() -> dict:
    send_vk(VK_VOLUME_UP)
    return {"ok": True, "output": "volume up"}

def vol_down() -> dict:
    send_vk(VK_VOLUME_DOWN)
    return {"ok": True, "output": "volume down"}

def mute_toggle() -> dict:
    send_vk(VK_VOLUME_MUTE)
    return {"ok": True, "output": "mute toggle"}

def set_mute(mute: bool) -> dict:
    try:
        if HAS_PYCAW:
            vol = _pycaw_volume_interface()
            vol.SetMute(int(mute), None)
            return {"ok": True}
        else:
            send_vk(VK_VOLUME_MUTE)
            return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ── Brightness (WMI — works on laptops / WMI-capable monitors) ───────────────

def get_brightness() -> dict:
    r = run_ps(
        "(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightness "
        "-ErrorAction SilentlyContinue).CurrentBrightness"
    )
    try:
        return {"ok": True, "brightness": int(r["output"])}
    except Exception:
        return {"ok": False, "error": "WMI brightness not supported on this monitor"}

def set_brightness(level: int) -> dict:
    level = max(0, min(100, level))
    r = run_ps(
        f"(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightnessMethods "
        f"-ErrorAction SilentlyContinue).WmiSetBrightness(1,{level})"
    )
    return {"ok": r["ok"], "brightness": level, "error": r.get("error","")}

# ── Screenshot ────────────────────────────────────────────────────────────────

def screenshot_b64() -> dict:
    tmp = os.path.join(os.environ.get("TEMP","C:\\Temp"), "mwc_ss.png")
    try:
        if HAS_PILLOW:
            img = ImageGrab.grab()
            # Resize to max 1280px wide
            w, h = img.size
            if w > 1280:
                img = img.resize((1280, int(h * 1280 / w)))
            img.save(tmp, "PNG", optimize=True)
        else:
            # PowerShell .NET screenshot
            ps = f"""
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$s  = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bm = New-Object System.Drawing.Bitmap($s.Width, $s.Height)
$gr = [System.Drawing.Graphics]::FromImage($bm)
$gr.CopyFromScreen($s.Location, [System.Drawing.Point]::Empty, $s.Size)
$bm.Save('{tmp}')
$gr.Dispose(); $bm.Dispose()
"""
            r = run_ps(ps, timeout=15)
            if not r["ok"]:
                return {"ok": False, "error": r["error"]}

        if not os.path.exists(tmp):
            return {"ok": False, "error": "Screenshot file not created"}

        with open(tmp, "rb") as f:
            data = base64.b64encode(f.read()).decode()
        os.unlink(tmp)
        return {"ok": True, "data": data, "mime": "image/png"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ── System actions ────────────────────────────────────────────────────────────

def lock_screen() -> dict:
    ctypes.windll.user32.LockWorkStation()
    return {"ok": True, "output": "Screen locked"}

def sleep_pc() -> dict:
    # SetSuspendState(hibernate=0, forceCritical=1, disableWakeEvent=0)
    ctypes.windll.powrprof.SetSuspendState(0, 1, 0)
    return {"ok": True, "output": "Sleeping"}

def shutdown_pc() -> dict:
    r = run_shell(["shutdown", "/s", "/t", "30"])
    return {"ok": r["ok"], "output": "Shutdown in 30s — run 'shutdown /a' to cancel"}

def restart_pc() -> dict:
    r = run_shell(["shutdown", "/r", "/t", "30"])
    return {"ok": r["ok"], "output": "Restart in 30s — run 'shutdown /a' to cancel"}

def cancel_shutdown() -> dict:
    r = run_shell(["shutdown", "/a"])
    return {"ok": r["ok"], "output": "Shutdown cancelled"}

# ── Dark mode ─────────────────────────────────────────────────────────────────

REG_PERSONALIZE = (
    r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
)

def get_darkmode() -> dict:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PERSONALIZE)
        val, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        winreg.CloseKey(key)
        return {"ok": True, "dark_mode": val == 0}
    except Exception as e:
        return {"ok": False, "error": str(e), "dark_mode": False}

def toggle_darkmode() -> dict:
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, REG_PERSONALIZE,
            0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE
        )
        cur, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        new    = 1 - cur   # toggle
        winreg.SetValueEx(key, "AppsUseLightTheme",   0, winreg.REG_DWORD, new)
        winreg.SetValueEx(key, "SystemUsesLightTheme", 0, winreg.REG_DWORD, new)
        winreg.CloseKey(key)
        return {"ok": True, "dark_mode": new == 0}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ── Clipboard ─────────────────────────────────────────────────────────────────

def get_clipboard() -> dict:
    r = run_ps("Get-Clipboard")
    return {"ok": True, "text": r.get("output", "")}

def set_clipboard(text: str) -> dict:
    safe = text.replace("'", "''")
    r = run_ps(f"Set-Clipboard -Value '{safe}'")
    return {"ok": r["ok"], "error": r.get("error", "")}

# ── Notifications ─────────────────────────────────────────────────────────────

def send_notification(title: str, message: str, subtitle: str = "") -> dict:
    def _q(s): return s.replace("'","''").replace('"','\\"')
    body = subtitle + " — " + message if subtitle else message
    ps = f"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null
$t = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
$x = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($t)
$x.GetElementsByTagName('text')[0].AppendChild($x.CreateTextNode('{_q(title)}')) | Out-Null
$x.GetElementsByTagName('text')[1].AppendChild($x.CreateTextNode('{_q(body)}'))  | Out-Null
$n = [Windows.UI.Notifications.ToastNotification]::new($x)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Murari WinControl').Show($n)
"""
    r = run_ps(ps, timeout=8)
    return {"ok": r["ok"], "error": r.get("error","")}

# ── Apps ──────────────────────────────────────────────────────────────────────

APP_EMOJI = {
    "chrome":"🌐","googlechrome":"🌐","firefox":"🦊","msedge":"🌐","opera":"🌐","brave":"🦁",
    "code":"💻","code - insiders":"💻","cursor":"🖱️","windsurf":"🏄",
    "devenv":"🛠️","visualstudio":"🛠️",
    "spotify":"🎵","itunes":"🎶","vlc":"▶️","mpc-hc":"▶️","mpc-be":"▶️",
    "slack":"💬","teams":"💬","discord":"💬","zoom":"📹","skype":"💬",
    "telegram":"✈️","whatsapp":"💬","signal":"🔒",
    "notepad":"📝","notepad++":"📝","obsidian":"🪨","notion":"📋",
    "word":"📄","excel":"📊","powerpoint":"📊","onenote":"📋","outlook":"📧",
    "winword":"📄","excel":"📊","powerpnt":"📊",
    "explorer":"📁","cmd":"⌨️","powershell":"💻","windowsterminal":"💻",
    "taskmgr":"📊","regedit":"🔑","mspaint":"🎨",
    "steam":"🎮","epicgameslauncher":"🎮",
    "1password":"🔑","bitwarden":"🔑","keepass":"🔑",
    "figma":"🎨","blender":"🎨","gimp":"🎨","inkscape":"✒️",
    "postman":"📮","insomnia":"😴","docker desktop":"🐳","wsl":"🐧",
    "default":"📱",
}

def emoji_for(name: str) -> str:
    lo = name.lower().replace(".exe","")
    for k, v in APP_EMOJI.items():
        if k in lo:
            return v
    return APP_EMOJI["default"]

def get_running_apps() -> dict:
    ps = """
Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $_.MainWindowTitle -ne '' } |
  Select-Object @{N='name';E={$_.ProcessName}},
                @{N='title';E={$_.MainWindowTitle}},
                @{N='pid';E={$_.Id}} |
  ConvertTo-Json -Compress
"""
    r = run_ps(ps, timeout=8)
    try:
        raw = json.loads(r["output"]) if r["output"] else []
        if isinstance(raw, dict): raw = [raw]   # single process comes as object
        apps = []
        seen = set()
        for p in raw:
            name = p.get("name","")
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            apps.append({
                "name":  name,
                "title": p.get("title",""),
                "pid":   p.get("pid", 0),
                "emoji": emoji_for(name),
            })
        apps.sort(key=lambda x: x["name"].lower())
        return {"ok": True, "apps": apps}
    except Exception as e:
        return {"ok": False, "error": str(e), "apps": []}

def get_installed_apps() -> dict:
    ps = r"""
$apps = @()
$paths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
foreach ($p in $paths) {
    if (Test-Path $p) {
        Get-ItemProperty $p |
          Where-Object { $_.DisplayName -and $_.DisplayName -ne '' } |
          Select-Object @{N='name';E={$_.DisplayName}},
                        @{N='path';E={$_.InstallLocation}} |
          ForEach-Object { $apps += $_ }
    }
}
$apps | Sort-Object name -Unique | ConvertTo-Json -Compress
"""
    r = run_ps(ps, timeout=15)
    try:
        raw = json.loads(r["output"]) if r["output"] else []
        if isinstance(raw, dict): raw = [raw]
        apps = [{"name": a.get("name",""), "path": a.get("path","") or "",
                 "emoji": emoji_for(a.get("name",""))}
                for a in raw if a.get("name","").strip()]
        return {"ok": True, "apps": apps[:200]}   # cap at 200
    except Exception as e:
        return {"ok": False, "error": str(e), "apps": []}

def focus_app(name: str) -> dict:
    # Bring main window to foreground via PowerShell + WinAPI
    safe = name.replace("'","''")
    ps = f"""
$p = Get-Process -Name '{safe}' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($p -and $p.MainWindowHandle -ne 0) {{
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public class Win32 {{
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
}}
'@
    [Win32]::ShowWindow($p.MainWindowHandle, 9)
    [Win32]::SetForegroundWindow($p.MainWindowHandle)
    Write-Output "focused"
}} else {{ Write-Error "not found" }}
"""
    r = run_ps(ps, timeout=8)
    return {"ok": "focused" in r["output"], "error": r.get("error","")}

def launch_app(path: str, name: str) -> dict:
    if path and os.path.exists(path):
        r = run_ps(f"Start-Process '{path.replace(chr(39), chr(39)*2)}'")
    else:
        r = run_ps(f"Start-Process '{name.replace(chr(39), chr(39)*2)}'")
    return {"ok": r["ok"], "error": r.get("error","")}

def quit_app(name: str) -> dict:
    safe = name.replace("'","''")
    r = run_ps(f"Get-Process -Name '{safe}' -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue")
    return {"ok": r["ok"], "error": r.get("error","")}

def force_quit_app(name: str) -> dict:
    safe = name.replace("'","''")
    r = run_ps(f"Get-Process -Name '{safe}' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue")
    return {"ok": r["ok"], "error": r.get("error","")}

# ── Terminal ──────────────────────────────────────────────────────────────────

def terminal_run_silent(cmd: str) -> dict:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, timeout=30
        )
        return {"ok": r.returncode==0, "output": r.stdout.strip(),
                "error": r.stderr.strip(), "returncode": r.returncode}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "output": "", "returncode": -1}
    except Exception as e:
        return {"ok": False, "error": str(e), "output": "", "returncode": -1}

def terminal_run_visible(cmd: str) -> dict:
    safe = cmd.replace('"','\\"')
    r = run_ps(f'Start-Process powershell -ArgumentList "-NoExit","-Command","{safe}"')
    return {"ok": r["ok"], "error": r.get("error","")}

# ── Status ────────────────────────────────────────────────────────────────────

def get_status() -> dict:
    with ThreadPoolExecutor(max_workers=4) as ex:
        fvol  = ex.submit(get_volume)
        fdark = ex.submit(get_darkmode)
        fmedia= ex.submit(get_now_playing)
        fbatt = ex.submit(get_battery)

    vol   = fvol.result()
    dark  = fdark.result()
    media = fmedia.result()
    batt  = fbatt.result()

    return {
        "volume":   vol.get("volume", 0),
        "muted":    vol.get("muted", False),
        "dark_mode":dark.get("dark_mode", False),
        "media":    media,
        "battery":  batt,
    }

def get_battery() -> dict:
    ps = """
$b = Get-WmiObject Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
if ($b) {
    $status = switch($b.BatteryStatus){ 2{'charging'} 1{'discharging'} default{'unknown'} }
    "$($b.EstimatedChargeRemaining)|$status"
} else { "none|none" }
"""
    r = run_ps(ps, timeout=6)
    parts = r.get("output","none|none").split("|")
    if parts[0] == "none":
        return {"ok": True, "percent": None, "charging": False, "plugged": False}
    try:
        pct = int(parts[0])
        charging = parts[1] == "charging"
        return {"ok": True, "percent": pct, "charging": charging, "plugged": charging}
    except Exception:
        return {"ok": True, "percent": None, "charging": False, "plugged": False}

def get_now_playing() -> dict:
    """Get current media info from the focused Spotify window title (Artist - Track)."""
    ps = """
$sp = Get-Process -Name spotify -ErrorAction SilentlyContinue |
       Where-Object { $_.MainWindowTitle -ne '' -and $_.MainWindowTitle -ne 'Spotify' } |
       Select-Object -First 1
if ($sp) { $sp.MainWindowTitle } else { '' }
"""
    r = run_ps(ps, timeout=5)
    title = r.get("output","").strip()
    if " - " in title:
        parts = title.split(" - ", 1)
        return {"ok": True, "artist": parts[0].strip(),
                "track": parts[1].strip(), "state": "playing"}
    return {"ok": True, "artist": "", "track": title or "", "state": "unknown"}

# ── Controls dict ─────────────────────────────────────────────────────────────

CONTROLS = {
    "play_pause":       media_play_pause,
    "next_track":       media_next,
    "prev_track":       media_prev,
    "stop":             media_stop,
    "vol_up":           vol_up,
    "vol_down":         vol_down,
    "mute":             lambda: set_mute(True),
    "unmute":           lambda: set_mute(False),
    "mute_toggle":      mute_toggle,
    "lock":             lock_screen,
    "sleep":            sleep_pc,
    "screenshot":       screenshot_b64,
    "dark_mode_toggle": toggle_darkmode,
    "shutdown":         shutdown_pc,
    "restart":          restart_pc,
    "cancel_shutdown":  cancel_shutdown,
    "bright_up":        lambda: set_brightness(min(100, get_brightness().get("brightness",50)+10)),
    "bright_down":      lambda: set_brightness(max(0,  get_brightness().get("brightness",50)-10)),
}

# ── HTTP Handler ──────────────────────────────────────────────────────────────

PUBLIC_PATHS = {"/","/index.html","/cert.pem","/api/ping",
                "/api/auth/status","/api/auth/login","/api/auth/setup"}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"  {self.address_string()} → {fmt % args}")

    def ip(self):    return self.client_address[0]
    def token(self): return (self.headers.get("X-Session-Token") or "").strip()
    def authed(self): return valid_session(self.token())

    def _sec_headers(self):
        self.send_header("X-Frame-Options","DENY")
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("Referrer-Policy","no-referrer")
        self.send_header("Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data: https://i.scdn.co https://mosaic.scdn.co; "
            "script-src 'self' 'unsafe-inline'")

    def send_json(self, data: dict, code: int = 200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",len(body))
        self.send_header("Access-Control-Allow-Origin","*")
        self._sec_headers()
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path: str, mime: str):
        with open(path,"rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type",mime)
        self.send_header("Content-Length",len(body))
        self._sec_headers()
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
        if urlparse(self.path).path in PUBLIC_PATHS: return True
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
                            "pin_length":_cfg.get("pin_length",6),
                            "platform":"windows",
                            "features":_cfg.get("features",[])})
        elif path == "/api/status":
            self.send_json(get_status())
        elif path == "/api/battery":
            self.send_json(get_battery())
        elif path == "/api/volume":
            try: self.send_json(set_volume(int(params.get("level",["50"])[0])))
            except: self.send_json({"ok":False,"error":"Invalid"},400)
        elif path == "/api/volume/get":
            self.send_json(get_volume())
        elif path == "/api/brightness":
            self.send_json(get_brightness())
        elif path == "/api/darkmode":
            self.send_json(get_darkmode())
        elif path == "/api/apps/running":
            self.send_json(get_running_apps())
        elif path == "/api/apps/installed":
            self.send_json(get_installed_apps())
        elif path == "/api/screenshot":
            self.send_json(screenshot_b64())
        elif path == "/api/clipboard":
            self.send_json(get_clipboard())
        elif path == "/api/control":
            a = params.get("action",[""])[0]
            if a in CONTROLS: self.send_json(CONTROLS[a]())
            else: self.send_json({"ok":False,"error":f"Unknown: {a}"},400)
        elif path == "/api/media/nowplaying":
            self.send_json(get_now_playing())
        else:
            self.send_json({"ok":False,"error":"Not found"},404)

    def do_POST(self):
        path = urlparse(self.path).path
        data = self.body()

        # ── Public auth endpoints ──
        if path == "/api/auth/login":
            ip = self.ip()
            if not rate_ok(ip):
                self.send_json({"ok":False,"error":"Too many attempts. Wait 5 minutes."},429)
                return
            if setup_required():
                self.send_json({"ok":False,"error":"Server not set up"},400); return
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
                self.send_json({"ok":False,"error":"Already configured"},400); return
            pin = data.get("pin","")
            if not (pin.isdigit() and 4 <= len(pin) <= 12):
                self.send_json({"ok":False,"error":"PIN must be 4–12 digits"},400); return
            salt, h = hash_pin(pin)
            _cfg["pin_salt"]   = salt
            _cfg["pin_hash"]   = h
            _cfg["pin_length"] = len(pin)
            save_config()
            self.send_json({"ok":True,"token":create_session()}); return

        # ── Authenticated routes ──
        if not self.guard(): return

        if path == "/api/apps/focus":
            self.send_json(focus_app(data.get("name","")))
        elif path == "/api/apps/launch":
            self.send_json(launch_app(data.get("path",""), data.get("name","")))
        elif path == "/api/apps/quit":
            self.send_json(quit_app(data.get("name","")))
        elif path == "/api/apps/force_quit":
            self.send_json(force_quit_app(data.get("name","")))
        elif path == "/api/volume/set":
            self.send_json(set_volume(int(data.get("level",50))))
        elif path == "/api/brightness/set":
            self.send_json(set_brightness(int(data.get("level",50))))
        elif path == "/api/clipboard":
            self.send_json(set_clipboard(data.get("text","")))
        elif path == "/api/notify":
            self.send_json(send_notification(
                data.get("title","WinControl"),
                data.get("message",""),
                data.get("subtitle","")
            ))
        elif path == "/api/darkmode/toggle":
            self.send_json(toggle_darkmode())
        elif path == "/api/terminal/run":
            cmd = data.get("command","")
            if data.get("visible"):
                self.send_json(terminal_run_visible(cmd))
            else:
                self.send_json(terminal_run_silent(cmd))
        elif path == "/api/auth/change_pin":
            op = data.get("old_pin",""); np = data.get("new_pin","")
            if not verify_pin(op, _cfg["pin_salt"], _cfg["pin_hash"]):
                self.send_json({"ok":False,"error":"Current PIN incorrect"})
            elif not (np.isdigit() and 4 <= len(np) <= 12):
                self.send_json({"ok":False,"error":"New PIN: 4–12 digits"})
            else:
                salt, h = hash_pin(np)
                _cfg["pin_salt"]   = salt
                _cfg["pin_hash"]   = h
                _cfg["pin_length"] = len(np)
                save_config()
                self.send_json({"ok":True})
        elif path == "/api/auth/logout":
            _sessions.pop(self.token(), None)
            self.send_json({"ok":True})
        else:
            self.send_json({"ok":False,"error":"Not found"},404)

# ── Entry point ───────────────────────────────────────────────────────────────

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

if __name__ == "__main__":
    PORT = 5001
    ip   = get_local_ip()
    load_config()
    if setup_required():
        interactive_setup()
    use_https = generate_cert(ip)

    server = HTTPServer(("0.0.0.0", PORT), Handler)
    proto  = "http"
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
    print("  🪟  Murari WinControl")
    print(f"  Platform : Windows {platform.version()}")
    print(f"  Deps     : {'Pillow + pycaw' if HAS_PILLOW or HAS_PYCAW else 'stdlib only'}")
    print(f"  Features : {', '.join(_cfg.get('features', ['all']))}")
    print("═"*56)
    print(f"  Protocol : {'HTTPS (TLS 1.2+)' if proto=='https' else 'HTTP'}")
    print(f"\n  📱  Android URL:  {proto}://{ip}:{PORT}")
    if proto == "https":
        print(f"\n  🔒  Cert fingerprint (SHA-256):")
        print(f"      {fp}")
        print(f"\n  ⚠   First visit: tap 'Advanced' → 'Proceed' to trust the cert")
    print("\n  Ctrl+C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
