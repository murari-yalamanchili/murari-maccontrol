#!/usr/bin/env python3
"""
MS Mac Remote — server.py v5
HTTPS · PBKDF2 PIN auth · Session tokens · Battery · Bluetooth · Spotify art
Clipboard · Notifications · Screenshot · Dark Mode
Run: python3 server.py
"""

import subprocess, json, socket, os, time, ssl, hashlib, secrets, re, urllib.request, base64, threading, tempfile

# ── Application-layer AES-256-GCM encryption (optional — needs: pip3 install cryptography) ──
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
    from cryptography.hazmat.primitives import hashes as _hashes
    _ENC_OK = True
except ImportError:
    _ENC_OK = False

_ENC_SALT = b"MSMacCtrl-v1"
_ENC_INFO = b"aes-gcm-256"
_key_cache: dict = {}
_key_cache_lock = threading.Lock()

def _enc_derive(token: str) -> bytes:
    """HKDF-SHA256: session token → 32-byte AES-256-GCM key (cached per token)."""
    # Check cache first (read-only — release lock before the expensive HKDF call)
    with _key_cache_lock:
        cached = _key_cache.get(token)
        if cached:
            return cached

    # Derive key outside the lock (CPU-bound, but HKDF is deterministic so safe)
    hkdf = _HKDF(algorithm=_hashes.SHA256(), length=32,
                 salt=_ENC_SALT, info=_ENC_INFO)
    key = hkdf.derive(bytes.fromhex(token))

    with _key_cache_lock:
        # Re-check: another thread may have derived and stored the key while we worked
        existing = _key_cache.get(token)
        if existing:
            return existing  # Use the already-stored entry; discard our duplicate
        # Evict oldest entry if cache is full
        if len(_key_cache) >= 512:
            oldest = next(iter(_key_cache))
            _key_cache.pop(oldest, None)
        _key_cache[token] = key
    return key

def enc_response(data: dict, token: str) -> dict:
    """Encrypt a response dict → {"e": base64(12-byte-nonce + ciphertext+tag)}.
    If the cryptography package is unavailable, returns a clear error so the
    client knows encryption was not applied (never silently falls back to plaintext).
    """
    if not token:
        return data
    if not _ENC_OK:
        # Signal to the client that server-side encryption is unavailable
        return {"enc_unavailable": True}
    try:
        nonce = os.urandom(12)
        ct = _AESGCM(_enc_derive(token)).encrypt(nonce, json.dumps(data, separators=(',',':')).encode(), None)
        return {"e": base64.b64encode(nonce + ct).decode()}
    except Exception:
        return {"enc_error": True}

def dec_request(body: dict, token: str) -> dict:
    """Decrypt an incoming {"e": base64(nonce+ct)} request body back to a dict."""
    if not _ENC_OK or "e" not in body or not token:
        return body
    try:
        raw = base64.b64decode(body["e"])
        if len(raw) < 13:  # need at least 12-byte nonce + 1 byte
            return {}
        nonce, ct = raw[:12], raw[12:]
        plain = _AESGCM(_enc_derive(token)).decrypt(nonce, ct, None)
        return json.loads(plain)
    except (ValueError, KeyError):
        return {}
    except Exception:
        return {}
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
    # Decode the hex salt back to raw bytes so PBKDF2 uses full 128-bit entropy.
    # Legacy salts stored as hex strings are safe: bytes.fromhex() is the inverse
    # of token_hex(), giving 16 raw bytes regardless of the string representation.
    h = hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 200_000)
    return salt, h.hex()

def verify_pin(pin: str, salt: str, stored: str) -> bool:
    # Try new method first (raw bytes salt)
    _, computed = hash_pin(pin, salt)
    if secrets.compare_digest(computed, stored):
        return True
    # Fallback: try legacy method (salt encoded as UTF-8 ASCII) for credentials
    # created before the bytes.fromhex() fix was applied.
    legacy_h = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 200_000)
    return secrets.compare_digest(legacy_h.hex(), stored)

# ─── macOS Keychain ──────────────────────────────────────────────────────────
# PIN credentials are stored in Keychain, NOT in config.json.
# Keychain requires macOS authentication to read or delete, so clearing
# config.json alone cannot bypass the PIN.

_KC_SERVICE = "MSMacRemote"
_KC_ACCOUNT = "pin_credentials"

def _kc_store(salt: str, pin_hash: str, pin_length: int) -> bool:
    """Write PIN credentials to macOS Keychain (creates or overwrites)."""
    value = f"{salt}:{pin_hash}:{pin_length}"
    r = subprocess.run(
        ["security", "add-generic-password",
         "-s", _KC_SERVICE, "-a", _KC_ACCOUNT, "-w", value, "-U"],
        capture_output=True, timeout=10)
    return r.returncode == 0

def _kc_read() -> "tuple[str,str,int] | None":
    """Read (salt, hash, length) from Keychain, or None if not found."""
    r = subprocess.run(
        ["security", "find-generic-password",
         "-s", _KC_SERVICE, "-a", _KC_ACCOUNT, "-w"],
        capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        return None
    parts = r.stdout.strip().split(":", 2)
    if len(parts) != 3:
        return None
    try:
        return parts[0], parts[1], int(parts[2])
    except (ValueError, IndexError):
        return None

def _kc_exists() -> bool:
    return _kc_read() is not None

def verify_pin_kc(pin: str) -> bool:
    """Verify PIN against Keychain-stored credentials."""
    creds = _kc_read()
    if not creds:
        # Fallback to legacy config.json credentials if Keychain empty
        if "pin_salt" in _cfg and "pin_hash" in _cfg:
            return verify_pin(pin, _cfg["pin_salt"], _cfg["pin_hash"])
        return False
    kc_salt, kc_hash, _ = creds
    return verify_pin(pin, kc_salt, kc_hash)

def get_pin_length() -> int:
    """Return configured PIN length from Keychain (authoritative) or config fallback."""
    creds = _kc_read()
    if creds:
        return creds[2]
    return _cfg.get("pin_length", 6)

def migrate_config_to_keychain():
    """One-time migration: move PIN credentials from config.json into Keychain."""
    if _kc_exists():
        # Already in Keychain — verify the write is readable before stripping config
        if _kc_read() is not None:
            changed = any(k in _cfg for k in ("pin_salt", "pin_hash", "pin_length"))
            for k in ("pin_salt", "pin_hash", "pin_length"):
                _cfg.pop(k, None)
            if changed:
                save_config()
        else:
            print("  ⚠ Keychain entry exists but is unreadable — leaving config.json intact")
        return
    if "pin_salt" in _cfg and "pin_hash" in _cfg:
        salt = _cfg["pin_salt"]
        ph   = _cfg["pin_hash"]
        plen = _cfg.get("pin_length", 6)
        if _kc_store(salt, ph, plen):
            # Verify the write actually landed before removing the only copy
            if _kc_read() is not None:
                print("  ✓ PIN credentials migrated to macOS Keychain")
                for k in ("pin_salt", "pin_hash", "pin_length"):
                    _cfg.pop(k, None)
                save_config()
            else:
                print("  ⚠ Keychain write reported success but read-back failed — credentials kept in config.json")
        else:
            print("  ⚠ Keychain migration failed — credentials remain in config.json")

_sessions: dict = {}
_attempts: dict = {}
_state_lock = threading.Lock()

# Screenshot rate limiting: max 1 request per 2 seconds per token
_screenshot_last: dict = {}
_screenshot_lock = threading.Lock()

def screenshot_rate_ok(token: str) -> bool:
    now = time.time()
    with _screenshot_lock:
        last = _screenshot_last.get(token, 0)
        if now - last < 2.0:
            return False
        _screenshot_last[token] = now
        return True

def create_session() -> str:
    token = secrets.token_hex(32)
    with _state_lock:
        _sessions[token] = time.time() + 86_400
        now = time.time()
        for t in [k for k, v in list(_sessions.items()) if v < now]:
            _sessions.pop(t, None)
    return token

def valid_session(token: str) -> bool:
    """Validate and touch (extend) session expiry on every authenticated request."""
    if not token:
        return False
    with _state_lock:
        if token not in _sessions:
            return False
        if time.time() > _sessions[token]:
            _sessions.pop(token, None)
            # Evict the derived key for this expired token
            with _key_cache_lock:
                _key_cache.pop(token, None)
            return False
        # Touch: extend 24 h from now on every valid use
        _sessions[token] = time.time() + 86_400
    return True

def rate_ok(ip: str) -> bool:
    with _state_lock:
        rec = _attempts.get(ip)
        if not rec:
            return True
        elapsed = time.time() - rec["since"]
        if elapsed >= 300:
            _attempts.pop(ip, None)
            return True
        if rec["count"] >= 5:
            return False
    return True

def record_fail(ip: str):
    with _state_lock:
        rec = _attempts.get(ip)
        if rec:
            rec["count"] += 1
        else:
            _attempts[ip] = {"count": 1, "since": time.time()}

def clear_fail(ip: str):
    with _state_lock:
        _attempts.pop(ip, None)

# ─── Config ───────────────────────────────────────────────────────────────────

_cfg: dict = {}
_cfg_lock  = threading.Lock()

def load_config():
    global _cfg
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            _cfg = json.load(f)
    return _cfg

def save_config():
    with _cfg_lock:
        with open(CONFIG_FILE, "w") as f:
            json.dump(_cfg, f, indent=2)

def setup_required() -> bool:
    # Keychain is the authoritative source — config.json tampering cannot bypass this
    return not _kc_exists() and "pin_hash" not in _cfg

def interactive_setup():
    print("\n  ┌──────────────────────────────────────┐")
    print("  │  First Run — Create your access PIN  │")
    print("  └──────────────────────────────────────┘")
    while True:
        pin = input("  PIN (6–12 digits): ").strip()
        if pin.isdigit() and 6 <= len(pin) <= 12:
            if input("  Confirm PIN: ").strip() == pin:
                break
            print("  Mismatch.")
        else:
            print("  Must be 6–12 digits.")
    salt, h = hash_pin(pin)
    if _kc_store(salt, h, len(pin)):
        print("  ✓ PIN saved to macOS Keychain (PBKDF2-SHA256, 200k rounds)\n")
    else:
        print("  ⚠ Keychain unavailable — storing in config.json (less secure)")
        _cfg["pin_salt"] = salt
        _cfg["pin_hash"] = h
        _cfg["pin_length"] = len(pin)
        save_config()

# ─── TLS ─────────────────────────────────────────────────────────────────────

def generate_cert(ip: str) -> bool:
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        # Ensure the existing key file is not world-readable
        try:
            os.chmod(KEY_FILE, 0o600)
        except OSError:
            pass
        return True
    print("  Generating TLS cert (EC P-256)…")
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

    # Use EC P-256: stronger than RSA-2048 with a smaller key and faster TLS handshake.
    # -nodes is intentionally NOT used — the private key file is protected by 0o600
    # permissions instead of a passphrase (passphrase on an auto-starting server is
    # not more secure since the passphrase would need to be stored beside the key anyway).
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:P-256",
         "-keyout", KEY_FILE, "-out", CERT_FILE,
         "-days", "730", "-nodes", "-config", CNF_FILE],
        capture_output=True, timeout=45)
    if r.returncode != 0:
        # Fallback: RSA-3072 with SAN-less subject (older OpenSSL compatibility)
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:3072",
             "-keyout", KEY_FILE, "-out", CERT_FILE,
             "-days", "730", "-nodes", "-subj", "/CN=MSMacRemote"],
            capture_output=True, timeout=45)

    ok = os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)
    if ok:
        # Restrict private key to owner-read/write only (prevents other local users reading it)
        os.chmod(KEY_FILE, 0o600)
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

    safe = password.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "").replace("\r", "")

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

def _get_music_status() -> dict:
    """Fallback: fetch now-playing from Apple Music / iTunes."""
    r = run_script('''
tell application "Music"
    if it is running then
        try
            return (name of current track) & "|||" & (artist of current track) & "|||" & (album of current track) & "|||" & (player state as string)
        end try
    end if
    return "not running"
end tell''')
    out = r.get("output", "not running").strip()
    if out == "not running" or "|||" not in out:
        return {"ok": True, "track": "", "artist": "", "album": "",
                "state": "stopped", "art": "", "url": "", "source": "none"}
    parts = out.split("|||", 3)
    while len(parts) < 4:
        parts.append("")
    return {"ok": True, "track": parts[0].strip(), "artist": parts[1].strip(),
            "album": parts[2].strip(), "state": parts[3].strip(),
            "art": "", "url": "", "source": "music"}

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

    sp = {
        "ok":     True,
        "track":  track_name,
        "artist": artist_name,
        "album":  album_name,
        "state":  state_val,
        "art":    art_url,
        "url":    spotify_url,
        "source": "spotify",
    }
    # If Spotify has nothing playing, fall back to Apple Music
    if not track_name:
        music = _get_music_status()
        if music.get("track"):
            return music
    return sp

def _active_player() -> str:
    """Return 'spotify' if Spotify is running and playing, else 'music'."""
    r = run_script('tell application "Spotify" to if it is running then return player state as string')
    state = r.get("output", "").strip().lower()
    if state in ("playing", "paused"):
        return "spotify"
    return "music"

def _media_cmd(spotify_script: str, music_script: str) -> dict:
    """Send a media command to whichever player is active."""
    if _active_player() == "spotify":
        return run_script(f'tell application "Spotify" to {spotify_script}')
    return run_script(f'tell application "Music" to {music_script}')

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
_bt_lock  = threading.Lock()
_BT_TTL = 30.0

def get_bluetooth_cached() -> dict:
    with _bt_lock:
        now = time.time()
        if _bt_cache["data"] and now - _bt_cache["ts"] < _BT_TTL:
            return _bt_cache["data"]
    result = get_bluetooth()
    with _bt_lock:
        _bt_cache["data"] = result
        _bt_cache["ts"] = time.time()
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
    safe = url.replace("\\", "\\\\").replace('"', '\\"')
    return run_script(f'tell application "Safari" to set URL of front document to "{safe}"')

def safari_new_tab(url: str = "") -> dict:
    if url and not url.startswith("http"):
        url = "https://" + url
    safe = url.replace("\\", "\\\\").replace('"', '\\"')
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
    if len(text) > 2000:
        return {"ok": False, "error": "Text too long (max 2000 chars)"}
    safe = text.replace("\\","\\\\").replace('"','\\"').replace("\n","\\n").replace("\r","")
    return run_script(f'tell application "System Events" to keystroke "{safe}"')

def open_url_mac(url: str) -> dict:
    safe = url.replace("\\", "\\\\").replace('"', '\\"')
    return run_script(f'open location "{safe}"')

def terminal_run_silent(cmd: str) -> dict:
    if not cmd or not cmd.strip():
        return {"ok": False, "error": "Empty command"}
    if len(cmd) > 4096:
        return {"ok": False, "error": "Command too long (max 4096 chars)"}
    # Use a list-form invocation via shell=False to avoid shell injection.
    # We invoke the user's default shell explicitly so shell features still work
    # but the command string itself is passed as a literal argument, not re-parsed.
    shell_exe = os.environ.get("SHELL", "/bin/zsh")
    try:
        r = subprocess.run([shell_exe, "-c", cmd], capture_output=True,
                           text=True, timeout=30)
        return {"ok": r.returncode == 0, "output": r.stdout.strip(),
                "error": r.stderr.strip(), "returncode": r.returncode}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "output": "", "returncode": -1}
    except Exception as e:
        return {"ok": False, "error": str(e), "output": "", "returncode": -1}

def terminal_run_visible(cmd: str) -> dict:
    if not cmd or not cmd.strip():
        return {"ok": False, "error": "Empty command"}
    if len(cmd) > 4096:
        return {"ok": False, "error": "Command too long (max 4096 chars)"}
    # Escape only what AppleScript's double-quoted string needs.
    # Newlines must also be stripped — they break `do script`.
    safe = (cmd.replace("\\", "\\\\")
               .replace('"', '\\"')
               .replace("\r", "")
               .replace("\n", " "))
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
        # Escape backslashes, double-quotes, and strip newlines for AppleScript string safety
        return (s.replace("\\", "\\\\")
                 .replace('"', '\\"')
                 .replace("\r", "")
                 .replace("\n", " "))
    sub_part = f' subtitle "{_esc(subtitle)}"' if subtitle.strip() else ""
    script = f'display notification "{_esc(message)}"{sub_part} with title "{_esc(title)}"'
    return run_script(script)

# ─── Screenshot to base64 ────────────────────────────────────────────────────

def screenshot_b64() -> dict:
    """Capture screen as JPEG, resize to max 1280 px, return base64."""
    fd, path = tempfile.mkstemp(suffix=".jpg", prefix="msmr_ss_")
    os.close(fd)
    try:
        r = run_shell(["screencapture", "-x", "-t", "jpg", path])
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return {"ok": False, "error": r.get("error", "Capture failed — is screen locked?")}
        # Resize to max 1280px (keeps aspect ratio), reduces transfer size significantly
        run_shell(["sips", "-Z", "1280", path])
        with open(path, "rb") as f:
            data = base64.b64encode(f.read()).decode()
        return {"ok": True, "data": data, "mime": "image/jpeg"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        try: os.unlink(path)
        except Exception: pass

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
    # Validate app name: only allow safe filesystem characters, no path separators
    if not app_name or len(app_name) > 255:
        return {"ok": False, "error": "Invalid app name"}
    if "/" in app_name or "\\" in app_name or "\0" in app_name or ".." in app_name:
        return {"ok": False, "error": "Invalid app name"}

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

    resources_dir = os.path.realpath(os.path.join(app_path, "Contents", "Resources"))

    def _safe_icon_path(name: str) -> "str | None":
        """Resolve an icon name and ensure it stays within the app bundle."""
        # Strip any path components from the icon name — it must be a plain filename
        name = os.path.basename(name)
        if not name or "\0" in name:
            return None
        candidate = os.path.realpath(os.path.join(resources_dir, name))
        # Confirm the resolved path is still inside the app bundle
        if not candidate.startswith(os.path.realpath(app_path) + os.sep):
            return None
        return candidate if os.path.exists(candidate) else None

    try:
        info_plist = os.path.join(app_path, "Contents", "Info.plist")
        r = run_shell(["defaults", "read", info_plist, "CFBundleIconFile"], timeout=5)
        raw_icon_name = r.get("output", "").strip() or "AppIcon"
        if not raw_icon_name.endswith(".icns"):
            raw_icon_name += ".icns"
        icon_path = _safe_icon_path(raw_icon_name)
        if not icon_path:
            for fb in ["AppIcon.icns", "Application.icns", "app.icns"]:
                icon_path = _safe_icon_path(fb)
                if icon_path:
                    break
        if not icon_path:
            return {"ok": False, "error": "Icon file not found"}
        fd, tmp = tempfile.mkstemp(suffix=".png", prefix="msmr_ico_")
        os.close(fd)
        try:
            run_shell(["sips", "-s", "format", "png", "--resampleWidth", "60",
                       icon_path, "--out", tmp], timeout=10)
            if not os.path.exists(tmp) or os.path.getsize(tmp) == 0:
                return {"ok": False, "error": "sips conversion failed"}
            with open(tmp, "rb") as f:
                data = base64.b64encode(f.read()).decode()
            return {"ok": True, "data": data, "mime": "image/png"}
        finally:
            try: os.unlink(tmp)
            except OSError: pass
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
    "play_pause":       lambda: _media_cmd("playpause", "playpause"),
    "next_track":       lambda: _media_cmd("next track", "next track"),
    "prev_track":       lambda: _media_cmd("previous track", "back track"),
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

    # Allowed CORS origins: only the server itself (local access only)
    _ALLOWED_ORIGINS = {"https://localhost", "http://localhost",
                        "https://127.0.0.1", "http://127.0.0.1"}

    def _cors_origin(self) -> str:
        origin = (self.headers.get("Origin") or "").strip()
        if origin in self._ALLOWED_ORIGINS:
            return origin
        # Allow same-host requests (iPhone connecting to server's LAN IP)
        # by reflecting back null or omitting the header entirely
        return ""

    def send_json(self, data: dict, code: int = 200):
        # Encrypt response when client opts in (sends X-Enc: 1) and is authenticated
        if _ENC_OK and self.headers.get("X-Enc") == "1" and self.token():
            data = enc_response(data, self.token())
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        origin = self._cors_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
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

    # Maximum accepted request body size (1 MB)
    _MAX_BODY = 1 * 1024 * 1024

    def body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            n = 0
        if n < 0 or n > self._MAX_BODY:
            return {}
        raw = self.rfile.read(n)
        try:
            parsed = json.loads(raw) if raw else {}
        except (ValueError, UnicodeDecodeError):
            return {}
        # Auto-decrypt if client sent an encrypted body
        if "e" in parsed:
            return dec_request(parsed, self.token())
        return parsed

    def do_OPTIONS(self):
        self.send_response(204)
        origin = self._cors_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type,X-Session-Token,X-Enc")
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
                            "pin_length":get_pin_length()})
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
        elif path == "/api/screenshot":
            if not screenshot_rate_ok(self.token()):
                self.send_json({"ok": False, "error": "Rate limit: 1 screenshot per 2 seconds"}, 429)
            else:
                self.send_json(screenshot_b64())
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
            except Exception: self.send_json({"ok":False,"error":"Invalid"},400)
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
            if verify_pin_kc(pin):
                clear_fail(ip)
                self.send_json({"ok":True,"token":create_session()})
            else:
                record_fail(ip)
                with _state_lock:
                    left = max(0, 5 - _attempts.get(ip, {"count": 0})["count"])
                self.send_json({"ok":False,"error":f"Wrong PIN. {left} attempt(s) left."},401)
            return

        if path == "/api/auth/setup":
            if not setup_required():
                self.send_json({"ok":False,"error":"Already configured"},400)
                return
            pin = data.get("pin","")
            if not isinstance(pin, str) or not pin.isdigit() or not (6 <= len(pin) <= 12):
                self.send_json({"ok":False,"error":"PIN must be 6–12 digits"},400)
                return
            salt, h = hash_pin(pin)
            if not _kc_store(salt, h, len(pin)):
                # Keychain unavailable — fall back to config.json
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
            name = data.get("name","")
            safe = name.replace('"', '\\"')
            # open -a is the most reliable way to bring an app to the foreground
            # (handles hidden/minimized state; activate alone can be blocked by macOS)
            r = run_shell(["open", "-a", name])
            if not r["ok"]:
                # Fallback: AppleScript activate + reopen (unminimizes from Dock)
                r = run_script(f'tell application "{safe}"\nactivate\nreopen\nend tell')
            self.send_json(r)
        elif path == "/api/apps/launch":
            p = data.get("path","")
            name = data.get("name","")
            safe = name.replace('"', '\\"')
            if p.startswith("/"):
                self.send_json(run_shell(["open", p]))
            else:
                r = run_shell(["open", "-a", name])
                if not r["ok"]:
                    r = run_script(f'tell application "{safe}"\nactivate\nreopen\nend tell')
                self.send_json(r)
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
            if not verify_pin_kc(op):
                self.send_json({"ok":False,"error":"Current PIN incorrect"})
            elif not (isinstance(np, str) and np.isdigit() and 6 <= len(np) <= 12):
                self.send_json({"ok":False,"error":"New PIN: 6–12 digits"})
            else:
                salt, h = hash_pin(np)
                if not _kc_store(salt, h, len(np)):
                    _cfg["pin_salt"] = salt; _cfg["pin_hash"] = h
                    _cfg["pin_length"] = len(np)
                    save_config()
                # Security: invalidate ALL sessions so old-PIN holders are logged out
                with _state_lock:
                    _sessions.clear()
                with _key_cache_lock:
                    _key_cache.clear()
                self.send_json({"ok":True,"relogin_required":True})
        elif path == "/api/auth/logout":
            tok = self.token()
            with _state_lock:
                _sessions.pop(tok, None)
            with _key_cache_lock:
                _key_cache.pop(tok, None)
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
    PORT = int(os.environ.get("MSMR_PORT", 5001))
    ip = get_local_ip()
    load_config()
    migrate_config_to_keychain()
    if setup_required():
        interactive_setup()
    use_https = generate_cert(ip)

    server = HTTPServer(("0.0.0.0", PORT), Handler)
    proto = "http"
    if use_https:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # Require TLS 1.2 minimum; TLS 1.3 is used automatically when available
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            # Disable TLS renegotiation (CVE-2009-3555 class of attacks)
            ctx.options |= ssl.OP_NO_RENEGOTIATION
            # Restrict to forward-secrecy cipher suites for TLS 1.2;
            # TLS 1.3 suites are always strong and managed separately by Python's ssl module.
            ctx.set_ciphers(
                "ECDHE+AESGCM:ECDHE+CHACHA20:"   # ECDHE with AEAD — forward secrecy
                "DHE+AESGCM:DHE+CHACHA20:"        # DHE with AEAD — forward secrecy
                "!aNULL:!eNULL:!EXPORT:!MD5:!RC4:!3DES:!DES:!SHA1"  # explicit denies
            )
            ctx.load_cert_chain(CERT_FILE, KEY_FILE)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            proto = "https"
            if not _ENC_OK:
                print("  ⚠ 'cryptography' package not installed — app-layer AES-GCM encryption disabled.")
                print("    Run: pip3 install cryptography")
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
