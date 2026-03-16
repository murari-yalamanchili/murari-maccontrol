<div align="center">

# 🍎🪟 Murari MacControl · WinControl

**Control your Mac or Windows PC from your phone — no app store, no account, no cloud.**

[![macOS](https://img.shields.io/badge/macOS-11%2B-black?logo=apple&logoColor=white)](https://www.apple.com/macos/)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-0078d4?logo=windows&logoColor=white)](https://microsoft.com/windows)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776ab?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](#requirements)
[![Local network only](https://img.shields.io/badge/network-local%20WiFi%20only-blue)](#security)

A self-hosted phone remote for your computer. Runs entirely on your local network — your data never leaves your devices.

**🌐 [Landing page](https://YOUR_USERNAME.github.io/murari-maccontrol)** · [Quick Start](#quick-start) · [Features](#features) · [Windows](#windows-branch) · [Security](#security) · [Contributing](#contributing)

</div>

---

## Branches

| Branch | Platform | Phone | Start |
|---|---|---|---|
| [`main`](../../tree/main) | macOS 11+ | iPhone / Safari | `bash setup.sh` |
| [`windows`](../../tree/windows) | Windows 10 / 11 | Android / any browser | `setup.bat` |

Both branches share the same `index.html` — the UI **auto-detects** the platform from the server and adapts itself instantly (different tabs, labels, controls, and cert trust instructions per OS).

---

## What you get

> A sleek mobile dashboard served directly from your computer. Open it in your phone's browser and optionally add it to your Home Screen for a native full-screen app feel.

### Dashboard
- Live clock and date
- Battery percentage with charging indicator
- Volume level, ping latency, and running app count at a glance
- Spotify mini-player (track, artist, album art)
- Horizontal scrolling row of running apps with real icons
- Eight quick-action tiles for the most common controls

### Apps tab
- Real macOS / Windows app icons fetched from the system
- Tap any running app to **immediately switch to it**
- Tap any installed app to **launch it**
- `⋯` manage button on running apps → Quit or Force Quit menu
- Search across all installed apps

### Everything else
- **Media** — Spotify playback, volume slider, mute, brightness
- **System** — screenshot viewer, dark mode, Sleep, Lock, Mission Control (Mac), Shutdown/Restart (Windows)
- **Unlock** (Mac) — wake display + simulate password entry
- **Power** (Windows) — Lock, Sleep, Shutdown, Restart, Cancel shutdown
- **Safari** (Mac only) — back/forward, new tab, navigate, execute JavaScript
- **Terminal** — shell (Mac) or PowerShell (Windows) commands with quick-command presets
- **Bluetooth** (Mac only) — list, connect, disconnect paired devices
- **Clipboard** — read from and push text to your computer
- **Notifications** — send native desktop notifications from your phone
- **Tools** — AppleScript runner (Mac) / PowerShell runner (Windows), Change PIN, security info

---

## Quick Start

### macOS (`main` branch)

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/murari-maccontrol.git
cd murari-maccontrol

# Start (creates PIN + TLS cert on first run, then starts server)
bash setup.sh

# Terminal prints:
#   📱 iPhone URL:  https://192.168.1.42:5001

# Open that URL in Safari on your iPhone (same WiFi)
# First visit: tap "Show Details" → "Visit This Website" to trust the cert
```

### Windows (`windows` branch)

```
1. Download the zip from Releases
2. Unzip anywhere — Desktop, Documents, anywhere
3. Double-click setup.bat
4. Interactive menu: choose features and dependency level
5. Your Android URL is printed — open it in Chrome on your phone
   First visit: tap "Advanced" → "Proceed" to trust the local cert
```

### Add to Home Screen (both platforms)

**iPhone:** Safari → Share button → Add to Home Screen
**Android:** Chrome → ⋮ menu → Add to Home screen

Both work as full-screen apps with no browser chrome.

---

## Features

### macOS (`main` branch)

| Category | Detail |
|---|---|
| 🎵 **Media** | Play/Pause, Next, Previous, Volume slider, Mute, Brightness up/down |
| 🎧 **Spotify** | Live track, artist, album art via oEmbed API, playback state |
| 📱 **Apps** | Real app icons (extracted via sips from .icns), launch, focus, quit, force-quit |
| 🖥️ **System** | Screenshot, Show Desktop, Mission Control, Launchpad, Dark Mode, Sleep |
| 🗑️ **Trash** | Empty Trash — non-blocking background process, no HTTP timeout |
| 🔓 **Unlock** | Wake display + AppleScript keyboard simulation to enter password |
| 🌐 **Safari** | Back/Forward/Reload, navigate, new tab, close tab, execute JavaScript |
| ⌨️ **Terminal** | Run shell commands silently or in Terminal.app, read window contents |
| 🔵 **Bluetooth** | List connected and paired devices, connect/disconnect (requires `blueutil`) |
| 📋 **Clipboard** | pbpaste read, pbcopy write |
| 🔔 **Notifications** | display notification via AppleScript |
| 🌙 **Dark Mode** | Toggle via System Events appearance preferences |
| 📸 **Screenshot Viewer** | screencapture + sips resize to 1280px, base64 streamed to phone |
| 🔒 **Auth** | PBKDF2-SHA256 PIN, 64-byte session tokens, rate limiting, TLS 1.2+ |

### Windows (`windows` branch)

| Category | Detail |
|---|---|
| 🎵 **Media** | Play/Pause, Next, Previous via Windows VK virtual key codes |
| 🔊 **Volume** | pycaw (precise) or waveOutSetVolume ctypes fallback, mute toggle |
| 📱 **Apps** | Running windows via Get-Process, installed apps via registry, focus, launch, quit, force-kill |
| 🖥️ **System** | Screenshot (.NET System.Drawing or Pillow), Dark Mode via registry key |
| ⚡ **Power** | Sleep (SetSuspendState), Shutdown, Restart (30s delay + cancel), Lock screen |
| 🌙 **Dark Mode** | winreg toggle of AppsUseLightTheme + SystemUsesLightTheme |
| 🔔 **Notifications** | Windows 10+ Toast notifications via PowerShell WinRT API |
| 📋 **Clipboard** | Get-Clipboard / Set-Clipboard via PowerShell |
| ☀️ **Brightness** | WMI WmiMonitorBrightnessMethods (laptop panels + WMI-capable monitors) |
| ⌨️ **Terminal** | Run PowerShell commands silently or in a new PS window |
| 🔒 **Auth** | Same PBKDF2-SHA256 PIN + TLS system as macOS version |

---

## Platform-adaptive UI

Both platforms use the **exact same `index.html`**. The server returns its platform in `/api/auth/status`, and the UI adapts before the login screen even appears:

```
Phone opens https://192.168.x.x:5001
        ↓
index.html → GET /api/auth/status → { "platform": "windows" }
        ↓
applyPlatform('windows') runs:
  • body.classList.add('platform-windows')  ← CSS mac-only/win-only switches
  • Logo 🍎 → 🪟,  title MacControl → WinControl
  • Cert trust hint: "Show Details" (Safari) vs "Advanced → Proceed" (Chrome)
  • Unlock tab: password entry (Mac) vs power buttons (Windows)
  • System grid: Mac-specific or Windows-specific buttons
  • Terminal quick commands: bash presets vs PowerShell presets
  • Script runner: AppleScript editor vs PowerShell editor
  • Clipboard labels: "Read Mac" vs "Read PC"
```

---

## PIN lock screen

The login screen dynamically builds exactly the right number of dots from `pin_length` returned by the server — no hardcoded 6-dot assumption. If `pin_length` is absent (older installs), flexible mode shows only filled dots plus one upcoming empty slot, growing as you type.

---

## Requirements

### macOS

- **macOS 11** (Big Sur) or later
- **Python 3.8+** — pre-installed on macOS, no pip needed
- **iPhone / iPad** on the same WiFi network
- **openssl** — pre-installed on macOS

**Optional:** `blueutil` for Bluetooth connect/disconnect — `brew install blueutil`

### Windows

- **Windows 10** or **Windows 11**
- **Python 3.8+** — [download from python.org](https://python.org/downloads) (check "Add to PATH")
- **Android phone** (or any browser) on the same WiFi
- **PowerShell 5+** — pre-installed on Windows 10/11
- **openssl** — for HTTPS (optional): `winget install ShiningLight.OpenSSL`

**Optional pip packages** (prompted interactively by setup.bat):
- `pillow` — better screenshot quality
- `pycaw` + `comtypes` — precise volume control

---

## Security

Both versions are designed for **local network use only**.

| Property | Detail |
|---|---|
| Transport | HTTPS / TLS 1.2+ with a self-signed RSA-2048 cert generated locally on first run |
| Authentication | PBKDF2-SHA256, 200,000 rounds — raw PIN never stored anywhere |
| Session tokens | 64-byte cryptographic random, 24-hour expiry, extended on every use |
| Rate limiting | 5 failed PIN attempts → 5-minute lockout per IP address |
| Network scope | Binds to `0.0.0.0:5001` — only reachable on your LAN |
| Per-user isolation | Every user generates their own cert, PIN hash, and session tokens independently |
| Sensitive files | `config.json`, `cert.pem`, `key.pem` are gitignored — never committed |

> ⚠️ **Do not expose port 5001 to the internet via port forwarding.** This tool is for trusted local networks only.

### Unlock permissions (macOS only)

Two permissions required in **System Settings → Privacy & Security**:

1. **Accessibility** → add your terminal app (Terminal, iTerm2, etc.)
2. **Automation → System Events** → enable for your terminal app

After granting both, restart the server. Unlock works best for display-sleep, not full logout screens.

---

## How it works

### macOS
```
iPhone (Safari)  ──HTTPS──▶  server.py  (Python 3, stdlib only)
                                 ├─ osascript   ──▶  Spotify, System Events, Finder
                                 ├─ shell cmds  ──▶  pmset, screencapture, sips, pbcopy
                                 ├─ /api/apps/icon  ──▶  sips extracts .icns → base64 PNG
                                 └─ index.html  ──▶  served as the PWA
```

### Windows
```
Android (Chrome)  ──HTTPS──▶  server_windows.py  (Python 3, stdlib + optional pip)
                                    ├─ ctypes.windll  ──▶  VK codes, LockWorkStation, SetSuspendState
                                    ├─ winreg         ──▶  Dark mode toggle
                                    ├─ PowerShell     ──▶  apps, clipboard, notifications, terminal
                                    ├─ pycaw (opt)    ──▶  precise volume
                                    ├─ Pillow (opt)   ──▶  screenshot resize
                                    └─ index.html     ──▶  served as the PWA (same file as macOS)
```

---

## Windows branch

The `windows` branch contains everything from `main` plus three files:

| File | Purpose |
|---|---|
| `server_windows.py` | Full Windows server — PowerShell + ctypes backend, identical API surface to server.py |
| `setup_windows.py` | Interactive feature selector — toggle features on/off with number keys, no Enter needed |
| `setup.bat` | Double-click launcher — checks Python/PowerShell/openssl, runs setup_windows.py |

### Interactive setup
```
  [1] ✓  Media Control          Play/Pause, Next, Previous, Volume, Mute
  [2] ✓  App Management         Launch, switch, kill & force-kill apps
  [3] ✓  System Controls        Lock screen, Sleep, Screenshot, Dark Mode
  [4] ✓  Clipboard              Read & push clipboard between phone and PC
  [5] ✓  Notifications          Send Windows toast notifications (Windows 10+)
  [6] ✗  Brightness Control     WMI / laptop panels only
  [7] ✓  Terminal / PowerShell  Run shell commands silently or in a new PS window

  Press number to toggle · A = all on · N = all off · Enter = confirm
```

---

## Project structure

### `main` branch
```
murari-maccontrol/
├── server.py           # macOS server — AppleScript + shell backend
├── index.html          # Single-file PWA — auto-adapts for Mac and Windows
├── setup.sh            # First-run setup + launcher
├── Makefile            # Developer shortcuts
├── release.sh          # Builds versioned zip for GitHub Releases
├── README.md
├── LICENSE             # MIT
├── CONTRIBUTING.md
├── .gitignore
├── docs/
│   └── index.html      # GitHub Pages landing page with OS auto-detection
│
│   # Generated locally — gitignored, never committed
├── config.json         # PIN hash + length (+ features/dep_level on Windows)
├── cert.pem            # TLS certificate (tied to your local IP)
├── key.pem             # TLS private key — never share this
└── ssl.cnf             # OpenSSL config used during cert generation
```

### `windows` branch adds
```
├── server_windows.py   # Windows server
├── setup_windows.py    # Interactive feature selector
└── setup.bat           # Double-click launcher
```

---

## Developer tools

### Makefile (macOS)

```bash
make run              # Start the server
make lint             # Check Python syntax + HTML structure
make check            # Verify git isn't tracking sensitive files
make clean            # Remove __pycache__, .DS_Store, temp files
make reset            # Delete cert + PIN → forces fresh setup
make release          # Build distributable zip (prompts for version)
make release v=1.2.0  # Build zip non-interactively
```

### release.sh

Builds a security-checked distribution zip:

```bash
bash release.sh v1.2.0
# → releases/murari-maccontrol-v1.2.0.zip
# Prints SHA-256 checksum + step-by-step GitHub release instructions
# Aborts if any sensitive file ends up in the zip
```

---

## GitHub Pages landing page

`docs/index.html` — enable via Settings → Pages → `main` branch, `/docs` folder.

- Detects visitor's OS from `navigator.userAgent`
- Highlights the correct download card with a coloured glow + "Recommended for you" badge
- Auto-switches the setup-steps tab to the detected OS
- Shows both equally for Linux / unknown visitors

Live at: `https://YOUR_USERNAME.github.io/murari-maccontrol`

---

## Configuration

`config.json` is generated locally on first run and gitignored:

```json
{
  "pin_salt":   "...",
  "pin_hash":   "...",
  "pin_length": 6,
  "features":   ["media", "apps", "system", "clipboard", "notifications", "terminal"],
  "dep_level":  "minimal"
}
```

`pin_length` drives the exact number of dots shown on the phone lock screen.  
`features` and `dep_level` are Windows-only keys set by `setup_windows.py`.

**Change PIN:** Tools tab → Change PIN.  
**Reset everything:** delete `config.json`, `cert.pem`, `key.pem`, re-run setup.

---

## Stopping the server

Press `Ctrl+C` in the terminal window.

**Background (macOS):**
```bash
nohup python3 server.py &> maccontrol.log &
echo "PID: $!"
```

**Background (Windows PowerShell):**
```powershell
Start-Process python -ArgumentList "server_windows.py" -WindowStyle Hidden
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

**Good first issues:**
- 🌍 More app emoji mappings in `APP_EMOJI`
- 🎛️ New quick-action dashboard tiles
- 🔧 Do Not Disturb / Focus Mode / Night Shift (macOS)
- 📱 PWA `manifest.json` with proper icons and splash screens
- 🧪 Tests for server helper functions
- 🪟 Windows Bluetooth support via PowerShell

---

## License

[MIT](LICENSE) © Murari Systems

---

<div align="center">

Built with ❤️ and zero dependencies · Local network only · Your data stays yours

**[⬇ Download for macOS](https://github.com/YOUR_USERNAME/murari-maccontrol/releases/latest)** &nbsp;·&nbsp; **[⬇ Download for Windows](https://github.com/YOUR_USERNAME/murari-maccontrol/releases/latest)** &nbsp;·&nbsp; **[🌐 Landing page](https://YOUR_USERNAME.github.io/murari-maccontrol)**

</div>
