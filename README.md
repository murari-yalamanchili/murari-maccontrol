<div align="center">

# 🍎 Murari MacControl

**Control your Mac from any iPhone — no app store, no account, no cloud.**

[![macOS](https://img.shields.io/badge/macOS-11%2B-black?logo=apple&logoColor=white)](https://www.apple.com/macos/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776ab?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](#requirements)
[![Local network only](https://img.shields.io/badge/network-local%20WiFi%20only-blue)](#security)

A self-hosted iPhone remote for your Mac. Runs entirely on your local network — your data never leaves your devices.

[Quick Start](#quick-start) · [Features](#features) · [Security](#security) · [Contributing](#contributing)

</div>

---

## What it looks like

> A sleek iOS-style dashboard served directly from your Mac — open it in Safari and optionally add it to your Home Screen for a native app feel.

- **Dashboard** — live clock, battery %, ping, running apps at a glance, Spotify mini-player, quick-action tiles
- **Apps** — real macOS app icons, one-tap focus/launch, long-press to quit or force-quit
- **Media** — Spotify playback with album art, volume slider, brightness
- **System** — screenshot viewer, dark mode toggle, Sleep/Lock, Empty Trash, Mission Control
- **Unlock** — wake & unlock your Mac remotely via keyboard simulation
- **Safari, Terminal, Bluetooth, Clipboard, Notifications** — full tabs for each

---

## Quick Start

```bash
# 1. Clone or download this repo
git clone https://github.com/YOUR_USERNAME/murari-maccontrol.git
cd murari-maccontrol

# 2. Run setup (creates your PIN, generates a TLS cert, starts the server)
bash setup.sh

# 3. The terminal prints something like:
#    📱 iPhone URL:  https://192.168.1.42:5001

# 4. Open that URL in Safari on your iPhone (same WiFi!)
#    First visit: tap "Show Details" → "Visit This Website" to trust the cert
```

That's it. No `pip install`, no Node, no Docker.

### Add to iPhone Home Screen

1. Open the URL in Safari
2. Tap the **Share** button → **Add to Home Screen**
3. Works like a native full-screen app

---

## Features

| Category | Actions |
|---|---|
| 🎵 **Media** | Play/Pause, Next, Previous, Volume slider, Mute, Brightness up/down |
| 🎧 **Spotify** | Live track, artist, album art (via oEmbed), playback state |
| 📱 **Apps** | Real macOS app icons, launch, focus (switch), quit, force-quit |
| 🖥️ **System** | Screenshot → Desktop, Show Desktop, Mission Control, Launchpad, Dark Mode, Sleep |
| 🗑️ **Trash** | Empty Trash (non-blocking, no timeout) |
| 🔓 **Unlock** | Wake display + simulate password entry (requires Accessibility permission) |
| 🌐 **Safari** | Back/Forward/Reload, navigate, new tab, close tab, execute JavaScript |
| ⌨️ **Terminal** | Run shell commands silently or in Terminal.app, read output |
| 🔵 **Bluetooth** | List connected & paired devices, connect/disconnect (requires `blueutil`) |
| 📋 **Clipboard** | Read Mac clipboard, push text to Mac clipboard |
| 🔔 **Notifications** | Send macOS notifications from your iPhone |
| 🌙 **Dark Mode** | Toggle system appearance |
| 📸 **Screenshot Viewer** | Capture and view your Mac screen on iPhone |
| 🔒 **Auth** | PBKDF2-SHA256 PIN, 64-byte session tokens, rate limiting, TLS 1.2+ |

---

## Requirements

- **macOS 11** (Big Sur) or later
- **Python 3.8+** — built into macOS, no extra install needed
- **iPhone / iPad** on the same WiFi network
- **openssl** — pre-installed on macOS (for TLS cert generation)

### Optional

- **[blueutil](https://github.com/toy/blueutil)** — for Bluetooth connect/disconnect: `brew install blueutil`

---

## Security

Murari MacControl is designed for **local network use only**.

| Property | Detail |
|---|---|
| Transport | HTTPS / TLS 1.2+ (self-signed cert, generated locally) |
| Authentication | PBKDF2-SHA256, 200 000 rounds |
| Session tokens | 64-byte cryptographic random, 24 h expiry |
| Rate limiting | 5 failed attempts → 5-minute lockout per IP |
| Network scope | Binds to `0.0.0.0:5001` — only reachable on your LAN |
| Sensitive files | `config.json`, `cert.pem`, `key.pem` are **local only** (see `.gitignore`) |

> ⚠️ **Do not expose port 5001 to the internet via port forwarding.** This tool is designed for trusted local networks only.

### Unlock / Accessibility

The Wake & Unlock feature uses AppleScript keyboard simulation and requires two permissions in **System Settings → Privacy & Security**:

1. **Accessibility** → add your terminal app (Terminal, iTerm2, etc.)
2. **Automation → System Events** → enable for your terminal app

After granting both, restart the server.

---

## How it works

```
iPhone (Safari)  ──HTTPS──▶  server.py (Python 3, stdlib only)
                                │
                                ├─ AppleScript  ──▶  System Events, Spotify, Finder…
                                ├─ shell cmds   ──▶  pmset, screencapture, sips, pbcopy…
                                └─ index.html   ──▶  served as the iOS web app
```

Everything runs in a single Python file using only the standard library. No frameworks, no package manager, no background services.

---

## Installation options

### Option A — Git clone (recommended)

```bash
git clone https://github.com/YOUR_USERNAME/murari-maccontrol.git
cd murari-maccontrol
bash setup.sh
```

### Option B — Download zip

1. Go to [Releases](https://github.com/YOUR_USERNAME/murari-maccontrol/releases)
2. Download the latest `murari-maccontrol-vX.Y.Z.zip`
3. Unzip and run `bash setup.sh`

### Option C — One-liner (curl)

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/murari-maccontrol/main/setup.sh | bash
```

---

## Configuration

All config is stored in `config.json` in the project folder (excluded from git):

```json
{
  "pin_salt": "...",
  "pin_hash": "...",
  "pin_length": 6
}
```

To **change your PIN**: go to the Tools tab in the app → Change PIN.

To **reset everything**: delete `config.json`, `cert.pem`, and `key.pem`, then re-run `setup.sh`.

---

## Stopping the server

Press `Ctrl+C` in the Terminal window where `setup.sh` is running.

To run in the background:

```bash
nohup python3 server.py &> maccontrol.log &
echo "Server PID: $!"
```

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Quick contribution ideas:
- 🌍 Add more app icons / emoji mappings
- 🎛️ New quick-action tiles for the Dashboard
- 🔧 Additional system controls (Do Not Disturb, Night Shift, etc.)
- 📱 Better iPhone PWA polish (icons, splash screens)
- 🧪 Tests for the Python server

---

## Project structure

```
murari-maccontrol/
├── server.py       # Python HTTP/HTTPS server — all backend logic
├── index.html      # Single-file iOS web app (HTML + CSS + JS)
├── setup.sh        # First-run setup + server launcher
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── .gitignore
│
│   # Generated locally — never committed
├── config.json     # PIN hash (gitignored)
├── cert.pem        # TLS certificate (gitignored)
├── key.pem         # TLS private key (gitignored)
└── ssl.cnf         # OpenSSL config (gitignored)
```

---

## License

[MIT](LICENSE) © Murari Systems

---

<div align="center">
Built with ❤️ and zero dependencies · Runs entirely on your Mac · Your data stays yours
</div>
