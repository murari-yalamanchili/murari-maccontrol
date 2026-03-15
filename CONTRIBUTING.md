# Contributing to Murari MacControl

Thank you for taking the time to contribute! 🎉

This project is intentionally minimal — a single Python server file and a single HTML file, zero dependencies. Contributions that keep it that way are most welcome.

---

## Ground rules

- **No new dependencies.** The server must run with `python3 server.py` on a stock macOS install. No `pip install`, no Node, no Homebrew required.
- **No cloud services.** Everything must work fully offline on a local network.
- **Security first.** Any change to auth, session handling, or network code needs a clear explanation of the security trade-offs.
- **One PR, one thing.** Small, focused pull requests are much easier to review than large multi-feature ones.

---

## Getting started

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/murari-maccontrol.git
cd murari-maccontrol

# Start the server (creates config + cert on first run)
bash setup.sh

# Open on iPhone or at https://localhost:5001 in your browser
```

There's no build step. Edit `server.py` or `index.html` and restart `setup.sh` to see changes.

---

## What to work on

### Good first issues

- **App emoji mappings** — add more entries to `APP_EMOJI` in `server.py` for popular apps
- **Quick-command presets** — add useful shell snippets to the Terminal tab's quick-command grid
- **Dashboard tiles** — add new quick-action cards to `page-dashboard` in `index.html`
- **Typo / doc fixes** — always welcome

### Bigger contributions

- **Do Not Disturb / Focus Mode toggle** — uses `shortcuts run` CLI or AppleScript
- **Night Shift / True Tone** — via `CoreBrightness` private framework (document the workaround clearly)
- **AirPlay controls** — current track routing
- **Multi-Mac support** — dashboard that can switch between multiple `server.py` instances
- **PWA manifest / icons** — proper `manifest.json` and splash screens for iOS home-screen install
- **Tests** — `server.py` currently has no tests; even basic smoke tests for the helper functions would help

---

## Code style

**Python (`server.py`)**
- Standard library only — no imports that aren't in `python3 -c "import X"` without extras
- Keep helper functions small and focused
- All AppleScript strings should escape `"` and `\` before interpolation
- Prefer `run_script()` for AppleScript, `run_shell()` for shell commands
- Add a `# ── Section name ──` comment block for any new logical section

**HTML/JS/CSS (`index.html`)**
- Everything stays in one file
- CSS variables for all colours — no hardcoded hex values in new rules
- JS: vanilla ES2020, no frameworks
- New UI sections follow the existing card/page pattern
- Touch targets ≥ 44px (Apple HIG minimum)
- Test on an actual iPhone in Safari — desktop Chrome behaviour differs

---

## Pull request checklist

- [ ] Tested on macOS (state which version)
- [ ] Tested in Safari on iPhone (state which iOS version)
- [ ] No new `pip`-installable dependencies added
- [ ] `config.json`, `cert.pem`, `key.pem` are still gitignored
- [ ] PR description explains *what* and *why*, not just *what*
- [ ] If touching auth/security code — explain the threat model impact

---

## Reporting bugs

Open a [GitHub Issue](../../issues) with:

1. macOS version (`sw_vers`)
2. Python version (`python3 --version`)
3. iPhone/iOS version
4. Steps to reproduce
5. What you expected vs. what happened
6. Terminal output from `setup.sh` (redact your IP/PIN if visible)

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
