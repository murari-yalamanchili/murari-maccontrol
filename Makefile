# ─────────────────────────────────────────────────────────────────────────────
# Murari MacControl — Makefile
#
# This project requires NO compilation. Python and HTML run as-is.
# This Makefile is purely a shortcut menu for common developer tasks.
#
# Usage:
#   make              → show this help
#   make run          → start the server (same as bash setup.sh)
#   make clean        → remove temp files and caches
#   make reset        → remove generated credentials (cert, key, config)
#   make lint         → check Python syntax
#   make check        → verify nothing sensitive is tracked by git
#   make release      → build a distributable zip (prompts for version)
#   make release v=1.0.0  → build zip non-interactively
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: all run clean reset lint check release help

# Default target — show help
all: help

# ── Run ───────────────────────────────────────────────────────────────────────
run:
	@bash setup.sh

# ── Clean ─────────────────────────────────────────────────────────────────────
clean:
	@echo "  Cleaning temp files…"
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@find . -name ".DS_Store" -delete 2>/dev/null || true
	@rm -f /tmp/msmr_*.jpg /tmp/msmr_*.png 2>/dev/null || true
	@echo "  ✓ Done"

# ── Reset credentials (forces fresh PIN + cert on next run) ──────────────────
reset: clean
	@echo ""
	@echo "  ⚠  This will delete your PIN and TLS certificate."
	@echo "  You will need to re-run 'make run' and create a new PIN."
	@echo ""
	@read -p "  Are you sure? (yes/no): " confirm && [ "$$confirm" = "yes" ] || (echo "  Cancelled." && exit 1)
	@rm -f config.json cert.pem key.pem ssl.cnf
	@echo "  ✓ Credentials removed. Run 'make run' to set up again."

# ── Lint ──────────────────────────────────────────────────────────────────────
lint:
	@echo "  Checking Python syntax…"
	@python3 -m py_compile server.py && echo "  ✓ server.py — OK"
	@echo ""
	@echo "  Checking for common issues…"
	@python3 -c "\
import ast, sys; \
src = open('server.py').read(); \
tree = ast.parse(src); \
funcs = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]; \
print(f'  ✓ {len(funcs)} functions defined'); \
print(f'  ✓ {len(src.splitlines())} lines total'); \
"
	@echo ""
	@echo "  Checking index.html…"
	@python3 -c "\
src = open('index.html').read(); \
checks = [ \
    ('<!DOCTYPE html>', 'DOCTYPE'), \
    ('viewport', 'viewport meta'), \
    ('apple-mobile-web-app-capable', 'PWA meta'), \
    ('initAuth', 'initAuth() present'), \
    ('startApp', 'startApp() present'), \
    ('api/auth/login', 'login endpoint'), \
    ('api/apps/running', 'apps endpoint'), \
]; \
[print(f'  {chr(10003) if k in src else chr(10007)} {label}') for k, label in checks]; \
"
	@echo ""
	@echo "  ✓ Lint complete"

# ── Security check — make sure git isn't tracking sensitive files ─────────────
check:
	@echo "  Checking git does not track sensitive files…"
	@echo ""
	@FAIL=0; \
	for f in config.json cert.pem key.pem ssl.cnf; do \
	  if git ls-files --error-unmatch "$$f" 2>/dev/null; then \
	    echo "  ✗ DANGER: $$f is tracked by git! Run: git rm --cached $$f"; \
	    FAIL=1; \
	  else \
	    echo "  ✓ $$f — not tracked (good)"; \
	  fi; \
	done; \
	echo ""; \
	if [ "$$FAIL" = "1" ]; then \
	  echo "  Fix: git rm --cached <file> then git commit"; \
	  exit 1; \
	else \
	  echo "  ✓ All sensitive files are safely gitignored"; \
	fi

# ── Release ───────────────────────────────────────────────────────────────────
release:
	@if [ -n "$(v)" ]; then \
	  bash release.sh "v$(v)"; \
	else \
	  bash release.sh; \
	fi

# ── Help ──────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  ╔═══════════════════════════════════════════╗"
	@echo "  ║   🍎  Murari MacControl — Developer CLI   ║"
	@echo "  ╚═══════════════════════════════════════════╝"
	@echo ""
	@echo "  This project needs NO compilation."
	@echo "  Python and HTML run directly — no build step."
	@echo ""
	@echo "  Commands:"
	@echo ""
	@echo "    make run              Start the server (= bash setup.sh)"
	@echo "    make clean            Remove __pycache__, .DS_Store, temp files"
	@echo "    make reset            Delete cert + PIN — forces fresh setup"
	@echo "    make lint             Check Python syntax + HTML structure"
	@echo "    make check            Verify git isn't tracking sensitive files"
	@echo "    make release          Build distributable zip (prompts version)"
	@echo "    make release v=1.0.0  Build zip for v1.0.0 non-interactively"
	@echo ""
	@echo "  First time?"
	@echo "    make run              ← start here"
	@echo ""
