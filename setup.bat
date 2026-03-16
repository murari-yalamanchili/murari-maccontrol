@echo off
:: ─────────────────────────────────────────────────────────────────────────────
:: Murari WinControl — Windows Launcher
:: Double-click this file to start the setup + server.
:: ─────────────────────────────────────────────────────────────────────────────
title Murari WinControl

echo.
echo   ╔══════════════════════════════════════════════╗
echo   ║   🪟  Murari WinControl                      ║
echo   ╚══════════════════════════════════════════════╝
echo.

:: ── Check Python ──────────────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo   ✗ Python not found.
    echo.
    echo   Install Python 3.8+ from https://python.org
    echo   Make sure to check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo   ✓ Python %PYVER%

:: ── Check PowerShell ──────────────────────────────────────────────────────────
powershell -Command "exit 0" >nul 2>&1
if errorlevel 1 (
    echo   ✗ PowerShell not found or not accessible.
    pause
    exit /b 1
)
echo   ✓ PowerShell available

:: ── Check openssl (for TLS cert) ──────────────────────────────────────────────
openssl version >nul 2>&1
if errorlevel 1 (
    echo.
    echo   ⚠  openssl not found — server will run over HTTP instead of HTTPS.
    echo   Install from https://slproweb.com/products/Win32OpenSSL.html
    echo   or run: winget install ShiningLight.OpenSSL
    echo.
    timeout /t 3 >nul
) else (
    for /f %%v in ('openssl version') do echo   ✓ %%v
)

echo.

:: ── Run interactive setup + server ────────────────────────────────────────────
python "%~dp0setup_windows.py"

:: ── If server exits, pause so user can read any error ────────────────────────
if errorlevel 1 (
    echo.
    echo   Server exited with an error. See above for details.
    echo.
    pause
)
