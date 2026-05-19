@echo off
title AI Sentinel — Setup
color 0A

echo.
echo  ============================================================
echo   AI SENTINEL — First Time Setup
echo  ============================================================
echo.
echo  This will:
echo    1. Add Windows Defender exclusion for i2pd.exe
echo       (prevents false-positive quarantine)
echo    2. Register AI Sentinel to start automatically at login
echo       (no terminal window — just a tray icon)
echo.

:: Verify Python is installed
python --version > nul 2>&1
if errorlevel 1 (
    echo  ERROR: Python not found.
    echo  Install Python 3.11+ from https://python.org then run this again.
    echo.
    pause
    exit /b 1
)

:: If not running as Administrator, relaunch with UAC elevation
:: (needed for the Defender exclusion step)
net session > nul 2>&1
if errorlevel 1 (
    echo  Requesting Administrator rights...
    echo  ^(Windows will ask for permission — click Yes^)
    echo.
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d ""%~dp0"" && python -m privacy.privacy_main --setup && echo. && echo  Done! AI Sentinel will start automatically at next login. && pause' -Verb RunAs -Wait"
    exit /b
)

cd /d "%~dp0"
python -m privacy.privacy_main --setup

echo.
echo  ============================================================
echo   Setup complete!
echo   AI Sentinel will start automatically at next login.
echo   You can also start it now: python -m privacy.privacy_main
echo  ============================================================
echo.
pause
