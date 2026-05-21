@echo off
chcp 65001 > nul
title AI Sentinel - Setup
color 0A
cd /d "%~dp0"

echo.
echo  ============================================================
echo   AI SENTINEL - Python Setup
echo   (If you have the .exe, just double-click it instead)
echo  ============================================================
echo.

:: Check Python
python --version > nul 2>&1
if errorlevel 1 (
    echo  ERROR: Python not found.
    echo  Download Python 3.11+ from https://www.python.org
    echo  Tick "Add Python to PATH" during install, then run this again.
    echo.
    pause
    exit /b 1
)

:: Install dependencies
echo  Installing packages...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo  ERROR: pip install failed. Check your internet connection.
    pause
    exit /b 1
)

:: Launch — auto-setup (Defender exclusion + autostart) runs automatically
:: on first launch inside privacy_main.py
echo.
echo  Starting AI Sentinel...
echo  On first launch you will see one Windows permission prompt — click Yes.
echo  That allows i2pd through Defender. It only happens once.
echo.

for /f "usebackq tokens=*" %%i in (`where pythonw.exe 2^>nul`) do (
    if not defined RUNNER set "RUNNER=%%i"
)
if not defined RUNNER (
    start "AI Sentinel" /min python "%~dp0privacy\privacy_main.py"
) else (
    start "" "%RUNNER%" "%~dp0privacy\privacy_main.py"
)

echo  AI Sentinel is starting.
echo  Look for the shield icon in the taskbar (bottom-right).
echo.
timeout /t 5 /nobreak > nul
