@echo off
title AI Sentinel — Setup
color 0A

echo.
echo  ============================================================
echo   AI SENTINEL — First Time Setup
echo  ============================================================
echo.
echo  This will:
echo    1. Install required Python packages
echo    2. Add Windows Defender exclusion for i2pd.exe
echo       (prevents false-positive quarantine)
echo    3. Register AI Sentinel to start automatically at login
echo    4. Start AI Sentinel right now
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

:: Move to the folder where install.bat lives
cd /d "%~dp0"

:: Install Python dependencies
echo  Installing Python dependencies...
echo.
python -m pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo  ERROR: pip install failed. Check your internet connection.
    pause
    exit /b 1
)
echo  Dependencies ready.
echo.

:: If not running as Administrator, relaunch with UAC elevation
:: (needed for the Defender exclusion step)
net session > nul 2>&1
if errorlevel 1 (
    echo  Requesting Administrator rights for Defender exclusion...
    echo  ^(Windows will show a permission prompt — click Yes^)
    echo.
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d ""%~dp0"" && python -m privacy.privacy_main --setup' -Verb RunAs -Wait"
    goto :launch
)

:: Already admin — run setup directly
python -m privacy.privacy_main --setup

:launch
echo.
echo  ============================================================
echo   Launching AI Sentinel now...
echo   Look for the shield icon in your taskbar (bottom-right).
echo  ============================================================
echo.

:: Start AI Sentinel in the background using pythonw (no terminal window)
:: /d sets the working directory so all relative paths resolve correctly
for /f "tokens=*" %%i in ('where pythonw.exe 2^>nul') do set PYTHONW=%%i
if "%PYTHONW%"=="" (
    :: pythonw not found — fall back to python in a minimised window
    start "AI Sentinel" /min python privacy\privacy_main.py
) else (
    start "" "%PYTHONW%" "%~dp0privacy\privacy_main.py"
)

echo  AI Sentinel is starting. The shield icon will appear shortly.
echo  If it does not appear within 30 seconds, run install.bat again.
echo.
timeout /t 5 /nobreak > nul
