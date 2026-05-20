@echo off
chcp 65001 > nul
title AI Sentinel - Setup
color 0A
cd /d "%~dp0"

echo.
echo  ============================================================
echo   AI SENTINEL - Setup
echo  ============================================================
echo.
echo  Steps:
echo    1. Check Python is installed
echo    2. Install required packages
echo    3. Allow i2pd through Windows Defender  ^(one-time^)
echo    4. Register AI Sentinel to start at login
echo    5. Start AI Sentinel now
echo.
echo  ============================================================
echo.

:: ---------------------------------------------------------------------------
:: Step 1 — Python check
:: ---------------------------------------------------------------------------
python --version > nul 2>&1
if errorlevel 1 (
    echo  ERROR: Python not found.
    echo.
    echo  Download Python 3.11+ from:
    echo    https://www.python.org/downloads/
    echo.
    echo  Make sure you tick "Add Python to PATH" during install.
    pause
    exit /b 1
)
echo  [1/5] Python found.

:: ---------------------------------------------------------------------------
:: Step 2 — Install dependencies
:: ---------------------------------------------------------------------------
echo  [2/5] Installing packages ^(may take 2-5 min on first run^)...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo  ERROR: Package install failed. Check your internet connection.
    pause
    exit /b 1
)
echo  [2/5] Packages ready.
echo.

:: ---------------------------------------------------------------------------
:: Step 3 — Windows Defender exclusion for data\i2p\
::           i2pd.exe is the I2P anonymity router. Defender flags it as a
::           false positive. This exclusion is permanent — you only do it once.
:: ---------------------------------------------------------------------------
echo  [3/5] Adding Defender exclusion for data\i2p\ ...
echo        ^(Windows will ask for Administrator permission — click Yes^)
echo.

:: Create the folder first so the exclusion path is valid
if not exist "data\i2p" mkdir "data\i2p"

:: Run Add-MpPreference in an elevated PowerShell and wait for it to finish.
:: The -Wait flag ensures we don't proceed until it's done.
powershell -Command "Start-Process powershell -ArgumentList '-NoProfile -NonInteractive -Command Add-MpPreference -ExclusionPath \"%~dp0data\i2p\"' -Verb RunAs -Wait" 2>nul
if errorlevel 1 (
    echo  WARNING: Could not add Defender exclusion automatically.
    echo  If AI Sentinel shows amber ^(no routing^), run this in Admin PowerShell:
    echo    Add-MpPreference -ExclusionPath "%~dp0data\i2p"
    echo.
) else (
    echo  [3/5] Defender exclusion added. i2pd will not be quarantined.
    echo.
)

:: ---------------------------------------------------------------------------
:: Step 4 — Register autostart (HKCU — no admin needed)
:: ---------------------------------------------------------------------------
echo  [4/5] Registering autostart at login...

:: Find pythonw.exe (silent — no terminal window at login)
set "RUNNER="
for /f "usebackq tokens=*" %%i in (`where pythonw.exe 2^>nul`) do (
    if not defined RUNNER set "RUNNER=%%i"
)
if not defined RUNNER set "RUNNER=python.exe"

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" ^
    /v "AI-Sentinel-Privacy" ^
    /t REG_SZ ^
    /d "\"%RUNNER%\" \"%~dp0privacy\privacy_main.py\"" ^
    /f > nul 2>&1

echo  [4/5] AI Sentinel will now start automatically when you log in.
echo.

:: ---------------------------------------------------------------------------
:: Step 5 — Launch AI Sentinel now
:: ---------------------------------------------------------------------------
echo  [5/5] Starting AI Sentinel...
echo.

if /i "%RUNNER%" == "python.exe" (
    start "AI Sentinel" /min python "%~dp0privacy\privacy_main.py"
) else (
    start "" "%RUNNER%" "%~dp0privacy\privacy_main.py"
)

echo  ============================================================
echo.
echo   AI Sentinel is running.
echo   Look for the shield icon in the taskbar bottom-right.
echo   Left-click the shield to open your threat log.
echo   Right-click for options.
echo.
echo   GREEN shield  = Full protection (I2P + scanning)
echo   AMBER shield  = Scanning only (I2P starting up or blocked)
echo   RED shield    = Threat detected
echo.
echo   If the shield stays AMBER after 5 minutes:
echo     1. Right-click tray icon - Stop AI Sentinel
echo     2. Open PowerShell as Administrator and run:
echo          Add-MpPreference -ExclusionPath "%~dp0data\i2p"
echo     3. Double-click start.bat to restart
echo.
echo  ============================================================
echo.
timeout /t 8 /nobreak > nul
