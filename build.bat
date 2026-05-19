@echo off
chcp 65001 > nul
title AI Sentinel - Build
color 0A
cd /d "%~dp0"

echo.
echo  ============================================================
echo   AI SENTINEL - Build Standalone Executable
echo  ============================================================
echo.

:: Check Python
python --version > nul 2>&1
if errorlevel 1 (
    echo  ERROR: Python not found.
    pause & exit /b 1
)

:: Install build dependencies
echo  Installing build dependencies...
python -m pip install pyinstaller pillow --quiet
if errorlevel 1 (
    echo  ERROR: pip install failed.
    pause & exit /b 1
)

:: Generate the .ico file
echo  Generating icon...
python build\make_icon.py
if errorlevel 1 (
    echo  ERROR: Icon generation failed.
    pause & exit /b 1
)

:: Run PyInstaller
echo.
echo  Building AIsentinel.exe (this takes 2-5 minutes)...
echo.
pyinstaller build\sentinel.spec --distpath dist --workpath build\work --noconfirm
if errorlevel 1 (
    echo.
    echo  ERROR: Build failed. See output above.
    pause & exit /b 1
)

echo.
echo  ============================================================
echo   Build complete!
echo   Executable: dist\AIsentinel\AIsentinel.exe
echo.
echo   To install, double-click:
echo     dist\AIsentinel\AIsentinel.exe
echo   It will register itself to start at login automatically.
echo  ============================================================
echo.
pause
