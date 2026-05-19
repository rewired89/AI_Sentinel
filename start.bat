@echo off
chcp 65001 > nul
title AI Sentinel
color 0A
cd /d "%~dp0"
python -m privacy.privacy_main
if errorlevel 1 (
    echo.
    echo  AI Sentinel exited with an error.
    echo  Check data\sentinel_startup.log for details.
    echo.
    pause
)
