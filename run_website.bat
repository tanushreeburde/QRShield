@echo off
title QRShield Web Inspector
echo ==========================================================
echo Starting QRShield Security Inspector Website...
echo ==========================================================
cd /d "%~dp0"
if exist backend\venv\Scripts\python.exe (
    backend\venv\Scripts\python.exe run_website.py
) else (
    python run_website.py
)
pause
