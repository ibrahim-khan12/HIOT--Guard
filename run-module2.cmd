@echo off
cd /d "%~dp0"
".venv\Scripts\python.exe" launch_module2.py
if errorlevel 1 pause
