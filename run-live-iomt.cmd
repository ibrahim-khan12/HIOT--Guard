@echo off
cd /d "%~dp0"
if exist "%LocalAppData%\Programs\Python\Python313\python.exe" (
  "%LocalAppData%\Programs\Python\Python313\python.exe" launch.py
) else (
  where py >nul 2>nul
  if errorlevel 1 (
    echo Python 3.10 or later is required. Install Python, then run this launcher again.
    pause
    exit /b 1
  )
  py -3 launch.py
)
if errorlevel 1 pause
