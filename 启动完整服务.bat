@echo off
cd /d "%~dp0"
where py >nul 2>&1
if %errorlevel%==0 (
  start "VeriWork Server" /min py server.py
  timeout /t 2 /nobreak >nul
  start "" "http://127.0.0.1:8000"
  exit /b
)
where python >nul 2>&1
if %errorlevel%==0 (
  start "VeriWork Server" /min python server.py
  timeout /t 2 /nobreak >nul
  start "" "http://127.0.0.1:8000"
  exit /b
)
echo Python 3 was not found. Please open index.html for demo mode.
pause
