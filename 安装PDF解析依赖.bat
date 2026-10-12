@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
) else (
  where py >nul 2>&1
  if %errorlevel%==0 (
    py -m pip install -r requirements.txt
  ) else (
    python -m pip install -r requirements.txt
  )
)
pause
