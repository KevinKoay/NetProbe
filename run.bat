@echo off
REM NetProbe launcher for Windows (no install needed if Python 3 is present)
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel%==0 (
    python "%~dp0netprobe.py" %*
    if errorlevel 1 pause
    goto :eof
)

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 "%~dp0netprobe.py" %*
    if errorlevel 1 pause
    goto :eof
)

echo.
echo [NetProbe] Python 3 was not found on this machine.
echo Install it from https://www.python.org/downloads/  (tick "Add python.exe to PATH")
echo or package this folder into a standalone .exe with:
echo     pip install pyinstaller ^&^& pyinstaller --onefile --windowed --name NetProbe netprobe.py
echo.
pause
