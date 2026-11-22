@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
where pythonw >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    start "" pythonw "%SCRIPT_DIR%clamav_gui.py" %*
    exit /b 0
)
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    python "%SCRIPT_DIR%clamav_gui.py" %*
    exit /b %ERRORLEVEL%
)
where py >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py -3 "%SCRIPT_DIR%clamav_gui.py" %*
    exit /b %ERRORLEVEL%
)
echo Python 3 with PySide6 is required to run ClamAV Security Center.
pause
exit /b 1
