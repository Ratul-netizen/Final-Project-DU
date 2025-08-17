@echo off
echo ========================================
echo   System Monitor - Stealth Build Tool
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7+ and try again
    pause
    exit /b 1
)

echo Python found. Starting build process...
echo.

REM Run the stealth build script
python build_stealth.py

echo.
echo Build process completed.
pause
