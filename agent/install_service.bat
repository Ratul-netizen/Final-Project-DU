@echo off
REM System Monitor Service Installer
echo Installing System Monitor Service...

REM Copy to system directory
copy "SystemMonitor.exe" "C:\Windows\System32\SystemMonitor.exe" >nul 2>&1

REM Create service
sc create "SystemMonitorSvc" binPath= "C:\Windows\System32\SystemMonitor.exe" start= auto DisplayName= "System Performance Monitor" >nul 2>&1

REM Start service
sc start "SystemMonitorSvc" >nul 2>&1

echo System Monitor Service installed successfully.
pause
