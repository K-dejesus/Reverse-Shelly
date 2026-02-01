@echo off
title Reverse Shelly - Listener
echo ========================================
echo   Reverse Shelly - Listener (Attacker)
echo ========================================
echo.
cd /d "%~dp0Reverse Shelly"

set /p LISTEN_IP="Enter your IP address (e.g. 192.168.1.100): "
set /p LISTEN_PORT="Enter port (e.g. 4444): "

echo.
echo Starting listener on %LISTEN_IP%:%LISTEN_PORT%...
echo.
python reverse_shell_listener.py %LISTEN_IP% %LISTEN_PORT%

pause
