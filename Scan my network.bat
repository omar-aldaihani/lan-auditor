@echo off
REM Double-click to scan this computer's network and open the HTML report.
cd /d "%~dp0"
py -m lanaudit --html lan-audit-report.html --open
echo.
pause
