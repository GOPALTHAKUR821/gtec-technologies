@echo off
setlocal
cd /d "%~dp0"
echo ========================================
echo   G TEC TECHNOLOGIES - STARTING
echo ========================================
where node >nul 2>nul || (echo Node.js is not installed. & pause & exit /b 1)
if not exist node_modules (
  echo Installing dependencies...
  call npm.cmd install
  if errorlevel 1 (echo npm install failed. & pause & exit /b 1)
)
echo Starting server at http://localhost:3000
call npm.cmd start
pause
