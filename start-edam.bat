@echo off
setlocal
cd /d "%~dp0"

where npm >nul 2>nul
if errorlevel 1 (
  echo Node.js and npm are required to run EDAM.
  echo Install Node.js LTS from https://nodejs.org/ and run this file again.
  pause
  exit /b 1
)

if not exist node_modules (
  echo Installing dependencies...
  call npm install
  if errorlevel 1 (
    echo Dependency installation failed.
    pause
    exit /b 1
  )
)

if not exist "node_modules\@rollup\rollup-win32-x64-msvc" (
  echo Repairing Windows dependencies...
  call npm install
  if errorlevel 1 (
    echo Dependency repair failed.
    echo Delete the node_modules folder, then run this file again.
    pause
    exit /b 1
  )
)

echo Starting EDAM...
echo Frontend: http://localhost:5173
echo Backend:  http://localhost:8787
call npm run dev
pause
