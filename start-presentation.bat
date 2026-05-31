@echo off
setlocal
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is required to run the EDAM presentation build.
  echo Install Node.js LTS from https://nodejs.org/ and run this file again.
  pause
  exit /b 1
)

if not exist dist\index.html (
  echo Missing dist\index.html.
  echo Before the presentation, run this once on your own computer:
  echo npm install
  echo npm run build
  echo.
  echo Then copy this whole folder to the USB or presentation computer.
  pause
  exit /b 1
)

echo Starting EDAM presentation mode...
echo Open: http://localhost:5173
node server\presentation.mjs
pause
