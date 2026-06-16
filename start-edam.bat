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
  call npm install --include=optional
  if errorlevel 1 (
    echo Dependency installation failed.
    pause
    exit /b 1
  )
)

set "ROLDOWN_BINDING=node_modules\@rolldown\binding-win32-x64-msvc"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ROLDOWN_BINDING=node_modules\@rolldown\binding-win32-arm64-msvc"
if /i "%PROCESSOR_ARCHITEW6432%"=="ARM64" set "ROLDOWN_BINDING=node_modules\@rolldown\binding-win32-arm64-msvc"

if not exist "%ROLDOWN_BINDING%" (
  echo Repairing Windows Vite dependencies...
  call npm install --include=optional
  if errorlevel 1 (
    echo Dependency repair failed.
    echo Delete the node_modules folder and package-lock.json, then run this file again.
    pause
    exit /b 1
  )
)

if not exist "%ROLDOWN_BINDING%" (
  echo Required native dependency is still missing:
  echo %ROLDOWN_BINDING%
  echo.
  echo Delete the node_modules folder and package-lock.json, then run this file again.
  pause
  exit /b 1
)

echo Starting EDAM...
echo.
echo Version check:
node --version
call npm --version
echo.
echo Frontend: http://localhost:5173
echo Backend:  http://localhost:8787
call npm run dev
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
  echo.
  echo EDAM stopped with exit code %EXIT_CODE%.
)
pause
exit /b %EXIT_CODE%
