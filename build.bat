@echo off
rem nScout - Windows build (double-click friendly).
rem Calls build.ps1 with ExecutionPolicy Bypass so users don't need to tweak policy.
setlocal
pushd "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\build.ps1"
set EXITCODE=%ERRORLEVEL%
popd
pause
exit /b %EXITCODE%
