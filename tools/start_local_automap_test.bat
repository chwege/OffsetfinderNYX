@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo NYX Local Automap - kurzer Read-only-Test
echo ============================================================
echo.
echo D2R sollte bereits laufen und ein Offline-Spiel geoeffnet sein.
echo Der Test zeichnet 20 Sekunden auf. Bleibe fuer diesen Diagnoselauf
echo einfach im aktuellen Gebiet.
echo.

if exist ".\sign_debug_dll.ps1" (
  powershell -NoProfile -ExecutionPolicy Bypass -File ".\sign_debug_dll.ps1"
  if errorlevel 1 (
    echo.
    echo SIGNIERUNG FEHLGESCHLAGEN. Der Test wurde nicht gestartet.
    pause
    exit /b 1
  )
) else (
  echo Kein lokales Signierskript gefunden. Verwende die installierte DLL unveraendert.
)

if not exist "scripts\logs" mkdir "scripts\logs"
del /q "scripts\logs\exit-markers-perf.log" 2>nul
del /q "local-automap-injector.log" 2>nul

echo Starte NYX. Die Aufzeichnung endet automatisch nach 20 Sekunden.
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { .\simple_injector.exe --diagnostic-once 20000 2>&1 | Tee-Object -FilePath '.\local-automap-injector.log' }"
set "INJECT_EXIT=%ERRORLEVEL%"

echo.
echo Test beendet. Relevante Logs:
echo %CD%\scripts\logs\exit-markers-perf.log
echo %CD%\local-automap-injector.log
echo.
pause
exit /b %INJECT_EXIT%
