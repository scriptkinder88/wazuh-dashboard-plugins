@echo off
REM ciscat-assessment.cmd  (AGENT side, Windows) - launcher
REM
REM Active Response on Windows cannot run .ps1 directly: it runs .cmd/.exe from
REM active-response\bin\. This launcher is what AR invokes; it calls the real
REM PowerShell assessment script.
REM
REM AR passes the alert JSON on STDIN; we do not need it for a manual/scheduled
REM assessment trigger, so we ignore it and just launch the script.
REM
REM Logs go to active-response\active-responses.log (written by the .ps1).

set SCRIPT="%~dp0ciscat-assessment.ps1"
set LOG="C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

echo %DATE% %TIME% ciscat-assessment.cmd: launcher invoked by Active Response >> %LOG%

REM -ExecutionPolicy Bypass so the script runs regardless of local policy.
REM At scale this .ps1 should be signed with the internal PKI.
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File %SCRIPT%

echo %DATE% %TIME% ciscat-assessment.cmd: powershell exited with code %ERRORLEVEL% >> %LOG%
exit /b %ERRORLEVEL%
