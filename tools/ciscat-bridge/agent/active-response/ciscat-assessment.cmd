@echo off
REM ciscat-assessment.cmd  (AGENT side, Windows) - Active Response launcher
REM
REM Active Response on Windows runs .exe or .cmd files from active-response\bin\, not .ps1: the
REM master's ossec.conf maps the command ciscat-assessment to this file (ar.conf on the agent).
REM
REM wazuh-execd writes the alert as one JSON line on stdin, then waits until this process exits
REM and its stdout is closed, and runs no other Active Response meanwhile (Wazuh os_execd/execd.c
REM and shared/exec_op.c). An assessment takes minutes, so the launcher reads the line and asks
REM ciscat-bootstrap.ps1 to start itself detached (-Detach): the bootstrap (files from the manager)
REM and the assessment then run in a process that holds none of execd's pipes, and this launcher
REM returns at once. Installed by hand once with ciscat-bootstrap.ps1; nothing else is.
REM
REM Logs go to active-response\active-responses.log (written by the .ps1 scripts).

setlocal
set "LOG=%~dp0..\active-responses.log"
set /p ALERT=
echo %DATE% %TIME% ciscat-assessment.cmd: launcher invoked by Active Response >> "%LOG%"

REM -ExecutionPolicy Bypass so the script runs regardless of local policy.
REM At scale this .ps1 should be signed with the internal PKI.
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0ciscat-bootstrap.ps1" -Detach < NUL > NUL 2>&1
set RC=%ERRORLEVEL%
echo %DATE% %TIME% ciscat-assessment.cmd: launcher done, exit code %RC% >> "%LOG%"
exit /b %RC%
