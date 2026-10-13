agent-windows - CIS-CAT bridge @VERSION@
=========================================
Where to unpack (PowerShell as administrator): never in C:\Users or C:\Temp. A folder only
administrators can change:
    New-Item -ItemType Directory -Force C:\CIS\install\@VERSION@ | Out-Null
    icacls C:\CIS /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /C /Q
    icacls C:\CIS /setowner "*S-1-5-32-544" /T /C /Q
    Expand-Archive <package zip> -DestinationPath C:\CIS\install\@VERSION@ -Force
The installer warns when the folder can be changed by non-administrators.

1. Master's public key: nothing to do. The agent receives it from the master with the group
   files and keeps the first one (it only installs and runs files of manifests signed with
   it). To pin it at install instead, copy ciscat-manifest.pub.xml (from master/agent-keys)
   into this folder or pass -PublicKey <file>, and compare the sha256 the installer prints with
   the one the master setup printed.

2. Install or update, PowerShell as administrator, in this folder:
     powershell -ExecutionPolicy Bypass -File .\install-windows-agent.ps1
   (CIS-CAT Pro elsewhere on the host: add -CopyAssessorFrom "<folder of Assessor-CLI.bat>")
   - C:\CIS owned by Administrators, writable only by SYSTEM and Administrators;
   - CIS-CAT Pro in C:\CIS\Assessor: installed or updated from the package when it carries the
     Assessor (ASSESSOR_VERSION), keeping the license and the benchmarks; a new version that
     does not start is rolled back;
   - exit.on.invalid.signature=false (the tailored benchmark is unsigned);
   - ciscat-assessment.cmd and ciscat-bootstrap.ps1 in ossec-agent\active-response\bin;
   - files of earlier versions moved to C:\CIS\backup-<date>.
   Everything else (benchmarks, OVAL/CPE, assessment and conversion scripts, license when the
   master has one) comes from the master at each run, through the signed manifest.
   Expected: "RESULT: OK". Exit code 0 = done.

3. Test, after the master setup and with the agent in the group of its OS:
     powershell -ExecutionPolicy Bypass -File .\ciscat-e2e-windows.ps1 -Step Pre
   then, after "run" on the master: -Step Watch, and when it ends: -Step Post
