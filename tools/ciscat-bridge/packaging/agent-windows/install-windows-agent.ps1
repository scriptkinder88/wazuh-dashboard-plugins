<#
  install-windows-agent.ps1 - CIS-CAT bridge @VERSION@, Windows agent preparation.
  Run in an elevated PowerShell on each Windows agent:
    powershell -ExecutionPolicy Bypass -File .\install-windows-agent.ps1
    powershell -ExecutionPolicy Bypass -File .\install-windows-agent.ps1 -CopyAssessorFrom "C:\Program Files (x86)\ciscat"
  The master's public key (manifests must be signed with it) comes from the master with the group
  files, and the agent keeps the first one it receives. To pin it at install time instead, put
  ciscat-manifest.pub.xml (master: /opt/ciscat/etc) next to this script or give -PublicKey <file>.
  What it does (and only this):
    1. C:\CIS, C:\CIS\bin, C:\CIS\results; C:\CIS owned by Administrators and writable only by
       SYSTEM and Administrators (the scripts there run as SYSTEM); when given, the master's
       public key in C:\CIS\ciscat-manifest.pub.xml
    2. CIS-CAT Pro in C:\CIS\Assessor: installs or updates it from the package when the package
       carries it (full agent package), else checks it, or copies it from -CopyAssessorFrom
    3. exit.on.invalid.signature=false in the Assessor settings (the custom benchmark is unsigned)
    4. installs ciscat-assessment.cmd and ciscat-bootstrap.ps1 (SHA-256 checked) in
       ossec-agent\active-response\bin; everything else comes from the manager at each run
    5. moves the files of earlier versions to C:\CIS\backup-<date>
  Prints RESULT: OK, or STOP / WARNING lines.
#>
param([string]$CopyAssessorFrom = "", [string]$PublicKey = "")
$ErrorActionPreference = "Stop"
$Root = "C:\CIS"
$Agent = "C:\Program Files (x86)\ossec-agent"
$Bin = Join-Path $Agent "active-response\bin"
$Files = @{
@FILES@
}
$warnings = 0
function Say($m) { Write-Host $m }
function Warn($m) { $script:warnings++; Write-Host "WARNING: $m" }
function Stop($m) { Write-Host "STOP: $m"; exit 1 }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Stop "run PowerShell as administrator" }
if (-not (Test-Path -LiteralPath $Bin)) { Stop "$Bin not found: install the Wazuh agent first" }
# the package should sit in a folder only administrators can change (for example C:\CIS\install\@VERSION@)
$pkgWriters = @((Get-Acl -LiteralPath $PSScriptRoot).Access | Where-Object {
    $_.AccessControlType -eq "Allow" -and ($_.FileSystemRights -band 0x116) -and
    $_.IdentityReference.Value -notmatch '(SYSTEM|Administrators|TrustedInstaller|CREATOR OWNER)$' })
if ($PSScriptRoot -match '^[A-Za-z]:\\(Users|Temp|Windows\\Temp)\\' -or $pkgWriters) {
    Warn "$PSScriptRoot can be changed by non-administrators ($(($pkgWriters | ForEach-Object { $_.IdentityReference.Value }) -join ', ')): use a folder only administrators can write, e.g. C:\CIS\install\@VERSION@ (see README.txt)"
}
if ($PublicKey) {
    if (-not (Test-Path -LiteralPath $PublicKey)) { Stop "$PublicKey not found" }
} else {
    $PublicKey = Join-Path $PSScriptRoot "ciscat-manifest.pub.xml"
    if (-not (Test-Path -LiteralPath $PublicKey)) { $PublicKey = "" }
}
if ($PublicKey) {
    try {
        $probe = [System.Security.Cryptography.RSA]::Create()
        $probe.FromXmlString((Get-Content -LiteralPath $PublicKey -Raw))
    } catch { Stop "$PublicKey is not an RSA public key: $($_.Exception.Message)" }
}
$stamp = Get-Date -Format "yyyyMMddHHmm"
$backup = Join-Path $Root "backup-$stamp"

Say "== 1. folders"
foreach ($d in $Root, (Join-Path $Root "bin"), (Join-Path $Root "results")) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}
# a junction or link under C:\CIS could send SYSTEM's writes elsewhere: refused
$links = @(Get-ChildItem -LiteralPath $Root -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue)
if ((Get-Item -LiteralPath $Root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { $links += Get-Item -LiteralPath $Root -Force }
if ($links) { Stop "links/junctions under ${Root}: $(($links | ForEach-Object FullName) -join ', ') - remove them and run again" }
# owner Administrators: a user who created C:\CIS before would otherwise keep the right to change its ACL
& icacls.exe $Root /setowner "*S-1-5-32-544" /T /C /Q | Out-Null
if ($LASTEXITCODE -ne 0) { Stop "could not set the owner of $Root (icacls exit $LASTEXITCODE)" }
# SYSTEM and Administrators: full control; Users: read and execute. No inherited entries (the
# root of C: lets authenticated users modify new subfolders).
# The entries are set on C:\CIS only; everything below it inherits them (/reset), so files keep
# working ACLs (setting (OI)(CI) entries file by file with /T would not).
& icacls.exe $Root /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /C /Q | Out-Null
if ($LASTEXITCODE -ne 0) { Stop "could not set the permissions of $Root (icacls exit $LASTEXITCODE)" }
& icacls.exe (Join-Path $Root "*") /reset /T /C /Q | Out-Null
if ($LASTEXITCODE -ne 0) { Stop "could not reset the permissions under $Root (icacls exit $LASTEXITCODE)" }
$keyDest = Join-Path $Root "ciscat-manifest.pub.xml"
Say "   $Root ready, owned by Administrators, writable only by SYSTEM and Administrators"
if ($PublicKey) {
    Copy-Item -LiteralPath $PublicKey -Destination $keyDest -Force
    Say "   master's public key: $keyDest  sha256 $((Get-FileHash -LiteralPath $keyDest -Algorithm SHA256).Hash.ToLower())"
    Say "   (compare with the sha256 that ciscat-master-setup.sh printed for ciscat-manifest.pub.xml)"
} elseif (Test-Path -LiteralPath $keyDest) {
    Say "   master's public key kept: $keyDest  sha256 $((Get-FileHash -LiteralPath $keyDest -Algorithm SHA256).Hash.ToLower())"
} else {
    Say "   master's public key: received from the master at the first run, then kept"
}

Say "== 2. CIS-CAT Pro Assessor"
$assessorDir = Join-Path $Root "Assessor"
$cli = Join-Path $assessorDir "Assessor-CLI.bat"
# a full agent package carries the Assessor (Assessor\ + ASSESSOR_VERSION, no license): install it,
# or update it when the version differs; the license is kept and a failed update rolled back
$pkgAssessor = Join-Path $PSScriptRoot "Assessor"
$pkgVersionFile = Join-Path $PSScriptRoot "ASSESSOR_VERSION"
if ((Test-Path -LiteralPath (Join-Path $pkgAssessor "Assessor-CLI.bat")) -and (Test-Path -LiteralPath $pkgVersionFile)) {
    $newVer = (Get-Content -LiteralPath $pkgVersionFile -Raw).Trim()
    $markFile = Join-Path $assessorDir ".bridge-assessor-version"
    $curVer = if (Test-Path -LiteralPath $markFile) { (Get-Content -LiteralPath $markFile -Raw).Trim() } else { "" }
    if ($newVer -eq $curVer -and (Test-Path -LiteralPath $cli)) {
        Say "   Assessor $newVer already installed"
    } else {
        Say "   installing Assessor $newVer (was: $(if ($curVer) { $curVer } else { 'none' }))"
        $newDir = "$assessorDir.new"
        if (Test-Path -LiteralPath $newDir) { Remove-Item -LiteralPath $newDir -Recurse -Force }
        & robocopy.exe $pkgAssessor $newDir /E /NFL /NDL /NJH /NJS /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { Stop "copy of the Assessor failed (robocopy exit $LASTEXITCODE)" }
        $oldDir = $null
        if (Test-Path -LiteralPath $assessorDir) {
            New-Item -ItemType Directory -Force -Path $backup | Out-Null
            $oldDir = Join-Path $backup "Assessor"
            if (Test-Path -LiteralPath $oldDir) { $oldDir = Join-Path $backup ("Assessor." + (Get-Date -Format "HHmmss") + "." + $PID) }
            Move-Item -LiteralPath $assessorDir -Destination $oldDir
            # the license and the benchmarks sent by the master stay, added to the package's
            foreach ($keep in "license", "benchmarks") {
                $oldKeep = Join-Path $oldDir $keep
                $newKeep = Join-Path $newDir $keep
                if (Test-Path -LiteralPath $oldKeep) {
                    New-Item -ItemType Directory -Force -Path $newKeep | Out-Null
                    & robocopy.exe $oldKeep $newKeep /E /NFL /NDL /NJH /NJS /NP | Out-Null
                    if ($LASTEXITCODE -ge 8) { Stop "copy of $oldKeep failed (robocopy exit $LASTEXITCODE)" }
                }
            }
        }
        Move-Item -LiteralPath $newDir -Destination $assessorDir
        & icacls.exe $assessorDir /reset /T /C /Q | Out-Null
        $ErrorActionPreference = "Continue"
        & (Join-Path $assessorDir "jre\bin\java.exe") -version 2>&1 | Out-Null
        $javaOk = ($LASTEXITCODE -eq 0)
        $ErrorActionPreference = "Stop"
        if (-not $javaOk) {
            Remove-Item -LiteralPath $assessorDir -Recurse -Force
            if ($oldDir) { Move-Item -LiteralPath $oldDir -Destination $assessorDir }
            Stop "the new Assessor does not start (java): previous one restored"
        }
        Set-Content -LiteralPath $markFile -Value $newVer -Encoding ASCII
        Say "   Assessor $newVer installed$(if ($oldDir) { " (previous one in $oldDir)" })"
    }
}
if (-not (Test-Path -LiteralPath $cli) -and $CopyAssessorFrom) {
    if (-not (Test-Path -LiteralPath (Join-Path $CopyAssessorFrom "Assessor-CLI.bat"))) { Stop "no Assessor-CLI.bat in $CopyAssessorFrom" }
    Say "   copying $CopyAssessorFrom -> $assessorDir"
    & robocopy.exe $CopyAssessorFrom $assessorDir /E /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { Stop "copy failed (robocopy exit $LASTEXITCODE)" }
    & icacls.exe $assessorDir /reset /T /C /Q | Out-Null
}
if (Test-Path -LiteralPath $cli) {
    Say "   present: $cli"
    $java = Join-Path $assessorDir "jre\bin\java.exe"
    if (Test-Path -LiteralPath $java) {
        # java -version writes to stderr: with "Stop", Windows PowerShell 5.1 makes that an error
        $ErrorActionPreference = "Continue"
        $jre = (& $java -version 2>&1 | Select-Object -First 1 | ForEach-Object { "$_" }) -join ''
        $ErrorActionPreference = "Stop"
        Say "   JRE: $jre"
    }
    else { Warn "no bundled JRE in $assessorDir\jre" }
    New-Item -ItemType Directory -Force -Path (Join-Path $assessorDir "benchmarks") | Out-Null
    $lp = Get-Content -LiteralPath (Join-Path $assessorDir "config\assessor-cli.properties") -ErrorAction SilentlyContinue |
        Where-Object { $_ -match '^\s*ciscat\.license\.filepath\s*=\s*(\S.*?)\s*$' } | ForEach-Object { $Matches[1] } | Select-Object -Last 1
    $lic = if ($lp) { Get-Item -LiteralPath $lp -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 } }
           else { Get-ChildItem -LiteralPath (Join-Path $assessorDir "license") -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 } | Select-Object -First 1 }
    if ($lic) { Say "   license: $($lic.FullName)" }
    else { Warn "CIS-CAT Pro license not found ($assessorDir\license, or ciscat.license.filepath): the assessments will stop until it is there" }
} else {
    Warn "CIS-CAT Pro not found in ${assessorDir}: install it there (or rerun with -CopyAssessorFrom <folder>)"
}

Say "== 3. Assessor settings"
$props = Join-Path $assessorDir "config\assessor-cli.properties"
if (Test-Path -LiteralPath $props) {
    $text = Get-Content -LiteralPath $props
    if ($text -match '^\s*exit\.on\.invalid\.signature\s*=\s*false\s*$') {
        Say "   exit.on.invalid.signature=false already set"
    } else {
        Copy-Item -LiteralPath $props -Destination "$props.bak-$stamp"
        $new = @($text | Where-Object { $_ -notmatch '^\s*exit\.on\.invalid\.signature\s*=' }) + "exit.on.invalid.signature=false"
        Set-Content -LiteralPath $props -Value $new -Encoding ASCII
        Say "   exit.on.invalid.signature=false set (previous file: $props.bak-$stamp)"
    }
} elseif (Test-Path -LiteralPath $cli) {
    Warn "$props not found: set exit.on.invalid.signature=false there"
}

Say "== 4. Active Response launcher and bootstrap"
foreach ($name in $Files.Keys) {
    $dest = Join-Path $Bin $name
    $tmp = Join-Path $env:TEMP "$name.$stamp"
    [IO.File]::WriteAllBytes($tmp, [Convert]::FromBase64String($Files[$name][1]))
    $hash = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash
    if ($hash -ne $Files[$name][0]) { Remove-Item -LiteralPath $tmp -Force; Stop "checksum mismatch for ${name}: nothing installed" }
    if (Test-Path -LiteralPath $dest) {
        New-Item -ItemType Directory -Force -Path $backup | Out-Null
        Copy-Item -LiteralPath $dest -Destination $backup
    }
    Move-Item -LiteralPath $tmp -Destination $dest -Force
    Unblock-File -LiteralPath $dest
    Say "   $name  $hash"
}

Say "== 5. files of earlier versions"
$legacy = @("ciscat-assessment.exe", "ciscat-bootstrap.exe", "ciscat-assessment.ps1", "ciscat-sca-setup.exe", "ciscat-sca-setup.cmd")
foreach ($name in $legacy) {
    $p = Join-Path $Bin $name
    if (Test-Path -LiteralPath $p) {
        New-Item -ItemType Directory -Force -Path $backup | Out-Null
        Move-Item -LiteralPath $p -Destination $backup -Force
        Say "   moved to $backup : $name"
    }
}
$conf = Join-Path $Agent "ossec.conf"
$wodle = Select-String -LiteralPath $conf -Pattern '<wodle name="cis-cat">' -Context 0, 3 -ErrorAction SilentlyContinue
if ($wodle -and ($wodle.Context.PostContext -join " ") -notmatch '<disabled>\s*yes\s*</disabled>') {
    Warn "the Wazuh cis-cat wodle is enabled in ${conf}: disable it (<disabled>yes</disabled>), the bridge runs CIS-CAT"
}

Say ""
if ($warnings) { Say "RESULT: DONE WITH $warnings WARNING(S) (see above)" } else { Say "RESULT: OK - agent ready for the CIS-CAT bridge @VERSION@" }
