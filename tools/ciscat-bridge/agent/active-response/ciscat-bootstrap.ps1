<#
  ciscat-bootstrap.ps1  (AGENT side, Windows)

  Started by the ciscat-assessment.cmd launcher (Active Response). Installed by hand once, next to
  the launcher, in ossec-agent\active-response\bin; everything else comes from the manager.

  1. -Detach (from the launcher): start this script again as a separate process and return, so
     wazuh-execd is released at once (it waits for the launcher, and runs no other Active Response
     meanwhile).
  2. One run at a time on the agent (named mutex).
  3. For every ciscat-manifest-<os>.csv the manager published in the agent's groups (shared
     folder): check each file's SHA-256 and install it to its destination, only under
     C:\CIS\Assessor\benchmarks (custom benchmark, OVAL and CPE files) or C:\CIS\bin (the
     assessment and conversion scripts). A file that does not verify is not installed.
  4. Run C:\CIS\bin\ciscat-assessment.ps1, which assesses every benchmark of the agent.

  Logs go to ossec-agent\active-response\active-responses.log.
#>
param(
    [string]$Root = "C:\CIS",
    [string]$SharedDir = "C:\Program Files (x86)\ossec-agent\shared",
    [string]$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log",
    [switch]$Detach
)
$ErrorActionPreference = "Stop"

function Log($msg) {
    $line = "{0} ciscat-bootstrap: {1}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $msg
    try { Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue } catch {}
    Write-Host $line
}

if ($Detach) {
    $argv = @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    foreach ($name in "Root", "SharedDir", "LogFile") {
        if ($PSBoundParameters.ContainsKey($name)) { $argv += @("-$name", "`"$($PSBoundParameters[$name])`"") }
    }
    try {
        $p = Start-Process -FilePath "powershell.exe" -ArgumentList $argv -WindowStyle Hidden -PassThru
        Log "assessment started in the background (process $($p.Id))"
        exit 0
    } catch {
        Log "ERROR: could not start the assessment: $($_.Exception.Message)"
        exit 1
    }
}

Log "=== start (running as $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)) ==="
$lock = New-Object System.Threading.Mutex($false, "Global\ciscat-assessment")
$owned = $false
try { $owned = $lock.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $owned = $true }
if (-not $owned) {
    Log "ERROR: another CIS-CAT assessment is running on this agent; this run is skipped"
    exit 1
}

# the only places a manifest may install to (no "..", no other folder)
$allowed = @((Join-Path $Root "Assessor\benchmarks"), (Join-Path $Root "bin")) |
    ForEach-Object { [System.IO.Path]::GetFullPath($_).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar }
function Allowed($dest) {
    if ($dest -match '\.\.') { return $false }
    $full = [System.IO.Path]::GetFullPath($dest)
    foreach ($a in $allowed) { if ($full.StartsWith($a, [System.StringComparison]::OrdinalIgnoreCase)) { return $true } }
    return $false
}

$manifests = @(Get-ChildItem -LiteralPath $SharedDir -Filter "ciscat-manifest-*.csv" -ErrorAction SilentlyContinue)
if (-not $manifests) {
    Log "ERROR: no ciscat-manifest-*.csv in $SharedDir (group files not synchronized yet?)"
    exit 1
}
$installed = 0; $refused = 0; $missing = 0
foreach ($m in $manifests) {
    Log "using manifest: $($m.Name)"
    foreach ($line in Get-Content -LiteralPath $m.FullName) {
        if ($line -match '^\s*#' -or -not $line.Trim()) { continue }
        $parts = $line.Split(";")
        if ($parts.Count -lt 3 -or -not $parts[2]) { continue }  # read from shared, not installed
        $name, $expected, $dest = $parts[0], $parts[1].ToUpper(), $parts[2]
        if ($name -notmatch '^[A-Za-z0-9._-]+$') { Log "REFUSED (not a plain file name): $name"; $refused++; continue }
        if (-not (Allowed $dest)) { Log "REFUSED (destination not allowed): $name -> $dest"; $refused++; continue }
        $src = Join-Path $SharedDir $name
        if (-not (Test-Path -LiteralPath $src)) { Log "MISSING in shared: $name"; $missing++; continue }
        $actual = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash
        if ($actual -ne $expected) { Log "REFUSED (sha256 mismatch): $name"; $refused++; continue }
        New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
        Copy-Item -LiteralPath $src -Destination $dest -Force
        $installed++
    }
}
Log "bootstrap done: installed=$installed refused=$refused missing=$missing"
if ($refused) {
    Log "ERROR: files refused, assessment not run"
    exit 2
}

$assessment = Join-Path $Root "bin\ciscat-assessment.ps1"
if (-not (Test-Path -LiteralPath $assessment)) {
    Log "ERROR: $assessment not installed (not in any manifest?)"
    exit 1
}
& $assessment -Root $Root -SharedDir $SharedDir -LogFile $LogFile
exit $LASTEXITCODE
