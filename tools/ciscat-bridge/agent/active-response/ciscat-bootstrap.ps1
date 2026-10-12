<#
  ciscat-bootstrap.ps1  (AGENT side, Windows)

  Started by the ciscat-assessment.cmd launcher (Active Response). Installed by hand once, next to
  the launcher, in ossec-agent\active-response\bin; everything else comes from the manager.

  1. -Detach (from the launcher): start this script again as a separate process and return, so
     wazuh-execd is released at once (it waits for the launcher, and runs no other Active Response
     meanwhile).
  2. One run at a time on the agent (named mutex).
  3. For every ciscat-manifest-<os>.csv the manager published in the agent's groups (shared
     folder): copy it and its .sig to C:\CIS\staging (SYSTEM and Administrators only), verify
     the signature with the master's public key (C:\CIS\ciscat-manifest.pub.xml, put there by
     the installer), then copy each file it lists to the staging folder, check its SHA-256 there
     and install it to its destination, only under C:\CIS\Assessor\benchmarks (custom
     benchmark, OVAL and CPE files), C:\CIS\bin (the assessment and conversion scripts) or
     C:\CIS\run (parameters and tailoring). Nothing of a manifest that does not verify is used.
  4. Run C:\CIS\bin\ciscat-assessment.ps1 on the parameters in C:\CIS\run.

  Logs go to ossec-agent\active-response\active-responses.log.
#>
param(
    [string]$Root = "C:\CIS",
    [string]$SharedDir = "C:\Program Files (x86)\ossec-agent\shared",
    [string]$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log",
    [string]$PublicKey = "",
    [switch]$Detach
)
$ErrorActionPreference = "Stop"

# Appends a line to the Active Response log, which wazuh-agent keeps open: shared read/write
# access and a few retries (Add-Content gives up on a sharing violation, without a word).
function Write-LogLine($path, $line) {
    for ($i = 0; $i -lt 10; $i++) {
        try {
            $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
            try {
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($line + "`r`n")
                $fs.Write($bytes, 0, $bytes.Length)
            } finally { $fs.Dispose() }
            return
        } catch { Start-Sleep -Milliseconds 300 }
    }
}

function Log($msg) {
    $line = "{0} ciscat-bootstrap: {1}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $msg
    Write-LogLine $LogFile $line
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
$RunDir = Join-Path $Root "run"
$Stage = Join-Path $Root "staging"
$allowed = @((Join-Path $Root "Assessor\benchmarks"), (Join-Path $Root "bin"), $RunDir) |
    ForEach-Object { [System.IO.Path]::GetFullPath($_).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar }
function Allowed($dest) {
    if ($dest -match '\.\.') { return $false }
    $full = [System.IO.Path]::GetFullPath($dest)
    foreach ($a in $allowed) { if ($full.StartsWith($a, [System.StringComparison]::OrdinalIgnoreCase)) { return $true } }
    return $false
}

if (-not $PublicKey) { $PublicKey = Join-Path $Root "ciscat-manifest.pub.xml" }
if (-not (Test-Path -LiteralPath $PublicKey)) {
    Log "ERROR: public key $PublicKey not found: install the agent with the master's ciscat-manifest.pub.xml"
    exit 1
}
$rsa = [System.Security.Cryptography.RSA]::Create()
$rsa.FromXmlString((Get-Content -LiteralPath $PublicKey -Raw))

# the agent stores group files with CRLF; the master signed them with LF
function Get-LfBytes($path) {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $out = New-Object System.IO.MemoryStream
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -eq 13 -and $i + 1 -lt $bytes.Length -and $bytes[$i + 1] -eq 10) { continue }
        $out.WriteByte($bytes[$i])
    }
    return ,$out.ToArray()
}

function Test-Manifest($manifest) {
    $sigFile = $manifest + ".sig"
    if (-not (Test-Path -LiteralPath $sigFile)) { Log "REFUSED (no signature $(Split-Path $sigFile -Leaf))"; return $false }
    try {
        $sig = [Convert]::FromBase64String(((Get-Content -LiteralPath $sigFile -Raw) -replace '\s', ''))
        $ok = $rsa.VerifyData((Get-LfBytes $manifest), $sig,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } catch { $ok = $false }
    if (-not $ok) { Log "REFUSED (signature not valid for the master's key): $(Split-Path $manifest -Leaf)" }
    return $ok
}

$manifests = @(Get-ChildItem -LiteralPath $SharedDir -Filter "ciscat-manifest-*.csv" -ErrorAction SilentlyContinue)
if (-not $manifests) {
    Log "ERROR: no ciscat-manifest-*.csv in $SharedDir (group files not synchronized yet?)"
    exit 1
}
# a clean staging folder, and a run folder holding only what this run verified
foreach ($d in $Stage, $RunDir) {
    if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}
$installed = 0; $refused = 0; $missing = 0
foreach ($m in $manifests) {
    Log "using manifest: $($m.Name)"
    $staged = Join-Path $Stage $m.Name
    Copy-Item -LiteralPath $m.FullName -Destination $staged -Force
    if (Test-Path -LiteralPath ($m.FullName + ".sig")) { Copy-Item -LiteralPath ($m.FullName + ".sig") -Destination ($staged + ".sig") -Force }
    if (-not (Test-Manifest $staged)) { $refused++; continue }
    Log "signature OK: $($m.Name)"
    foreach ($line in Get-Content -LiteralPath $staged) {
        if ($line -match '^\s*#' -or -not $line.Trim()) { continue }
        $parts = $line.Split(";")
        if ($parts.Count -lt 3 -or -not $parts[2]) { continue }
        $name, $expected, $dest = $parts[0], $parts[1].ToUpper(), $parts[2]
        if ($name -notmatch '^[A-Za-z0-9._-]+$') { Log "REFUSED (not a plain file name): $name"; $refused++; continue }
        if (-not (Allowed $dest)) { Log "REFUSED (destination not allowed): $name -> $dest"; $refused++; continue }
        $src = Join-Path $SharedDir $name
        if (-not (Test-Path -LiteralPath $src)) { Log "MISSING in shared: $name"; $missing++; continue }
        # checked and installed from the protected copy, which nobody else can change meanwhile
        $copy = Join-Path $Stage $name
        Copy-Item -LiteralPath $src -Destination $copy -Force
        $actual = (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash
        if ($actual -ne $expected) { Log "REFUSED (sha256 mismatch): $name"; $refused++; continue }
        New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
        Copy-Item -LiteralPath $copy -Destination $dest -Force
        $installed++
    }
}
Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
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
& $assessment -Root $Root -SharedDir $RunDir -LogFile $LogFile
exit $LASTEXITCODE
