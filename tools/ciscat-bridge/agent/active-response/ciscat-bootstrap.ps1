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

  A final agent package (unpacked in C:\) lays down C:\CIS\Assessor and, next to this script, the
  list of the Assessor's files (ciscat-assessor.sha256). Every run C:\CIS is made writable by
  SYSTEM and Administrators only (a folder unpacked in C:\ inherits the rights of C:\, where
  users may change files); at the first run with a new list the Assessor is checked against it:
  a file that differs stops the run, files that are not in the list (left by an earlier Assessor
  version) are moved aside. The license, benchmarks, reports, logs and settings are not checked.

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

$who = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { "$env:USERDOMAIN\$env:USERNAME" }
Log "=== start (running as $who) ==="
$lock = New-Object System.Threading.Mutex($false, "Global\ciscat-assessment")
$owned = $false
try { $owned = $lock.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $owned = $true }
if (-not $owned) {
    Log "ERROR: another CIS-CAT assessment is running on this agent; this run is skipped"
    exit 1
}

# C:\CIS: owned by Administrators, writable only by SYSTEM and Administrators, read by Users
if (Test-Path -LiteralPath $Root) {
    & icacls.exe $Root /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /C /Q | Out-Null
}

# the Assessor of a final agent package, checked once per package against the list of its files
$assessorList = Join-Path $PSScriptRoot "ciscat-assessor.sha256"
$assessorChecked = Join-Path $Root "assessor-checked"
if (Test-Path -LiteralPath $assessorList) {
    $listSha = (Get-FileHash -LiteralPath $assessorList -Algorithm SHA256).Hash
    $done = if (Test-Path -LiteralPath $assessorChecked) { (Get-Content -LiteralPath $assessorChecked -Raw).Trim() } else { "" }
    if ($done -ne $listSha) {
        Remove-Item -LiteralPath $assessorChecked -Force -ErrorAction SilentlyContinue
        $assessorDir = Join-Path $Root "Assessor"
        if (-not (Test-Path -LiteralPath $assessorDir)) { Log "ERROR: $assessorDir not found: unpack the agent package"; exit 3 }
        & icacls.exe $Root /setowner "*S-1-5-32-544" /T /C /Q | Out-Null
        $want = @{}
        foreach ($line in Get-Content -LiteralPath $assessorList) {
            if ($line -match '^([0-9a-fA-F]{64})  (.+)$') { $want[$Matches[2]] = $Matches[1].ToUpper() }
        }
        $bad = @()
        foreach ($rel in $want.Keys) {
            $p = Join-Path $assessorDir $rel
            if (-not (Test-Path -LiteralPath $p -PathType Leaf) -or
                (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ne $want[$rel]) { $bad += $rel }
        }
        if ($bad) {
            $bad | Select-Object -First 20 | ForEach-Object { Log "REFUSED (Assessor file differs from the package): $_" }
            Log "ERROR: the Assessor in $assessorDir is not the one of the agent package ($($bad.Count) file(s)): assessment not run"
            exit 3
        }
        $backupDir = Join-Path $Root ("backup-assessor-" + (Get-Date -Format "yyyyMMddHHmmss"))
        $moved = 0
        foreach ($f in @(Get-ChildItem -LiteralPath $assessorDir -Recurse -File -Force)) {
            $rel = $f.FullName.Substring($assessorDir.Length + 1).Replace('\', '/')
            if ($rel -match '^(license|benchmarks|reports|logs|config)/' -or $rel -match '^\.bridge-' -or $want.ContainsKey($rel)) { continue }
            $to = Join-Path $backupDir $rel
            New-Item -ItemType Directory -Force -Path (Split-Path $to) | Out-Null
            Move-Item -LiteralPath $f.FullName -Destination $to -Force
            $moved++
        }
        if ($moved) { Log "moved $moved file(s) of an earlier Assessor to $backupDir" }
        Set-Content -LiteralPath $assessorChecked -Value $listSha -Encoding ASCII
        Log "Assessor checked against the agent package: $($want.Count) file(s) OK"
    }
}

# the only places a manifest may install to (no "..", no other folder)
$RunDir = Join-Path $Root "run"
$Stage = Join-Path $Root "staging"
$licenseDest = Join-Path $Root "Assessor\license\license.xml"
$allowed = @((Join-Path $Root "Assessor\benchmarks"), (Join-Path $Root "bin"), $RunDir) |
    ForEach-Object { [System.IO.Path]::GetFullPath($_).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar }
function Allowed($dest) {
    if ($dest -match '\.\.') { return $false }
    if ($dest -ieq $licenseDest) { return $true }
    $full = [System.IO.Path]::GetFullPath($dest)
    foreach ($a in $allowed) { if ($full.StartsWith($a, [System.StringComparison]::OrdinalIgnoreCase)) { return $true } }
    return $false
}

if (-not $PublicKey) {
    # pinned by a final agent package next to this script, else kept in C:\CIS
    $pinned = Join-Path $PSScriptRoot "ciscat-manifest.pub.xml"
    $PublicKey = if (Test-Path -LiteralPath $pinned) { $pinned } else { Join-Path $Root "ciscat-manifest.pub.xml" }
}
# The master's public key comes with the group files. Without a key of its own (installed with
# -PublicKey) the agent keeps the first valid one it receives (trust on first use); from then on
# only the kept key counts, and a different key in the group is ignored. New master key: reinstall
# with -PublicKey, or delete the kept key.
function Get-KeyText($path) { ((Get-Content -LiteralPath $path -Raw) -replace '\s', '') }
function Get-TextSha($text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString("x2") }) -join "")
}
$sharedKey = Join-Path $SharedDir "ciscat-manifest.pub.xml"
$sharedItem = Get-Item -LiteralPath $sharedKey -Force -ErrorAction SilentlyContinue
if ($sharedItem -and -not ($sharedItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
  try {
    $received = Get-KeyText $sharedKey
    if (-not (Test-Path -LiteralPath $PublicKey)) {
        try {
            if ($received -notmatch '^<RSAKeyValue><Modulus>[A-Za-z0-9+/=]+</Modulus><Exponent>[A-Za-z0-9+/=]+</Exponent></RSAKeyValue>$') {
                throw "not an RSA public key"
            }
            $probe = [System.Security.Cryptography.RSA]::Create()
            $probe.FromXmlString($received)
            [System.IO.File]::WriteAllText($PublicKey, $received + "`r`n")
            Log "master's public key received and kept: $PublicKey (key sha256 $(Get-TextSha $received))"
        } catch {
            Log "WARNING: $sharedKey not kept: $($_.Exception.Message)"
        }
    } elseif ($received -cne (Get-KeyText $PublicKey)) {
        Log "WARNING: the group's public key (key sha256 $(Get-TextSha $received)) differs from the kept one (key sha256 $(Get-TextSha (Get-KeyText $PublicKey))): ignored"
    }
  } catch {
    # the agent may be rewriting the group files: the kept key, if any, still applies
    Log "WARNING: cannot read the public key in the group files now: $($_.Exception.Message)"
  }
}
if (-not (Test-Path -LiteralPath $PublicKey)) {
    Log "ERROR: public key $PublicKey not found and none received from the master yet"
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
        $b64 = $dest.EndsWith(":b64")
        if ($b64) { $dest = $dest.Substring(0, $dest.Length - 4) }
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
        if ($b64) {
            # base64 text (the license): decoded byte for byte
            try {
                $bytes = [Convert]::FromBase64String(((Get-Content -LiteralPath $copy -Raw) -replace '\s', ''))
                [System.IO.File]::WriteAllBytes($dest + ".new", $bytes)
                Move-Item -LiteralPath ($dest + ".new") -Destination $dest -Force
                Log "installed (base64): $name -> $dest"
            } catch { Log "REFUSED (base64 decoding failed): $name"; $refused++; continue }
        } else {
            Copy-Item -LiteralPath $copy -Destination $dest -Force
        }
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
