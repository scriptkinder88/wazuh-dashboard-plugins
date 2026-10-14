<#
  ciscat-e2e-windows.ps1 - end-to-end check of the CIS-CAT bridge on a Windows agent.
  Run in an elevated PowerShell:
    powershell -ExecutionPolicy Bypass -File .\ciscat-e2e-windows.ps1 -Step Pre     before the run
    powershell -ExecutionPolicy Bypass -File .\ciscat-e2e-windows.ps1 -Step Watch   right after "run" on the master
    powershell -ExecutionPolicy Bypass -File .\ciscat-e2e-windows.ps1 -Step Post    when Watch ends
  Read-only. Prints EXPECT / GOT and PASS, FAIL or WAIT per check.
#>
param(
    [ValidateSet("Pre", "Watch", "Post")][string]$Step = "Pre",
    [int]$WatchMinutes = 30,
    [string]$Agent = "C:\Program Files (x86)\ossec-agent",
    [string]$Root = "C:\CIS"
)
$ErrorActionPreference = "Continue"
$Expected = @{
    "ciscat-assessment.cmd" = "@CMD_SHA@"
    "ciscat-bootstrap.ps1"  = "@BOOT_SHA@"
}
$Ciscat = Join-Path $Root "Assessor"
$Shared = Join-Path $Agent "shared"
$Bin = Join-Path $Agent "active-response\bin"
$ArLog = Join-Path $Agent "active-response\active-responses.log"
$OssecLog = Join-Path $Agent "ossec.log"
$Results = Join-Path $Root "results"
$script:n = @{ PASS = 0; FAIL = 0; WAIT = 0 }

function Check($code, $title, $expect, $got, [bool]$ok, [bool]$wait = $false) {
    $state = if ($ok) { "PASS" } elseif ($wait) { "WAIT" } else { "FAIL" }
    $script:n[$state]++
    Write-Host ("[{0}] {1} {2}`n        EXPECT: {3}`n        GOT:    {4}" -f $state, $code, $title, $expect, $got)
}
function Info($code, $text) { Write-Host "[INFO] $code $text" }
function Hash($p) { if (Test-Path -LiteralPath $p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash } else { "missing" } }

# the benchmarks this agent gets: one ciscat-params-<os>.txt per OS group (older managers: one file)
function Benchmarks {
    $files = @(Get-ChildItem -LiteralPath $Shared -Filter "ciscat-params-*.txt" -ErrorAction SilentlyContinue)
    if (-not $files) { $files = @(Get-ChildItem -LiteralPath $Shared -Filter "ciscat-params.txt" -ErrorAction SilentlyContinue) }
    foreach ($f in $files) {
        $b = @{ File = $f.Name; Os = ($f.BaseName -replace '^ciscat-params-?', '') }
        foreach ($line in Get-Content -LiteralPath $f.FullName) {
            if ($line -match '^\s*(Profile|FlatName|CustomXccdf)\s*=\s*(.+?)\s*$') { $b[$Matches[1]] = $Matches[2] }
        }
        $b
    }
}

# the ciscat lines of the AR log since the last "launcher invoked"
function LastRun {
    if (-not (Test-Path -LiteralPath $ArLog)) { return @() }
    $lines = @(Get-Content -LiteralPath $ArLog -Tail 3000 | Where-Object { $_ -match 'ciscat' })
    $start = -1
    for ($i = $lines.Count - 1; $i -ge 0; $i--) { if ($lines[$i] -match 'launcher invoked|=== start') { $start = $i; if ($lines[$i] -match 'launcher invoked') { break } } }
    if ($start -lt 0) { return @() }
    return $lines[$start..($lines.Count - 1)]
}
function LineTime($line) {
    if ($line -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})') { return [datetime]::ParseExact($Matches[1], "yyyy-MM-dd HH:mm:ss", $null) }
    return $null
}

function Pre {
    Write-Host "== host $env:COMPUTERNAME  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
    Check "W1" "Wazuh agent service" "Running" ($(if ($svc) { $svc.Status } else { "not found" })) ($svc -and $svc.Status -eq "Running")
    # VERSION (older agents), VERSION.json (4.8 and later), else the version of wazuh-agent.exe
    $ver = Get-Content -LiteralPath (Join-Path $Agent "VERSION") -TotalCount 1 -ErrorAction SilentlyContinue
    if (-not $ver) {
        try { $ver = (Get-Content -LiteralPath (Join-Path $Agent "VERSION.json") -Raw -ErrorAction Stop | ConvertFrom-Json).version } catch { }
    }
    if (-not $ver) { $ver = (Get-Item -LiteralPath (Join-Path $Agent "wazuh-agent.exe") -ErrorAction SilentlyContinue).VersionInfo.ProductVersion }
    Info "W1" "agent version: $(if ($ver) { $ver } else { 'not found' })"

    $ar = Get-Content -LiteralPath (Join-Path $Shared "ar.conf") -ErrorAction SilentlyContinue | Where-Object { $_ -match '^ciscat-assessment0 ' }
    Check "W2" "the master maps ciscat-assessment0 to the launcher" "ciscat-assessment0 - ciscat-assessment.cmd - 0" ($(if ($ar) { $ar } else { "missing in shared\ar.conf" })) ($ar -match ' - ciscat-assessment\.cmd - ')

    foreach ($name in "ciscat-assessment.cmd", "ciscat-bootstrap.ps1") {
        $h = Hash (Join-Path $Bin $name)
        Check "W3" "$name in active-response\bin (@VERSION@)" $Expected[$name] $h ($h -eq $Expected[$name])
    }
    $acl = (Get-Acl -LiteralPath $Root -ErrorAction SilentlyContinue).Access | Where-Object {
        $_.AccessControlType -eq "Allow" -and ($_.FileSystemRights -match "Write|Modify|FullControl") -and
        $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @("S-1-5-18", "S-1-5-32-544") }
    Check "W3" "$Root writable only by SYSTEM and Administrators (scripts there run as SYSTEM; set by the bootstrap at each run)" "no other write access" ($(if ($acl) { ($acl | ForEach-Object { "$($_.IdentityReference): $($_.FileSystemRights)" }) -join "; " } else { "ok" })) (-not $acl -and (Test-Path -LiteralPath $Root))
    # pinned by a final agent package next to the bootstrap, else kept in C:\CIS
    $key = Join-Path $Bin "ciscat-manifest.pub.xml"
    if (-not (Test-Path -LiteralPath $key)) { $key = Join-Path $Root "ciscat-manifest.pub.xml" }
    $sharedKey = Join-Path $Shared "ciscat-manifest.pub.xml"
    $keyText = { param($p) ((Get-Content -LiteralPath $p -Raw) -replace '\s', '') }
    $keyOk = $true
    if (Test-Path -LiteralPath $key) {
        $kgot = "kept, sha256 " + (Get-FileHash -LiteralPath $key -Algorithm SHA256).Hash.ToLower()
        if ((Test-Path -LiteralPath $sharedKey) -and ((& $keyText $key) -ne (& $keyText $sharedKey))) {
            $kgot += " - the group's key DIFFERS (new master key?)"; $keyOk = $false
        }
    } elseif (Test-Path -LiteralPath $sharedKey) {
        $kgot = "from the master, kept at the first run"
    } else {
        $kgot = "missing: not received from the master yet (group sync pending?)"; $keyOk = $false
    }
    Check "W3" "master's public key (manifests must be signed with it)" "$key, or in shared" $kgot $keyOk
    $assessor = Join-Path $Ciscat "Assessor-CLI.bat"
    Check "W4" "CIS-CAT Pro Assessor" $assessor ($(if (Test-Path -LiteralPath $assessor) { "present" } else { "missing" })) (Test-Path -LiteralPath $assessor)
    $java = Join-Path $Ciscat "jre\bin\java.exe"
    if (Test-Path -LiteralPath $java) { Info "W4" ("JRE: " + ((& $java -version 2>&1 | Select-Object -First 1) -join '')) } else { Info "W4" "no bundled JRE in $Ciscat\jre" }
    $props = Get-Content -LiteralPath (Join-Path $Ciscat "config\assessor-cli.properties") -ErrorAction SilentlyContinue
    $lp = $props | Where-Object { $_ -match '^\s*ciscat\.license\.filepath\s*=\s*(\S.*?)\s*$' } | ForEach-Object { $Matches[1] } | Select-Object -Last 1
    $lic = if ($lp) { Get-Item -LiteralPath $lp -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 } }
           else { Get-ChildItem -LiteralPath (Join-Path $Ciscat "license") -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 } | Select-Object -First 1 }
    Check "W4" "CIS-CAT Pro license" "a license file ($Ciscat\license or ciscat.license.filepath)" ($(if ($lic) { $lic.FullName } else { "not found" })) ([bool]$lic)
    $sig = $props | Where-Object { $_ -match '^\s*exit\.on\.invalid\.signature\s*=' }
    Check "W5" "custom benchmark accepted unsigned" "exit.on.invalid.signature=false" ($(if ($sig) { $sig } else { "not set" })) ($sig -match '=\s*false')

    $bench = @(Benchmarks)
    Check "W7" "benchmarks published for this agent" "one ciscat-params-<os>.txt per OS group" (($bench | ForEach-Object { $_.File }) -join ", ") ($bench.Count -gt 0)
    foreach ($b in $bench) {
        Info "W7" "$($b.File): FlatName=$($b.FlatName) CustomXccdf=$($b.CustomXccdf) Profile=$($b.Profile)"
        $custom = Join-Path $Shared $b.CustomXccdf
        Check "W8" "custom benchmark of $($b.Os) in shared" $custom ($(if ($b.CustomXccdf -and (Test-Path -LiteralPath $custom)) { "present" } else { "missing" })) ($b.CustomXccdf -and (Test-Path -LiteralPath $custom))
        $manifest = Join-Path $Shared "ciscat-manifest-$($b.Os).csv"
        $scripts = @(Select-String -LiteralPath $manifest -Pattern '^(ciscat-assessment|ciscat-csv-to-flat)\.ps1;' -ErrorAction SilentlyContinue)
        Check "W6" "scripts of $($b.Os) published by the master" "ciscat-assessment.ps1 and ciscat-csv-to-flat.ps1 -> $Root\bin" ("{0} of 2 in the manifest" -f $scripts.Count) ($scripts.Count -eq 2)
        if (Test-Path -LiteralPath $manifest) {
            $bad = @()
            foreach ($line in Get-Content -LiteralPath $manifest) {
                if ($line -match '^#' -or -not $line.Trim()) { continue }
                $parts = $line.Split(";")
                if ((Hash (Join-Path $Shared $parts[0])) -ne $parts[1].ToUpper()) { $bad += $parts[0] }
            }
            Check "W9" "files of $($b.Os) as published by the master" "every sha256 of ciscat-manifest-$($b.Os).csv equal" ($(if ($bad) { "differ: " + ($bad -join ", ") } else { "all equal" })) (-not $bad)
        }
    }
    $linux = @(Get-ChildItem -LiteralPath $Shared -Filter "ciscat-refresh-*.conf" -ErrorAction SilentlyContinue)
    Check "W10" "no Linux benchmark sent to this Windows agent" "no ciscat-refresh-*.conf in shared" ($(if ($linux) { ($linux.Name -join ", ") } else { "none" })) (-not $linux)

    $conf = Join-Path $Shared "agent.conf"
    $policies = @(Select-String -LiteralPath $conf -Pattern '<policy>\s*([^<]+?)\s*</policy>' -AllMatches -ErrorAction SilentlyContinue | ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value })
    Check "W11" "SCA policies loaded from the groups" "one .yml per benchmark" ($policies -join ", ") ($policies.Count -ge $bench.Count -and $policies.Count -gt 0)
    foreach ($p in $policies) {
        $file = Join-Path $Shared (Split-Path $p -Leaf)
        $flat = Select-String -LiteralPath $file -Pattern "'f:([^']+?)(?: ->|')" -ErrorAction SilentlyContinue | Select-Object -First 1
        $flatPath = if ($flat) { $flat.Matches[0].Groups[1].Value } else { "" }
        $windowsPath = $flatPath -like "$Results\*"
        Check "W12" "policy $(Split-Path $p -Leaf) reads its results file" "$Results\<name>.ciscat-flat" ($(if (Test-Path -LiteralPath $file) { $flatPath } else { "policy file missing in shared" })) ((Test-Path -LiteralPath $file) -and $windowsPath)
    }
    foreach ($f in Get-ChildItem -LiteralPath $Results -Filter *.ciscat-flat -ErrorAction SilentlyContinue) {
        Info "W13" ("results now: {0}  {1:yyyy-MM-dd HH:mm}  {2} lines" -f $f.Name, $f.LastWriteTime, @(Get-Content -LiteralPath $f.FullName).Count)
    }
}

function Watch {
    # a run that already ended (watch started late): show it and stop
    $last = @(LastRun)
    if ($last -and $last[-1] -match '=== done|ABORTED') {
        $end = LineTime $last[-1]
        if ($end -and ((Get-Date) - $end).TotalMinutes -lt 60) {
            Write-Host "== the last run already ended:"
            $last | Select-Object -Last 4 | ForEach-Object { Write-Host "  log> $_" }
            Write-Host "== now -Step Post (or a new 'run' on the master, then -Step Watch)"
            return
        }
    }
    Write-Host "== watching the AR log and the processes for up to $WatchMinutes min (Ctrl+C to stop)"
    $seen = if (Test-Path -LiteralPath $ArLog) { @(Get-Content -LiteralPath $ArLog).Count } else { 0 }
    # a run started before the watch and still going counts as started
    $t0 = Get-Date; $invoked = [bool]($last -and $last[-1] -notmatch '=== done|ABORTED')
    while ((Get-Date) - $t0 -lt [timespan]::FromMinutes($WatchMinutes)) {
        if (Test-Path -LiteralPath $ArLog) {
            $all = @(Get-Content -LiteralPath $ArLog)
            if ($all.Count -gt $seen) {
                $all[$seen..($all.Count - 1)] | Where-Object { $_ -match 'ciscat' } | ForEach-Object {
                    Write-Host "  log> $_"
                    if ($_ -match 'launcher invoked|=== start') { $invoked = $true }
                }
                $seen = $all.Count
                if ($all[-1] -match '=== done|ABORTED') { Write-Host "== the run ended: now -Step Post"; return }
            }
        }
        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue 2>$null | Where-Object { $_.CommandLine -match 'ciscat|Assessor|CIS\\' -and $_.ProcessId -ne $PID }
        if ($procs | Where-Object { $_.CommandLine -match 'ciscat-assessment|Assessor' }) { $invoked = $true }
        $elapsed = [int]((Get-Date) - $t0).TotalSeconds
        Write-Host ("  {0,4}s  running: {1}" -f $elapsed, $(if ($procs) { ($procs | ForEach-Object { "$($_.Name)[$($_.ProcessId)]" }) -join ", " } else { "none" }))
        if (-not $invoked -and $elapsed -ge 180) {
            Write-Host "[FAIL] the Active Response did not start the launcher within 3 minutes"
            Write-Host "       check: shared\ar.conf (W2), and these ossec.log lines:"
            Get-Content -LiteralPath $OssecLog -Tail 400 | Where-Object { $_ -match 'execd|active.response|ciscat' } | Select-Object -Last 15 | ForEach-Object { "         $_" }
            return
        }
        Start-Sleep -Seconds 15
    }
    Write-Host "== stopped after $WatchMinutes min: run -Step Post"
}

function Post {
    $run = @(LastRun)
    # the launcher writes the Windows locale date: the time of the run is the script's first line
    $t = $run | ForEach-Object { LineTime $_ } | Where-Object { $_ } | Select-Object -First 1
    Check "P1" "the Active Response started the launcher" "a 'launcher invoked' line" ($(if ($run) { $run[0] } else { "no ciscat run in the AR log" })) ([bool]$run)
    if (-not $run) { return }
    foreach ($pattern in @("launcher done, exit code 0", "assessment started in the background", "bootstrap done: installed=", "refused=0", "from ciscat-params", "running CIS-CAT", "SUCCESS: flatten written", "=== done")) {
        $hit = $run | Where-Object { $_ -match [regex]::Escape($pattern) } | Select-Object -Last 1
        Check "P2" "step: $pattern" $pattern ($(if ($hit) { $hit } else { "not in this run" })) ([bool]$hit)
    }
    $run | Where-Object { $_ -match 'ERROR|WARNING|ABORTED' } | ForEach-Object { Info "P2" $_ }
    foreach ($b in @(Benchmarks)) {
        $flat = Join-Path $Results "$($b.FlatName).ciscat-flat"
        if (Test-Path -LiteralPath $flat) {
            $f = Get-Item -LiteralPath $flat
            $lines = @(Get-Content -LiteralPath $flat)
            $pass = @($lines | Where-Object { $_ -match ':pass$' }).Count
            $fail = @($lines | Where-Object { $_ -match ':fail$' }).Count
            Check "P3" "results of $($b.Os) written by this run" ("after {0:yyyy-MM-dd HH:mm:ss}" -f $t) ("{0:yyyy-MM-dd HH:mm:ss}  pass={1} fail={2}" -f $f.LastWriteTime, $pass, $fail) ($t -and $f.LastWriteTime -ge $t -and $lines.Count -gt 0)
        } else {
            Check "P3" "results of $($b.Os) written by this run" $flat "missing" $false
        }
    }
    $sca = @(Get-Content -LiteralPath $OssecLog -Tail 2000 | Where-Object { $_ -match 'sca' } | Select-Object -Last 8)
    $scanned = @($sca | Where-Object { (LineTime ($_ -replace '/', '-')) -ge $t -and $_ -match 'Evaluation finished|Security Configuration Assessment scan finished|Starting evaluation' })
    Check "P4" "SCA re-read the results after the run" "an SCA scan in ossec.log after the run" ($(if ($scanned) { $scanned[$scanned.Count - 1] } else { "no SCA scan since the run (every 1h with the bridge; restart the agent to scan now)" })) ([bool]$scanned) $true
    $sca | ForEach-Object { Info "P4" $_ }
}

switch ($Step) { "Pre" { Pre } "Watch" { Watch } "Post" { Post } }
Write-Host ("`nSUMMARY: PASS={0} FAIL={1} WAIT={2}" -f $script:n.PASS, $script:n.FAIL, $script:n.WAIT)
