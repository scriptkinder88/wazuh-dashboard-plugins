<#
  ciscat-assessment.ps1  (AGENT side, Windows)

  Invoked by Active Response via the ciscat-assessment.cmd launcher (AR on Windows
  cannot run .ps1 directly). Performs the full agent-side assessment:
    1. move the pushed files (custom XCCDF + benchmark + OVAL) from the Wazuh shared
       folder to the CIS-CAT benchmarks/ folder
    2. run CIS-CAT with the tailored profile
    3. flatten the latest CSV report into results/
  Steps 2 and 3 run for every benchmark of the agent (one ciscat-params-<os>.txt per OS group).
  It does NOT copy the SCA policy (that is loaded from shared/ by the agent config).

  DEFENSIVE BY DESIGN: verifies every precondition before acting, logs every step to
  active-responses.log, and stops cleanly on any problem (no half state). This matters
  because Active Response runs this as SYSTEM, a different context from an interactive user.

  All log lines are prefixed so they are greppable in:
    C:\Program Files (x86)\ossec-agent\active-response\active-responses.log
#>

param(
    [string]$Ciscat   = "C:\Program Files (x86)\ciscat",
    [string]$SharedDir = "C:\Program Files (x86)\ossec-agent\shared",
    [string]$Profile  = "xccdf_org.cisecurity.benchmarks_profile_TAILORED_Level_1_-_Member_Server",
    [string]$FlatName = "cis_win2025_v2.0.0",
    # the custom benchmark file name as pushed into shared/ (must match what the manager dropped)
    [string]$CustomXccdf = ""
)

$ErrorActionPreference = "Stop"
$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

function Log($msg) {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "$ts ciscat-assessment: $msg"
    try { Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue } catch {}
    # to the host, not the pipeline: functions return their result through the pipeline
    Write-Host $line
}

function Fail($msg) {
    Log "ERROR: $msg"
    Log "ABORTED (no assessment run)."
    exit 1
}

Log "=== start (running as $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)) ==="

# Benchmarks of this agent: one ciscat-params-<os>.txt per OS group it belongs to (Key=Value
# lines published by the manager), or the single ciscat-params.txt of an older manager. They
# run one after the other. Parameters given on the command line run that one benchmark only.
$defaults = @{ Profile = $Profile; FlatName = $FlatName; CustomXccdf = $CustomXccdf }

function Read-Params($file) {
    $set = @{ Source = $file.Name }
    foreach ($line in Get-Content -Path $file.FullName -ErrorAction SilentlyContinue) {
        if ($line -match '^\s*(Profile|FlatName|CustomXccdf)\s*=\s*(.+?)\s*$') {
            $name = $Matches[1]
            $value = $Matches[2]
            # file names only: the values are joined to the CIS-CAT folders below
            if ($name -ne "Profile" -and $value -notmatch '^[A-Za-z0-9._-]+$') {
                Log "ignored in $($file.Name) (not a file name): $name=$value"
                continue
            }
            $set[$name] = $value
            Log "from $($file.Name): $name=$value"
        }
    }
    foreach ($k in $defaults.Keys) { if (-not $set.ContainsKey($k)) { $set[$k] = $defaults[$k] } }
    return $set
}

$runs = @()
$given = @("Profile", "FlatName", "CustomXccdf") | Where-Object { $PSBoundParameters.ContainsKey($_) }
if ($given) {
    $runs += @{ Source = "command line"; Profile = $Profile; FlatName = $FlatName;
                CustomXccdf = $CustomXccdf }
} else {
    $files = @(Get-ChildItem -Path $SharedDir -Filter "ciscat-params-*.txt" -ErrorAction SilentlyContinue |
               Sort-Object Name)
    if (-not $files) {
        $files = @(Get-ChildItem -Path $SharedDir -Filter "ciscat-params.txt" -ErrorAction SilentlyContinue)
    }
    foreach ($f in $files) { $runs += Read-Params $f }
    if (-not $runs) {
        $runs += @{ Source = "defaults"; Profile = $Profile; FlatName = $FlatName;
                    CustomXccdf = $CustomXccdf }
    }
}

# --- Precondition checks (verify before acting) ---
$assessor = Join-Path $Ciscat "Assessor-CLI.bat"
$benchDir = Join-Path $Ciscat "benchmarks"
$reportDir = Join-Path $Ciscat "reports"
$resultDir = Join-Path $Ciscat "results"
$flatScript = Join-Path $Ciscat "CISCAT-CsvToFlat.ps1"

# CIS-CAT Pro itself is licensed software provisioned on each agent, never
# distributed by the manager. Without it, stop here: withdraw the previous
# results so SCA stops reporting them as current (the policy requires the
# flatten file), and log the message the manager rule ciscat_rules.xml alerts on.
if (-not (Test-Path $assessor)) {
    foreach ($run in $runs) {
        $oldFlat = Join-Path $resultDir "$($run.FlatName).ciscat-flat"
        if (Test-Path $oldFlat) {
            Move-Item -Force -Path $oldFlat -Destination "$oldFlat.stale" -ErrorAction SilentlyContinue
        }
    }
    Fail "CIS-CAT Pro not found on $([Environment]::MachineName): $assessor is missing. Assessment stopped; previous results withdrawn from SCA."
}
if (-not (Test-Path $flatScript)) { Fail "flatten script not found: $flatScript" }
if (-not (Test-Path $benchDir))   { Fail "benchmarks folder not found: $benchDir" }
foreach ($d in @($reportDir, $resultDir)) {
    if (-not (Test-Path $d)) {
        Log "creating missing folder: $d"
        New-Item -ItemType Directory -Force -Path $d | Out-Null
    }
}

# --- Step 1: copy pushed content from shared/ to benchmarks/ ---
# The manager pushes into shared/ the custom XCCDF (*-custom.xml) and the benchmark's OVAL and
# CPE files (*-oval.xml, *-cpe-oval.xml, *-cpe-dictionary.xml). Only those are copied: shared/
# also holds the files of the agent's other groups.
if (Test-Path $SharedDir) {
    $xmls = Get-ChildItem -Path $SharedDir -Filter *.xml -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '(-custom|-oval|-cpe-dictionary)\.xml$' }
    if ($xmls) {
        foreach ($f in $xmls) {
            $dest = Join-Path $benchDir $f.Name
            try {
                Copy-Item -Path $f.FullName -Destination $dest -Force
                Log "copied to benchmarks: $($f.Name)"
            } catch {
                Fail "could not copy $($f.Name) to benchmarks: $($_.Exception.Message)"
            }
        }
    } else {
        Log "no .xml found in shared/ (assuming benchmarks already in place)"
    }
} else {
    Log "shared dir not found ($SharedDir); assuming benchmarks already in place"
}

# --- Steps 2 and 3, per benchmark: run CIS-CAT with the tailored profile, flatten its report ---
# Returns $true when the flatten file of the benchmark was written by this run.
function Invoke-Benchmark($run) {
    Log "--- benchmark from $($run.Source): $($run.FlatName) ---"
    $custom = $run.CustomXccdf
    # If CustomXccdf not given, try to find a *-custom.xml in benchmarks/ (the tailored one).
    if ([string]::IsNullOrEmpty($custom)) {
        $cand = Get-ChildItem -Path $benchDir -Filter *custom*.xml -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime | Select-Object -Last 1
        if (-not $cand) {
            Log "ERROR: no custom benchmark (*custom*.xml) found in $benchDir and none provided"
            return $false
        }
        $custom = $cand.FullName
        Log "auto-selected custom benchmark: $($cand.Name)"
    } elseif (-not (Test-Path $custom)) {
        # if a bare name was passed, resolve it inside benchmarks/
        $maybe = Join-Path $benchDir $custom
        if (-not (Test-Path $maybe)) { Log "ERROR: custom benchmark not found: $custom"; return $false }
        $custom = $maybe
    }

    Log "running CIS-CAT: -b `"$custom`" -p `"$($run.Profile)`""
    $runStart = Get-Date
    # With "Stop", Windows PowerShell 5.1 turns any line the Assessor writes to stderr into a
    # terminating error; its exit code is checked instead.
    $ErrorActionPreference = "Continue"
    try {
        & $assessor -b "$custom" -p "$($run.Profile)" -nts -csv -rd "$reportDir" 2>&1 |
            ForEach-Object { Log "  ciscat> $_" }
        $assessorExit = $LASTEXITCODE
    } catch {
        Log "ERROR: CIS-CAT execution failed: $($_.Exception.Message)"
        return $false
    } finally {
        $ErrorActionPreference = "Stop"
    }
    if ($assessorExit -ne 0) { Log "WARNING: CIS-CAT exited with code $assessorExit" }

    # Only a report written by this run: an older one would be reported as new results.
    $latestCsv = Get-ChildItem -Path (Join-Path $reportDir "*.csv") -ErrorAction SilentlyContinue |
                 Where-Object { $_.LastWriteTime -ge $runStart } |
                 Sort-Object LastWriteTime | Select-Object -Last 1
    if (-not $latestCsv) {
        Log "ERROR: no CSV report produced in $reportDir by this run (assessment failed?)"
        return $false
    }
    Log "flattening report: $($latestCsv.Name)"
    try {
        & $flatScript -CsvPath $latestCsv.FullName -FlatName $run.FlatName -OutDir $resultDir 2>&1 |
            ForEach-Object { Log "  flatten> $_" }
    } catch {
        Log "ERROR: flatten failed: $($_.Exception.Message)"
        return $false
    }
    $flatFile = Join-Path $resultDir "$($run.FlatName).ciscat-flat"
    if (-not (Test-Path $flatFile)) {
        Log "ERROR: flatten file not found after run: $flatFile"
        return $false
    }
    Log "SUCCESS: flatten written -> $flatFile"
    return $true
}

$failed = 0
foreach ($run in $runs) {
    if (-not (Invoke-Benchmark $run)) { $failed++ }
}
if ($failed) {
    Log "ABORTED: $failed of $($runs.Count) benchmark(s) failed."
    exit 1
}
Log "=== done ($($runs.Count) benchmark(s)) ==="
exit 0
