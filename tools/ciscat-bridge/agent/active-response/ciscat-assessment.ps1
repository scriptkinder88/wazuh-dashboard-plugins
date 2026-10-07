<#
  ciscat-assessment.ps1  (AGENT side, Windows)

  Invoked by Active Response via the ciscat-assessment.cmd launcher (AR on Windows
  cannot run .ps1 directly). Performs the full agent-side assessment:
    1. move the pushed files (custom XCCDF + benchmark + OVAL) from the Wazuh shared
       folder to the CIS-CAT benchmarks/ folder
    2. run CIS-CAT with the tailored profile
    3. flatten the latest CSV report into results/
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
    Write-Output $line
}

function Fail($msg) {
    Log "ERROR: $msg"
    Log "ABORTED (no assessment run)."
    exit 1
}

Log "=== start (running as $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)) ==="

# Per-OS settings published by the manager in the OS group (ciscat-params.txt: Key=Value lines).
# They apply unless the parameter was given on the command line.
$paramsFile = Join-Path $SharedDir "ciscat-params.txt"
if (Test-Path $paramsFile) {
    foreach ($line in Get-Content -Path $paramsFile -ErrorAction SilentlyContinue) {
        if ($line -match '^\s*(Profile|FlatName|CustomXccdf)\s*=\s*(.+?)\s*$') {
            $name = $Matches[1]
            $value = $Matches[2]
            # file names only: the values are joined to the CIS-CAT folders below
            if ($name -ne "Profile" -and $value -notmatch '^[A-Za-z0-9._-]+$') {
                Log "ignored in ciscat-params.txt (not a file name): $name=$value"
                continue
            }
            if (-not $PSBoundParameters.ContainsKey($name)) {
                Set-Variable -Name $name -Value $value
                Log "from ciscat-params.txt: $name=$value"
            }
        }
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
    $oldFlat = Join-Path $resultDir "$FlatName.ciscat-flat"
    if (Test-Path $oldFlat) {
        Move-Item -Force -Path $oldFlat -Destination "$oldFlat.stale" -ErrorAction SilentlyContinue
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

# --- Determine which benchmark file to assess ---
# If CustomXccdf not given, try to find a *-custom.xml in benchmarks/ (the tailored one).
if ([string]::IsNullOrEmpty($CustomXccdf)) {
    $cand = Get-ChildItem -Path $benchDir -Filter *custom*.xml -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime | Select-Object -Last 1
    if ($cand) { $CustomXccdf = $cand.FullName; Log "auto-selected custom benchmark: $($cand.Name)" }
    else { Fail "no custom benchmark (*custom*.xml) found in $benchDir and none provided" }
} elseif (-not (Test-Path $CustomXccdf)) {
    # if a bare name was passed, resolve it inside benchmarks/
    $maybe = Join-Path $benchDir $CustomXccdf
    if (Test-Path $maybe) { $CustomXccdf = $maybe }
    else { Fail "custom benchmark not found: $CustomXccdf" }
}

# --- Step 2: run CIS-CAT with the tailored profile ---
Log "running CIS-CAT: -b `"$CustomXccdf`" -p `"$Profile`""
$runStart = Get-Date
# With "Stop", Windows PowerShell 5.1 turns any line the Assessor writes to stderr into a
# terminating error; its exit code is checked instead.
$ErrorActionPreference = "Continue"
try {
    & $assessor -b "$CustomXccdf" -p "$Profile" -nts -csv -rd "$reportDir" 2>&1 |
        ForEach-Object { Log "  ciscat> $_" }
    $assessorExit = $LASTEXITCODE
} catch {
    Fail "CIS-CAT execution failed: $($_.Exception.Message)"
} finally {
    $ErrorActionPreference = "Stop"
}
if ($assessorExit -ne 0) { Log "WARNING: CIS-CAT exited with code $assessorExit" }

# --- Step 3: flatten the CSV report of this run ---
# Only a report written by this run: an older one would be reported as new results.
$latestCsv = Get-ChildItem -Path (Join-Path $reportDir "*.csv") -ErrorAction SilentlyContinue |
             Where-Object { $_.LastWriteTime -ge $runStart } |
             Sort-Object LastWriteTime | Select-Object -Last 1
if (-not $latestCsv) { Fail "no CSV report produced in $reportDir by this run (assessment failed?)" }
Log "flattening report: $($latestCsv.Name)"
try {
    & $flatScript -CsvPath $latestCsv.FullName -FlatName $FlatName -OutDir $resultDir 2>&1 |
        ForEach-Object { Log "  flatten> $_" }
} catch {
    Fail "flatten failed: $($_.Exception.Message)"
}

$flatFile = Join-Path $resultDir "$FlatName.ciscat-flat"
if (Test-Path $flatFile) {
    Log "SUCCESS: flatten written -> $flatFile"
    Log "=== done ==="
    exit 0
} else {
    Fail "flatten file not found after run: $flatFile"
}
