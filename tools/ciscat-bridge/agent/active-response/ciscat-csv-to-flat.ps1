# ciscat-csv-to-flat.ps1 (AGENT side, Windows): CIS-CAT CSV report -> SCA flatten file + manual
# list. Published by the manager in the OS group and installed by ciscat-bootstrap.ps1.
# Produces:
#   <OutDir>\<FlatName>.ciscat-flat    one line per scored control: <rule>:<pass|fail>
#   <OutDir>\<FlatName>.ciscat-manual  controls not auto-evaluated (manual/error/unknown) + anomalies
# Summary rows (Total.../Actual Pass...) and malformed rows are discarded.
#
# CIS-CAT CSV is headerless (include.csv.headers=false), 15 columns.
# col 11 = rule number (short, e.g. 1.2.3), col 13 = result, col 12 = title.

param(
    [Parameter(Mandatory=$true)][string]$CsvPath,
    [Parameter(Mandatory=$true)][string]$FlatName,   # e.g. cis_win2025_v2.0.0  (benchmark key)
    [string]$OutDir = "C:\CIS\results"
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path $CsvPath)) { throw "CSV not found: $CsvPath" }
New-Item -ItemType Directory -Force $OutDir | Out-Null
$flatPath   = Join-Path $OutDir "$FlatName.ciscat-flat"
$manualPath = Join-Path $OutDir "$FlatName.ciscat-manual"

$rows = Import-Csv $CsvPath -Header (0..14 | ForEach-Object { "c$_" })

$flat   = New-Object System.Collections.Generic.List[string]
$manual = New-Object System.Collections.Generic.List[string]
$n_pass = 0; $n_fail = 0; $n_manual = 0; $n_summary = 0; $n_malformed = 0

foreach ($r in $rows) {
    $rule   = $r.c11
    $result = if ($r.c13) { $r.c13.Trim().ToLower() } else { "" }
    $title  = $r.c12
    if (-not $rule -or $rule -notmatch '^\d+(\.\d+)*$') {
        # A row without a numeric rule id is either a CIS-CAT summary line (expected:
        # "Total,Pass: ...", "Actual Pass: ...,Score: ...") or genuinely malformed (which
        # would mean a real control was lost). Distinguish them so the log is self-documenting
        # for audit: summary is benign, malformed>0 must be investigated.
        $firstField = if ($rule) { $rule } elseif ($r.c1) { $r.c1 } else { "" }
        if ($firstField -match '^(Total|Actual Pass)') { $n_summary++ }
        else { $n_malformed++; $manual.Add(("MALFORMED`t{0}" -f (($r.PSObject.Properties.Value) -join ','))) }
        continue
    }
    switch ($result) {
        "pass" { $flat.Add("$($rule):pass"); $n_pass++ }
        "fail" { $flat.Add("$($rule):fail"); $n_fail++ }
        default {
            $manual.Add(("{0}`t{1}`t{2}" -f $rule, $result, $title))
            $n_manual++
        }
    }
}

$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($flatPath,   ($flat   -join "`n") + "`n", $utf8)
[System.IO.File]::WriteAllText($manualPath, ($manual -join "`n") + "`n", $utf8)

Write-Output "[+] Flatten : $flatPath"
Write-Output "[+] Manual  : $manualPath"
Write-Output "[+] pass=$n_pass  fail=$n_fail  manual/other=$n_manual  summary=$n_summary  malformed=$n_malformed"
if ($n_malformed -gt 0) {
    Write-Output "[!] WARNING: $n_malformed malformed row(s) - real controls may have been lost. See $manualPath (MALFORMED lines)."
}
Write-Output "[+] flatten lines = $($flat.Count)  (expected = pass+fail)"
