# ==========================================================
# Nessus Patch Validation Report
# ==========================================================

# File Locations

$BeforeCsv = "Enter file path here"
$AfterCsv  = "Enter file path here"

$TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"

$SummaryCsv   = "Where you want your summary csv placed\PatchSummary_$TimeStamp.csv"
$MitigatedCsv = "Where you want your mitigated cve file placed\MitigatedFindings_$TimeStamp.csv"
$NewCsv       = "Where you want your new cves that were discovered between scan dates placed\NewFindings_$TimeStamp.csv"

# ==========================================================
# Load CSV Files
# ==========================================================

$Before = Import-Csv $BeforeCsv
$After  = Import-Csv $AfterCsv

# ==========================================================
# Exclude Informational Plugins
# ==========================================================

$ExcludedPluginIDs = @(
    "19506",   # Nessus Scan Information
    "22964",   # Service Detection
    "24270",   # WMI Information
    "24272",   # Windows Version
    "45590",   # Common Platform Enumeration
    "84239",   # Debugging Log Report
    "34220"    # Netstat Portscanner (WMI)
)

$Before = $Before | Where-Object {
    $_.'Plugin ID' -notin $ExcludedPluginIDs -and
    $_.Name -notlike "*Debugging Log Report*"
}

$After = $After | Where-Object {
    $_.'Plugin ID' -notin $ExcludedPluginIDs -and
    $_.Name -notlike "*Debugging Log Report*"
}

# ==========================================================
# Build Lookup Tables
# ==========================================================

$BeforeKeys = @{}
$AfterKeys = @{}

foreach ($Item in $Before) {

    if ($Item.CVE -and $Item.CVE.Trim() -ne "") {
        $Key = "$($Item.Host)|$($Item.'Plugin ID')|$($Item.CVE)"
    }
    else {
        $Key = "$($Item.Host)|$($Item.'Plugin ID')"
    }

    $BeforeKeys[$Key] = $true
}

foreach ($Item in $After) {

    if ($Item.CVE -and $Item.CVE.Trim() -ne "") {
        $Key = "$($Item.Host)|$($Item.'Plugin ID')|$($Item.CVE)"
    }
    else {
        $Key = "$($Item.Host)|$($Item.'Plugin ID')"
    }

    $AfterKeys[$Key] = $true
}

# ==========================================================
# Compare Findings
# ==========================================================

$MitigatedCount = 0
$RemainingCount = 0
$NewCount = 0

foreach ($Key in $BeforeKeys.Keys) {

    if ($AfterKeys.ContainsKey($Key)) {
        $RemainingCount++
    }
    else {
        $MitigatedCount++
    }
}

foreach ($Key in $AfterKeys.Keys) {

    if (-not $BeforeKeys.ContainsKey($Key)) {
        $NewCount++
    }
}

$TotalBefore = $BeforeKeys.Count
$TotalAfter  = $AfterKeys.Count

# ==========================================================
# Patch Percentage
# ==========================================================

if ($TotalBefore -gt 0)
{
    $PatchPercent = (($MitigatedCount * 100.0) / $TotalBefore)
}
else
{
    $PatchPercent = 0
}

$PatchPercent = "{0:N2}" -f $PatchPercent

# ==========================================================
# Export Summary CSV
# ==========================================================

$Summary = [PSCustomObject]@{
    RunDate            = Get-Date
    BeforeFindings     = $TotalBefore
    AfterFindings      = $TotalAfter
    MitigatedFindings  = $MitigatedCount
    RemainingFindings  = $RemainingCount
    NewFindings        = $NewCount
    PatchPercent       = $PatchPercent
}

$Summary | Export-Csv $SummaryCsv -NoTypeInformation

# ==========================================================
# Export Mitigated Findings
# ==========================================================

$Before |
Where-Object {
    $Key = if ($_.CVE -and $_.CVE.Trim() -ne "") {
        "$($_.Host)|$($_.'Plugin ID')|$($_.CVE)"
    }
    else {
        "$($_.Host)|$($_.'Plugin ID')"
    }

    -not $AfterKeys.ContainsKey($Key)
} |
Export-Csv $MitigatedCsv -NoTypeInformation

# ==========================================================
# Export New Findings
# ==========================================================

$After |
Where-Object {
    $Key = if ($_.CVE -and $_.CVE.Trim() -ne "") {
        "$($_.Host)|$($_.'Plugin ID')|$($_.CVE)"
    }
    else {
        "$($_.Host)|$($_.'Plugin ID')"
    }

    -not $BeforeKeys.ContainsKey($Key)
} |
Export-Csv $NewCsv -NoTypeInformation

# ==========================================================
# Console Output
# ==========================================================

Write-Host ""
Write-Host "========== PATCH VALIDATION ==========" -ForegroundColor Cyan
Write-Host ""

Write-Host "Before Findings : $TotalBefore"
Write-Host "After Findings  : $TotalAfter"

Write-Host ""
Write-Host "Mitigated       : $MitigatedCount" -ForegroundColor Green
Write-Host "Remaining       : $RemainingCount" -ForegroundColor Yellow
Write-Host "New Findings    : $NewCount" -ForegroundColor Red

Write-Host ""
Write-Host "Patch %         : $PatchPercent"

Write-Host ""
Write-Host "Summary CSV     : $SummaryCsv" -ForegroundColor Cyan
Write-Host "Mitigated CSV   : $MitigatedCsv" -ForegroundColor Green
Write-Host "New Findings CSV: $NewCsv" -ForegroundColor Red
