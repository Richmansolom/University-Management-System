param(
  [string]$InputJson = "reports/grype-report.json",
  [string]$OutputText = "reports/vulnerability-analysis.txt"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $InputJson)) {
  throw "Missing Grype report: $InputJson"
}

$data = Get-Content $InputJson -Raw | ConvertFrom-Json
$matches = @($data.matches)
$severities = @("Critical","High","Medium","Low","Negligible","Unknown")
$counts = @{}
foreach ($s in $severities) { $counts[$s] = 0 }

foreach ($m in $matches) {
  $sev = $m.vulnerability.severity
  if ([string]::IsNullOrWhiteSpace($sev)) { $sev = "Unknown" }
  if (-not $counts.ContainsKey($sev)) { $counts[$sev] = 0 }
  $counts[$sev]++
}

$lines = @()
$lines += "Vulnerability Analysis Summary"
$lines += "=============================="
$lines += "Total: $($matches.Count)"
foreach ($s in $severities) {
  $lines += "${s}: $($counts[$s])"
}
$lines += ""
$lines += "Top Findings (up to 10):"
foreach ($m in ($matches | Select-Object -First 10)) {
  $lines += "$($m.vulnerability.id) | $($m.vulnerability.severity) | $($m.artifact.name) $($m.artifact.version)"
}

[System.IO.File]::WriteAllText($OutputText, ($lines -join "`n"))
Write-Host "✅ Wrote vulnerability summary to $OutputText"
