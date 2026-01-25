param(
  [Parameter(Mandatory=$true)]
  [string]$InputSbom,

  [Parameter(Mandatory=$true)]
  [string]$AppMetadata,

  [Parameter(Mandatory=$true)]
  [string]$OutputSbom
)

$ErrorActionPreference = "Stop"

Write-Host "DEBUG: InputSbom   = $InputSbom"
Write-Host "DEBUG: AppMetadata = $AppMetadata"
Write-Host "DEBUG: OutputSbom  = $OutputSbom"

# -----------------------------
# Load inputs
# -----------------------------
if (-not (Test-Path $InputSbom)) { throw "❌ Input SBOM not found: $InputSbom" }
if (-not (Test-Path $AppMetadata)) { throw "❌ App metadata not found: $AppMetadata" }

$sbom = Get-Content $InputSbom -Raw | ConvertFrom-Json
$app  = Get-Content $AppMetadata -Raw | ConvertFrom-Json

# -----------------------------
# Helper: force safe strings
# -----------------------------
function SafeStr($v) {
  if ($null -eq $v -or $v -eq "") { return "unknown" }
  return [string]$v
}

# -----------------------------
# Build application component (for components[])
# -----------------------------
$appComponent = @{
  type        = "application"
  name        = SafeStr $app.name
  version     = SafeStr $app.version
  description = SafeStr $app.description
  supplier    = @{
    name = SafeStr $app.supplier.name
    url  = SafeStr $app.supplier.url
  }
  licenses    = @(
    @{ license = @{ id = SafeStr $app.license } }
  )
  externalReferences = @(
    @{
      type = "vcs"
      url  = SafeStr $app.repository
    }
  )
  properties = @(
    @{ name = "language";      value = SafeStr $app.language },
    @{ name = "author";        value = SafeStr $app.author },
    @{ name = "build_system";  value = SafeStr $app.build_system },
    @{ name = "entry_point";   value = SafeStr $app.entry_point },
    @{ name = "source_file";   value = SafeStr $app.source_file }
  )
}

# -----------------------------
# Inject into components[]
# -----------------------------
if (-not $sbom.components) {
  $sbom | Add-Member -MemberType NoteProperty -Name components -Value @()
}

$sbom.components += $appComponent

# -----------------------------
# NTIA COMPLIANCE: Set root metadata.component
# -----------------------------
$rootComponent = @{
  type        = "application"
  name        = SafeStr $app.name
  version     = SafeStr $app.version
  description = SafeStr $app.description
  supplier    = @{
    name = SafeStr $app.supplier.name
    url  = SafeStr $app.supplier.url
  }
  licenses    = @(
    @{ license = @{ id = SafeStr $app.license } }
  )
  externalReferences = @(
    @{
      type = "vcs"
      url  = SafeStr $app.repository
    }
  )
}

# Ensure metadata exists
if (-not $sbom.metadata) {
  $sbom | Add-Member -MemberType NoteProperty -Name metadata -Value @{}
}

# Ensure timestamp exists (NTIA requirement)
if (-not $sbom.metadata.timestamp) {
  $sbom.metadata.timestamp = (Get-Date).ToString("o")
}

# Set root component (NTIA requirement)
$sbom.metadata.component = $rootComponent

# -----------------------------
# Write enriched SBOM
# -----------------------------
Write-Host "DEBUG: About to write enriched SBOM to: $OutputSbom"

$sbom |
  ConvertTo-Json -Depth 30 |
  Set-Content -Path $OutputSbom -Encoding utf8

Write-Host "✅ Enriched SBOM written to $OutputSbom"
