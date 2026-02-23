param(
  [Parameter(Mandatory=$true)]
  [string]$InputSbom,

  [Parameter(Mandatory=$true)]
  [string]$OutputSbom
)

$ErrorActionPreference = "Stop"

function Write-Utf8NoBom([string]$path, [string]$content) {
  [System.IO.File]::WriteAllText(
    $path,
    $content,
    (New-Object System.Text.UTF8Encoding $false)
  )
}

function Ensure-PropertiesArray($component) {
  if (-not ($component.PSObject.Properties.Name -contains "properties")) {
    $component | Add-Member -MemberType NoteProperty -Name properties -Value @()
    return
  }
  if ($component.properties -is [string] -or -not ($component.properties -is [System.Collections.IEnumerable])) {
    $component.properties = @($component.properties)
  }
}

# Infer supplier from purl for OS/distro packages (Hoppr NTIA requirement)
function Get-DefaultSupplier($component) {
  $purl = [string]$component.purl
  if ([string]::IsNullOrWhiteSpace($purl)) { return "Unknown" }
  if ($purl -match "pkg:deb/ubuntu/") { return "Canonical Ltd." }
  if ($purl -match "pkg:deb/debian/") { return "Debian Project" }
  return "Unknown"
}

# Ensure license entry has Hoppr-required 'licensing' field (CycloneDX optional)
function Ensure-LicensingField($licEntry) {
  if (-not $licEntry.PSObject.Properties.Name -contains "licensing") {
    $licEntry | Add-Member -MemberType NoteProperty -Name licensing -Value @{} -Force
  }
}

function Normalize-ComponentLicenses($component) {
  if (-not $component) { return }

  # Hoppr: add supplier if missing
  if (-not $component.supplier -or -not $component.supplier.name) {
    $supplierName = Get-DefaultSupplier $component
    $component.supplier = @{ name = $supplierName; url = @() }
  }

  # Hoppr: add licenses if missing
  if (-not $component.licenses -or $component.licenses.Count -eq 0) {
    $component.licenses = @(@{ license = @{ name = "unknown" }; licensing = @{} })
    return
  }

  $normalized = @()
  $licenseNames = @()
  foreach ($lic in @($component.licenses)) {
    if ($null -eq $lic) { continue }

    if ($lic -is [string]) {
      $entry = @{ license = @{ name = [string]$lic }; licensing = @{} }
      $normalized += $entry
      $licenseNames += [string]$lic
      continue
    }

    if ($lic.PSObject.Properties.Name -contains "expression") {
      Ensure-LicensingField $lic
      $normalized += $lic
      $licenseNames += [string]$lic.expression
      continue
    }

    $licenseObj = $lic.license
    if ($licenseObj -is [string]) {
      $lic.license = @{ name = [string]$licenseObj }
      $licenseObj = $lic.license
    } elseif (-not $licenseObj) {
      $lic.license = @{ name = "unknown" }
      $licenseObj = $lic.license
    }

    if (-not ($licenseObj.PSObject.Properties.Name -contains "name") -or [string]::IsNullOrWhiteSpace([string]$licenseObj.name)) {
      if ($licenseObj.PSObject.Properties.Name -contains "id") {
        $licenseObj | Add-Member -MemberType NoteProperty -Name name -Value ([string]$licenseObj.id) -Force
      } else {
        $licenseObj | Add-Member -MemberType NoteProperty -Name name -Value "unknown" -Force
      }
    }

    if ($licenseObj.PSObject.Properties.Name -contains "id") {
      $licenseObj.PSObject.Properties.Remove("id")
    }

    Ensure-LicensingField $lic

    if ($licenseObj.name) {
      $licenseNames += [string]$licenseObj.name
    }
    $normalized += $lic
  }

  if ($licenseNames.Count -gt 1) {
    Ensure-PropertiesArray $component
    $component.properties += @{ name = "license.list"; value = ($licenseNames -join ", ") }
    $component.licenses = @(@{ license = @{ name = "Multiple" }; licensing = @{} })
  } else {
    $component.licenses = $normalized
  }
}

if (-not (Test-Path $InputSbom)) { throw "Input SBOM not found: $InputSbom" }
$sbomRaw = Get-Content $InputSbom -Raw
if ([string]::IsNullOrWhiteSpace($sbomRaw)) {
  throw "Input SBOM is empty."
}

$sbom = $sbomRaw | ConvertFrom-Json

# Hoppr: SBOM metadata must have licenses field
if (-not $sbom.metadata) {
  $sbom | Add-Member -MemberType NoteProperty -Name metadata -Value ([ordered]@{}) -Force
}
if (-not $sbom.metadata.licenses -or $sbom.metadata.licenses.Count -eq 0) {
  $sbom.metadata.licenses = @(@{ license = @{ name = "unknown" }; licensing = @{} })
}

foreach ($c in @($sbom.components)) {
  Normalize-ComponentLicenses $c
}

if ($sbom.metadata -and $sbom.metadata.component) {
  Normalize-ComponentLicenses $sbom.metadata.component
}

$sbomJson = $sbom | ConvertTo-Json -Depth 40
Write-Utf8NoBom -path $OutputSbom -content $sbomJson
Write-Host "✅ Normalized SBOM written to $OutputSbom"
