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

function Normalize-ComponentLicenses($component) {
  if (-not $component -or -not $component.licenses) { return }
  $normalized = @()
  $licenseNames = @()
  foreach ($lic in @($component.licenses)) {
    if ($null -eq $lic) { continue }

    if ($lic -is [string]) {
      $normalized += @{ license = @{ name = [string]$lic } }
      $licenseNames += [string]$lic
      continue
    }

    if ($lic.PSObject.Properties.Name -contains "expression") {
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

    if ($licenseObj.name) {
      $licenseNames += [string]$licenseObj.name
    }
    $normalized += $lic
  }

  if ($licenseNames.Count -gt 1) {
    Ensure-PropertiesArray $component
    $component.properties += @{ name = "license.list"; value = ($licenseNames -join ", ") }
    $component.licenses = @(@{ license = @{ name = "Multiple" } })
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

foreach ($c in @($sbom.components)) {
  Normalize-ComponentLicenses $c
}

if ($sbom.metadata -and $sbom.metadata.component) {
  Normalize-ComponentLicenses $sbom.metadata.component
}

$sbomJson = $sbom | ConvertTo-Json -Depth 40
Write-Utf8NoBom -path $OutputSbom -content $sbomJson
Write-Host "✅ Normalized SBOM written to $OutputSbom"
