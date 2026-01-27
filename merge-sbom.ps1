param(
  [Parameter(Mandatory=$true)]
  [string]$InputSbom,

  [Parameter(Mandatory=$true)]
  [string]$AppMetadata,

  [Parameter(Mandatory=$true)]
  [string]$OutputSbom
)

$ErrorActionPreference = "Stop"

function SafeStr($v) {
  if ($null -eq $v -or [string]::IsNullOrWhiteSpace([string]$v)) { return "unknown" }
  return [string]$v
}

function Write-Utf8NoBom([string]$path, [string]$content) {
  [System.IO.File]::WriteAllText(
    $path,
    $content,
    (New-Object System.Text.UTF8Encoding $false)
  )
}

# --- Load inputs ---
if (-not (Test-Path $InputSbom)) { throw "Input SBOM not found: $InputSbom" }
if (-not (Test-Path $AppMetadata)) { throw "App metadata not found: $AppMetadata" }

$sbomRaw = Get-Content $InputSbom -Raw
if ([string]::IsNullOrWhiteSpace($sbomRaw)) {
  throw "Input SBOM is empty. Check Syft output and Docker access."
}

try {
  $sbom = $sbomRaw | ConvertFrom-Json
} catch {
  $preview = $sbomRaw.Substring(0, [Math]::Min(200, $sbomRaw.Length))
  throw "Input SBOM is not valid JSON. First bytes: $preview"
}

$app  = Get-Content $AppMetadata -Raw | ConvertFrom-Json

# Ensure metadata exists and is writable
if (-not ($sbom.PSObject.Properties.Name -contains "metadata") -or $null -eq $sbom.metadata -or ($sbom.metadata -is [string])) {
  if ($sbom.PSObject.Properties.Name -contains "metadata") {
    $sbom.metadata = [ordered]@{}
  } else {
    $sbom | Add-Member -MemberType NoteProperty -Name metadata -Value ([ordered]@{})
  }
}

# Timestamp (NTIA)
$sbom.metadata.timestamp = (Get-Date).ToString("o")

# Supplier (NTIA) - ensure CycloneDX expects array for url
$supplierName = SafeStr $app.supplier.name
$supplierUrls = @()
foreach ($item in @($app.supplier.url)) {
  if ($null -ne $item -and $item -ne "") {
    $supplierUrls += [string]$item
  }
}
$supplierUrls = [object[]]$supplierUrls
if ($sbom.metadata.PSObject.Properties.Name -contains "supplier") {
  $sbom.metadata.supplier = @{ name = $supplierName; url = $supplierUrls }
} else {
  $sbom.metadata | Add-Member -MemberType NoteProperty -Name supplier -Value @{ name = $supplierName; url = $supplierUrls }
}

# Build a stable bom-ref for the custom app component
$appName    = SafeStr $app.name
$appVersion = SafeStr $app.version
$appBomRef  = "pkg:generic/$($appName)@$($appVersion)"

# --- Custom application component (NTIA: name + version + supplier/publisher) ---
$customComponent = @{
  "bom-ref"   = $appBomRef
  type        = "application"
  name        = $appName
  version     = $appVersion
  description = SafeStr $app.description
  publisher   = $supplierName
  supplier    = @{ name = $supplierName; url = $supplierUrls }
  licenses    = @(@{ license = @{ id = SafeStr $app.license } })
  externalReferences = @(
    @{ type = "vcs"; url = SafeStr $app.repository }
  )
  properties = @(
    @{ name = "language";      value = SafeStr $app.language },
    @{ name = "author";        value = SafeStr $app.author },
    @{ name = "build_system";  value = SafeStr $app.build_system },
    @{ name = "entry_point";   value = SafeStr $app.entry_point },
    @{ name = "source_file";   value = SafeStr $app.source_file }
  )
}

# Ensure components array exists
if (-not $sbom.components) {
  $sbom | Add-Member -MemberType NoteProperty -Name components -Value @()
}

# Add custom component if not already present
$already = $false
foreach ($c in $sbom.components) {
  if ($c.name -eq $appName -and $c.version -eq $appVersion) { $already = $true; break }
}
if (-not $already) {
  $sbom.components += $customComponent
}

# NTIA-friendly: also set metadata.component (top-level product)
$sbom.metadata.component = $customComponent

# --- Dependencies (NTIA) ---
# Create a basic dependency graph: root app depends on all other components that have bom-ref
if (-not $sbom.dependencies) {
  $sbom | Add-Member -MemberType NoteProperty -Name dependencies -Value @()
}

# Ensure every component has bom-ref (Syft usually does, but just in case)
foreach ($c in $sbom.components) {
  if (-not $c.'bom-ref') {
    $c | Add-Member -MemberType NoteProperty -Name 'bom-ref' -Value ("anon:" + [guid]::NewGuid().ToString())
  }
}

$depRefs = @()
foreach ($c in $sbom.components) {
  if ($c.'bom-ref' -ne $appBomRef) {
    $depRefs += $c.'bom-ref'
  }
}

# Replace or add root dependency entry
$rootIndex = -1
for ($i=0; $i -lt $sbom.dependencies.Count; $i++) {
  if ($sbom.dependencies[$i].ref -eq $appBomRef) { $rootIndex = $i; break }
}

$rootDep = @{ ref = $appBomRef; dependsOn = $depRefs }
if ($rootIndex -ge 0) {
  $sbom.dependencies[$rootIndex] = $rootDep
} else {
  $sbom.dependencies += $rootDep
}

# --- Write enriched SBOM ---
$sbomJson = $sbom | ConvertTo-Json -Depth 40
Write-Utf8NoBom -path $OutputSbom -content $sbomJson
Write-Host "✅ Enriched SBOM written to $OutputSbom"
