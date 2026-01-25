param(
    [Parameter(Mandatory = $true)]
    [string]$SbomFile
)

Write-Host "NTIA SBOM Minimum Elements Check"
Write-Host "--------------------------------"

if (-not (Test-Path $SbomFile)) {
    Write-Error "SBOM file not found: $SbomFile"
    exit 1
}

$sbom = Get-Content $SbomFile -Raw | ConvertFrom-Json
$errors = @()

# 1. Supplier
$supplier = $sbom.metadata.component.supplier.name
if ([string]::IsNullOrWhiteSpace($supplier)) {
    $errors += "supplier missing"
} else {
    Write-Host "✔ supplier present"
}

# 2. Name
$name = $sbom.metadata.component.name
if ([string]::IsNullOrWhiteSpace($name)) {
    $errors += "name missing"
} else {
    Write-Host "✔ name present"
}

# 3. Version
$version = $sbom.metadata.component.version
if ([string]::IsNullOrWhiteSpace($version)) {
    $errors += "version missing"
} else {
    Write-Host "✔ version present"
}

# 4. Timestamp
$timestamp = $sbom.metadata.timestamp
if ([string]::IsNullOrWhiteSpace($timestamp)) {
    $errors += "timestamp missing"
} else {
    Write-Host "✔ timestamp present"
}

# 5. Component Type
$type = $sbom.metadata.component.type
if ([string]::IsNullOrWhiteSpace($type)) {
    $errors += "component type missing"
} else {
    Write-Host "✔ component type present"
}

# 6. Dependencies
if (-not $sbom.dependencies -or $sbom.dependencies.Count -eq 0) {
    $errors += "dependencies missing"
} else {
    Write-Host "✔ dependencies present"
}

Write-Host ""

if ($errors.Count -gt 0) {
    Write-Host "FAIL: SBOM does NOT meet NTIA Minimum Elements"
    $errors | ForEach-Object { Write-Host " - $_" }
    exit 1
} else {
    Write-Host "PASS: SBOM meets NTIA Minimum Elements."
    exit 0
}
