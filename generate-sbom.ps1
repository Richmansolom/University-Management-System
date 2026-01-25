param(
  [string]$ImageName = "ums-cpp-app",
  [string]$ImageTag  = "1.0",
  [string]$SbomDir   = "sbom"
)

$ErrorActionPreference = "Stop"

function Assert-Command($cmd) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
    throw "Missing required command: $cmd"
  }
}

Assert-Command docker

# Paths
$repoRoot = Get-Location
$sbomPath = Join-Path $repoRoot $SbomDir
if (-not (Test-Path $sbomPath)) { New-Item -ItemType Directory -Path $sbomPath | Out-Null }

$rawSbom      = Join-Path $sbomPath "sbom-cyclonedx.json"
$enrichedSbom = Join-Path $sbomPath "sbom-enriched.json"
$appMeta      = Join-Path $repoRoot "app-metadata.json"
$mergeScript  = Join-Path $repoRoot "merge-sbom.ps1"

if (-not (Test-Path $appMeta)) { throw "❌ Missing app-metadata.json in repo root." }
if (-not (Test-Path $mergeScript)) { throw "❌ Missing merge-sbom.ps1 in repo root." }

$image = "$ImageName`:$ImageTag"

Write-Host "==> Building Docker image: $image"
docker build -t $image . | Out-Host

Write-Host "==> Pulling Syft (COTS SBOM tool)"
docker pull anchore/syft:latest | Out-Host

Write-Host "==> Generating raw CycloneDX SBOM from image"
docker run --rm `
  -v /var/run/docker.sock:/var/run/docker.sock `
  anchore/syft:latest $image -o cyclonedx-json > $rawSbom

Write-Host "✅ Raw SBOM saved: $rawSbom"

Write-Host "==> Enriching SBOM with custom C++ application metadata"
Write-Host "==> Enriching SBOM with custom C++ application metadata"

powershell -ExecutionPolicy Bypass -File $mergeScript `
  -InputSbom $rawSbom `
  -AppMetadata $appMeta `
  -OutputSbom $enrichedSbom

if (-not (Test-Path $enrichedSbom)) {
  throw "❌ Enrichment failed: sbom-enriched.json was not created."
}

Write-Host "✅ Enriched SBOM written to $enrichedSbom"

Write-Host "==> Validating SBOMs with CycloneDX-CLI (validator)"
docker pull cyclonedx/cyclonedx-cli:latest | Out-Host

docker run --rm -v "${sbomPath}:/data" cyclonedx/cyclonedx-cli:latest validate --input-file /data/sbom-cyclonedx.json | Out-Host
docker run --rm -v "${sbomPath}:/data" cyclonedx/cyclonedx-cli:latest validate --input-file /data/sbom-enriched.json | Out-Host


Write-Host ""
Write-Host "✅ Done."
Write-Host "   Raw SBOM:      $rawSbom"
Write-Host "   Enriched SBOM: $enrichedSbom"
