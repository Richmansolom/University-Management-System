param(
  [string]$PqAlgorithm = "mldsa87",
  [string]$OutputDir = "sbom-signing/pq-keys",
  [string]$OpenSslPath = "openssl",
  [string[]]$OpenSslProviderArgs = @("-provider","oqsprovider","-provider","default"),
  [string]$Digest = "sha512"
)

$ErrorActionPreference = "Stop"

function Assert-Command($cmd) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
    throw "Missing required command: $cmd"
  }
}

function Ensure-Dir([string]$path) {
  if (-not (Test-Path $path)) {
    New-Item -ItemType Directory -Path $path | Out-Null
  }
}

Assert-Command $OpenSslPath
Ensure-Dir $OutputDir

$keyPath = Join-Path $OutputDir "sbom-pq.key"
$pubPath = Join-Path $OutputDir "sbom-pq.pub"

& $OpenSslPath genpkey -algorithm $PqAlgorithm @OpenSslProviderArgs -out $keyPath | Out-Null
& $OpenSslPath pkey @OpenSslProviderArgs -in $keyPath -pubout -out $pubPath | Out-Null

$keyB64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($keyPath))
$pubB64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($pubPath))

Write-Host "✅ PQ signing keys generated:"
Write-Host "   Private key: $keyPath"
Write-Host "   Public key:  $pubPath"
Write-Host ""
Write-Host "Add these GitLab CI variables:"
Write-Host "SIGNING_METHOD=pq"
Write-Host "SBOM_PQ_KEY_B64=$keyB64"
Write-Host "SBOM_PQ_PUB_B64=$pubB64"
Write-Host "PQ_SIGNING_ALGO=urn:nist:alg:ml-dsa-87"
Write-Host "PQ_SIGNING_DIGEST=$Digest"
