param(
  [ValidateSet("rsa3072","p384")]
  [string]$Profile = "rsa3072",
  [ValidateSet("sha384","sha512")]
  [string]$Digest = "sha384",
  [string]$OutputDir = "sbom-signing/ci-keys",
  [string]$OpenSslPath = "openssl"
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

$keyPath = Join-Path $OutputDir "sbom-signing.key"
$pubPath = Join-Path $OutputDir "sbom-signing.pub"

if ($Profile -eq "rsa3072") {
  & $OpenSslPath genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out $keyPath | Out-Null
} else {
  & $OpenSslPath genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve -out $keyPath | Out-Null
}

& $OpenSslPath pkey -in $keyPath -pubout -out $pubPath | Out-Null

$keyB64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($keyPath))
$pubB64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($pubPath))

Write-Host "✅ CI signing keys generated:"
Write-Host "   Private key: $keyPath"
Write-Host "   Public key:  $pubPath"
Write-Host ""
Write-Host "Add these GitLab CI variables:"
Write-Host "SBOM_SIGNING_KEY_B64=$keyB64"
Write-Host "SBOM_SIGNING_PUB_B64=$pubB64"
Write-Host "SBOM_SIGNING_ALGO=" + ($(if ($Profile -eq "rsa3072") { "RS384" } else { "ES384" }))
Write-Host "SBOM_SIGNING_DIGEST=$Digest"
