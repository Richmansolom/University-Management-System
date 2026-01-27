param(
  [Parameter(Mandatory = $true)]
  [string]$InputSbom,
  [ValidateSet("openssl","gpg")]
  [string]$Signer = "openssl",
  [ValidateSet("sha384","sha512")]
  [string]$Digest = "sha384",
  [string]$PublicKeyPath,
  [string]$CertificatePath,
  [string]$OpenSslPath = "openssl"
)

$ErrorActionPreference = "Stop"

function Get-TempFilePath([string]$extension) {
  $tmp = [System.IO.Path]::GetTempFileName()
  if ($extension) {
    $withExt = [System.IO.Path]::ChangeExtension($tmp, $extension)
    Move-Item -Path $tmp -Destination $withExt -Force | Out-Null
    return $withExt
  }
  return $tmp
}

function Write-Utf8NoBom([string]$path, [string]$content) {
  [System.IO.File]::WriteAllText(
    $path,
    $content,
    (New-Object System.Text.UTF8Encoding $false)
  )
}

function From-Base64Url([string]$value) {
  $pad = 4 - ($value.Length % 4)
  if ($pad -lt 4) {
    $value += ("=" * $pad)
  }
  $b64 = $value.Replace('-','+').Replace('_','/')
  return [System.Convert]::FromBase64String($b64)
}

if (-not (Test-Path $InputSbom)) {
  throw "SBOM file not found: $InputSbom"
}

$sbom = Get-Content $InputSbom -Raw | ConvertFrom-Json
if (-not $sbom.signature) {
  throw "No signature found in SBOM."
}

$signature = $sbom.signature
if (-not $signature.value) {
  throw "Signature value is missing."
}

if ($sbom.PSObject.Properties.Name -contains "signature") {
  $sbom.PSObject.Properties.Remove("signature")
}
if ($signature.excludes) {
  foreach ($name in $signature.excludes) {
    if ($sbom.PSObject.Properties.Name -contains $name) {
      $sbom.PSObject.Properties.Remove($name)
    }
  }
}

$payloadJson = $sbom | ConvertTo-Json -Depth 100 -Compress
$payloadFile = Get-TempFilePath "json"
$sigFile = Get-TempFilePath "sig"
Write-Utf8NoBom -path $payloadFile -content $payloadJson

$sigBytes = From-Base64Url $signature.value
[System.IO.File]::WriteAllBytes($sigFile, $sigBytes)

if ($Signer -eq "openssl") {
  $openssl = Get-Command $OpenSslPath -ErrorAction SilentlyContinue
  if (-not $openssl) {
    throw "OpenSSL not found: $OpenSslPath"
  }

  $pubKey = $PublicKeyPath
  if (-not $pubKey -and $CertificatePath) {
    $pubKey = Get-TempFilePath "pub"
    & $openssl x509 -in $CertificatePath -pubkey -noout > $pubKey
  }
  if (-not $pubKey) {
    throw "PublicKeyPath or CertificatePath is required for openssl verification."
  }

  & $openssl dgst "-$Digest" -verify $pubKey -signature $sigFile $payloadFile | Out-Null
} else {
  $gpg = Get-Command gpg -ErrorAction SilentlyContinue
  if (-not $gpg) {
    throw "gpg not found in PATH."
  }
  & $gpg --verify $sigFile $payloadFile | Out-Null
}

Remove-Item $payloadFile, $sigFile -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "✅ Signature verification passed."
