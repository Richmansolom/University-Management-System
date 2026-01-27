param(
  [Parameter(Mandatory = $true)]
  [string]$InputSbom,
  [Parameter(Mandatory = $true)]
  [string]$OutputSbom,
  [ValidateSet("openssl","gpg")]
  [string]$Signer = "openssl",
  [string]$Algorithm = "RS384",
  [ValidateSet("sha384","sha512")]
  [string]$Digest = "sha384",
  [string]$KeyPath,
  [string]$KeyId,
  [string]$GpgKeyId,
  [string]$OpenSslPath = "openssl",
  [string[]]$OpenSslProviderArgs = @()
)

$ErrorActionPreference = "Stop"
$algoProvided = $PSBoundParameters.ContainsKey("Algorithm")

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

function To-Base64Url([byte[]]$bytes) {
  $b64 = [System.Convert]::ToBase64String($bytes)
  return $b64.Replace('+','-').Replace('/','_').TrimEnd('=')
}

if (-not (Test-Path $InputSbom)) {
  throw "SBOM file not found: $InputSbom"
}

$sbom = Get-Content $InputSbom -Raw | ConvertFrom-Json
if ($sbom.PSObject.Properties.Name -contains "signature") {
  $sbom.PSObject.Properties.Remove("signature")
}

$payloadJson = $sbom | ConvertTo-Json -Depth 100 -Compress
$payloadFile = Get-TempFilePath "json"
$sigFile = Get-TempFilePath "sig"
Write-Utf8NoBom -path $payloadFile -content $payloadJson

if ($Signer -eq "openssl") {
  if (-not $KeyPath) {
    throw "KeyPath is required for openssl signing."
  }
  $openssl = Get-Command $OpenSslPath -ErrorAction SilentlyContinue
  if (-not $openssl) {
    throw "OpenSSL not found: $OpenSslPath"
  }

  & $openssl dgst "-$Digest" @OpenSslProviderArgs -sign $KeyPath -out $sigFile $payloadFile | Out-Null
} else {
  $gpg = Get-Command gpg -ErrorAction SilentlyContinue
  if (-not $gpg) {
    throw "gpg not found in PATH."
  }
  if (-not $algoProvided) {
    $Algorithm = "urn:openpgp:rsa3072"
  }
  $gpgArgs = @("--batch","--yes","--detach-sign","--output",$sigFile)
  if ($GpgKeyId) {
    $gpgArgs += @("--local-user",$GpgKeyId)
  }
  $gpgArgs += $payloadFile
  & $gpg @gpgArgs | Out-Null
}

$sigBytes = [System.IO.File]::ReadAllBytes($sigFile)
$sigValue = To-Base64Url $sigBytes

$signature = [ordered]@{
  algorithm = $Algorithm
  value = $sigValue
  excludes = @("signature")
}
if ($KeyId) {
  $signature.keyId = $KeyId
} elseif ($Signer -eq "gpg" -and $GpgKeyId) {
  $signature.keyId = $GpgKeyId
}

$sbom.signature = $signature
$outputJson = $sbom | ConvertTo-Json -Depth 100
Write-Utf8NoBom -path $OutputSbom -content $outputJson

Remove-Item $payloadFile, $sigFile -Force -ErrorAction SilentlyContinue | Out-Null

Write-Host "✅ Signed SBOM written to $OutputSbom"
