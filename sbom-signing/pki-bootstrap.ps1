param(
  [string]$OutputDir = "sbom-signing/pki",
  [ValidateSet("cnsa1-rsa3072","cnsa1-p384","cnsa2-pq")]
  [string]$Profile = "cnsa1-rsa3072",
  [ValidateSet("sha384","sha512")]
  [string]$Digest = "sha384",
  [string]$PqAlgorithm,
  [string[]]$OpenSslProviderArgs = @(),
  [string]$OpenSslPath = "openssl",
  [string]$OrgName = "University SBOM CA",
  [string]$RootCommonName = "UMS SBOM Root CA",
  [string]$IntermediateCommonName = "UMS SBOM Intermediate CA",
  [string]$SignerCommonName = "UMS SBOM Signing"
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

Assert-Command $OpenSslPath

Ensure-Dir $OutputDir
$rootDir = Join-Path $OutputDir "root"
$intDir = Join-Path $OutputDir "intermediate"
$leafDir = Join-Path $OutputDir "signer"
Ensure-Dir $rootDir
Ensure-Dir $intDir
Ensure-Dir $leafDir

function New-Key([string]$path) {
  if ($Profile -eq "cnsa1-rsa3072") {
    & $OpenSslPath genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out $path | Out-Null
  } elseif ($Profile -eq "cnsa1-p384") {
    & $OpenSslPath genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve -out $path | Out-Null
  } else {
    if (-not $PqAlgorithm) {
      throw "PqAlgorithm is required for cnsa2-pq (ex: mldsa87)."
    }
    & $OpenSslPath genpkey -algorithm $PqAlgorithm @OpenSslProviderArgs -out $path | Out-Null
  }
}

function New-Cert(
  [string]$keyPath,
  [string]$certPath,
  [string]$subject,
  [string]$extSection,
  [string]$extContent,
  [string]$days,
  [string]$issuerKey,
  [string]$issuerCert
) {
  $csr = [System.IO.Path]::ChangeExtension($certPath, ".csr")
  $extFile = Get-TempFilePath "ext"
  Write-Utf8NoBom -path $extFile -content $extContent

  & $OpenSslPath req -new -key $keyPath -subj $subject -out $csr | Out-Null
  if ($issuerKey -and $issuerCert) {
    & $OpenSslPath x509 -req -in $csr -CA $issuerCert -CAkey $issuerKey -CAcreateserial -out $certPath -days $days "-$Digest" -extfile $extFile -extensions $extSection | Out-Null
  } else {
    & $OpenSslPath req -x509 -new -key $keyPath -subj $subject -out $certPath -days $days "-$Digest" -extfile $extFile -extensions $extSection | Out-Null
  }
  Remove-Item $extFile -Force -ErrorAction SilentlyContinue | Out-Null
  Remove-Item $csr -Force -ErrorAction SilentlyContinue | Out-Null
}

$rootKey = Join-Path $rootDir "root-ca.key"
$rootCert = Join-Path $rootDir "root-ca.crt"
$intKey = Join-Path $intDir "intermediate-ca.key"
$intCert = Join-Path $intDir "intermediate-ca.crt"
$leafKey = Join-Path $leafDir "sbom-signer.key"
$leafCert = Join-Path $leafDir "sbom-signer.crt"

New-Key $rootKey
$extRoot = @"
[ v3_ca ]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
"@
New-Cert $rootKey $rootCert "/O=$OrgName/CN=$RootCommonName" "v3_ca" $extRoot "3650" $null $null

New-Key $intKey
$extIntermediate = @"
[ v3_ca ]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
"@
New-Cert $intKey $intCert "/O=$OrgName/CN=$IntermediateCommonName" "v3_ca" $extIntermediate "1825" $rootKey $rootCert

New-Key $leafKey
$extLeaf = @"
[ v3_signing ]
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
"@
New-Cert $leafKey $leafCert "/O=$OrgName/CN=$SignerCommonName" "v3_signing" $extLeaf "365" $intKey $intCert

Write-Host "✅ PKI bootstrap complete:"
Write-Host "   Root CA:        $rootCert"
Write-Host "   Intermediate:   $intCert"
Write-Host "   SBOM Signer:    $leafCert"
