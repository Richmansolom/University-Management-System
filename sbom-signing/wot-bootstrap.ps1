param(
  [Parameter(Mandatory = $true)]
  [string]$Name,
  [Parameter(Mandatory = $true)]
  [string]$Email,
  [string]$OutputDir = "sbom-signing/wot",
  [ValidateSet("rsa3072")]
  [string]$KeyType = "rsa3072",
  [string]$Expires = "2y"
)

$ErrorActionPreference = "Stop"

function Ensure-Dir([string]$path) {
  if (-not (Test-Path $path)) {
    New-Item -ItemType Directory -Path $path | Out-Null
  }
}

$gpg = Get-Command gpg -ErrorAction SilentlyContinue
if (-not $gpg) {
  throw "gpg not found in PATH."
}

Ensure-Dir $OutputDir
$uid = "$Name <$Email>"

& gpg --batch --yes --quick-gen-key $uid $KeyType sign $Expires | Out-Null

$fprLine = (gpg --list-keys --with-colons $uid | Where-Object { $_ -like "fpr:*" } | Select-Object -First 1)
if (-not $fprLine) {
  throw "Failed to locate GPG fingerprint for $uid"
}

$fingerprint = ($fprLine -split ":")[9]
$pubKeyPath = Join-Path $OutputDir "sbom-wot-public.asc"
& gpg --armor --export $fingerprint | Out-File -FilePath $pubKeyPath -Encoding ascii

Write-Host "✅ Web-of-Trust key created"
Write-Host "   Fingerprint: $fingerprint"
Write-Host "   Public key:  $pubKeyPath"
