param(
  [ValidateSet("container","native")]
  [string]$Mode     = "container",
  [ValidateSet("auto","docker","podman")]
  [string]$ContainerRuntime = "auto",
  [string]$SourcePath = ".",
  [string]$ImageName = "ums-cpp-app",
  [string]$ImageTag  = "1.0",
  [string]$SbomDir   = "sbom",
  [string]$AppMetadataPath = "app-metadata.json",
  [string]$RequirementsReport = "",
  [switch]$RunTrivy,
  [switch]$RunDistro2Sbom
)

$ErrorActionPreference = "Stop"

function Assert-Command($cmd) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
    throw "Missing required command: $cmd"
  }
}

function Resolve-ContainerRuntime([string]$requested) {
  if ($requested -eq "docker" -or $requested -eq "podman") {
    Assert-Command $requested
    return $requested
  }
  if (Get-Command docker -ErrorAction SilentlyContinue) { return "docker" }
  if (Get-Command podman -ErrorAction SilentlyContinue) { return "podman" }
  throw "Missing required command: docker or podman"
}

function Write-Utf8NoBom([string]$path, [string]$content) {
  [System.IO.File]::WriteAllText(
    $path,
    $content,
    (New-Object System.Text.UTF8Encoding $false)
  )
}

$containerCmd = Resolve-ContainerRuntime $ContainerRuntime

# Detect Windows even on Windows PowerShell
$isWindowsOs = $env:OS -eq "Windows_NT"

# Paths
$repoRoot = Get-Location
$sbomPath = Join-Path $repoRoot $SbomDir
if (-not (Test-Path $sbomPath)) { New-Item -ItemType Directory -Path $sbomPath | Out-Null }

$rawSbom      = Join-Path $sbomPath "sbom-cyclonedx.json"
$enrichedSbom = Join-Path $sbomPath "sbom-enriched.json"
$distroSbom   = Join-Path $sbomPath "sbom-distro-cyclonedx.json"
$appMeta      = Join-Path $repoRoot $AppMetadataPath
$mergeScript  = Join-Path $repoRoot "merge-sbom.ps1"
$ntiaScript   = Join-Path $repoRoot "check-ntia.ps1"

if (-not (Test-Path $appMeta)) { throw "❌ Missing app-metadata.json in repo root." }
if (-not (Test-Path $mergeScript)) { throw "❌ Missing merge-sbom.ps1 in repo root." }
if (-not $RequirementsReport) { $RequirementsReport = Join-Path $sbomPath "requirements-summary.txt" }

$image = "$ImageName`:$ImageTag"

Write-Host "==> Pulling Syft (COTS SBOM tool)"
& $containerCmd pull anchore/syft:latest | Out-Host

if ($Mode -eq "container") {
  Write-Host "==> Building Docker image: $image"
  & $containerCmd build -t $image . | Out-Host

  Write-Host "==> Generating raw CycloneDX SBOM from image"
  if ($containerCmd -eq "docker") {
    $rawContent = & $containerCmd run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/syft:latest $image -o cyclonedx-json
    Write-Utf8NoBom -path $rawSbom -content $rawContent
  } else {
    $imageTar = Join-Path $sbomPath "image.tar"
    & $containerCmd save $image -o $imageTar | Out-Host
    $rawContent = & $containerCmd run --rm -v "${sbomPath}:/data" anchore/syft:latest "oci-archive:/data/image.tar" -o cyclonedx-json
    Write-Utf8NoBom -path $rawSbom -content $rawContent
  }
} else {
  $resolvedSource = (Resolve-Path $SourcePath).Path
  Write-Host "==> Generating raw CycloneDX SBOM from source path: $resolvedSource"
  $rawContent = & $containerCmd run --rm -v "${resolvedSource}:/src" anchore/syft:latest dir:/src -o cyclonedx-json
  Write-Utf8NoBom -path $rawSbom -content $rawContent
}

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
& $containerCmd pull cyclonedx/cyclonedx-cli:latest | Out-Host

$rawValidateExit = 0
$enrichedValidateExit = 0
& $containerCmd run --rm -v "${sbomPath}:/data" cyclonedx/cyclonedx-cli:latest validate --input-file /data/sbom-cyclonedx.json | Out-Host
$rawValidateExit = $LASTEXITCODE
& $containerCmd run --rm -v "${sbomPath}:/data" cyclonedx/cyclonedx-cli:latest validate --input-file /data/sbom-enriched.json | Out-Host
$enrichedValidateExit = $LASTEXITCODE

if (Test-Path $ntiaScript) {
  Write-Host "==> NTIA Minimum Elements check (local)"
  powershell -ExecutionPolicy Bypass -File $ntiaScript -SbomFile $enrichedSbom | Out-Host
  $ntiaLocalExit = $LASTEXITCODE
} else {
  $ntiaLocalExit = 1
}

$hopctl = Get-Command hopctl -ErrorAction SilentlyContinue
if ($hopctl) {
  Write-Host "==> NTIA validation with Hoppr (hopctl)"
  hopctl validate sbom --sbom $rawSbom --profile ntia | Out-Host
  $rawExit = $LASTEXITCODE
  hopctl validate sbom --sbom $enrichedSbom --profile ntia | Out-Host
  $enrichedExit = $LASTEXITCODE
  if ($rawExit -ne 0 -or $enrichedExit -ne 0) {
    Write-Host "==> Hoppr CLI failed; falling back to Hoppr Docker image"
    & $containerCmd run --rm -v "${sbomPath}:/data" -w /data hoppr/hopctl validate sbom --sbom sbom-cyclonedx.json --profile ntia | Out-Host
    & $containerCmd run --rm -v "${sbomPath}:/data" -w /data hoppr/hopctl validate sbom --sbom sbom-enriched.json --profile ntia | Out-Host
    $rawExit = $LASTEXITCODE
    $enrichedExit = $LASTEXITCODE
  }
} else {
  Write-Host "==> Hoppr (hopctl) not installed; using Hoppr Docker image"
  & $containerCmd run --rm -v "${sbomPath}:/data" -w /data hoppr/hopctl validate sbom --sbom sbom-cyclonedx.json --profile ntia | Out-Host
  $rawExit = $LASTEXITCODE
  & $containerCmd run --rm -v "${sbomPath}:/data" -w /data hoppr/hopctl validate sbom --sbom sbom-enriched.json --profile ntia | Out-Host
  $enrichedExit = $LASTEXITCODE
}

if ($RunTrivy) {
  Write-Host "==> Vulnerability scan with Trivy"
  if ($Mode -eq "container") {
    if ($containerCmd -eq "docker") {
      & $containerCmd run --rm `
        -v /var/run/docker.sock:/var/run/docker.sock `
        aquasec/trivy:latest image $image | Out-Host
    } else {
      $imageTar = Join-Path $sbomPath "image.tar"
      if (-not (Test-Path $imageTar)) {
        & $containerCmd save $image -o $imageTar | Out-Host
      }
      & $containerCmd run --rm -v "${sbomPath}:/data" aquasec/trivy:latest image --input /data/image.tar | Out-Host
    }
  } else {
    $resolvedSource = (Resolve-Path $SourcePath).Path
    & $containerCmd run --rm -v "${resolvedSource}:/src" aquasec/trivy:latest fs /src | Out-Host
  }
}

if ($RunDistro2Sbom -and $Mode -eq "native") {
  $distro2sbom = Get-Command distro2sbom -ErrorAction SilentlyContinue
  if (-not $distro2sbom -and $env:APPDATA) {
    $pythonRoot = Join-Path $env:APPDATA "Python"
    if (Test-Path $pythonRoot) {
      $candidate = Get-ChildItem -Path $pythonRoot -Recurse -Filter distro2sbom.exe -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($candidate) {
        $distro2sbom = $candidate.FullName
      }
    }
  }
  if ($distro2sbom) {
    Write-Host "==> Distro2SBOM (native OS packages)"
    if ($isWindowsOs) {
      $inputFile = Join-Path $sbomPath "distro2sbom-windows.txt"
      $wmiCmd = Get-Command Get-WmiObject -ErrorAction SilentlyContinue
      try {
        if ($wmiCmd) {
          $products = Get-WmiObject -Class Win32_Product -ErrorAction Stop
        } else {
          $products = Get-CimInstance -ClassName Win32_Product -ErrorAction Stop
        }
        if ($products) {
          $products | Out-File -FilePath $inputFile -Force -Encoding utf8
        }
      } catch {
        Write-Host "==> Failed to collect Windows product list: $($_.Exception.Message)"
        $inputFile = $null
      }
      if ($inputFile -and (Test-Path $inputFile)) {
        $osName = "Windows"
        $osRelease = [System.Environment]::OSVersion.Version.ToString()
        try {
          $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
          if ($osInfo.Caption) { $osName = $osInfo.Caption }
          if ($osInfo.Version) { $osRelease = $osInfo.Version }
        } catch {
          # Fall back to defaults
        }
        & $distro2sbom --distro windows --name "$osName" --release "$osRelease" --distro-namespace "microsoft" `
          --input-file $inputFile --sbom cyclonedx --format json --output-file $distroSbom | Out-Host
      } else {
        Write-Host "==> Distro2SBOM input file not created; skipping"
      }
    } else {
      & $distro2sbom --distro auto --system --sbom cyclonedx --format json --output-file $distroSbom | Out-Host
    }
    if ($LASTEXITCODE -eq 0 -and (Test-Path $distroSbom)) {
      Write-Host "✅ Distro2SBOM written to $distroSbom"
      $cleanedDistroSbom = Join-Path $sbomPath "sbom-distro-cyclonedx.cleaned.json"
      try {
        $distroData = Get-Content $distroSbom -Raw | ConvertFrom-Json
        if ($distroData.metadata -and $distroData.metadata.PSObject.Properties.Name -contains "distributionConstraints") {
          $distroData.metadata.PSObject.Properties.Remove("distributionConstraints")
        }
        $cleanJson = $distroData | ConvertTo-Json -Depth 50
        [System.IO.File]::WriteAllText(
          $cleanedDistroSbom,
          $cleanJson,
          (New-Object System.Text.UTF8Encoding $false)
        )
        Write-Host "✅ Cleaned Distro2SBOM written to $cleanedDistroSbom"
      } catch {
        Write-Host "==> Failed to clean Distro2SBOM: $($_.Exception.Message)"
      }
    } else {
      Write-Host "==> Distro2SBOM failed; output not reliable"
    }
  } else {
    Write-Host "==> Distro2SBOM not installed; skipping"
  }
}


Write-Host ""
Write-Host "✅ Done."
Write-Host "   Raw SBOM:      $rawSbom"
Write-Host "   Enriched SBOM: $enrichedSbom"

$summary = @()
$summary += "SBOM Requirements Summary"
$summary += "========================="
$summary += "CycloneDX validate (raw):      " + ($(if ($rawValidateExit -eq 0) { "PASS" } else { "FAIL" }))
$summary += "CycloneDX validate (enriched): " + ($(if ($enrichedValidateExit -eq 0) { "PASS" } else { "FAIL" }))
$summary += "NTIA Minimum Elements (local): " + ($(if ($ntiaLocalExit -eq 0) { "PASS" } else { "FAIL" }))
$summary += "Hoppr NTIA (raw):              " + ($(if ($rawExit -eq 0) { "PASS" } else { "FAIL" }))
$summary += "Hoppr NTIA (enriched):         " + ($(if ($enrichedExit -eq 0) { "PASS" } else { "FAIL" }))

Write-Utf8NoBom -path $RequirementsReport -content ($summary -join "`n")
Write-Host "   Requirements: $RequirementsReport"
