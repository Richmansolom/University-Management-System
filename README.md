## SBOM + Application Security Pipeline for C/C++ Applications

Using Docker/Podman, Syft, CycloneDX, Hoppr, custom metadata, Trivy, and Grype.

### 1) Overview

This project implements a reproducible SBOM and application-security pipeline for a custom C/C++ application using:

**COTS SBOM tools**
- Syft (SBOM generation)
- CycloneDX-CLI (SBOM validation)
- Hoppr (NTIA validation)
- Trivy (vulnerability scanning)
- Grype (SBOM vulnerability scan in CI)

**Custom capability**
- `merge-sbom.ps1` to enrich SBOMs with first-party application metadata

**Pipeline flow**
1. Build the C++ application into a container image (container mode) or scan a source path (native mode)
2. Generate a CycloneDX SBOM using Syft
3. Enrich the SBOM with custom metadata describing the application
4. Validate the raw and enriched SBOMs (CycloneDX-CLI)
5. Check NTIA Minimum Elements (local script + Hoppr)
6. Scan for OS and library vulnerabilities (Trivy locally, Grype in CI)
7. Publish SBOM and report artifacts (GitHub Actions and/or GitLab CI)

### 2) Repository Structure
```
university-management-system/
├── src/                         # C++ source files
├── Makefile                     # Build instructions
├── Dockerfile                   # Builds the C++ app into a container
├── app-metadata.json            # Custom application metadata
├── merge-sbom.ps1               # Enriches SBOM with app metadata
├── generate-sbom.ps1            # Local orchestration script
├── check-ntia.ps1               # NTIA Minimum Elements checks
├── sbom/                        # Generated SBOM outputs (gitignored)
│   ├── sbom-cyclonedx.json
│   └── sbom-enriched.json
├── .gitlab-ci.yml               # GitLab CI pipeline
└── .github/
    └── workflows/
        └── sbom-pipeline.yml    # GitHub Actions pipeline
```

### 3) Prerequisites

**Local development**
- Windows 10/11
- PowerShell 7+
- Docker Desktop or Podman
- Git
- Hoppr CLI (optional)

**Verify**
```
docker --version
pwsh --version
git --version
hopctl --version
```

### 4) Build the C++ App into a Docker Image

**Dockerfile (excerpt)**
```
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    build-essential \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN make
CMD ["./university_app"]
```

**Local build test**
```
docker build -t ums-cpp-app:1.0 .
docker run --rm ums-cpp-app:1.0
```

### 5) Quick Run (Scripted)

**Container mode**
```
pwsh ./generate-sbom.ps1 -Mode container -ImageName ums-cpp-app -ImageTag 1.0 -RunTrivy
```

**Native mode**
```
pwsh ./generate-sbom.ps1 -Mode native -SourcePath . -RunTrivy -RunDistro2Sbom
```

### 6) Generate a Raw SBOM with Syft

**Container mode**
```
docker run --rm `
  -v /var/run/docker.sock:/var/run/docker.sock `
  anchore/syft:latest ums-cpp-app:1.0 `
  -o cyclonedx-json > sbom/sbom-cyclonedx.json
```

**Native mode**
```
docker run --rm `
  -v ${PWD}:/src `
  anchore/syft:latest dir:/src `
  -o cyclonedx-json > sbom/sbom-cyclonedx.json
```

### 7) Define Custom Application Metadata

**`app-metadata.json` (example)**
```
{
  "name": "University Management System",
  "version": "1.0.0",
  "description": "C++ console-based system for managing university operations",
  "language": "C++",
  "author": "Solomon",
  "repository": "https://github.com/Richmansolom/University-Management-System",
  "build_system": "Makefile",
  "entry_point": "./university_app",
  "source_file": "src/ums.cpp",
  "license": "MIT",
  "supplier": {
    "name": "Solomon",
    "url": ["https://github.com/Richmansolom"]
  }
}
```

### 8) Enrich the SBOM with Custom Metadata

`merge-sbom.ps1` loads the Syft SBOM and `app-metadata.json`, injects a CycloneDX application component, and writes `sbom-enriched.json`.

**Manual execution**
```
pwsh ./merge-sbom.ps1 `
  -InputSbom sbom/sbom-cyclonedx.json `
  -AppMetadata app-metadata.json `
  -OutputSbom sbom/sbom-enriched.json
```

### 9) Validate SBOMs

**CycloneDX-CLI**
```
docker pull cyclonedx/cyclonedx-cli:latest
docker run --rm -v ${PWD}/sbom:/data cyclonedx/cyclonedx-cli:latest validate --input-file /data/sbom-cyclonedx.json
docker run --rm -v ${PWD}/sbom:/data cyclonedx/cyclonedx-cli:latest validate --input-file /data/sbom-enriched.json
```

**NTIA Minimum Elements (local)**
```
pwsh ./check-ntia.ps1 -SbomFile sbom/sbom-enriched.json
```

**NTIA Minimum Elements (Hoppr)**
```
hopctl validate sbom --sbom sbom/sbom-cyclonedx.json --profile ntia
hopctl validate sbom --sbom sbom/sbom-enriched.json --profile ntia
```

**Hoppr via Docker**
```
docker run --rm -v ${PWD}:/data -w /data hoppr/hopctl validate sbom --sbom sbom/sbom-cyclonedx.json --profile ntia
docker run --rm -v ${PWD}:/data -w /data hoppr/hopctl validate sbom --sbom sbom/sbom-enriched.json --profile ntia
```

### 10) Sign and Distribute SBOMs

This repository includes a PKI and Web-of-Trust workflow for SBOM signing with embedded signatures (JSF). See `SBOM_SIGNING_GUIDE.md`.

### 11) Scan Vulnerabilities (Trivy)
```
docker run --rm aquasec/trivy:latest image ums-cpp-app:1.0
docker run --rm -v ${PWD}:/src aquasec/trivy:latest fs /src
```

### 12) GitLab CI/CD Pipeline

The GitLab pipeline builds a sample C++ project, generates SBOMs, signs and validates them, runs Hoppr NTIA checks, and scans SBOMs with Grype:
- `.gitlab-ci.yml`
- `sbom-pipeline-app/`

### 13) Optional COTS Extensions
- Distro2SBOM for OS package SBOMs (native mode)
- Hoppr CLI for stricter NTIA validation profiles

**Distro2SBOM (native OS packages)**
```
pip install distro2sbom
distro2sbom --distro auto --system --sbom cyclonedx --format json --output-file sbom/sbom-distro-cyclonedx.json
```

### 14) GitHub Actions Pipeline

`.github/workflows/sbom-pipeline.yml` provides a GitHub Actions workflow for SBOM generation and Trivy scanning.

### 15) .gitignore
```
# SBOM artifacts (generated)
sbom/
sbom-*.json
```

### 16) Reuse for Any Other C++ Project

Only three files must change:
1. `Dockerfile`
2. `Makefile` (or build command)
3. `app-metadata.json`

Everything else remains identical.

### 17) Metadata Template
- `app-metadata.template.json` is a ready-to-copy metadata template.
