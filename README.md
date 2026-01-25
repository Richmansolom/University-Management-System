**SBOM + Application Security Pipeline for C/C++ Applications**

(Using Docker, Syft, CycloneDX, Custom Metadata, and Trivy)

1. Overview

This project implements a reproducible SBOM and application-security pipeline for a custom C/C++ application using a combination of:

COTS SBOM tools

Syft (SBOM generation)

CycloneDX-CLI (SBOM validation)

Trivy (vulnerability scanning)

Custom developed capability

A PowerShell script (merge-sbom.ps1) to enrich SBOMs with first-party application metadata

The pipeline:

1. Builds the C++ application into a Docker image

2.Generates a CycloneDX SBOM from the image using Syft

3. Enriches the SBOM with custom metadata describing the application

4. Validates the raw and enriched SBOMs

5. Scans the image for OS and library vulnerabilities
6. Publishes SBOM artifacts via GitHub Actions
**Repository Structure**
university-management-system/
├── src/                         # C++ source files
├── Makefile                     # Build instructions for the app
├── Dockerfile                   # Builds the C++ app into a container
├── app-metadata.json            # Custom application metadata
├── merge-sbom.ps1               # Enriches SBOM with app metadata
├── generate-sbom.ps1            # Local orchestration script (optional)
├── sbom/                        # Generated SBOM outputs (gitignored)
│   ├── sbom-cyclonedx.json
│   └── sbom-enriched.json
└── .github/
    └── workflows/
        └── sbom-pipeline.yml    # CI pipeline

**3. Prerequisites**
Local Development
Windows 10/11
PowerShell 7+
Docker Desktop
Git
**Verify:**
docker --version
pwsh --version
git --version

**4. Step 1 — Build the C++ App into a Docker Image
Dockerfile**
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
**Local build test:**
docker build -t ums-cpp-app:1.0 .
docker run --rm ums-cpp-app:1.0

**5. Step 2 — Generate a Raw SBOM with Syft
Command**
docker run --rm `
  -v /var/run/docker.sock:/var/run/docker.sock `
  anchore/syft:latest ums-cpp-app:1.0 `
  -o cyclonedx-json > sbom/sbom-cyclonedx.json
  
 ** Output**
sbom/sbom-cyclonedx.json

**6. Step 3 — Define Custom Application Metadata
app-metadata.json**
{
  "name": "University Management System",
  "version": "1.0",
  "description": "C++ console-based system for managing university operations",
  "language": "C++",
  "author": "Richman Solom",
  "repository": "https://github.com/Richmansolom/University-Management-System",
  "build_system": "Makefile",
  "entry_point": "main",
  "source_file": "src/ums.cpp",
  "license": "MIT",
  "supplier": {
    "name": "Richman Solom",
    "url": "https://github.com/Richmansolom"
  }
}

7. Step 4 — Enrich the SBOM with Custom Metadata
merge-sbom.ps1
This script:
Loads the Syft SBOM
Loads app-metadata.json
Injects a new CycloneDX application component
Writes sbom-enriched.json
Key properties added:
name
version
description
supplier
licenses
externalReferences (VCS URL)
properties (language, author, entry point, etc.)

Manual execution
pwsh ./merge-sbom.ps1 `
  -InputSbom sbom/sbom-cyclonedx.json `
  -AppMetadata app-metadata.json `
  -OutputSbom sbom/sbom-enriched.json

8.**Step 5 — Validate SBOMs
Pull CycloneDX-CLI**
docker pull cyclonedx/cyclonedx-cli:latest

**Validate raw SBOM**
docker run --rm -v ${PWD}/sbom:/data `
  cyclonedx/cyclonedx-cli:latest validate `
  --input-file /data/sbom-cyclonedx.json
**Validate enriched SBOM**
docker run --rm -v ${PWD}/sbom:/data `
  cyclonedx/cyclonedx-cli:latest validate `
  --input-file /data/sbom-enriched.json

  9. **Step 6 — Scan Vulnerabilities with Trivy**
docker run --rm aquasecurity/trivy:latest image ums-cpp-app:1.0'

**10. Step 7 — GitHub Actions Pipeline
.github/workflows/sbom-pipeline.yml**
name: SBOM + Vulnerability Pipeline

on:
  push:
    branches: [ "main", "master" ]
  pull_request:
    branches: [ "main", "master" ]

jobs:
  sbom-security:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout source
        uses: actions/checkout@v4

      - name: Set up Docker
        uses: docker/setup-buildx-action@v3

      - name: Install PowerShell
        run: |
          sudo apt-get update
          sudo apt-get install -y powershell

      - name: Build UMS Docker image
        run: |
          docker build -t ums-cpp-app:1.0 .

      - name: Generate SBOM with Syft (CycloneDX)
        run: |
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            anchore/syft:latest ums-cpp-app:1.0 \
            -o cyclonedx-json > sbom-cyclonedx.json

      - name: Enrich SBOM with custom metadata
        shell: pwsh
        run: |
          ./merge-sbom.ps1 `
            -InputSbom "sbom-cyclonedx.json" `
            -AppMetadata "app-metadata.json" `
            -OutputSbom "sbom-enriched.json"

      - name: Validate SBOMs with CycloneDX-CLI
        run: |
          docker run --rm -v $PWD:/data cyclonedx/cyclonedx-cli:latest validate --input-file /data/sbom-cyclonedx.json
          docker run --rm -v $PWD:/data cyclonedx/cyclonedx-cli:latest validate --input-file /data/sbom-enriched.json

      - name: Scan image vulnerabilities with Trivy
        uses: aquasecurity/trivy-action@0.20.0
        with:
          image-ref: ums-cpp-app:1.0
          format: table
          exit-code: 0
          ignore-unfixed: true
          vuln-type: os,library
          severity: CRITICAL,HIGH

      - name: Upload SBOM artifacts
        uses: actions/upload-artifact@v4
        with:
          name: sbom-results
          path: |
            sbom-cyclonedx.json
            sbom-enriched.json

11. Step 8 — .gitignore
# SBOM artifacts (generated)
sbom/
sbom-*.json

**12. How to Reuse This for Any Other C++ Project

Only 3 files must change:
**
1. Dockerfile
2. Makefile or build comman
3. app-metadata.json
Everything else remains identical.
