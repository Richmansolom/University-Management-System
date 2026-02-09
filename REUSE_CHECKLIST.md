## Reuse Checklist for Another C/C++ Application

Use this checklist to apply the SBOM + vulnerability pipeline to a new project.

### 1) Project configuration
- Update `app-metadata.json` with the new app details.
- Update `Dockerfile` and `Makefile` (or build command) for the new app.
- Confirm the source entry point and repository URL.

### 2) Local SBOM run (optional)
- Container mode:
  - `pwsh ./generate-sbom.ps1 -Mode container -ImageName <image> -ImageTag <tag> -RunTrivy`
- Native mode:
  - `pwsh ./generate-sbom.ps1 -Mode native -SourcePath <path> -RunTrivy -RunDistro2Sbom`

### 3) CI configuration
- GitLab:
  - Set `SIGNING_METHOD=openssl|gpg|pq` in `.gitlab-ci.yml` or CI variables.
  - Add required signing key variables from `SBOM_SIGNING_GUIDE.md`.
- GitHub:
  - Trigger the **SBOM + Vulnerability Pipeline** workflow.
  - Ensure artifacts include `reports/` outputs.

### 4) Validate outputs
- `reports/requirements-summary.txt` should show PASS for CycloneDX + NTIA local.
- Hoppr may show WARN due to third-party license metadata gaps.
- Review `reports/vulnerability-analysis.txt` and `reports/grype-report.txt`.

