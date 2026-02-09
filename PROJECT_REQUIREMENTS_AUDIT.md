## Project Requirements Audit

This audit maps the project goals to concrete implementation evidence and notes any required configuration.

### 1) SBOM generator for custom C/C++ apps using COTS tools
- **Status:** Implemented
- **Evidence:**
  - `generate-sbom.ps1` orchestrates Syft, CycloneDX-CLI, Hoppr, Trivy.
  - `merge-sbom.ps1` enriches with first-party metadata from `app-metadata.json`.
  - `check-ntia.ps1` performs NTIA Minimum Elements checks.
  - `sbom-pipeline-app/` provides a multi-component C++ example.
- **Notes:** Supports container and native modes via `-Mode container|native`.

### 2) SBOM validation against NTIA Minimum Elements
- **Status:** Implemented
- **Evidence:**
  - Local NTIA check: `check-ntia.ps1`
  - Hoppr validation: `hopctl validate sbom --profile ntia`
- **Notes:** Hoppr can emit warnings due to missing license metadata from COTS components. Logs are captured in `reports/hoppr-*.log` (CI) and `sbom/hoppr-*.log` (local).

### 3) Key distribution infrastructure and signed SBOMs
- **Status:** Implemented (requires configuration)
- **Evidence:**
  - PKI/WoT workflow: `SBOM_SIGNING_GUIDE.md`
  - Signing + verification scripts: `sbom-signing/`
- **Required Configuration:**
  - CI variables for signing keys (GitLab) or GitHub Secrets for optional signing.
  - Use `generate-ci-keys.ps1` or `generate-pq-keys.ps1` to create keys.
- **Notes:** Root CA is designed to remain offline. Public material should be published via a trusted URL.

### 4) GitLab CI/CD pipeline for build + SBOM + sign + validate + scan
- **Status:** Implemented (signing optional)
- **Evidence:** `.gitlab-ci.yml`
- **Notes:** Set `SIGNING_METHOD=openssl|gpg|pq` and provide keys to enable signed SBOM validation.

### 5) Vulnerability analysis report as artifacts
- **Status:** Implemented
- **Evidence:**
  - GitLab: `reports/grype-report.*` and `reports/vulnerability-analysis.txt`
  - GitHub: `reports/` artifacts uploaded in workflow

### 6) Reuse for other C/C++ apps
- **Status:** Implemented
- **Evidence:** `REUSE_CHECKLIST.md`, `app-metadata.template.json`

