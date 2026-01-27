# SBOM Signing and Key Distribution Infrastructure

This guide adds a PKI and Web-of-Trust (WOT) signing workflow for CycloneDX SBOMs, embeds signatures inside the SBOM (JSF), and validates the resulting SBOM structure with CycloneDX-CLI or Hoppr.

## Security Principles (Key Protection)
- Keep the root CA offline; use an intermediate CA for day-to-day signing.
- Store signing keys in a hardware-backed keystore (HSM/TPM) when possible.
- Use short-lived signing certificates and rotate on a fixed cadence.
- Separate duties: CA management and SBOM signing should be distinct roles.
- Publish only public material (certs, public keys, fingerprints).

## Cryptographic Profiles
**CNSA 2.0 (Post-Quantum)**  
- Signatures: ML-DSA-87 (via OpenSSL + oqs-provider).  
- Use `sha512` or provider defaults as required by the PQ implementation.

**CNSA 1.0 (Classical)**  
- RSA-3072 with SHA-384 (`RS384`) or P-384 (`ES384`).

## PKI (OpenSSL) Workflow
### 1) Bootstrap PKI (Root → Intermediate → Signing Cert)
Classical RSA-3072:
```
pwsh ./sbom-signing/pki-bootstrap.ps1 -Profile cnsa1-rsa3072
```
Classical P-384:
```
pwsh ./sbom-signing/pki-bootstrap.ps1 -Profile cnsa1-p384
```
Post-Quantum (ML-DSA-87) using oqs-provider:
```
pwsh ./sbom-signing/pki-bootstrap.ps1 `
  -Profile cnsa2-pq `
  -PqAlgorithm mldsa87 `
  -Digest sha512 `
  -OpenSslProviderArgs @("-provider","oqsprovider","-provider","default")
```
Notes:
- Confirm the exact PQ algorithm name using `openssl list -signature-algorithms` after installing oqs-provider.
- Keep the root key offline and distribute only `root-ca.crt` and `intermediate-ca.crt`.

### 1b) Generate CI signing keys (for GitLab CI variables)
```
pwsh ./sbom-signing/generate-ci-keys.ps1 -Profile rsa3072 -Digest sha384
```
This outputs base64 values for:
- `SBOM_SIGNING_KEY_B64`
- `SBOM_SIGNING_PUB_B64`
and recommends the matching `SBOM_SIGNING_ALGO`/`SBOM_SIGNING_DIGEST`.

### 1c) Generate PQ CI signing keys (CNSA 2.0)
```
pwsh ./sbom-signing/generate-pq-keys.ps1 `
  -PqAlgorithm mldsa87 `
  -Digest sha512 `
  -OpenSslProviderArgs @("-provider","oqsprovider","-provider","default")
```
This outputs base64 values for:
- `SBOM_PQ_KEY_B64`
- `SBOM_PQ_PUB_B64`
and sets `SIGNING_METHOD=pq` with the recommended `PQ_SIGNING_ALGO`/`PQ_SIGNING_DIGEST`.

### 2) Sign an SBOM (Embed JSF signature)
```
pwsh ./sbom-signing/sign-sbom.ps1 `
  -InputSbom sbom/sbom-enriched.json `
  -OutputSbom sbom/sbom-enriched.signed.json `
  -Signer openssl `
  -KeyPath sbom-signing/pki/signer/sbom-signer.key `
  -Algorithm RS384 `
  -Digest sha384 `
  -KeyId "UMS-SBOM-SIGNER-2026"
```
PQ example (algorithm URI required by JSF for non-JWA algorithms):
```
pwsh ./sbom-signing/sign-sbom.ps1 `
  -InputSbom sbom/sbom-enriched.json `
  -OutputSbom sbom/sbom-enriched.signed.json `
  -Signer openssl `
  -KeyPath sbom-signing/pki/signer/sbom-signer.key `
  -Algorithm "urn:nist:alg:ml-dsa-87" `
  -Digest sha512 `
  -OpenSslProviderArgs @("-provider","oqsprovider","-provider","default") `
  -KeyId "UMS-SBOM-MLDSA87-2026"
```

### 3) Verify the SBOM signature
```
pwsh ./sbom-signing/verify-sbom.ps1 `
  -InputSbom sbom/sbom-enriched.signed.json `
  -Signer openssl `
  -CertificatePath sbom-signing/pki/signer/sbom-signer.crt `
  -Digest sha384
```

### 4) Validate SBOM structure (CycloneDX or Hoppr)
CycloneDX-CLI:
```
docker run --rm -v "${PWD}:/data" cyclonedx/cyclonedx-cli:latest `
  validate --input-file /data/sbom/sbom-enriched.signed.json
```
Hoppr:
```
hopctl validate sbom --sbom sbom/sbom-enriched.signed.json --profile ntia
```

## Web-of-Trust (GnuPG) Workflow
### 1) Create a WOT signing key (CNSA 1.0: RSA-3072)
```
pwsh ./sbom-signing/wot-bootstrap.ps1 -Name "SBOM Signer" -Email "signer@example.org"
```
Publish the exported public key (`sbom-signing/wot/sbom-wot-public.asc`) to:
- Public keyservers (global distribution), and/or
- Your organization security portal or repository.

### 2) Sign an SBOM (Embed JSF signature)
```
pwsh ./sbom-signing/sign-sbom.ps1 `
  -InputSbom sbom/sbom-enriched.json `
  -OutputSbom sbom/sbom-enriched.signed.json `
  -Signer gpg `
  -Algorithm "urn:openpgp:rsa3072" `
  -GpgKeyId "<GPG_FINGERPRINT>"
```

### 3) Verify the SBOM signature
```
pwsh ./sbom-signing/verify-sbom.ps1 `
  -InputSbom sbom/sbom-enriched.signed.json `
  -Signer gpg
```

### 4) Validate SBOM structure (CycloneDX or Hoppr)
Same commands as the PKI workflow.

## GitLab CI Signing Methods
OpenSSL (default):
- `SIGNING_METHOD=openssl`
- `SBOM_SIGNING_KEY_B64`, `SBOM_SIGNING_PUB_B64`
- `SBOM_SIGNING_ALGO`, `SBOM_SIGNING_DIGEST`

GPG (Web-of-Trust):
- `SIGNING_METHOD=gpg`
- `SBOM_GPG_PRIVATE_KEY_B64`, `SBOM_GPG_PUBLIC_KEY_B64`
- `SBOM_GPG_KEY_ID` (optional), `GPG_SIGNING_ALGO`

Post-Quantum (CNSA 2.0):
- `SIGNING_METHOD=pq`
- `SBOM_PQ_KEY_B64`, `SBOM_PQ_PUB_B64`
- `PQ_SIGNING_ALGO`, `PQ_SIGNING_DIGEST`
- `PQ_OPENSSL_IMAGE`, `PQ_OPENSSL_PROVIDERS`

## Global Key Distribution
PKI:
- Publish `root-ca.crt` and `intermediate-ca.crt` to a public URL.
- Pin cert fingerprints in documentation and CI policies.
- Rotate leaf keys/certs regularly; keep the root offline.

Web-of-Trust:
- Publish GPG fingerprint and public key on keyservers.
- Encourage third-party signatures on your signing key.
- Revoke keys immediately if compromise is suspected.

## Notes on Embedded Signatures
- CycloneDX uses JSF signatures under the `signature` property.
- This repository embeds signatures directly in the SBOM while maintaining schema validity.
- CycloneDX-CLI and Hoppr validate schema and structural correctness; cryptographic verification is performed by `verify-sbom.ps1`.
