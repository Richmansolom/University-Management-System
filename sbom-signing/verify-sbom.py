import argparse
import base64
import json
import subprocess
import tempfile
from pathlib import Path


def b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify JSF signature in CycloneDX SBOM.")
    parser.add_argument("--input", required=True, help="Path to signed SBOM JSON")
    parser.add_argument("--public-key", required=True, help="Public key path (PEM)")
    parser.add_argument("--digest", default="sha384", help="Digest algorithm for openssl")
    parser.add_argument(
        "--openssl-provider",
        action="append",
        default=[],
        help="OpenSSL provider to load (repeatable)",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise SystemExit(f"SBOM file not found: {input_path}")

    sbom = json.loads(input_path.read_text(encoding="utf-8-sig"))
    signature = sbom.get("signature")
    if not signature or "value" not in signature:
        raise SystemExit("Signature value is missing.")

    sbom.pop("signature", None)
    excludes = signature.get("excludes") or []
    for name in excludes:
        sbom.pop(name, None)

    with tempfile.TemporaryDirectory() as tmpdir:
        payload_path = Path(tmpdir) / "payload.json"
        sig_path = Path(tmpdir) / "payload.sig"
        write_json(payload_path, sbom)
        sig_path.write_bytes(b64url_decode(signature["value"]))

        provider_args = []
        for provider in args.openssl_provider:
            provider_args.extend(["-provider", provider])

        cmd = [
            "openssl",
            "dgst",
            f"-{args.digest}",
            *provider_args,
            "-verify",
            str(args.public_key),
            "-signature",
            str(sig_path),
            str(payload_path),
        ]
        subprocess.check_call(cmd)

    print("Signature verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
