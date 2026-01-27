import argparse
import base64
import json
import subprocess
import tempfile
from pathlib import Path


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Embed JSF signature in CycloneDX SBOM.")
    parser.add_argument("--input", required=True, help="Path to unsigned SBOM JSON")
    parser.add_argument("--output", required=True, help="Path to signed SBOM JSON")
    parser.add_argument("--key", required=True, help="Signing key path (PEM)")
    parser.add_argument("--algorithm", default="RS384", help="JSF algorithm name")
    parser.add_argument("--digest", default="sha384", help="Digest algorithm for openssl")
    parser.add_argument(
        "--openssl-provider",
        action="append",
        default=[],
        help="OpenSSL provider to load (repeatable)",
    )
    parser.add_argument("--key-id", default="", help="Optional key identifier")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        raise SystemExit(f"SBOM file not found: {input_path}")

    sbom = json.loads(input_path.read_text(encoding="utf-8-sig"))
    sbom.pop("signature", None)

    with tempfile.TemporaryDirectory() as tmpdir:
        payload_path = Path(tmpdir) / "payload.json"
        sig_path = Path(tmpdir) / "payload.sig"
        write_json(payload_path, sbom)

        provider_args = []
        for provider in args.openssl_provider:
            provider_args.extend(["-provider", provider])

        cmd = [
            "openssl",
            "dgst",
            f"-{args.digest}",
            *provider_args,
            "-sign",
            str(args.key),
            "-out",
            str(sig_path),
            str(payload_path),
        ]
        subprocess.check_call(cmd)

        sig_value = b64url_encode(sig_path.read_bytes())

    signature = {
        "algorithm": args.algorithm,
        "value": sig_value,
        "excludes": ["signature"],
    }
    if args.key_id:
        signature["keyId"] = args.key_id

    sbom["signature"] = signature
    output_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    print(f"Signed SBOM written to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
