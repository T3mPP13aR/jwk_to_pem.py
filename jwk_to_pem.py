#!/usr/bin/env python3
"""
Convert an RSA public JWK JSON file to PEM.

Supported JWK fields:
- kty: must be "RSA"
- n: RSA modulus (base64url)
- e: RSA exponent (base64url)

Examples:
    python3 jwk_to_pem.py --jwk-file public.jwk
    python3 jwk_to_pem.py --jwk-file public.jwk --out public.pem

Dependencies:
    pip install cryptography
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class JWKConversionError(ValueError):
    """Raised when JWK input cannot be converted to a valid RSA public key."""


@dataclass(frozen=True)
class RSAPublicJWK:
    """Minimal RSA public JWK representation."""
    kty: str
    n: str
    e: str
    kid: str | None = None
    use: str | None = None
    alg: str | None = None


def base64url_decode(data: str) -> bytes:
    """Decode a base64url string, accepting omitted padding."""
    if not isinstance(data, str) or not data.strip():
        raise JWKConversionError("Expected a non-empty base64url string.")

    normalized = data.strip().replace("\n", "").replace("\r", "")
    padding = "=" * (-len(normalized) % 4)

    try:
        return base64.urlsafe_b64decode(normalized + padding)
    except Exception as exc:
        raise JWKConversionError("Invalid base64url-encoded value.") from exc


def base64url_to_int(data: str) -> int:
    """Convert a base64url-encoded unsigned integer to Python int."""
    raw = base64url_decode(data)
    if not raw:
        raise JWKConversionError("Decoded integer is empty.")
    return int.from_bytes(raw, byteorder="big", signed=False)


def load_json_file(path: Path) -> dict[str, Any]:
    """Load and parse a JSON file."""
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise JWKConversionError(f"Could not read file: {path}") from exc

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise JWKConversionError(f"Invalid JSON in file: {path}") from exc

    if not isinstance(data, dict):
        raise JWKConversionError("Top-level JSON value must be an object.")

    return data


def extract_rsa_public_jwk(data: dict[str, Any]) -> RSAPublicJWK:
    """
    Extract RSA public JWK from JSON object.

    Supports either:
    - a direct JWK object
    - a JWKS object with a 'keys' array (uses the first RSA key found)
    """
    if "keys" in data:
        keys = data.get("keys")
        if not isinstance(keys, list):
            raise JWKConversionError("'keys' must be an array in JWKS input.")

        for item in keys:
            if isinstance(item, dict) and item.get("kty") == "RSA" and "n" in item and "e" in item:
                data = item
                break
        else:
            raise JWKConversionError("No RSA public key with 'n' and 'e' found in JWKS.")

    kty = data.get("kty")
    n = data.get("n")
    e = data.get("e")

    if kty != "RSA":
        raise JWKConversionError("JWK 'kty' must be 'RSA'.")
    if not isinstance(n, str) or not n.strip():
        raise JWKConversionError("JWK is missing a valid 'n' value.")
    if not isinstance(e, str) or not e.strip():
        raise JWKConversionError("JWK is missing a valid 'e' value.")

    return RSAPublicJWK(
        kty=kty,
        n=n,
        e=e,
        kid=data.get("kid"),
        use=data.get("use"),
        alg=data.get("alg"),
    )


def jwk_to_public_key(jwk: RSAPublicJWK) -> rsa.RSAPublicKey:
    """Build an RSA public key object from RSA public JWK fields."""
    n = base64url_to_int(jwk.n)
    e = base64url_to_int(jwk.e)

    if n <= 0:
        raise JWKConversionError("Modulus 'n' must be a positive integer.")
    if e <= 0:
        raise JWKConversionError("Exponent 'e' must be a positive integer.")

    try:
        public_numbers = rsa.RSAPublicNumbers(e=e, n=n)
        return public_numbers.public_key()
    except ValueError as exc:
        raise JWKConversionError("Invalid RSA public numbers in JWK.") from exc


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> bytes:
    """Serialize RSA public key to PEM (SubjectPublicKeyInfo)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert an RSA public JWK or JWKS JSON file to PEM."
    )
    parser.add_argument(
        "--jwk-file",
        required=True,
        type=Path,
        help="Path to a JWK or JWKS JSON file.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="Write PEM output to file instead of stdout.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        data = load_json_file(args.jwk_file)
        jwk = extract_rsa_public_jwk(data)
        public_key = jwk_to_public_key(jwk)
        pem = public_key_to_pem(public_key)
    except JWKConversionError as exc:
        print(f"[!] Conversion failed: {exc}", file=sys.stderr)
        return 1

    if args.out:
        try:
            args.out.write_bytes(pem)
        except OSError as exc:
            print(f"[!] Could not write output file: {exc}", file=sys.stderr)
            return 1
    else:
        sys.stdout.buffer.write(pem)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
