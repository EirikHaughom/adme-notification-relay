#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Port of `tests/test-get.ps1` (PowerShell) to Python.

Usage:
  - Simple ping (no challenge):
      python tests/test-get.py

  - Run the challenge handshake flow (requires HMAC_SECRET to be set and to be a hex-string):
      python tests/test-get.py --challenge

Notes:
  - The server expects two query parameters: crc and hmac. This script will build an HMAC token
    using the same chaining algorithm implemented in the original PowerShell script.
  - The HMAC secret used for the challenge MUST be provided via the environment variable
    HMAC_SECRET and should be a hex-string (alphanumeric hex, even-length) to match the server
    implementation.
"""

import argparse
import base64
import datetime
import hmac
import hashlib
import os
import re
import sys
import uuid

import requests


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert a hex string into bytes. Pads with a leading 0 if needed (odd length).
    Accepts an optional '0x' prefix. If the input is not a valid hex string, fallback to
    returning its UTF-8 encoding (useful for local testing with plain secrets).
    """
    if not hex_str:
        return b""
    s = str(hex_str).strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    # If it looks like a hex string, try converting; otherwise fall back to UTF-8 bytes
    if re.fullmatch(r"[A-Fa-f0-9]+", s):
        if len(s) % 2 == 1:
            s = "0" + s
        try:
            return bytes.fromhex(s)
        except ValueError:
            # Unexpected; fall through to utf-8 fallback
            pass

    # Fallback to treating the input as UTF-8 bytes so non-hex secrets can be used for testing
    print(
        f"Warning: Provided string {hex_str!r} is not a valid hex string; using its UTF-8 bytes instead.",
        file=sys.stderr,
    )
    return str(hex_str).encode("utf-8")


def hmac_sha256_bytes(key_bytes: bytes, data_bytes: bytes) -> bytes:
    """Return HMAC-SHA256 digest for the given key and data."""
    return hmac.new(key_bytes, data_bytes, hashlib.sha256).digest()


def is_hex_string(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Fa-f0-9]+", s or ""))


def parse_challenge_flag(value) -> bool:
    """Normalize the argparse "challenge" argument to a boolean.
    - If the flag is absent -> False
    - If present without value (nargs='?') -> True
    - If present with a value (string) -> truthy strings (1/true/yes) treated as True
    """
    if value is False:
        return False
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes")
    return bool(value)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test GET/ping and optional HMAC challenge flow for osdu-relay (port of test-get.ps1)"
    )
    parser.add_argument(
        "-s", "--hmac-secret",
        default=None,
        help=(
            "HMAC secret (hex string) to run the challenge handshake. "
            "If not provided, performs a simple ping. This overrides the HMAC_SECRET environment variable."
        ),
    )
    parser.add_argument(
        "-e", "--endpoint",
        default="http://localhost:7071/api/osdu-relay",
        help="Endpoint URL to call (default: http://localhost:7071/api/osdu-relay)")

    args = parser.parse_args()

    # Prefer the CLI-provided secret, but allow HMAC_SECRET env var as a fallback
    secret_cli = args.hmac_secret
    endpoint = args.endpoint

    secret_hex = secret_cli if secret_cli is not None else os.environ.get("HMAC_SECRET")

    if secret_hex:
        # basic validation and helpful warning if the secret doesn't look hex-ish
        if not is_hex_string(secret_hex) or (len(secret_hex) % 2 != 0):
            print(
                "Warning: HMAC secret does not appear to be a hex-like string. The challenge flow expects a hex secret.",
                file=sys.stderr,
            )

        # Build parameters for the challenge token
        nonce_hex = uuid.uuid4().hex  # 32 hex chars
        epoch = datetime.datetime(1970, 1, 1)
        expiry_ms = int((datetime.datetime.utcnow() - epoch).total_seconds() * 1000.0 + 60000)
        expiry_str = str(expiry_ms)
        timestamp_str = str(expiry_ms - 30000)

        # exact field order and quoting is important; match server's formatting
        data_str = '{{"expireMillisecond": "{0}","hashMechanism": "hmacSHA256","endpointUrl": "{1}","nonce": "{2}"}}'.format(
            expiry_str, endpoint, nonce_hex
        )

        # perform HMAC chain as implemented in the server
        try:
            secret_bytes = hex_to_bytes(secret_hex)
            nonce_bytes = hex_to_bytes(nonce_hex)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)

        encrypted_nonce = hmac_sha256_bytes(secret_bytes, nonce_bytes)
        encrypted_timestamp = hmac_sha256_bytes(encrypted_nonce, timestamp_str.encode("utf-8"))
        signed_key = hmac_sha256_bytes(encrypted_timestamp, b"de-notification-service")
        final_sig = hmac_sha256_bytes(signed_key, data_str.encode("utf-8"))

        sig_hex = "".join("{:02x}".format(b) for b in final_sig)
        data_b64 = base64.b64encode(data_str.encode("utf-8")).decode("ascii")
        hmac_token = f"{data_b64}.{sig_hex}"

        # Use a simple CRC/test value; the server will combine HMAC_SECRET + CRC to compute the responseHash
        crc = "test-crc"

        url = f"{endpoint}?crc={crc}&hmac={hmac_token}"
        print("GET -> " + url)

        try:
            # Use requests.get directly with the constructed URL to behave like the PowerShell curl call
            resp = requests.get(url, timeout=30)
            print(resp.text)
        except requests.RequestException as exc:
            print(f"Request failed: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        print("GET -> " + endpoint)
        try:
            resp = requests.get(endpoint, timeout=30)
            print(resp.text)
        except requests.RequestException as exc:
            print(f"Request failed: {exc}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
