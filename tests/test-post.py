#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Port of `tests/test-post.ps1` (PowerShell) to Python.

Usage:
  python tests/test-post.py
  python tests/test-post.py -s mySecret
  python tests/test-post.py -e http://localhost:7071/api/osdu-relay -f path/to/osdu-body.json

Behavior:
  - Reads `osdu-body.json` (by default from the same directory as this script).
  - Computes HMAC-SHA256 over the raw file bytes using the provided secret (CLI -s or HMAC_SECRET env var).
  - If no secret is provided, falls back to the literal string `testSecret` (same as the PowerShell script).
  - POSTs the file bytes to the endpoint with headers:
      Content-Type: application/json
      Authorization: hmac <hex-signature>
  - Attempts to parse the response as JSON and prints the first array element if the response is a list, otherwise prints the parsed JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from typing import Any

import requests


def resolve_script_dir() -> str:
    """Return the directory containing this script or the current working directory as a fallback."""
    try:
        return os.path.dirname(os.path.abspath(__file__)) or os.getcwd()
    except Exception:
        return os.getcwd()


def compute_hmac_hex(secret: str, data_bytes: bytes) -> str:
    """Compute HMAC-SHA256 (hex lowercase) of data_bytes using the given secret string (UTF-8).

    This mirrors the PowerShell script which uses UTF-8 bytes of the secret.
    """
    if isinstance(secret, str):
        key_bytes = secret.encode("utf-8")
    else:
        key_bytes = secret
    return hmac.new(key_bytes, data_bytes, hashlib.sha256).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Test POST for osdu-relay (port of test-post.ps1)")
    parser.add_argument(
        "-s",
        "--hmac-secret",
        dest="hmac_secret",
        default=None,
        help="HMAC secret (overrides HMAC_SECRET env var); if omitted falls back to 'testSecret'.",
    )
    parser.add_argument(
        "-e",
        "--endpoint",
        dest="endpoint",
        default="http://localhost:7071/api/osdu-relay",
        help="Endpoint URL to call (default: http://localhost:7071/api/osdu-relay)",
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="file",
        default=None,
        help="Path to JSON file to POST (default: osdu-body.json next to this script)",
    )

    args = parser.parse_args()

    secret = args.hmac_secret if args.hmac_secret is not None else os.environ.get("HMAC_SECRET", "testSecret")
    endpoint = args.endpoint
    file_path = args.file if args.file else os.path.join(resolve_script_dir(), "osdu-body.json")

    if not os.path.exists(file_path):
        print(f"File '{file_path}' not found. Please create 'osdu-body.json' in the script folder or pass -f FILE", file=sys.stderr)
        sys.exit(1)

    # Read raw bytes so we compute the HMAC over the exact bytes.
    try:
        with open(file_path, "rb") as fh:
            body_bytes = fh.read()
    except OSError as exc:
        print(f"Failed to read '{file_path}': {exc}", file=sys.stderr)
        sys.exit(1)

    sig_hex = compute_hmac_hex(secret, body_bytes)

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"hmac {sig_hex}",
    }

    print(f"POST -> {endpoint} (file: {file_path})")

    try:
        resp = requests.post(endpoint, headers=headers, data=body_bytes, timeout=30)
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        sys.exit(1)

    text = resp.text

    # Try to parse JSON; if it fails print the raw text
    try:
        parsed: Any = resp.json()
    except ValueError:
        print(text)
        return

    # PowerShell pipeline did: ConvertFrom-Json | Select-Object -First 1
    # So if the response is a list, prefer the first element
    if isinstance(parsed, (list, tuple)):
        out = parsed[0] if len(parsed) > 0 else parsed
    else:
        out = parsed

    # Print pretty JSON (ensure_ascii=False keeps unicode readable)
    try:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    except (TypeError, ValueError):
        # Fallback: print the raw repr
        print(repr(out))


if __name__ == "__main__":
    main()
