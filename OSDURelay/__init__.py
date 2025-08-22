"""
OSDU Relay for Azure Event Grid (Azure Function)

This module accepts OSDU notification callbacks, verifies HMAC signatures (header or query),
handles OSDU-style handshake/challenge requests, translates OSDU DataNotification items into
Azure Event Grid events (when needed), and forwards them to an Event Grid topic.

The original behavior and configuration are preserved. Environment variables control
behavior and keys; see variables below for names.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import azure.functions as func
import requests

# ---------------------------------------------------------------------------
# Configuration (driven by environment)
# ---------------------------------------------------------------------------
HMAC_SECRET = os.environ.get("HMAC_SECRET", "")
HMAC_HEADER = os.environ.get("HMAC_HEADER", "Authorization")
HMAC_ALGO = os.environ.get("HMAC_ALGO", "sha256").lower()
SIGNATURE_FORMAT = os.environ.get("SIGNATURE_FORMAT", "hex").lower()   # "hex" or "base64"
SIGNATURE_PREFIX = os.environ.get("SIGNATURE_PREFIX", "hmac ")

# Challenge/handshake behavior
CHALLENGE_HMAC_REQUIRED = os.environ.get("CHALLENGE_HMAC_REQUIRED", "true").lower() == "true"
# Choice for challenge response hash representation. Known values:
# - base64-raw (recommended): raw SHA-256 bytes base64-encoded
# - base64-hex (legacy): hex string of SHA-256, base64-encoded
# - hex: hex string of SHA-256
CHALLENGE_HASH_ENCODING = os.environ.get("CHALLENGE_HASH_ENCODING", "base64-hex").lower()

# Event Grid configuration (required)
EVENT_GRID_ENDPOINT = os.environ["EVENT_GRID_ENDPOINT"]
EVENT_GRID_KEY = os.environ["EVENT_GRID_KEY"]

# Event types: either single event type for all ops, or map by op
EVENT_TYPE_MODE = os.environ.get("EVENT_TYPE_MODE", "single").lower()
EVENT_TYPE_SINGLE = os.environ.get("EVENT_TYPE_SINGLE", "osdu.record.changed")
EVENT_TYPE_BY_OP_CREATE = os.environ.get("EVENT_TYPE_BY_OP_CREATE", "osdu.record.create")
EVENT_TYPE_BY_OP_UPDATE = os.environ.get("EVENT_TYPE_BY_OP_UPDATE", "osdu.record.update")
EVENT_TYPE_BY_OP_DELETE = os.environ.get("EVENT_TYPE_BY_OP_DELETE", "osdu.record.delete")

# Internal constants for OSDU-style signature chain (used during handshake verification)
NOTIFICATION_SERVICE = "de-notification-service"
EXPIRE_DURATION_MS = 30000

# ---------------------------------------------------------------------------
# Cryptographic helpers
# ---------------------------------------------------------------------------

def _digest(body: bytes) -> bytes:
    """Return HMAC-SHA256 digest bytes for the given body using configured secret.

    Only SHA-256 is supported in this implementation (consistent with original behavior).
    """
    if HMAC_ALGO != "sha256":
        raise ValueError("Only sha256 is supported in this template.")
    return hmac.new(HMAC_SECRET.encode("utf-8"), body, hashlib.sha256).digest()


def _constant_time_equals(a: Optional[str], b: Optional[str]) -> bool:
    """Safely compare two strings in constant time; treat None as empty string."""
    return hmac.compare_digest((a or "").strip(), (b or "").strip())


def _compute_signature(body: bytes) -> str:
    """Compute the signature string for a body according to SIGNATURE_FORMAT.

    Returns either a hex string (default) or a base64 string when configured.
    """
    raw = _digest(body)
    if SIGNATURE_FORMAT == "base64":
        return base64.b64encode(raw).decode("utf-8")
    return raw.hex()

# ---------------------------------------------------------------------------
# Incoming signature extraction + verification helpers
# ---------------------------------------------------------------------------

def _extract_incoming_signature(req: func.HttpRequest) -> str:
    """Extract the HMAC signature provided by the caller.

    Order of precedence:
    1. Header named by HMAC_HEADER (default: 'Authorization')
    2. Any header named 'hmac' (case-insensitive)
    3. Query parameter 'hmac'

    Optional SIGNATURE_PREFIX is removed (case-insensitive) if present.
    """
    # 1) Preferred header (e.g., Authorization: hmac <sig>)
    sig = req.headers.get(HMAC_HEADER, "")

    # 2) Fallback: a header literally named 'hmac' (case-insensitive)
    if not sig:
        for k, v in req.headers.items():
            if k.lower() == "hmac":
                sig = v or ""
                break

    # 3) Fallback to query parameter
    if not sig:
        sig = req.params.get("hmac", "")

    # Remove optional prefix like 'hmac ' (case-insensitive)
    if sig and SIGNATURE_PREFIX and sig.lower().startswith(SIGNATURE_PREFIX.lower()):
        sig = sig[len(SIGNATURE_PREFIX):]

    return sig

# ---------------------------------------------------------------------------
# Helpers used for OSDU handshake verification (challenge)
# ---------------------------------------------------------------------------

def _hex_to_bytes(s: Optional[str]) -> bytes:
    """Convert a hex-like string into bytes.

    Accepts optional '0x' prefix. If `s` does not look like a hex string, we
    fall back to returning UTF-8 bytes of the string. This keeps behavior
    compatible with the original code (useful for local testing with non-hex
    secrets).
    """
    if s is None:
        return b""
    val = str(s).strip()
    # Accept optional 0x prefix
    if val.startswith(("0x", "0X")):
        val = val[2:]
    # If it looks like hex, try converting
    if re.fullmatch(r"[A-Fa-f0-9]+", val):
        if len(val) % 2 == 1:
            val = "0" + val  # pad odd-length hex
        try:
            return bytes.fromhex(val)
        except Exception as ex:  # pragma: no cover - protective fallback
            logging.warning(f"_hex_to_bytes: bytes.fromhex failed: {ex}; falling back to UTF-8 bytes.")
    else:
        logging.debug("_hex_to_bytes: input does not match hex pattern; falling back to UTF-8 bytes.")
    return val.encode("utf-8")


def _hmac_sha256_bytes(data: bytes, key: bytes) -> bytes:
    """HMAC-SHA256 producing raw bytes (convenience wrapper)."""
    return hmac.new(key, data, hashlib.sha256).digest()


def _compute_signature_chain(secret_hex: str, nonce_hex: str, timestamp_str: str, data_str: str) -> bytes:
    """Perform the OSDU-style chained HMAC derivation used in challenge tokens.

    The steps follow the documented chain:
      encrypted_nonce = HMAC(secret, nonce)
      encrypted_timestamp = HMAC(encrypted_nonce, timestamp)
      signed_key = HMAC(encrypted_timestamp, NOTIFICATION_SERVICE)
      final_signature = HMAC(signed_key, data)

    Returns the raw signature bytes.
    """
    secret_bytes = _hex_to_bytes(secret_hex)
    nonce_bytes = _hex_to_bytes(nonce_hex)

    encrypted_nonce = _hmac_sha256_bytes(nonce_bytes, secret_bytes)
    encrypted_timestamp = _hmac_sha256_bytes(timestamp_str.encode("utf-8"), encrypted_nonce)
    signed_key = _hmac_sha256_bytes(NOTIFICATION_SERVICE.encode("utf-8"), encrypted_timestamp)
    return _hmac_sha256_bytes(data_str.encode("utf-8"), signed_key)


def _get_signed_signature(url: str, secret_hex: str, expire_ms_str: str, nonce_hex: str) -> str:
    """Given handshake payload components, reproduce the expected signature (hex string).

    Validates that the expiry hasn't passed and then computes the signature bytes
    via _compute_signature_chain, returning a lowercase hex string.
    """
    if not url or not secret_hex:
        raise ValueError("Error generating signature")
    expiry = int(expire_ms_str)
    if int(time.time() * 1000) > expiry:
        raise ValueError("Signature expired")

    # Timestamp used inside the chain (matches original implementation)
    timestamp = str(expiry - EXPIRE_DURATION_MS)

    # Data must be formatted exactly as expected by the signer
    data = f'{{"expireMillisecond": "{expire_ms_str}","hashMechanism": "hmacSHA256","endpointUrl": "{url}","nonce": "{nonce_hex}"}}'
    sig_bytes = _compute_signature_chain(secret_hex, nonce_hex, timestamp, data)
    return sig_bytes.hex()


def _verify_token_signature(hmac_token: str, secret_hex: str) -> None:
    """Verify an OSDU-style token of the form <base64_payload>.<hex_signature>.

    Raises ValueError when the token is missing/invalid/expired.
    """
    if not hmac_token:
        raise ValueError("Missing HMAC signature")
    if not secret_hex:
        raise ValueError("Missing secret value")

    parts = hmac_token.split(".")
    if len(parts) != 2:
        raise ValueError("Invalid signature")

    data_b64, request_sig = parts[0], parts[1]

    # Decode payload (first segment). Payload is base64-encoded JSON.
    data_bytes = base64.b64decode(data_b64)
    try:
        payload = json.loads(data_bytes.decode("utf-8"))
    except Exception:  # pragma: no cover - defensive
        payload = {}

    url = payload.get("endpointUrl")
    nonce = payload.get("nonce")
    expire_ms = payload.get("expireMillisecond")

    if not url or not nonce or not expire_ms:
        raise ValueError("Missing attributes in signature")

    new_sig = _get_signed_signature(url, secret_hex, str(expire_ms), nonce)
    if not _constant_time_equals(request_sig.lower(), new_sig.lower()):
        raise ValueError("Invalid signature")

# ---------------------------------------------------------------------------
# Challenge response hash
# ---------------------------------------------------------------------------

def _get_response_hash(input_str: str) -> str:
    """Compute a SHA-256 over input_str and return encoded hash according to
    CHALLENGE_HASH_ENCODING.
    """
    digest = hashlib.sha256(input_str.encode("utf-8")).digest()
    sha_hex = digest.hex()
    enc = CHALLENGE_HASH_ENCODING
    if enc in ("base64-raw", "raw-base64", "base64"):
        return base64.b64encode(digest).decode("utf-8")
    if enc in ("base64-hex", "hex-base64"):
        return base64.b64encode(sha_hex.encode("utf-8")).decode("utf-8")
    if enc == "hex":
        return sha_hex
    logging.warning(f"Unknown CHALLENGE_HASH_ENCODING='{CHALLENGE_HASH_ENCODING}', defaulting to base64-raw")
    return base64.b64encode(digest).decode("utf-8")

# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

def _is_valid_hex_like_secret(s: Optional[str]) -> bool:
    """Simple check: non-empty alphanumeric (hex-like), even length."""
    return bool(s) and bool(re.fullmatch(r"[A-Za-z0-9]+", s)) and len(s) % 2 == 0


def _forward_to_event_grid(body: bytes) -> requests.Response:
    """Post the (JSON) body to the configured Event Grid endpoint using SAS key."""
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "aeg-sas-key": EVENT_GRID_KEY,
    }
    resp = requests.post(EVENT_GRID_ENDPOINT, data=body, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp

# ---------------------------------------------------------------------------
# Schema detection & translation: Event Grid vs OSDU DataNotification
# ---------------------------------------------------------------------------

def _is_eventgrid_event(obj: Dict[str, Any]) -> bool:
    required_keys = {"id", "eventType", "eventTime", "subject", "data", "dataVersion"}
    return isinstance(obj, dict) and required_keys.issubset(obj.keys())


def _is_eventgrid_batch(payload: Any) -> bool:
    return isinstance(payload, list) and all(isinstance(it, dict) and _is_eventgrid_event(it) for it in payload)


def _is_osdu_data_notification_item(obj: Dict[str, Any]) -> bool:
    # OSDU DataNotification items typically contain id, kind and op at minimum
    return isinstance(obj, dict) and {"id", "kind", "op"}.issubset(obj.keys())


def _is_osdu_data_notification(payload: Any) -> bool:
    return isinstance(payload, list) and len(payload) > 0 and all(_is_osdu_data_notification_item(it) for it in payload)


def _event_type_for_op(op: str) -> str:
    op_l = (op or "").lower()
    if EVENT_TYPE_MODE == "by_op":
        if op_l == "create":
            return EVENT_TYPE_BY_OP_CREATE
        if op_l == "update":
            return EVENT_TYPE_BY_OP_UPDATE
        if op_l == "delete":
            return EVENT_TYPE_BY_OP_DELETE
    return EVENT_TYPE_SINGLE


def _translate_osdu_to_eventgrid(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Translate a list of OSDU DataNotification items into Event Grid event objects."""
    now_iso = datetime.now(timezone.utc).isoformat()
    events: List[Dict[str, Any]] = []
    for it in items:
        record_id = str(it.get("id"))
        kind = str(it.get("kind", ""))
        op = str(it.get("op", ""))
        subject = f"/osdu/{kind}/{record_id}" if kind else f"/osdu/{record_id}"

        # Base data for Event Grid 'data' field; copy optional fields when present
        data = {
            "recordId": record_id,
            "kind": kind,
            "op": op,
            **({"recordUpdated": it.get("recordUpdated")} if "recordUpdated" in it else {}),
            **({"deletionType": it.get("deletionType")} if "deletionType" in it else {}),
            # Preserve any additional fields conservatively
            **{k: v for k, v in it.items() if k not in {"id", "kind", "op", "recordUpdated", "deletionType"}},
        }

        ev = {
            "id": str(uuid.uuid4()),
            "eventType": _event_type_for_op(op),
            "eventTime": now_iso,
            "subject": subject,
            "data": data,
            "dataVersion": "1.0",
        }
        events.append(ev)
    return events

# ---------------------------------------------------------------------------
# Azure Function entry point
# ---------------------------------------------------------------------------

def main(req: func.HttpRequest) -> func.HttpResponse:  # pragma: no cover - exercised by integration tests
    """Main Azure Function handler.

    Behavior summary:
    - GET: minimal readiness response; if 'crc' and 'hmac' query params are present,
      attempt OSDU-style challenge verification and return a JSON responseHash.
    - POST: verify incoming HMAC signature (header or query); optionally translate
      OSDU DataNotification list into Event Grid schema; forward to Event Grid.
    """
    try:
        # --------------------
        # GET: readiness / handshake
        # --------------------
        if req.method and req.method.upper() == "GET":
            crc = req.params.get("crc")
            hmac_token = req.params.get("hmac")

            # If both challenge params present, perform verification and respond
            if crc and hmac_token:
                if not HMAC_SECRET:
                    logging.error("HMAC_SECRET not configured.")
                    return func.HttpResponse("Server misconfigured.", status_code=500)

                # optional heuristic warning for secret format
                if not _is_valid_hex_like_secret(HMAC_SECRET):
                    logging.warning("HMAC_SECRET may not conform to OSDU requirements (alphanumeric, even length).")

                try:
                    if CHALLENGE_HMAC_REQUIRED:
                        _verify_token_signature(hmac_token, HMAC_SECRET)
                    else:
                        # still attempt verification, but ignore failure if not required
                        try:
                            _verify_token_signature(hmac_token, HMAC_SECRET)
                        except Exception as ex:
                            logging.info(f"Challenge signature check skipped/ignored: {ex}")

                    response_hash = _get_response_hash(f"{HMAC_SECRET}{crc}")
                    body = json.dumps({"responseHash": response_hash})
                    return func.HttpResponse(body, status_code=200, mimetype="application/json")
                except Exception as ex:
                    logging.warning(f"Challenge verification failed: {ex}")
                    return func.HttpResponse(str(ex), status_code=401)

            # If only one of crc/hmac present and strict mode is enabled, reject
            if (crc and not hmac_token) or (hmac_token and not crc):
                if CHALLENGE_HMAC_REQUIRED:
                    return func.HttpResponse("Missing crc or hmac for challenge.", status_code=400)

            # Default GET response
            return func.HttpResponse("OSDU Relay for Azure Event Grid is ready.", status_code=200)

        # --------------------
        # POST: verify HMAC signature then forward (possibly translating payload)
        # --------------------
        body = req.get_body() or b""
        incoming_sig = _extract_incoming_signature(req)

        if not HMAC_SECRET:
            logging.error("HMAC_SECRET not configured.")
            return func.HttpResponse("Server misconfigured.", status_code=500)

        if not incoming_sig:
            return func.HttpResponse("Missing HMAC signature.", status_code=401)

        computed = _compute_signature(body)
        if not _constant_time_equals(incoming_sig, computed):
            logging.warning("HMAC signature mismatch.")
            logging.warning(f"Computed: {computed}")
            logging.warning(f"Incoming: {incoming_sig}")
            return func.HttpResponse("Invalid signature.", status_code=401)

        # Signature OK -> attempt to detect/translate schema
        translated_body = body
        try:
            payload = json.loads(body.decode("utf-8-sig"))
            if isinstance(payload, list):
                if _is_eventgrid_batch(payload):
                    translated_body = body  # already Event Grid schema
                elif _is_osdu_data_notification(payload):
                    logging.info("Translating OSDU DataNotification payload to Event Grid schema.")
                    eg_events = _translate_osdu_to_eventgrid(payload)
                    translated_body = json.dumps(eg_events).encode("utf-8")
                else:
                    logging.info("Unknown list payload schema; forwarding as-is.")
            else:
                logging.info("Non-list payload; forwarding as-is.")
        except Exception as ex:
            logging.warning(f"Failed to parse JSON payload for translation: {ex}; forwarding as-is.")

        # Optional dry-run: return the translated payload without forwarding
        dry_run = (req.params.get("dryRun", "0") or "0").lower() in ("1", "true", "yes")
        if dry_run:
            return func.HttpResponse(body=translated_body, status_code=200, mimetype="application/json")

        # Forward to Event Grid
        eg_resp = _forward_to_event_grid(translated_body)
        return func.HttpResponse(f"Forwarded to Event Grid: {eg_resp.status_code}", status_code=200)

    except requests.HTTPError as http_err:
        logging.exception("Event Grid publish failed.")
        # http_err may include .response with details
        resp = getattr(http_err, "response", None)
        code = getattr(resp, "status_code", "")
        text = getattr(resp, "text", "")
        return func.HttpResponse(f"Event Grid error: {code} {text}", status_code=502)
    except Exception as ex:
        logging.exception("Unhandled error.")
        return func.HttpResponse(f"Error: {str(ex)}", status_code=500)
