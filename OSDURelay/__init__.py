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
from azure.identity import DefaultAzureCredential
from azure.eventgrid import EventGridPublisherClient
from azure.keyvault.secrets import SecretClient
from urllib.parse import urlparse
import requests

# ---------------------------------------------------------------------------
# Configuration (driven by environment)
# ---------------------------------------------------------------------------
HMAC_SECRET = os.environ.get("HMAC_SECRET", "")
# Key Vault configuration (optional). If provided, the function will attempt to
# retrieve the HMAC secret from Key Vault using DefaultAzureCredential (managed identity
# when running in Azure). You can provide either the full secret URI (KEY_VAULT_SECRET_URI)
# or the vault URL + secret name (KEY_VAULT_URL and KEY_VAULT_SECRET_NAME).
KEY_VAULT_SECRET_URI = os.environ.get("KEY_VAULT_SECRET_URI", "")
KEY_VAULT_URL = os.environ.get("KEY_VAULT_URL", "")
KEY_VAULT_SECRET_NAME = os.environ.get("KEY_VAULT_SECRET_NAME", "")

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

# Event Grid configuration
# EVENT_GRID_ENDPOINT is required. Authentication can be via:
#  - Managed Identity / AAD (DefaultAzureCredential). Set EVENT_GRID_AUTH to "managed" (default) and grant Data Sender role.
#  - Access Key. Set EVENT_GRID_AUTH to "key" and provide EVENT_GRID_KEY.
EVENT_GRID_ENDPOINT = os.environ["EVENT_GRID_ENDPOINT"]
EVENT_GRID_AUTH = os.environ.get("EVENT_GRID_AUTH", "managed").lower()  # managed | key
EVENT_GRID_NAMESPACE_TOPIC = os.environ.get("EVENT_GRID_NAMESPACE_TOPIC", "")  # only for Namespaces
EVENT_GRID_KEY = os.environ.get("EVENT_GRID_KEY", "")

# Event types: either single event type for all ops, or map by op
EVENT_TYPE_MODE = os.environ.get("EVENT_TYPE_MODE", "single").lower()
EVENT_TYPE_SINGLE = os.environ.get("EVENT_TYPE_SINGLE", "osdu.record.changed")
EVENT_TYPE_BY_OP_CREATE = os.environ.get("EVENT_TYPE_BY_OP_CREATE", "osdu.record.create")
EVENT_TYPE_BY_OP_UPDATE = os.environ.get("EVENT_TYPE_BY_OP_UPDATE", "osdu.record.update")
EVENT_TYPE_BY_OP_DELETE = os.environ.get("EVENT_TYPE_BY_OP_DELETE", "osdu.record.delete")

# Internal constants for OSDU-style signature chain (used during handshake verification)
NOTIFICATION_SERVICE = "de-notification-service"
EXPIRE_DURATION_MS = 30000

# Cache for retrieved secret (to avoid repeated Key Vault calls)
_cached_hmac_secret: Optional[str] = None

# Default CloudEvent source when publishing via Event Grid Namespace
EVENT_GRID_CLOUD_SOURCE = os.environ.get("EVENT_GRID_CLOUD_SOURCE", "/osdu/relay")


def _fetch_secret_from_keyvault() -> Optional[str]:
    """Attempt to fetch the HMAC secret from Key Vault using DefaultAzureCredential.

    Supports:
      - KEY_VAULT_SECRET_URI (full secret URI): https://<vault>.vault.azure.net/secrets/<name>[/<version>]
      - KEY_VAULT_URL + KEY_VAULT_SECRET_NAME (vault base URL and secret name)
    """
    global _cached_hmac_secret
    if not (KEY_VAULT_SECRET_URI or (KEY_VAULT_URL and KEY_VAULT_SECRET_NAME)):
        return None
    try:
        if KEY_VAULT_SECRET_URI:
            parsed = urlparse(KEY_VAULT_SECRET_URI)
            vault_url = f"{parsed.scheme}://{parsed.netloc}"
            path_parts = [p for p in parsed.path.split("/") if p]
            if len(path_parts) >= 2 and path_parts[0].lower() == "secrets":
                secret_name = path_parts[1]
                secret_version = path_parts[2] if len(path_parts) >= 3 else None
            else:
                raise ValueError("KEY_VAULT_SECRET_URI does not contain a valid secret path.")
        else:
            vault_url = KEY_VAULT_URL
            secret_name = KEY_VAULT_SECRET_NAME
            secret_version = None

        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=vault_url, credential=credential)
        if secret_version:
            secret_bundle = client.get_secret(secret_name, secret_version)
        else:
            secret_bundle = client.get_secret(secret_name)
        value = secret_bundle.value or ""
        logging.info("Fetched HMAC secret from Key Vault (vault=%s, secret=%s)", vault_url, secret_name)
        return value
    except Exception as ex:
        logging.exception("Failed to fetch secret from Key Vault: %s", ex)
        raise


def _get_hmac_secret() -> Optional[str]:
    """Return the HMAC secret, preferring Key Vault (if configured), otherwise env var HMAC_SECRET."""
    global _cached_hmac_secret
    if _cached_hmac_secret:
        return _cached_hmac_secret

    try:
        kv = _fetch_secret_from_keyvault()
        if kv:
            _cached_hmac_secret = kv
            return _cached_hmac_secret
    except Exception:
        # Not fatal for local/dev; fall back to env var
        logging.info("Key Vault secret lookup failed; using HMAC_SECRET from environment if present.")

    if HMAC_SECRET:
        _cached_hmac_secret = HMAC_SECRET
        return _cached_hmac_secret

    return None

# ---------------------------------------------------------------------------
# Cryptographic helpers
# ---------------------------------------------------------------------------


def _digest(body: bytes) -> bytes:
    """Return HMAC-SHA256 digest bytes for the given body using configured secret.

    Only SHA-256 is supported in this implementation (consistent with original behavior).
    """
    if HMAC_ALGO != "sha256":
        raise ValueError("Only sha256 is supported in this template.")
    secret = _get_hmac_secret()
    if not secret:
        raise ValueError("Missing HMAC secret (configure KEY_VAULT_SECRET_URI/KEY_VAULT_URL+KEY_VAULT_SECRET_NAME or HMAC_SECRET env var)")
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()



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
    """Publish payload to Event Grid using Managed Identity (AAD) when configured, else fallback to Access Key.

    When EVENT_GRID_AUTH == "managed":
      - Uses DefaultAzureCredential and EventGridPublisherClient.
      - For Namespace endpoints, optionally supply EVENT_GRID_NAMESPACE_TOPIC.

    When EVENT_GRID_AUTH == "key":
      - Uses HTTP POST with aeg-sas-key header (legacy path).
    """
    # Prefer Managed Identity / AAD
    if EVENT_GRID_AUTH == "managed":
        try:
            credential = DefaultAzureCredential()
            # For Event Grid Basic, endpoint should be full https URL.
            # For Namespaces, endpoint is hostname without scheme per SDK docs, but SDK accepts both.
            namespace_topic = EVENT_GRID_NAMESPACE_TOPIC or None
            client = EventGridPublisherClient(
                EVENT_GRID_ENDPOINT,
                credential,
                namespace_topic=namespace_topic,
            )
            # The SDK expects Python objects (dict/list) not raw bytes; parse once
            payload = json.loads(body.decode("utf-8"))
            # If targeting Namespace, ensure CloudEvent schema
            if namespace_topic and isinstance(payload, list):
                def to_cloudevent(ev: Dict[str, Any]) -> Dict[str, Any]:
                    # Map EventGridEvent-like dict to CloudEvent dict
                    if isinstance(ev, dict) and {"eventType", "data"}.issubset(ev.keys()):
                        return {
                            "id": ev.get("id") or str(uuid.uuid4()),
                            "source": EVENT_GRID_CLOUD_SOURCE,
                            "type": ev.get("eventType") or EVENT_TYPE_SINGLE,
                            "subject": ev.get("subject"),
                            "time": ev.get("eventTime"),
                            "data": ev.get("data", {}),
                            "specversion": "1.0",
                        }
                    # Assume already CloudEvent-like
                    return ev

                payload = [to_cloudevent(it) for it in payload]

            client.send(payload)
            # Mimic requests.Response minimal contract for callers
            class _Resp:
                status_code = 200
                text = "OK"

                def raise_for_status(self):
                    return None

            return _Resp()
        except Exception as ex:
            logging.exception("Managed Identity publish failed; falling back to key if configured. Error: %s", ex)
            # If key available, try fallback; else re-raise wrapped as HTTPError-like
            if not EVENT_GRID_KEY:
                raise

    # Fallback to Access Key over HTTP
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
      OSDU DataNotification items into Event Grid events; forward them to Event Grid.
    """
    try:
        # Log incoming request details for debugging (method, url, headers, params, body)
        try:
            raw_body = req.get_body() or b""
            try:
                body_text = raw_body.decode("utf-8")
            except Exception:
                # Fallback to replace so logging never fails on binary content
                body_text = raw_body.decode("utf-8", errors="replace")
        except Exception as ex:
            raw_body = b""
            body_text = f"<<unreadable body: {ex}>>"

        headers_dict = dict(req.headers) if hasattr(req, "headers") else {}
        params_dict = dict(req.params) if hasattr(req, "params") else {}
        request_url = getattr(req, "url", "")

        logging.info("Incoming HTTP request:")
        logging.info(f"    Method: {req.method}")
        logging.info(f"    URL: {request_url}")
        logging.info(f"    Headers: {headers_dict}")
        logging.info(f"    Query Params: {params_dict}")
        # Limit body logged length to prevent extremely large logs
        logging.info(f"    Body (first 20k chars): {body_text[:20000]}")

        # --------------------
        # GET: readiness / handshake
        # --------------------
        if req.method and req.method.upper() == "GET":
            crc = req.params.get("crc")
            hmac_token = req.params.get("hmac")

            # If both challenge params present, perform verification and respond
            if crc and hmac_token:
                secret_val = _get_hmac_secret()
                if not secret_val:
                    logging.error("HMAC secret not configured. Set KEY_VAULT_SECRET_URI or HMAC_SECRET env var.")
                    return func.HttpResponse("Server misconfigured.", status_code=500)

                # optional heuristic warning for secret format
                if not _is_valid_hex_like_secret(secret_val):
                    logging.warning("HMAC secret may not conform to OSDU requirements (alphanumeric, even length).")

                try:
                    if CHALLENGE_HMAC_REQUIRED:
                        _verify_token_signature(hmac_token, secret_val)
                    else:
                        # still attempt verification, but ignore failure if not required
                        try:
                            _verify_token_signature(hmac_token, secret_val)
                        except Exception as ex:
                            logging.info(f"Challenge signature check skipped/ignored: {ex}")

                    response_hash = _get_response_hash(f"{secret_val}{crc}")
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

        secret_val = _get_hmac_secret()
        if not secret_val:
            logging.error("HMAC secret not configured. Set KEY_VAULT_SECRET_URI or HMAC_SECRET env var.")
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
