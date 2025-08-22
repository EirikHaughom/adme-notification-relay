import os
import re
import hmac
import hashlib
import base64
import json
import logging
import time
import uuid
from datetime import datetime, timezone
import azure.functions as func
import requests

# ---- Config via env ----
HMAC_SECRET = os.environ.get("HMAC_SECRET", "")
HMAC_HEADER = os.environ.get("HMAC_HEADER", "Authorization")
HMAC_ALGO = os.environ.get("HMAC_ALGO", "sha256").lower()
SIGNATURE_FORMAT = os.environ.get("SIGNATURE_FORMAT", "hex").lower()   # "hex" or "base64"
SIGNATURE_PREFIX = os.environ.get("SIGNATURE_PREFIX", "hmac ")

# Challenge/handshake behavior
CHALLENGE_HMAC_REQUIRED = os.environ.get("CHALLENGE_HMAC_REQUIRED", "true").lower() == "true"
# How to encode the challenge response hash; options: "base64-raw" (recommended), "base64-hex" (legacy), "hex"
CHALLENGE_HASH_ENCODING = os.environ.get("CHALLENGE_HASH_ENCODING", "base64-hex").lower()

EVENT_GRID_ENDPOINT = os.environ["EVENT_GRID_ENDPOINT"]
EVENT_GRID_KEY = os.environ["EVENT_GRID_KEY"]

# ---- Event mapping config ----
# MODE: 'single' uses one eventType for all OSDU ops; 'by_op' maps create/update/delete separately.
EVENT_TYPE_MODE = os.environ.get("EVENT_TYPE_MODE", "single").lower()  # 'single' or 'by_op'
EVENT_TYPE_SINGLE = os.environ.get("EVENT_TYPE_SINGLE", "osdu.record.changed")
EVENT_TYPE_BY_OP_CREATE = os.environ.get("EVENT_TYPE_BY_OP_CREATE", "osdu.record.create")
EVENT_TYPE_BY_OP_UPDATE = os.environ.get("EVENT_TYPE_BY_OP_UPDATE", "osdu.record.update")
EVENT_TYPE_BY_OP_DELETE = os.environ.get("EVENT_TYPE_BY_OP_DELETE", "osdu.record.delete")

# ---- Signature verification constants ----
NOTIFICATION_SERVICE = "de-notification-service"
EXPIRE_DURATION_MS = 30000

def _digest(body: bytes) -> bytes:
    if HMAC_ALGO != "sha256":
        raise ValueError("Only sha256 is supported in this template.")
    return hmac.new(HMAC_SECRET.encode("utf-8"), body, hashlib.sha256).digest()

def _constant_time_equals(a: str, b: str) -> bool:
    # Normalize case/whitespace for safety
    return hmac.compare_digest(a.strip(), b.strip())

def _compute_signature(body: bytes) -> str:
    raw = _digest(body)
    if SIGNATURE_FORMAT == "base64":
        return base64.b64encode(raw).decode("utf-8")
    # default hex
    return raw.hex()

def _extract_incoming_signature(req: func.HttpRequest) -> str:
    # 1) Preferred header (e.g., Authorization: hmac <sig>)
    sig = req.headers.get(HMAC_HEADER, "")
    # 2) Fallback header named "hmac"
    if not sig:
        # Case-insensitive lookup for 'hmac' header
        for k, v in req.headers.items():
            if k.lower() == "hmac":
                sig = v or ""
                break
    # 3) Query parameter ?hmac=...
    if not sig:
        sig = req.params.get("hmac", "")
    # Normalize by removing optional signature prefix
    if sig and SIGNATURE_PREFIX and sig.lower().startswith(SIGNATURE_PREFIX.lower()):
        sig = sig[len(SIGNATURE_PREFIX):]
    return sig

# ------------- Helpers for OSDU-style challenge verification -------------
def _hex_to_bytes(s: str) -> bytes:
    s = s.strip()
    return bytes.fromhex(s)

def _hmac_sha256_bytes(data: bytes, key: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def _compute_signature_chain(secret_hex: str, nonce_hex: str, timestamp_str: str, data_str: str) -> bytes:
    secret_bytes = _hex_to_bytes(secret_hex)
    nonce_bytes = _hex_to_bytes(nonce_hex)
    encrypted_nonce = _hmac_sha256_bytes(nonce_bytes, secret_bytes)
    encrypted_timestamp = _hmac_sha256_bytes(timestamp_str.encode("utf-8"), encrypted_nonce)
    signed_key = _hmac_sha256_bytes(NOTIFICATION_SERVICE.encode("utf-8"), encrypted_timestamp)
    return _hmac_sha256_bytes(data_str.encode("utf-8"), signed_key)

def _get_signed_signature(url: str, secret_hex: str, expire_ms_str: str, nonce_hex: str) -> str:
    if not url or not secret_hex:
        raise ValueError("Error generating signature")
    expiry = int(expire_ms_str)
    if int(time.time() * 1000) > expiry:
        raise ValueError("Signature expired")
    timestamp = str(expiry - EXPIRE_DURATION_MS)
    # Ensure field order and formatting match what the signer expects exactly
    data = f'{{"expireMillisecond": "{expire_ms_str}","hashMechanism": "hmacSHA256","endpointUrl": "{url}","nonce": "{nonce_hex}"}}'
    sig_bytes = _compute_signature_chain(secret_hex, nonce_hex, timestamp, data)
    return sig_bytes.hex()

def _verify_token_signature(hmac_token: str, secret_hex: str) -> None:
    if not hmac_token:
        raise ValueError("Missing HMAC signature")
    if not secret_hex:
        raise ValueError("Missing secret value")
    parts = hmac_token.split(".")
    if len(parts) != 2:
        raise ValueError("Invalid signature")
    data_b64, request_sig = parts[0], parts[1]
    data_bytes = base64.b64decode(data_b64)
    try:
        payload = json.loads(data_bytes.decode("utf-8"))
    except Exception:
        # Fallback: payload might not be strict JSON, try as raw string-to-JSON
        payload = {}
    url = payload.get("endpointUrl")
    nonce = payload.get("nonce")
    expire_ms = payload.get("expireMillisecond")
    if not url or not nonce or not expire_ms:
        raise ValueError("Missing attributes in signature")
    new_sig = _get_signed_signature(url, secret_hex, str(expire_ms), nonce)
    if not _constant_time_equals(request_sig.lower(), new_sig.lower()):
        raise ValueError("Invalid signature")

def _get_response_hash(input_str: str) -> str:
    # Compute SHA-256 over input and encode based on configured preference
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

def _is_valid_hex_like_secret(s: str) -> bool:
    # Docs: only alphanumeric, even length (implies hex-like). Be permissive on case.
    return bool(re.fullmatch(r"[A-Za-z0-9]+", s)) and len(s) % 2 == 0

def _forward_to_event_grid(body: bytes):
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "aeg-sas-key": EVENT_GRID_KEY
    }
    resp = requests.post(EVENT_GRID_ENDPOINT, data=body, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp

# -------------------- Schema detection and translation --------------------
def _is_eventgrid_event(obj: dict) -> bool:
    required_keys = {"id", "eventType", "eventTime", "subject", "data", "dataVersion"}
    return isinstance(obj, dict) and required_keys.issubset(obj.keys())

def _is_eventgrid_batch(payload) -> bool:
    return isinstance(payload, list) and all(isinstance(it, dict) and _is_eventgrid_event(it) for it in payload)

def _is_osdu_data_notification_item(obj: dict) -> bool:
    # Per OSDU DataNotification sample: id, kind, op, optional recordUpdated/deletionType
    return isinstance(obj, dict) and {"id", "kind", "op"}.issubset(obj.keys())

def _is_osdu_data_notification(payload) -> bool:
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

def _translate_osdu_to_eventgrid(items: list[dict]) -> list[dict]:
    now_iso = datetime.now(timezone.utc).isoformat()
    events = []
    for it in items:
        record_id = str(it.get("id"))
        kind = str(it.get("kind", ""))
        op = str(it.get("op", ""))
        subject = f"/osdu/{kind}/{record_id}" if kind else f"/osdu/{record_id}"
        ev = {
            "id": str(uuid.uuid4()),
            "eventType": _event_type_for_op(op),
            "eventTime": now_iso,
            "subject": subject,
            "data": {
                "recordId": record_id,
                "kind": kind,
                "op": op,
                # Pass through optional fields when present
                **({"recordUpdated": it.get("recordUpdated")} if "recordUpdated" in it else {}),
                **({"deletionType": it.get("deletionType")} if "deletionType" in it else {}),
                # Preserve any additional fields conservatively
                **{k: v for k, v in it.items() if k not in {"id", "kind", "op", "recordUpdated", "deletionType"}}
            },
            "dataVersion": "1.0",
        }
        events.append(ev)
    return events

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Support GET for handshake/probe; return 200 with minimal info
        if req.method and req.method.upper() == "GET":
            # If OSDU challenge parameters are present, run verification
            crc = req.params.get("crc")
            hmac_token = req.params.get("hmac")
            if crc and hmac_token:
                # Secret expected in HEX format
                if not HMAC_SECRET:
                    logging.error("HMAC_SECRET not configured.")
                    return func.HttpResponse("Server misconfigured.", status_code=500)
                # Optionally validate that secret conforms to docs
                if not _is_valid_hex_like_secret(HMAC_SECRET):
                    logging.warning("HMAC_SECRET may not conform to OSDU requirements (alphanumeric, even length).")
                try:
                    if CHALLENGE_HMAC_REQUIRED:
                        _verify_token_signature(hmac_token, HMAC_SECRET)
                    else:
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
            # If one of crc/hmac is present but not both, decide behavior based on strictness
            if (crc and not hmac_token) or (hmac_token and not crc):
                if CHALLENGE_HMAC_REQUIRED:
                    return func.HttpResponse("Missing crc or hmac for challenge.", status_code=400)
            return func.HttpResponse("OSDU Message Broker for Azure Event Grid is ready.", status_code=200)

        # POST path
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

        # Signature OK → detect schema and translate OSDU notifications into Event Grid schema
        translated_body = body
        try:
            payload = json.loads(body.decode("utf-8"))
            if isinstance(payload, list):
                if _is_eventgrid_batch(payload):
                    # Already Event Grid schema: forward as-is
                    translated_body = body
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
        return func.HttpResponse(f"Event Grid error: {http_err.response.status_code} {http_err.response.text}", status_code=502)
    except Exception as ex:
        logging.exception("Unhandled error.")
        return func.HttpResponse(f"Error: {str(ex)}", status_code=500)
