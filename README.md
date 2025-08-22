# OSDU Notification Relay for Azure Event Grid

This repository contains a small Azure Functions-based relay that accepts OSDU notification callbacks, validates HMAC signatures (including the OSDU handshake/challenge), optionally translates OSDU DataNotification payloads into Azure Event Grid events, and forwards events to an Event Grid topic.

Key files
- `OSDURelay/` — Azure Function implementation (`__init__.py`, `function.json`). Route: `/api/osdu-relay`.
- `local.settings.json` — local development environment variables (not for production).
- `requirements.txt` — Python dependencies.
- `tests/` — convenience scripts used to exercise GET/POST behavior (`test-get.py`, `test-post.py`, `osdu-body.json`, `event.json`).

Overview
--------
The function performs the following responsibilities:
- Verify incoming HMAC signatures from headers or query string.
- Handle OSDU 'challenge' handshake (GET with `crc` and `hmac`) and emit the expected response hash.
- Detect whether an incoming POST payload is already Event Grid schema or an OSDU DataNotification list.
  - If OSDU DataNotification list => translate each item into Event Grid event objects.
  - If Event Grid schema already, forward as-is.
- Forward the (translated) payload to the configured Event Grid endpoint using the provided SAS key.

Configuration (environment variables)
-------------------------------------
The function is controlled by environment variables (set in `local.settings.json` for local dev). Important variables:

- `EVENT_GRID_ENDPOINT` (required) — Event Grid topic endpoint (e.g. https://<my-topic>.<region>.eventgrid.azure.net/api/events)
- `EVENT_GRID_KEY` (required) — SAS key for your Event Grid topic
- `HMAC_SECRET` — secret used to validate HMAC signatures (UTF-8 by default; for OSDU challenge chaining a hex-like secret is expected)
- `HMAC_HEADER` — header to read signature from (default `Authorization`)
- `HMAC_ALGO` — signature algorithm (currently only `sha256` supported)
- `SIGNATURE_FORMAT` — `hex` (default) or `base64` used for incoming/outgoing signature format
- `SIGNATURE_PREFIX` — prefix to strip from header value (defaults to `hmac `)
- `CHALLENGE_HMAC_REQUIRED` — `true|false` whether the GET challenge must be validated against `HMAC_SECRET`
- `CHALLENGE_HASH_ENCODING` — how challenge responseHash is encoded (e.g., `base64-hex`, `base64-raw`, `hex`)
- `EVENT_TYPE_MODE` — `single` or `by_op` (controls whether eventType is same for all records or mapped by create/update/delete)
- `EVENT_TYPE_SINGLE`, `EVENT_TYPE_BY_OP_CREATE`, `EVENT_TYPE_BY_OP_UPDATE`, `EVENT_TYPE_BY_OP_DELETE` — values used to populate Event Grid eventType

Security note: Never commit real secrets (e.g., `EVENT_GRID_KEY` or `HMAC_SECRET`) to source control. Use Azure Key Vault / managed identities in production.

Local development
-----------------
Prereqs:
- Python 3.10+ (3.12 tested in this workspace)
- Azure Functions Core Tools v4 (for local host emulation)
- Azure CLI (optional, for deployment)

Windows PowerShell quick start (from repository root):

1) Create and activate a virtual environment and install dependencies:

   python -m venv .venv; .\.venv\Scripts\Activate.ps1; python -m pip install -r requirements.txt

2) Ensure `local.settings.json` contains the required values mentioned above. Example values are already present in the repo for local testing, but replace placeholders with your own values when necessary.

3) Run the function locally:

   func host start

   (You can also use the VS Code task `func: host start` as configured in this workspace.)

Testing the function
--------------------
- To POST a sample OSDU DataNotification payload and automatically compute the HMAC header, run:

  python tests/test-post.py

  The script computes the required `Authorization: hmac <hex>` header using `HMAC_SECRET` env var (or `testSecret` fallback) and posts the `tests/osdu-body.json` to the local function at `http://localhost:7071/api/osdu-relay`.

- To test GET / handshake / readiness:

  python tests/test-get.py             # ping (no challenge) by default
  python tests/test-get.py --challenge # performs the OSDU handshake using the configured secret (requires `HMAC_SECRET`)

- You can also use curl/Invoke-WebRequest. Example (POSIX/cURL style):

  curl -X POST "http://localhost:7071/api/osdu-relay" -H "Content-Type: application/json" -H "Authorization: hmac <signature>" --data @tests/osdu-body.json

  Note: on Windows PowerShell the `curl` alias maps to Invoke-WebRequest; prefer the provided Python test scripts to compute the correct signature.

How the function decides translation
-----------------------------------
- Incoming JSON that is a list will be inspected:
  - If it *already* matches Event Grid event schema (objects with keys `id`, `eventType`, `eventTime`, `subject`, `data`, `dataVersion`), it is forwarded unchanged.
  - If it looks like an OSDU DataNotification list (items having `id`, `kind`, `op`), the function translates each item into an Event Grid event object and forwards the resulting list.
  - Otherwise the body is forwarded as-is.

Forwarding / Dry-run
--------------------
- Use query parameter `?dryRun=1` (or `true`) on a POST to return the translated payload without forwarding to Event Grid.

Deploying to Azure
------------------
A simple example using Azure CLI + Functions Core Tools:

1) Login and set subscription:

   az login
   az account set --subscription <YOUR_SUBSCRIPTION_ID>

2) Create a resource group and storage account (example):

   az group create --name <RG> --location <LOCATION>
   az storage account create --name <STORAGE_NAME> --resource-group <RG> --location <LOCATION> --sku Standard_LRS

3) Create Function App for Python (Consumption plan example):

   az functionapp create --resource-group <RG> --consumption-plan-location <LOCATION> --name <FUNCTION_APP_NAME> --storage-account <STORAGE_NAME> --location <LOCATION> --runtime python --runtime-version 3.10 --functions-version 4

4) Set application settings (replace placeholders):

   az functionapp config appsettings set --name <FUNCTION_APP_NAME> --resource-group <RG> --settings \
       HMAC_SECRET="<your-secret>" \
       EVENT_GRID_ENDPOINT="https://<your-eventgrid-host>/api/events" \
       EVENT_GRID_KEY="<your-event-grid-key>" \
       HMAC_HEADER="Authorization" \
       SIGNATURE_FORMAT="hex"

   Add any additional settings from the configuration list above as needed.

5) Deploy code (from repo root):

   func azure functionapp publish <FUNCTION_APP_NAME> --python

Security and production notes
-----------------------------
- Do not put secrets in `local.settings.json` or in Git. Use Azure Key Vault and reference secrets via App Service/Function App settings or use Managed Identity.
- Consider restricting Event Grid topic access with appropriate RBAC or private endpoints.
- Enable Application Insights and review logs (host.json already contains a minimal Application Insights sampling config).

Troubleshooting
---------------
- If signature checks fail, confirm the HMAC computed by the client uses the same bytes (UTF-8) as the server.
- The OSDU challenge flow expects a chained HMAC construction when using a hex-like secret; see `tests/test-get.py` for an example implementation of the chain.
- Use `?dryRun=1` to see the payload that would be sent to Event Grid.

Contributing
------------
Ideas and fixes welcome. For production hardening, consider adding additional tests, monitoring, and better secrets management.

License
-------
This repository is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 Eirik Haughom

