# OSDU Notification Relay for Azure Event Grid

This repository contains a small Azure Functions-based relay that accepts OSDU notification callbacks, validates HMAC signatures (including the OSDU handshake/challenge), optionally translates OSDU DataNotification payloads into Azure Event Grid events, and forwards events to an Event Grid topic.

## Why pair OSDU with Azure Event Grid?

- Decouple producers and consumers with reliable, scalable pub/sub and easy fan‑out to many subscribers.
- Use built‑in capabilities like filtering, retries, and dead‑lettering to increase delivery reliability.
- Secure by design with Managed Identity/RBAC and optional private networking to protect endpoints and keys.
- Route events to a wide range of Azure services (Functions, Logic Apps, Service Bus, Storage) or custom webhooks with minimal code.

## Key files

- `OSDURelay/` — Azure Function implementation (`__init__.py`, `function.json`). Route: `/api/osdu-relay`.
- `local.settings.json` — local development environment variables (not for production).
- `requirements.txt` — Python dependencies.
- `tests/` — convenience scripts used to exercise GET/POST behavior (`test-get.py`, `test-post.py`, `osdu-body.json`, `event.json`).

## Overview

The function performs the following responsibilities:

- Verify incoming HMAC signatures from headers or query string.
- Handle OSDU 'challenge' handshake (GET with `crc` and `hmac`) and emit the expected response hash.
- Detect whether an incoming POST payload is already Event Grid schema or an OSDU DataNotification list.
  - If OSDU DataNotification list => translate each item into Event Grid event objects.
  - If Event Grid schema already, forward as-is.
- Forward the (translated) payload to the configured Event Grid endpoint using the provided SAS key.

## Azure prerequisites (resources)

You’ll need the following Azure resources in place (names are examples):

- Resource Group (RG)
- Storage Account (Functions state)
- Function App (Python)
- Key Vault (to store HMAC secret, optional but recommended)
- Event Grid destination
  - Either a Basic Topic or Domain
  - Or an Event Grid Namespace with a Namespace Topic

Example Azure CLI for creating Key Vault and Event Grid resources:

```powershell
# Variables
$RG = "RG_NAME"
$LOC = "LOCATION"
$KV = "KV_NAME"
$FUNC = "FUNC_NAME"
$EGTopic = "EG_TOPIC_NAME"              # For Basic
$EGNamespace = "EG_NAMESPACE_NAME"      # For Namespace
$EGNsTopic = "EG_NAMESPACE_TOPIC_NAME"  # For Namespace

# Create Key Vault
az keyvault create --name $KV --resource-group $RG --location $LOC | Out-Null
# Optional: store HMAC secret in the vault
az keyvault secret set --vault-name $KV --name "HmacSecret" --value "REPLACE_WITH_SECRET" | Out-Null

# Create Event Grid Basic Topic (choose one path)
az eventgrid topic create --name $EGTopic --resource-group $RG --location $LOC | Out-Null

# Or: Create Event Grid Namespace + Namespace Topic
az eventgrid namespace create --name $EGNamespace --resource-group $RG --location $LOC | Out-Null
az eventgrid namespace topic create --namespace-name $EGNamespace --name $EGNsTopic --resource-group $RG | Out-Null
```

## Configuration (environment variables)

Set these in `local.settings.json` for local dev or as App Settings in Azure. “Required?” values are Yes, No, or Conditional.

| Variable | Required? | Default | Description |
| --- | --- | --- | --- |
| `EVENT_GRID_ENDPOINT` | Yes | — | Event Grid endpoint. Basic topics/domains: full URL like `https://TOPIC.REGION.eventgrid.azure.net/api/events`. Namespaces: the endpoint host (or URL) like `NAMESPACE.REGION.eventgrid.azure.net`. |
| `EVENT_GRID_AUTH` | No | `managed` | Auth mode for publishing: `managed` (Managed Identity/AAD via DefaultAzureCredential), `sp` (Service Principal: Client ID/Secret), or `key` (access key header). |
| `EVENT_GRID_KEY` | Conditional | — | Required only when `EVENT_GRID_AUTH=key`. Event Grid access key used for the `aeg-sas-key` header. |
| `EVENT_GRID_NAMESPACE_TOPIC` | Conditional | — | Required when publishing to an Event Grid Namespace (the Namespace Topic name). Not used for Basic topics/domains. |
| `EVENT_GRID_CLOUD_SOURCE` | No | `/osdu/relay` | Default CloudEvent `source` when converting to CloudEvents for Namespace publishing. |
| `HMAC_SECRET` | Conditional | — | Secret used to validate HMAC signatures. Provide if Key Vault is not configured. For OSDU challenge chaining, a hex-like secret is expected. |
| `KEY_VAULT_SECRET_URI` | Conditional | — | Full Key Vault secret URI (e.g., `https://<vault>.vault.azure.net/secrets/<name>[/<version>]`). Provide this or the `KEY_VAULT_URL` + `KEY_VAULT_SECRET_NAME` pair to fetch the HMAC secret via AAD. |
| `KEY_VAULT_URL` | Conditional | — | Vault URL (e.g., `https://<vault>.vault.azure.net`). Use together with `KEY_VAULT_SECRET_NAME` instead of `KEY_VAULT_SECRET_URI`. |
| `KEY_VAULT_SECRET_NAME` | Conditional | — | Secret name in Key Vault. Use together with `KEY_VAULT_URL`. |
| `KEY_VAULT_AUTH` | No | `managed` | Auth mode for Key Vault: `managed` (DefaultAzureCredential) or `sp` (Service Principal: Client ID/Secret). |
| `HMAC_HEADER` | No | `Authorization` | Header to read the signature from. |
| `HMAC_ALGO` | No | `sha256` | Signature algorithm. Only `sha256` is supported. |
| `SIGNATURE_FORMAT` | No | `hex` | Outgoing/expected signature encoding: `hex` or `base64`. |
| `SIGNATURE_PREFIX` | No | `hmac` | Prefix stripped from incoming header value (case-insensitive). Default is "hmac " (with a trailing space). |
| `CHALLENGE_HMAC_REQUIRED` | No | `true` | Whether GET challenge verification must validate the `hmac` token. |
| `CHALLENGE_HASH_ENCODING` | No | `base64` | Encoding for the challenge `responseHash`: `base64-raw` (aka `base64`), `base64-hex`, or `hex`. |
| `EVENT_TYPE_MODE` | No | `single` | Event type strategy for translated OSDU items: `single` or `by_op`. |
| `EVENT_TYPE_SINGLE` | No | `osdu.record.changed` | Event type used when `EVENT_TYPE_MODE=single`. |
| `EVENT_TYPE_BY_OP_CREATE` | No | `osdu.record.create` | Event type for create operations when `EVENT_TYPE_MODE=by_op`. |
| `EVENT_TYPE_BY_OP_UPDATE` | No | `osdu.record.update` | Event type for update operations when `EVENT_TYPE_MODE=by_op`. |
| `EVENT_TYPE_BY_OP_DELETE` | No | `osdu.record.delete` | Event type for delete operations when `EVENT_TYPE_MODE=by_op`. |

Service Principal variables (used when `*_AUTH=sp`). You can set shared defaults via `AZURE_*` and optionally override per service:

| Variable | Required? | Default | Description |
| --- | --- | --- | --- |
| `AZURE_TENANT_ID` | Conditional | — | Default tenant for SP auth. Used if per-service tenant is not provided. |
| `AZURE_CLIENT_ID` | Conditional | — | Default client ID for SP auth. Used if per-service client ID is not provided. |
| `AZURE_CLIENT_SECRET` | Conditional | — | Default client secret for SP auth. Used if per-service client secret is not provided. |
| `KEY_VAULT_TENANT_ID` | Conditional | — | Tenant to use specifically for Key Vault when `KEY_VAULT_AUTH=sp`. Falls back to `AZURE_TENANT_ID`. |
| `KEY_VAULT_CLIENT_ID` | Conditional | — | Client ID to use specifically for Key Vault when `KEY_VAULT_AUTH=sp`. Falls back to `AZURE_CLIENT_ID`. |
| `KEY_VAULT_CLIENT_SECRET` | Conditional | — | Client secret to use specifically for Key Vault when `KEY_VAULT_AUTH=sp`. Falls back to `AZURE_CLIENT_SECRET`. |
| `EVENT_GRID_TENANT_ID` | Conditional | — | Tenant to use specifically for Event Grid when `EVENT_GRID_AUTH=sp`. Falls back to `AZURE_TENANT_ID`. |
| `EVENT_GRID_CLIENT_ID` | Conditional | — | Client ID to use specifically for Event Grid when `EVENT_GRID_AUTH=sp`. Falls back to `AZURE_CLIENT_ID`. |
| `EVENT_GRID_CLIENT_SECRET` | Conditional | — | Client secret to use specifically for Event Grid when `EVENT_GRID_AUTH=sp`. Falls back to `AZURE_CLIENT_SECRET`. |

Notes on “Conditional”:

- `EVENT_GRID_KEY` is required only in key auth mode (`EVENT_GRID_AUTH=key`).
- `EVENT_GRID_NAMESPACE_TOPIC` is required only when targeting Event Grid Namespace.
- One of `HMAC_SECRET` or the Key Vault settings (`KEY_VAULT_SECRET_URI` OR `KEY_VAULT_URL` + `KEY_VAULT_SECRET_NAME`) must be configured so the function can validate signatures.
- For SP auth, provide either the shared `AZURE_*` or the per-service `KEY_VAULT_*` / `EVENT_GRID_*` credentials depending on which service(s) you use SP for.

Security note: Never commit real secrets (e.g., `EVENT_GRID_KEY` or `HMAC_SECRET`) to source control. Use Azure Key Vault / managed identities in production.

## Local development

Prereqs:

- Python 3.10+ (3.12 tested in this workspace)
- Azure Functions Core Tools v4 (for local host emulation)
- Azure CLI (optional, for deployment)

Windows PowerShell quick start (from repository root):

1. Create and activate a virtual environment and install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

1. Ensure `local.settings.json` contains the required values mentioned above. Example values are already present in the repo for local testing, but replace placeholders with your own values when necessary.

1. Run the function locally:

```powershell
func host start
```

   (You can also use the VS Code task `func: host start` as configured in this workspace.)

## Run in a container (Docker)

There are two options: plain Docker or docker-compose (includes Azurite for local Storage).

### Option 1: Plain Docker

- Copy `.env.example` to `.env` and fill in values. For local Docker, either:
   - Use a real storage connection string for `AzureWebJobsStorage`, or
   - Start Azurite yourself and point `AzureWebJobsStorage` at it.

- Build and run:

```powershell
docker build -t osdu-notification-broker:local .
docker run --rm -p 7071:80 --env-file .env osdu-notification-broker:local
```

### Option 2: docker-compose (with Azurite)

- Copy `.env.example` to `.env` and fill in the required values (no need to set `AzureWebJobsStorage`; compose injects an Azurite connection string).

- Start:

```powershell
docker compose up --build
```

The function will be available at `http://localhost:7071/api/osdu-relay`.

Notes:

- For local testing, if you don’t have Managed Identity available, set `EVENT_GRID_AUTH=key` and provide `EVENT_GRID_KEY` along with a valid `EVENT_GRID_ENDPOINT`.
- Never commit real secrets; `.dockerignore` excludes `local.settings.json`. Use `.env` for local only.

## Testing the function

- To POST a sample OSDU DataNotification payload and automatically compute the HMAC header, run:

```powershell
python tests/test-post.py
```

  The script computes the required `Authorization: hmac <hex>` header using `HMAC_SECRET` env var (or `testSecret` fallback) and posts the `tests/osdu-body.json` to the local function at `http://localhost:7071/api/osdu-relay`.

- To test GET / handshake / readiness:

```powershell
python tests/test-get.py             # ping (no challenge) by default
python tests/test-get.py --challenge # performs the OSDU handshake using the configured secret (requires HMAC_SECRET)
```

- You can also use curl/Invoke-WebRequest. Example (POSIX/cURL style):

```bash
curl -X POST "http://localhost:7071/api/osdu-relay" \
   -H "Content-Type: application/json" \
   -H "Authorization: hmac [signature]" \
   --data @tests/osdu-body.json
```

  Note: on Windows PowerShell the `curl` alias maps to Invoke-WebRequest; prefer the provided Python test scripts to compute the correct signature.

### Handshake parameter names

The function accepts the following query parameter names for the OSDU challenge handshake for compatibility with various implementations:

- `crc` (preferred) or `crcToken` (aliases: `challenge`, `token`)
- `hmac` (preferred) or `hmacToken` (aliases: `signature`, `sig`)

The response contains `{ "responseHash": "..." }`, where `responseHash` defaults to Base64 of the raw SHA‑256 digest of `HMAC_SECRET + crc` (`CHALLENGE_HASH_ENCODING=base64`). You can switch to `base64-hex` or `hex` via app settings.

## How the function decides translation

- Incoming JSON that is a list will be inspected:
  - If it *already* matches Event Grid event schema (objects with keys `id`, `eventType`, `eventTime`, `subject`, `data`, `dataVersion`), it is forwarded unchanged.
  - If it looks like an OSDU DataNotification list (items having `id`, `kind`, `op`), the function translates each item into an Event Grid event object and forwards the resulting list.
  - Otherwise the body is forwarded as-is.

## Forwarding / Auth

- Managed Identity: Enable system-assigned or user-assigned identity on the Function App and assign RBAC role "Event Grid Data Sender" to the target topic/domain/namespace topic. Set `EVENT_GRID_AUTH=managed`. No key is required.
- Key auth: Set `EVENT_GRID_AUTH=key` and provide `EVENT_GRID_KEY` to use the legacy `aeg-sas-key` header.
- Service Principal (Client ID/Secret): Set `EVENT_GRID_AUTH=sp` and provide `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` (or the Event Grid-specific overrides). Ensure the app registration has proper RBAC, e.g., "Event Grid Data Sender" on your target. For Key Vault access via SP, set `KEY_VAULT_AUTH=sp` and provide the `AZURE_*` values or Key Vault-specific overrides, and grant it secret read permissions (RBAC role like "Key Vault Secrets User" or an access policy).

## Troubleshooting / Dry-run

- Use query parameter `?dryRun=1` (or `true`) on a POST to return the translated payload without forwarding to Event Grid.

## Deploying to Azure

A simple example using Azure CLI + Functions Core Tools:

1. Login and set subscription:

    ```powershell
    az login
    az account set --subscription YOUR_SUBSCRIPTION_ID
    ```

1. Create a resource group and storage account (example):

    ```powershell
    az group create --name RG_NAME --location LOCATION
    az storage account create --name STORAGE_NAME --resource-group RG_NAME --location LOCATION --sku Standard_LRS
    ```

1. Create Function App for Python (Consumption plan example):

    ```powershell
    az functionapp create --resource-group RG_NAME --consumption-plan-location LOCATION --name FUNCTION_APP_NAME --storage-account STORAGE_NAME --location LOCATION --runtime python --runtime-version 3.10 --functions-version 4
    ```

1. Set application settings (replace placeholders):

    ```powershell
    az functionapp config appsettings set `
       --name FUNCTION_APP_NAME `
       --resource-group RG_NAME `
       --settings `
      KEY_VAULT_URL="https://KV_NAME.vault.azure.net" `
      KEY_VAULT_SECRET_NAME="HmacSecret" `
       EVENT_GRID_ENDPOINT="https://TOPIC_NAME.REGION.eventgrid.azure.net/api/events" `
       EVENT_GRID_KEY="YOUR_EVENTGRID_ACCESS_KEY"
    ```

   If you're not using Key Vault, set `HMAC_SECRET="YOUR_SECRET"` instead of the `KEY_VAULT_*` settings. Add any additional settings from the configuration list above as needed.

1. Assign Managed Identity roles (Key Vault + Event Grid)

    If using Managed Identity (recommended):

    ```powershell
    # Ensure the Function App has a system-assigned managed identity
    az functionapp identity assign --name $FUNC --resource-group $RG | Out-Null
    
    # Get the identity principalId
    $principalId = az functionapp identity show --name $FUNC --resource-group $RG --query principalId -o tsv
    
    # Key Vault access: use either RBAC (recommended) or Access Policy
    
    # RBAC: assign data-plane role 'Key Vault Secrets User' at the Key Vault scope
    $kvId = az keyvault show --name $KV --resource-group $RG --query id -o tsv
    az role assignment create --assignee-object-id $principalId --assignee-principal-type ServicePrincipal `
       --role "Key Vault Secrets User" --scope $kvId | Out-Null
    
    # (Alternative) Access policy model: grant secret get (and list if desired)
    # az keyvault set-policy -n $KV --object-id $principalId --secret-permissions get list
    
    # Event Grid permission: assign 'Event Grid Data Sender'
    # For Basic Topic
    $egTopicId = az eventgrid topic show --name $EGTopic --resource-group $RG --query id -o tsv
    az role assignment create --assignee-object-id $principalId --assignee-principal-type ServicePrincipal `
       --role "Event Grid Data Sender" --scope $egTopicId | Out-Null
    
    # For Namespace Topic (if using Namespace)
    $egNsTopicId = az eventgrid namespace topic show --namespace-name $EGNamespace --name $EGNsTopic `
       --resource-group $RG --query id -o tsv
    az role assignment create --assignee-object-id $principalId --assignee-principal-type ServicePrincipal `
       --role "Event Grid Data Sender" --scope $egNsTopicId | Out-Null
    ```

1. Configure app settings for Managed Identity

    - Set `EVENT_GRID_AUTH=managed`.
    - If using Namespace: set `EVENT_GRID_NAMESPACE_TOPIC` and use the Namespace endpoint as `EVENT_GRID_ENDPOINT`.
    - If using Key Vault: set `KEY_VAULT_SECRET_URI` or `KEY_VAULT_URL` + `KEY_VAULT_SECRET_NAME`.

1. Deploy code (from repo root):

    ```powershell
    func azure functionapp publish FUNCTION_APP_NAME --python
    ```

### Deploy as Azure Container App

- Build and push the container (to ACR or your registry), then deploy with Azure Container Apps.
- See `deploy/aca/README.md` for a step-by-step guide and a sample manifest at `deploy/aca/containerapp.yaml`.

## Security and production notes

- Do not put secrets in `local.settings.json` or in Git. Use Azure Key Vault and reference secrets via App Service/Function App settings or use Managed Identity.
- Consider restricting Event Grid topic access with appropriate RBAC or private endpoints.
- Enable Application Insights and review logs (host.json already contains a minimal Application Insights sampling config).

## Troubleshooting

- If signature checks fail, confirm the HMAC computed by the client uses the same bytes (UTF-8) as the server.
- The OSDU challenge flow expects a chained HMAC construction when using a hex-like secret; see `tests/test-get.py` for an example implementation of the chain.
- Use `?dryRun=1` to see the payload that would be sent to Event Grid.

## Contributing

Ideas and fixes welcome. For production hardening, consider adding additional tests, monitoring, and better secrets management.

Key Vault + Managed Identity

- In production, enable the Function App's Managed Identity (system-assigned or a user-assigned identity) and grant it access to the Key Vault secret. You can either use Key Vault access policies (Secret GET) or Azure RBAC for Key Vault (e.g., "Key Vault Secrets User").
- When running in Azure, DefaultAzureCredential will automatically use the managed identity to authenticate and retrieve the secret from Key Vault.

## License

This repository is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
