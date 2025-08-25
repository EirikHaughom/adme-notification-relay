# OSDU Notification Relay

Minimal webhook relay that:

- Validates OSDU HMAC (including challenge handshake on GET)
- Translates OSDU DataNotification payloads to Event Grid events
- Publishes to Azure Event Grid using Managed Identity (preferred), Service Principal or Access Key

Endpoint: `GET/POST /api/osdu-relay`

Key files: `OSDURelay/` (function), `deploy/aca/containerapp.yaml` (ACA sample), `tests/` (local helpers).

## Table of Contents

- [Mandatory configuration (app settings / env vars)](#mandatory-configuration-app-settings--env-vars)
    - [Startup validation](#startup-validation)
- [Deploy as Azure Function (Managed Identity)](#deploy-as-azure-function-managed-identity)
- [Deploy as Azure Container App (Managed Identity)](#deploy-as-azure-container-app-managed-identity)
- [Local testing (optional)](#local-testing-optional)
- [Security](#security)
- [License](#license)

## Mandatory configuration (app settings / env vars)

Provide these at runtime (Azure Function App or Container App):

- `EVENT_GRID_ENDPOINT`: Event Grid publish endpoint
  - Basic Topic/Domain: `https://TOPIC_NAME.REGION.eventgrid.azure.net/api/events`
  - Namespace: use your Namespace endpoint host or URL; also set EVENT_GRID_NAMESPACE_TOPIC
- `EVENT_GRID_AUTH`: managed (default) | key | sp
- `EVENT_GRID_NAMESPACE_TOPIC`: required if publishing to an Event Grid Namespace
- `HMAC_SECRET`: only if you don’t use Key Vault
- Or use Key Vault (recommended):
  - `KEY_VAULT_SECRET_URI` (e.g., <https://VAULT_NAME.vault.azure.net/secrets/HmacSecret/[VERSION]>)
  - or `KEY_VAULT_URL` + `KEY_VAULT_SECRET_NAME`

Azure Functions runtime settings (always required):

- `AzureWebJobsStorage`: storage connection string
- `FUNCTIONS_WORKER_RUNTIME`: python

Notes:

- Prefer Managed Identity + Key Vault. Do not store real secrets in Git.
- If EVENT_GRID_AUTH=key, set EVENT_GRID_KEY.

### Startup validation

On container/function startup, the app validates required settings and fails fast with an aggregated error list if misconfigured. Typical checks:

- EVENT_GRID_ENDPOINT is required
- EVENT_GRID_AUTH must be one of: managed, key, sp (key: requires EVENT_GRID_KEY; sp: requires EVENT_GRID_TENANT_ID/EVENT_GRID_CLIENT_ID/EVENT_GRID_CLIENT_SECRET or shared AZURE_* equivalents)
- HMAC secret must be provided via Key Vault (KEY_VAULT_SECRET_URI or KEY_VAULT_URL + KEY_VAULT_SECRET_NAME) or HMAC_SECRET
- If using Key Vault with KEY_VAULT_AUTH=sp, requires KEY_VAULT_TENANT_ID/CLIENT_ID/CLIENT_SECRET (or shared AZURE_*)

If any are missing, startup aborts and logs a clear message, e.g.:

```text
Configuration error(s) detected:
 - EVENT_GRID_ENDPOINT is required (...)
 - EVENT_GRID_AUTH must be one of: managed, key, sp.
 - Provide HMAC secret via KEY_VAULT_SECRET_URI ... or set HMAC_SECRET ...
```

## Deploy as Azure Function (Managed Identity)

Prereqs: Azure CLI, Functions Core Tools, Contributor rights.

1. Variables (PowerShell)

    ```powershell
    $SUB="<subscriptionId>"
    $RG="osdu-relay-rg"
    $LOC="westeurope"
    $STG="osdurelaystg$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    $FUNC="osdu-relay-func"
    $KV="osdurelay-kv"
    # Choose one path for Event Grid
    $EG_TOPIC="osdu-eg-topic"          # Basic Topic name
    $EG_NAMESPACE="osdu-eg-ns"         # Namespace name
    $EG_NS_TOPIC="osdu-eg-ns-topic"    # Namespace Topic name
    ```

1. Login and resource group

    ```powershell
    az login
    az account set --subscription $SUB
    az group create -n $RG -l $LOC
    ```

1. Storage, Key Vault, Event Grid

    ```powershell
    az storage account create -n $STG -g $RG -l $LOC --sku Standard_LRS
    az keyvault create -n $KV -g $RG -l $LOC
    # Store your HMAC secret in Key Vault
    az keyvault secret set --vault-name $KV --name HmacSecret --value "<REPLACE_WITH_SECRET>"
    
    # EITHER: Basic Topic
    az eventgrid topic create -n $EG_TOPIC -g $RG -l $LOC
    $EG_ENDPOINT = "https://$EG_TOPIC.$LOC-1.eventgrid.azure.net/api/events"
    
    # OR: Namespace + Namespace Topic
    # az eventgrid namespace create -n $EG_NAMESPACE -g $RG -l $LOC
    # az eventgrid namespace topic create --namespace-name $EG_NAMESPACE -n $EG_NS_TOPIC -g $RG
    # $EG_ENDPOINT = "$EG_NAMESPACE.$LOC-1.eventgrid.azure.net"  # use namespace endpoint host or URL
    ```

1. Function App and Managed Identity

    ```powershell
    az functionapp create --resource-group $RG --consumption-plan-location $LOC `
       --name $FUNC --storage-account $STG --runtime python --runtime-version 3.12 --functions-version 4
    
    az functionapp identity assign -g $RG -n $FUNC | Out-Null
    $PRINCIPAL = az functionapp identity show -g $RG -n $FUNC --query principalId -o tsv
    ```

1. Grant access (Key Vault + Event Grid)

    ```powershell
    $KV_ID = az keyvault show -n $KV -g $RG --query id -o tsv
    az role assignment create --assignee-object-id $PRINCIPAL --assignee-principal-type ServicePrincipal `
       --role "Key Vault Secrets User" --scope $KV_ID | Out-Null
    
    # Basic Topic scope (if using Basic)
    $EG_TOPIC_ID = az eventgrid topic show -n $EG_TOPIC -g $RG --query id -o tsv 2>$null
    if ($EG_TOPIC_ID) {
       az role assignment create --assignee-object-id $PRINCIPAL --assignee-principal-type ServicePrincipal `
          --role "Event Grid Data Sender" --scope $EG_TOPIC_ID | Out-Null
    }
    
    # Namespace Topic scope (if using Namespace)
    # $EG_NS_TOPIC_ID = az eventgrid namespace topic show --namespace-name $EG_NAMESPACE -n $EG_NS_TOPIC -g $RG --query id -o tsv
    # az role assignment create --assignee-object-id $PRINCIPAL --assignee-principal-type ServicePrincipal `
    #   --role "Event Grid Data Sender" --scope $EG_NS_TOPIC_ID | Out-Null
    ```

1. Configure app settings

    ```powershell
    # Use Key Vault (preferred)
    az functionapp config appsettings set -g $RG -n $FUNC --settings `
       KEY_VAULT_URL="https://$KV.vault.azure.net" `
       KEY_VAULT_SECRET_NAME="HmacSecret" `
       EVENT_GRID_ENDPOINT="$EG_ENDPOINT" `
       EVENT_GRID_AUTH="managed" `
       EVENT_GRID_NAMESPACE_TOPIC="$EG_NS_TOPIC"
    ```

1. Deploy code

    ```powershell
    func azure functionapp publish $FUNC --python
    ```

    Endpoint: `https://$FUNC.azurewebsites.net/api/osdu-relay`

## Deploy as Azure Container App (Managed Identity)

Prereqs: Azure CLI. No private registry needed; image is on Docker Hub.

1. Variables

    ```powershell
    $SUB="<subscriptionId>"
    $RG="osdu-relay-rg"
    $LOC="westeurope"
    $ACA_ENV="osdu-relay-env"
    $APP="osdu-relay-aca"
    $STG="osdurelaystg$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    $KV="osdurelay-kv"
    $EG_TOPIC="osdu-eg-topic"
    ```

1. Login and resource group

    ```powershell
    az login
    az account set --subscription $SUB
    az group create -n $RG -l $LOC
    ```

1. Storage, Key Vault, Event Grid

    ```powershell
    az storage account create -n $STG -g $RG -l $LOC --sku Standard_LRS
    $STG_CONN = az storage account show-connection-string -n $STG -g $RG --query connectionString -o tsv
    
    az keyvault create -n $KV -g $RG -l $LOC
    az keyvault secret set --vault-name $KV --name HmacSecret --value "<REPLACE_WITH_SECRET>"
    
    az eventgrid topic create -n $EG_TOPIC -g $RG -l $LOC
    $EG_ENDPOINT = "https://$EG_TOPIC.$LOC-1.eventgrid.azure.net/api/events"
    ```

1. Container Apps environment and app

    ```powershell
    az containerapp env create -g $RG -n $ACA_ENV -l $LOC

    # Use the public image on Docker Hub
    az containerapp create -g $RG -n $APP --environment $ACA_ENV `
       --image eirikhaughom/adme-notification-relay:main `
       --ingress external --target-port 80 `
       --system-assigned `
       --secrets storage-conn="$STG_CONN" `
       --env-vars `
          AzureWebJobsStorage=secretref:storage-conn `
          FUNCTIONS_WORKER_RUNTIME=python `
          EVENT_GRID_ENDPOINT=$EG_ENDPOINT `
          EVENT_GRID_AUTH=managed `
          KEY_VAULT_URL=https://$KV.vault.azure.net `
          KEY_VAULT_SECRET_NAME=HmacSecret
    ```

1. Grant access (Managed Identity)

    ```powershell
    $PRINCIPAL = az containerapp show -g $RG -n $APP --query identity.principalId -o tsv
    $KV_ID = az keyvault show -n $KV -g $RG --query id -o tsv
    $EG_TOPIC_ID = az eventgrid topic show -n $EG_TOPIC -g $RG --query id -o tsv
    
    az role assignment create --assignee-object-id $PRINCIPAL --assignee-principal-type ServicePrincipal `
       --role "Key Vault Secrets User" --scope $KV_ID | Out-Null
    az role assignment create --assignee-object-id $PRINCIPAL --assignee-principal-type ServicePrincipal `
       --role "Event Grid Data Sender" --scope $EG_TOPIC_ID | Out-Null
    ```

1. Get URL and test

    ```powershell
    az containerapp show -g $RG -n $APP --query properties.configuration.ingress.fqdn -o tsv
    # Open: https://<FQDN>/api/osdu-relay
    ```

Tip: A ready-to-edit manifest is in `deploy/aca/containerapp.yaml` and already points to the Docker Hub image; no registry credentials are required.

## Local testing (optional)

```powershell
# Install deps and run locally
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
func host start

# Exercise GET/POST
python tests/test-get.py
python tests/test-post.py
```

## Security

- Prefer Managed Identity + Key Vault for secrets.
- Grant minimum RBAC: Key Vault Secrets User, Event Grid Data Sender.
- Never commit real secrets to Git.

## License

MIT (see [LICENSE](./LICENSE)).
