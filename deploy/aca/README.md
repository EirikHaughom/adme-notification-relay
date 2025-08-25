# Deploy to Azure Container Apps

This project runs as an Azure Functions host inside a custom container. You can deploy the image to Azure Container Apps (ACA) for a fully managed, HTTP-in, autoscaled service.

## Prereqs

- Azure CLI and Azure Container Apps extension
- An Azure Container Apps Environment
- A Storage connection string (Functions runtime requirement)
- Event Grid destination configured (endpoint + key, or use Managed Identity)

## Image location

The container image is published publicly to Docker Hub:

- Repository: eirikhaughom/adme-notification-relay
- Tag: main

Pull directly with:

```powershell
docker pull eirikhaughom/adme-notification-relay:main
```

## Create secrets and deploy

### Step 1: Prepare values

- Storage connection string for `AzureWebJobsStorage`
- Event Grid endpoint and key (or set `EVENT_GRID_AUTH=managed` and assign RBAC)

### Step 2: Edit the manifest

Update `deploy/aca/containerapp.yaml` and replace placeholders:

- `<SUBSCRIPTION_ID>`, `<RG_NAME>`, `<ENV_NAME>` for the Container Apps Environment
- `<AZURE_STORAGE_CONNECTION_STRING>`
- `<TOPIC_OR_NAMESPACE_HOST>`, `<EVENT_GRID_KEY>` or set `EVENT_GRID_AUTH=managed`
- `<HMAC_SECRET>` (or use Key Vault via `KEY_VAULT_SECRET_URI` and Managed Identity)

### Step 3: Create or update the Container App

```powershell
az containerapp create `
  --resource-group <RG_NAME> `
  --environment <ENV_NAME> `
  --name osdu-notification-broker `
  --yaml deploy/aca/containerapp.yaml
```

To update later:

```powershell
az containerapp update `
  --resource-group <RG_NAME> `
  --name osdu-notification-broker `
  --yaml deploy/aca/containerapp.yaml
```

## Using Managed Identity

- Set `EVENT_GRID_AUTH=managed`. Assign the Container App’s managed identity the role "Event Grid Data Sender" on the target Topic/Namespace Topic.
- To fetch `HMAC_SECRET` from Key Vault, set `KEY_VAULT_SECRET_URI` (or `KEY_VAULT_URL` + `KEY_VAULT_SECRET_NAME`) and assign Key Vault data-plane permission via RBAC (e.g., "Key Vault Secrets User").
- Ensure the identity type in the manifest is `SystemAssigned` or your `UserAssigned` identity is configured and referenced.

## Notes

- Ingress targetPort is 80 because the Azure Functions base image listens on 80.
- Scale rules are example values; adjust for your traffic.
- The manifest references the Docker Hub image; no registry credentials are required.
