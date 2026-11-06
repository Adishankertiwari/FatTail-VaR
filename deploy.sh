#!/usr/bin/env bash
# deploy.sh - provision Azure resources and deploy the EVT Risk platform.
# Run in Azure Cloud Shell (bash) or a terminal after `az login`.
# Run it STEP BY STEP the first time (names must be globally unique; student
# subscriptions may restrict regions or role assignments - see notes inline).
set -euo pipefail

# ----------------------------- 1. VARIABLES (edit these) -----------------------------
SUFFIX="${SUFFIX:-$RANDOM}"                 # makes global names unique
RG="rg-evt-risk"
LOCATION="centralindia"                     # pick a region your subscription allows
SQL_SERVER="evt-sql-$SUFFIX"
SQL_DB="evt_risk"
SQL_ADMIN="sqladminuser"
SQL_ADMIN_PASSWORD="${SQL_ADMIN_PASSWORD:?export SQL_ADMIN_PASSWORD first (strong, 16+ chars)}"
STORAGE="evtstore$SUFFIX"                   # lowercase letters/digits only, 3-24 chars
CONTAINER="raw-csv-uploads"
ACR="evtacr$SUFFIX"                         # lowercase letters/digits only
PLAN="plan-evt-risk"
APP="evt-risk-api-$SUFFIX"
IMAGE="evt-risk-api:v1"
JWT_SECRET="${JWT_SECRET:-$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')}"
DEMO_QUANT_PASSWORD="${DEMO_QUANT_PASSWORD:?export DEMO_QUANT_PASSWORD (12+ chars)}"
DEMO_VIEWER_PASSWORD="${DEMO_VIEWER_PASSWORD:?export DEMO_VIEWER_PASSWORD (12+ chars)}"

# ----------------------------- 2. RESOURCE GROUP -----------------------------
az group create -n "$RG" -l "$LOCATION"

# ----------------------------- 3. AZURE SQL -----------------------------
az sql server create -g "$RG" -n "$SQL_SERVER" -l "$LOCATION" \
  --admin-user "$SQL_ADMIN" --admin-password "$SQL_ADMIN_PASSWORD"
az sql db create -g "$RG" -s "$SQL_SERVER" -n "$SQL_DB" --service-objective Basic
# Allow Azure services (the App Service) to reach the server:
az sql server firewall-rule create -g "$RG" -s "$SQL_SERVER" -n AllowAzureServices \
  --start-ip-address 0.0.0.0 --end-ip-address 0.0.0.0
# Allow YOUR machine so you can run schema.sql (and use Power BI Desktop):
MY_IP="$(curl -s https://api.ipify.org)"
az sql server firewall-rule create -g "$RG" -s "$SQL_SERVER" -n MyIP \
  --start-ip-address "$MY_IP" --end-ip-address "$MY_IP"

echo ">>> PAUSE: now run schema.sql against $SQL_SERVER.database.windows.net / $SQL_DB"
echo ">>> then create the app login in that database:"
echo ">>>   CREATE USER [evt_api] WITH PASSWORD = '<strong password>';"
echo ">>>   ALTER ROLE app_runtime ADD MEMBER [evt_api];"
read -r -p "Enter the evt_api password you set: " -s DB_APP_PASSWORD; echo

# ----------------------------- 4. BLOB STORAGE (private container) -----------------------------
az storage account create -g "$RG" -n "$STORAGE" -l "$LOCATION" --sku Standard_LRS \
  --kind StorageV2 --allow-blob-public-access false --min-tls-version TLS1_2
STORAGE_CONN="$(az storage account show-connection-string -g "$RG" -n "$STORAGE" --query connectionString -o tsv)"
az storage container create --name "$CONTAINER" --connection-string "$STORAGE_CONN" --public-access off

# ----------------------------- 5. BUILD THE IMAGE -----------------------------
az acr create -g "$RG" -n "$ACR" --sku Basic
# If ACR Tasks is blocked on your subscription, build locally instead:
#   az acr login -n $ACR && docker build -t $ACR.azurecr.io/$IMAGE . && docker push $ACR.azurecr.io/$IMAGE
az acr build -r "$ACR" -t "$IMAGE" .

# ----------------------------- 6. APP SERVICE (Linux container) -----------------------------
az appservice plan create -g "$RG" -n "$PLAN" --is-linux --sku B1
az webapp create -g "$RG" -p "$PLAN" -n "$APP" \
  --container-image-name "$ACR.azurecr.io/$IMAGE" --container-registry-url "https://$ACR.azurecr.io"

# Let the web app pull from ACR using its managed identity (no registry password).
# If role assignment is blocked on your subscription: `az acr update -n $ACR --admin-enabled true`
# and pass --container-registry-user/--container-registry-password to `az webapp config container set`.
az webapp identity assign -g "$RG" -n "$APP"
PRINCIPAL_ID="$(az webapp identity show -g "$RG" -n "$APP" --query principalId -o tsv)"
ACR_ID="$(az acr show -n "$ACR" --query id -o tsv)"
az role assignment create --assignee "$PRINCIPAL_ID" --role AcrPull --scope "$ACR_ID"
az resource update --ids "$(az webapp show -g "$RG" -n "$APP" --query id -o tsv)/config/web" \
  --set properties.acrUseManagedIdentityCreds=true

# ----------------------------- 7. APP SETTINGS (secrets stay out of the image) -----------------------------
# ENV is intentionally NOT set to "production" so /docs (Swagger UI) stays available for your demo.
az webapp config appsettings set -g "$RG" -n "$APP" --settings \
  WEBSITES_PORT=8000 \
  DB_SERVER="$SQL_SERVER.database.windows.net" \
  DB_NAME="$SQL_DB" \
  DB_USER="evt_api" \
  DB_PASSWORD="$DB_APP_PASSWORD" \
  JWT_SECRET="$JWT_SECRET" \
  AZURE_STORAGE_CONNECTION_STRING="$STORAGE_CONN" \
  BLOB_CONTAINER="$CONTAINER" \
  SEED_DEMO_USERS=1 \
  DEMO_QUANT_PASSWORD="$DEMO_QUANT_PASSWORD" \
  DEMO_VIEWER_PASSWORD="$DEMO_VIEWER_PASSWORD" >/dev/null

az webapp update -g "$RG" -n "$APP" --https-only true
az webapp config set -g "$RG" -n "$APP" --min-tls-version 1.2 --health-check-path "/api/health" >/dev/null
az webapp log config -g "$RG" -n "$APP" --docker-container-logging filesystem
az webapp restart -g "$RG" -n "$APP"

echo
echo "Deployed:  https://$APP.azurewebsites.net/docs"
echo "Logs:      az webapp log tail -g $RG -n $APP"
echo "Teardown:  az group delete -n $RG --yes --no-wait"