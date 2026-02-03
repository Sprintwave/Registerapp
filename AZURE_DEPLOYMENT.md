# Azure Deployment Guide

## Option 1: Azure App Service + Azure SQL (Recommended)

### Prerequisites
- Azure account
- GitHub repository with your code

### Step 1: Create Azure Resources

```bash
# Login to Azure CLI
az login

# Create resource group
az group create --name care-register-rg --location eastus

# Create Azure SQL Server
az sql server create \
  --name care-register-server \
  --resource-group care-register-rg \
  --location eastus \
  --admin-user careradmin \
  --admin-password YourSecurePassword123!

# Create Azure SQL Database
az sql db create \
  --resource-group care-register-rg \
  --server care-register-server \
  --name care-register-db \
  --service-objective S0

# Create App Service Plan
az appservice plan create \
  --name care-register-plan \
  --resource-group care-register-rg \
  --sku B1 \
  --is-linux

# Create Web App
az webapp create \
  --resource-group care-register-rg \
  --plan care-register-plan \
  --name care-register-app \
  --runtime "PYTHON:3.11"
```

### Step 2: Configure Environment Variables

```bash
# Get SQL connection string
az sql db show-connection-string \
  --client pyodbc \
  --name care-register-db \
  --server care-register-server

# Set environment variables
az webapp config appsettings set \
  --resource-group care-register-rg \
  --name care-register-app \
  --settings \
    AZURE_SQL_CONNECTION_STRING="Driver={ODBC Driver 18 for SQL Server};Server=tcp:care-register-server.database.windows.net,1433;Database=care-register-db;Uid=careradmin;Pwd=YourSecurePassword123!;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;" \
    SECRET_KEY="your-generated-secret-key-here" \
    SCM_DO_BUILD_DURING_DEPLOYMENT=true
```

### Step 3: Deploy from GitHub

```bash
# Configure deployment source
az webapp deployment source config \
  --resource-group care-register-rg \
  --name care-register-app \
  --repo-url https://github.com/yourusername/care-register \
  --branch main \
  --manual-integration
```

## Option 2: Azure Container Apps + Cosmos DB

### Benefits
- More modern architecture
- Better scaling
- Multi-region deployment

### Setup
```bash
# Create Cosmos DB account
az cosmosdb create \
  --name care-register-cosmos \
  --resource-group care-register-rg \
  --kind GlobalDocumentDB \
  --default-consistency-level Session

# Create container registry
az acr create \
  --resource-group care-register-rg \
  --name careregisteracr \
  --sku Basic

# Create container app environment
az containerapp env create \
  --name care-register-env \
  --resource-group care-register-rg \
  --location eastus
```

## Cost Comparison

### Azure App Service + SQL Database
- **App Service (B1)**: ~$14/month
- **SQL Database (S0)**: ~$15/month
- **Total**: ~$29/month

### Azure Functions + Tables (Serverless)
- **Functions**: Pay per execution (~$1-5/month for low traffic)
- **Azure Tables**: ~$0.05/GB/month
- **Total**: ~$1-10/month depending on usage

### Azure Container Apps + Cosmos DB
- **Container Apps**: ~$10-20/month
- **Cosmos DB**: ~$25/month minimum
- **Total**: ~$35-45/month

## Recommendation

**For your Care Register app, go with Azure App Service + Azure SQL Database because:**

1. **Minimal Code Changes**: Your existing Flask app works almost unchanged
2. **Familiar Technology**: SQL database with relationships you already understand
3. **Reliability**: Enterprise-grade with 99.95% SLA
4. **Easy Management**: Azure portal provides excellent monitoring and logging
5. **Cost-Effective**: Good balance of features and cost for small to medium apps

## Security Considerations

- Use Azure Key Vault for secrets
- Enable Azure AD authentication
- Configure firewall rules for SQL Database
- Use managed identities where possible
- Enable Application Insights for monitoring
