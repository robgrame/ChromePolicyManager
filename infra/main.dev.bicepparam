using './main.bicep'

// ============================================================
// DEV environment - cost-optimized SKUs
//   App Service: B1 | SQL: Basic | APIM: Developer | AppConfig: Free
// ============================================================
param environmentName = 'dev'
param skuTier = 'dev'
param location = 'westeurope'

// Service Bus is optional in dev (API falls back to synchronous processing)
param deployServiceBus = false

// Replace with your tenant/app values (or pass via --parameters on the CLI)
param tenantId = 'YOUR_TENANT_ID'
param clientId = 'YOUR_CLIENT_ID'
param clientSecret = 'REPLACE_WITH_KEYVAULT_REFERENCE'
