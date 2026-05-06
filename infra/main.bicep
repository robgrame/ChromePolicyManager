// Chrome Policy Manager - Infrastructure (Bicep)
// This file defines the Azure infrastructure for the solution.
// Components: App Service, Azure SQL, APIM, App Configuration, Key Vault

targetScope = 'resourceGroup'

@description('Environment name (dev, staging, prod)')
param environmentName string = 'dev'

@description('Azure region for resources')
param location string = resourceGroup().location

@description('Entra ID tenant ID')
param tenantId string

@description('App registration client ID')
param clientId string

@secure()
@description('App registration client secret')
param clientSecret string

var prefix = 'cpm-${environmentName}'
var tags = {
  project: 'ChromePolicyManager'
  environment: environmentName
}

// App Service Plan
resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: '${prefix}-plan'
  location: location
  tags: tags
  sku: {
    name: 'B1'
    tier: 'Basic'
  }
  properties: {
    reserved: false // Windows
  }
}

// App Service - API
resource apiAppService 'Microsoft.Web/sites@2023-12-01' = {
  name: '${prefix}-api'
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      netFrameworkVersion: 'v10.0'
      appSettings: [
        { name: 'AzureAd__TenantId', value: tenantId }
        { name: 'AzureAd__ClientId', value: clientId }
        { name: 'AzureAd__ClientSecret', value: clientSecret }
        { name: 'ASPNETCORE_ENVIRONMENT', value: environmentName == 'prod' ? 'Production' : 'Development' }
      ]
      connectionStrings: [
        {
          name: 'DefaultConnection'
          connectionString: 'Server=tcp:${sqlServer.properties.fullyQualifiedDomainName},1433;Database=${sqlDatabase.name};Authentication=Active Directory Default;'
          type: 'SQLAzure'
        }
      ]
    }
  }
}

// Azure SQL Server
resource sqlServer 'Microsoft.Sql/servers@2023-08-01-preview' = {
  name: '${prefix}-sql'
  location: location
  tags: tags
  properties: {
    administratorLogin: 'sqladmin'
    administratorLoginPassword: clientSecret // Use Key Vault in production
    administrators: {
      azureADOnlyAuthentication: true
      principalType: 'Application'
      login: 'ChromePolicyManager API'
      sid: apiAppService.identity.principalId
      tenantId: tenantId
    }
  }
}

// Azure SQL Database
resource sqlDatabase 'Microsoft.Sql/servers/databases@2023-08-01-preview' = {
  parent: sqlServer
  name: 'ChromePolicyManager'
  location: location
  tags: tags
  sku: {
    name: 'Basic'
    tier: 'Basic'
  }
}

// Azure App Configuration
resource appConfig 'Microsoft.AppConfiguration/configurationStores@2023-03-01' = {
  name: '${prefix}-config'
  location: location
  tags: tags
  sku: {
    name: 'Free'
  }
}

// Key Vault
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '${prefix}-kv'
  location: location
  tags: tags
  properties: {
    tenantId: tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
  }
}

// API Management
resource apim 'Microsoft.ApiManagement/service@2023-09-01-preview' = {
  name: '${prefix}-apim'
  location: location
  tags: tags
  sku: {
    name: 'Consumption'
    capacity: 0
  }
  properties: {
    publisherEmail: 'admin@yourdomain.com'
    publisherName: 'Chrome Policy Manager'
  }
}

// APIM - Management API (Admin portal)
resource apimManagementApi 'Microsoft.ApiManagement/service/apis@2023-09-01-preview' = {
  parent: apim
  name: 'management-api'
  properties: {
    displayName: 'Chrome Policy Management API'
    path: 'management'
    protocols: [ 'https' ]
    serviceUrl: 'https://${apiAppService.properties.defaultHostName}'
    subscriptionRequired: true
  }
}

// APIM - Device API (Client-facing)
resource apimDeviceApi 'Microsoft.ApiManagement/service/apis@2023-09-01-preview' = {
  parent: apim
  name: 'device-api'
  properties: {
    displayName: 'Chrome Policy Device API'
    path: 'device'
    protocols: [ 'https' ]
    serviceUrl: 'https://${apiAppService.properties.defaultHostName}'
    subscriptionRequired: false // Uses device token auth
  }
}

// Outputs
output apiUrl string = 'https://${apiAppService.properties.defaultHostName}'
output apimGatewayUrl string = apim.properties.gatewayUrl
output appConfigEndpoint string = appConfig.properties.endpoint
output keyVaultUri string = keyVault.properties.vaultUri
