// Chrome Policy Manager - Infrastructure (Bicep)
// This file defines the Azure infrastructure for the solution.
// Components: App Service, Azure SQL, APIM, App Configuration, Key Vault, App Insights

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

// Log Analytics Workspace
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: '${prefix}-workspace'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

// Application Insights
resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${prefix}-insights'
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalyticsWorkspace.id
  }
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
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: applicationInsights.properties.ConnectionString }
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

// App Service - Admin
resource adminAppService 'Microsoft.Web/sites@2023-12-01' = {
  name: '${prefix}-admin'
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
        { name: 'ASPNETCORE_ENVIRONMENT', value: environmentName == 'prod' ? 'Production' : 'Development' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: applicationInsights.properties.ConnectionString }
        { name: 'ApiBaseUrl', value: 'https://${prefix}-api.azurewebsites.net' }
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

// API Management - Developer SKU with mTLS
resource apim 'Microsoft.ApiManagement/service@2023-09-01-preview' = {
  name: '${prefix}-apim2'
  location: location
  tags: tags
  sku: {
    name: 'Developer'
    capacity: 1
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    publisherEmail: 'admin@yourdomain.com'
    publisherName: 'Chrome Policy Manager'
    hostnameConfigurations: [
      {
        type: 'Proxy'
        hostName: '${prefix}-apim2.azure-api.net'
        negotiateClientCertificate: true
        defaultSslBinding: true
        certificateSource: 'BuiltIn'
      }
    ]
  }
}

// APIM App Insights logger
resource apimLogger 'Microsoft.ApiManagement/service/loggers@2023-09-01-preview' = {
  parent: apim
  name: 'appinsights'
  properties: {
    loggerType: 'applicationInsights'
    credentials: {
      instrumentationKey: applicationInsights.properties.InstrumentationKey
    }
    isBuffered: true
  }
}

// APIM diagnostics - log all API calls to App Insights
resource apimDiagnostics 'Microsoft.ApiManagement/service/diagnostics@2023-09-01-preview' = {
  parent: apim
  name: 'applicationinsights'
  properties: {
    loggerId: apimLogger.id
    alwaysLog: 'allErrors'
    sampling: {
      samplingType: 'fixed'
      percentage: 100
    }
  }
}

// Service Bus Namespace (for async device report processing)
resource serviceBusNamespace 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {
  name: '${prefix}-sb'
  location: location
  tags: tags
  sku: {
    name: 'Basic'
    tier: 'Basic'
  }
}

// Service Bus Queue - Device Reports
resource deviceReportQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: serviceBusNamespace
  name: 'device-reports'
  properties: {
    maxDeliveryCount: 5
    lockDuration: 'PT5M'
    defaultMessageTimeToLive: 'P7D'
    deadLetteringOnMessageExpiration: true
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

// APIM - Device API (Client-facing, mTLS)
resource apimDeviceApi 'Microsoft.ApiManagement/service/apis@2023-09-01-preview' = {
  parent: apim
  name: 'device-api'
  properties: {
    displayName: 'Chrome Policy Device API'
    path: ''
    protocols: [ 'https' ]
    serviceUrl: 'https://${apiAppService.properties.defaultHostName}/api/devices'
    subscriptionRequired: false // Auth is via mTLS client certificate
  }
}

// Outputs
output apiUrl string = 'https://${apiAppService.properties.defaultHostName}'
output adminUrl string = 'https://${adminAppService.properties.defaultHostName}'
output apimGatewayUrl string = apim.properties.gatewayUrl
output appConfigEndpoint string = appConfig.properties.endpoint
output keyVaultUri string = keyVault.properties.vaultUri
output serviceBusNamespace string = serviceBusNamespace.name
output appInsightsConnectionString string = applicationInsights.properties.ConnectionString
output appInsightsInstrumentationKey string = applicationInsights.properties.InstrumentationKey
