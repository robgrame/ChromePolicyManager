// Chrome Policy Manager - Infrastructure (Bicep)
// This file defines the Azure infrastructure for the solution.
// Components: VNet, App Service (VNet integrated), Azure SQL (Private Endpoint),
//             Service Bus (Private Endpoint, MI-only), APIM, App Configuration, Key Vault, App Insights
//
// Security policies enforced by subscription:
//   - No SAS authentication (use Managed Identity everywhere)
//   - No public network access on data-plane resources (use Private Endpoints)

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

@description('VNet address prefix')
param vnetAddressPrefix string = '10.0.0.0/16'

@description('App Service integration subnet prefix')
param appSubnetPrefix string = '10.0.1.0/24'

@description('Private Endpoints subnet prefix')
param privateEndpointSubnetPrefix string = '10.0.2.0/24'

var prefix = 'cpm-${environmentName}'
var tags = {
  project: 'ChromePolicyManager'
  environment: environmentName
}

// ============================================================
// Networking - VNet, Subnets, Private DNS Zones
// ============================================================

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: '${prefix}-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [vnetAddressPrefix]
    }
    subnets: [
      {
        name: 'app-integration'
        properties: {
          addressPrefix: appSubnetPrefix
          delegations: [
            {
              name: 'appServiceDelegation'
              properties: {
                serviceName: 'Microsoft.Web/serverFarms'
              }
            }
          ]
        }
      }
      {
        name: 'private-endpoints'
        properties: {
          addressPrefix: privateEndpointSubnetPrefix
        }
      }
    ]
  }
}

// Private DNS Zones
resource privateDnsZoneSql 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink${environment().suffixes.sqlServerHostname}'
  location: 'global'
  tags: tags
}

resource privateDnsZoneServiceBus 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.servicebus.windows.net'
  location: 'global'
  tags: tags
}

// Link DNS zones to VNet
resource dnsZoneLinkSql 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: privateDnsZoneSql
  name: '${prefix}-sql-link'
  location: 'global'
  properties: {
    virtualNetwork: { id: vnet.id }
    registrationEnabled: false
  }
}

resource dnsZoneLinkServiceBus 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: privateDnsZoneServiceBus
  name: '${prefix}-sb-link'
  location: 'global'
  properties: {
    virtualNetwork: { id: vnet.id }
    registrationEnabled: false
  }
}

// ============================================================
// Observability
// ============================================================

resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: '${prefix}-workspace'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

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

// ============================================================
// App Service Plan + Apps (with VNet integration)
// ============================================================

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
    virtualNetworkSubnetId: vnet.properties.subnets[0].id
    siteConfig: {
      netFrameworkVersion: 'v10.0'
      vnetRouteAllEnabled: true // Route all traffic through VNet (needed for Private Endpoints)
      appSettings: [
        { name: 'AzureAd__TenantId', value: tenantId }
        { name: 'AzureAd__ClientId', value: clientId }
        { name: 'AzureAd__ClientSecret', value: clientSecret }
        { name: 'AzureAd__AllowWebApiToBeAuthorizedByACL', value: 'true' }
        { name: 'ASPNETCORE_ENVIRONMENT', value: environmentName == 'prod' ? 'Production' : 'Development' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: applicationInsights.properties.ConnectionString }
        { name: 'ServiceBus__FullyQualifiedNamespace', value: deployServiceBus ? '${serviceBusNamespace.name}.servicebus.windows.net' : '' }
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
    virtualNetworkSubnetId: vnet.properties.subnets[0].id
    siteConfig: {
      netFrameworkVersion: 'v10.0'
      vnetRouteAllEnabled: true
      appSettings: [
        { name: 'ASPNETCORE_ENVIRONMENT', value: environmentName == 'prod' ? 'Production' : 'Development' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: applicationInsights.properties.ConnectionString }
        { name: 'ApiBaseUrl', value: 'https://${prefix}-api.azurewebsites.net' }
      ]
    }
  }
}

// ============================================================
// Azure SQL Server (Private Endpoint, no public access)
// ============================================================

resource sqlServer 'Microsoft.Sql/servers@2023-08-01-preview' = {
  name: '${prefix}-sql'
  location: location
  tags: tags
  properties: {
    administratorLogin: 'sqladmin'
    administratorLoginPassword: clientSecret // Use Key Vault in production
    publicNetworkAccess: 'Disabled'
    administrators: {
      azureADOnlyAuthentication: true
      principalType: 'Application'
      login: 'ChromePolicyManager API'
      sid: apiAppService.identity.principalId
      tenantId: tenantId
    }
  }
}

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

// SQL Server Private Endpoint
resource sqlPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: '${prefix}-sql-pe'
  location: location
  tags: tags
  properties: {
    subnet: { id: vnet.properties.subnets[1].id }
    privateLinkServiceConnections: [
      {
        name: '${prefix}-sql-plsc'
        properties: {
          privateLinkServiceId: sqlServer.id
          groupIds: ['sqlServer']
        }
      }
    ]
  }
}

resource sqlPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = {
  parent: sqlPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'sqlServer'
        properties: {
          privateDnsZoneId: privateDnsZoneSql.id
        }
      }
    ]
  }
}

// ============================================================
// Service Bus (Optional - for async report processing)
// Requires Standard tier for Private Endpoints (cost consideration).
// When not deployed, the API falls back to synchronous processing.
// Set deployServiceBus=true for production with async processing needs.
// ============================================================

@description('Deploy Service Bus for async processing (Standard tier required for PE, adds ~€10/month)')
param deployServiceBus bool = false

resource serviceBusNamespace 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = if (deployServiceBus) {
  name: '${prefix}-sb'
  location: location
  tags: tags
  sku: {
    name: 'Standard'
    tier: 'Standard'
  }
  properties: {
    disableLocalAuth: true // No SAS — Managed Identity only
    publicNetworkAccess: 'Disabled'
  }
}

resource deviceReportQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = if (deployServiceBus) {
  parent: serviceBusNamespace
  name: 'device-reports'
  properties: {
    maxDeliveryCount: 5
    lockDuration: 'PT5M'
    defaultMessageTimeToLive: 'P7D'
    deadLetteringOnMessageExpiration: true
  }
}

// Service Bus Private Endpoint
resource serviceBusPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = if (deployServiceBus) {
  name: '${prefix}-sb-pe'
  location: location
  tags: tags
  properties: {
    subnet: { id: vnet.properties.subnets[1].id }
    privateLinkServiceConnections: [
      {
        name: '${prefix}-sb-plsc'
        properties: {
          privateLinkServiceId: serviceBusNamespace.id
          groupIds: ['namespace']
        }
      }
    ]
  }
}

resource serviceBusPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = if (deployServiceBus) {
  parent: serviceBusPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'serviceBus'
        properties: {
          privateDnsZoneId: privateDnsZoneServiceBus.id
        }
      }
    ]
  }
}

// RBAC: API Managed Identity → Service Bus Data Owner
resource serviceBusRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployServiceBus) {
  name: guid(serviceBusNamespace.id, apiAppService.identity.principalId, '090c5cfd-751d-490a-894a-3ce6f1109419')
  scope: serviceBusNamespace
  properties: {
    principalId: apiAppService.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '090c5cfd-751d-490a-894a-3ce6f1109419') // Azure Service Bus Data Owner
    principalType: 'ServicePrincipal'
  }
}

// ============================================================
// App Configuration
// ============================================================

resource appConfig 'Microsoft.AppConfiguration/configurationStores@2023-03-01' = {
  name: '${prefix}-config'
  location: location
  tags: tags
  sku: {
    name: 'Free'
  }
}

// ============================================================
// Key Vault
// ============================================================

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

// ============================================================
// API Management - Developer SKU with mTLS
// ============================================================

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

// APIM - Device API (Client-facing, mTLS)
resource apimDeviceApi 'Microsoft.ApiManagement/service/apis@2023-09-01-preview' = {
  parent: apim
  name: 'device-api'
  properties: {
    displayName: 'Chrome Policy Device API'
    path: ''
    protocols: ['https']
    serviceUrl: 'https://${apiAppService.properties.defaultHostName}/api/devices'
    subscriptionRequired: false // Auth is via mTLS client certificate
  }
}

// ============================================================
// Outputs
// ============================================================

output apiUrl string = 'https://${apiAppService.properties.defaultHostName}'
output adminUrl string = 'https://${adminAppService.properties.defaultHostName}'
output apimGatewayUrl string = apim.properties.gatewayUrl
output appConfigEndpoint string = appConfig.properties.endpoint
output keyVaultUri string = keyVault.properties.vaultUri
output serviceBusNamespace string = deployServiceBus ? serviceBusNamespace.name : ''
output appInsightsConnectionString string = applicationInsights.properties.ConnectionString
output vnetId string = vnet.id
