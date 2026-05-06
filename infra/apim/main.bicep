// Azure API Management - Consumption tier
// Acts as security gateway for device-facing endpoints
// Validates device JWT tokens, rate limits, and authenticates to backend with managed identity

@description('Azure region for APIM')
param location string = resourceGroup().location

@description('APIM instance name')
param apimName string = 'cpm-dev-apim'

@description('Publisher email for APIM')
param publisherEmail string

@description('Publisher name for APIM')
param publisherName string = 'Chrome Policy Manager'

@description('Backend API URL')
param backendApiUrl string = 'https://cpm-dev-api.azurewebsites.net'

@description('Entra ID tenant ID for JWT validation')
param tenantId string

@description('Device client app registration ID (audience for device tokens)')
param deviceClientId string

@description('API app registration ID (audience claim in tokens)')
param apiAudience string

// APIM instance - Consumption tier (serverless, pay-per-call)
resource apim 'Microsoft.ApiManagement/service@2023-09-01-preview' = {
  name: apimName
  location: location
  sku: {
    name: 'Consumption'
    capacity: 0
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    publisherEmail: publisherEmail
    publisherName: publisherName
  }
}

// Named value for tenant ID (used in policies)
resource tenantIdValue 'Microsoft.ApiManagement/service/namedValues@2023-09-01-preview' = {
  parent: apim
  name: 'tenant-id'
  properties: {
    displayName: 'tenant-id'
    value: tenantId
    secret: false
  }
}

// Named value for device client ID
resource deviceClientIdValue 'Microsoft.ApiManagement/service/namedValues@2023-09-01-preview' = {
  parent: apim
  name: 'device-client-id'
  properties: {
    displayName: 'device-client-id'
    value: deviceClientId
    secret: false
  }
}

// Named value for API audience
resource apiAudienceValue 'Microsoft.ApiManagement/service/namedValues@2023-09-01-preview' = {
  parent: apim
  name: 'api-audience'
  properties: {
    displayName: 'api-audience'
    value: apiAudience
    secret: false
  }
}

// Backend definition pointing to the App Service API
resource backend 'Microsoft.ApiManagement/service/backends@2023-09-01-preview' = {
  parent: apim
  name: 'cpm-backend'
  properties: {
    title: 'Chrome Policy Manager API'
    description: 'Backend App Service hosting the CPM API'
    url: backendApiUrl
    protocol: 'http'
    credentials: {
      header: {}
      query: {}
    }
    tls: {
      validateCertificateChain: true
      validateCertificateName: true
    }
  }
}

// API definition for device endpoints
resource deviceApi 'Microsoft.ApiManagement/service/apis@2023-09-01-preview' = {
  parent: apim
  name: 'cpm-device-api'
  properties: {
    displayName: 'Chrome Policy Manager - Device API'
    description: 'Device-facing endpoints for Chrome policy delivery and compliance reporting'
    path: 'api/devices'
    protocols: ['https']
    subscriptionRequired: false // Auth is via Entra JWT, not subscription keys
    serviceUrl: '${backendApiUrl}/api/devices'
  }
}

// Operation: Get effective policy
resource getEffectivePolicy 'Microsoft.ApiManagement/service/apis/operations@2023-09-01-preview' = {
  parent: deviceApi
  name: 'get-effective-policy'
  properties: {
    displayName: 'Get Effective Policy'
    method: 'GET'
    urlTemplate: '/{deviceId}/effective-policy'
    templateParameters: [
      {
        name: 'deviceId'
        required: true
        type: 'string'
        description: 'Entra device ID'
      }
    ]
  }
}

// Operation: Submit device report
resource submitDeviceReport 'Microsoft.ApiManagement/service/apis/operations@2023-09-01-preview' = {
  parent: deviceApi
  name: 'submit-device-report'
  properties: {
    displayName: 'Submit Device Report'
    method: 'POST'
    urlTemplate: '/{deviceId}/report'
    templateParameters: [
      {
        name: 'deviceId'
        required: true
        type: 'string'
        description: 'Entra device ID'
      }
    ]
  }
}

// API-level policy (applies to all device operations)
resource deviceApiPolicy 'Microsoft.ApiManagement/service/apis/policies@2023-09-01-preview' = {
  parent: deviceApi
  name: 'policy'
  properties: {
    format: 'xml'
    value: loadTextContent('policies/device-api-policy.xml')
  }
}

// Output APIM managed identity for backend configuration
output apimPrincipalId string = apim.identity.principalId
output apimGatewayUrl string = apim.properties.gatewayUrl
output apimName string = apim.name
