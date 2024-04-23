@description('The Azure region into which the resources should be deployed.')
param location string

@description('The name of the Log Analytics Workspace where Sentinel will be deployed.')
param workspaceName string

@description('The tenant ID where the resources will be deployed.')
param tenantId string

@description('The state of the AzureActiveDirectory data connector')
param azureADDataConnectorState string

@description('The state of the AzureActivity data connector')
param azureActivityDataConnectorState string

targetScope = 'subscription'


resource resourceGroup 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  location: location
  name: 'New-Sentinel-RG'
  properties: {}
}

module sentinel './modules/sentinel/deploy.bicep' = {
  scope: resourceGroup
  name: 'SentinelDeployment'
  params: {
    location: location
    workspaceName: workspaceName
    tenantId: tenantId
    azureADDataConnectorState: azureADDataConnectorState
    azureActivityDataConnectorState: azureActivityDataConnectorState
  }
}




