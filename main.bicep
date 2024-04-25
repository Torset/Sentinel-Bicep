@description('The Azure region into which the resources should be deployed.')
param location string

@description('The name of the Log Analytics Workspace where Sentinel will be deployed.')
param workspaceName string

@description('The tenant ID where the resources will be deployed.')
param tenantId string

@description('Enable Entity Analytics')
param enableEntityAnalytics bool

@description('Enable UEBA')
param enableUeba bool

@description('Enable EyesOn')
param enableEyesOn bool

@description('Enable Anomalies')
param enableAnomalies bool

@description('Name of the resource Group where Sentinel will be deployed')
param sentinelRgName string

@description('Name of the resource Group where Automation rules / playbooks for Sentinel will be deployed')
param sentinelAutomationRgName string


targetScope = 'subscription'


resource sentinelRg 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  location: location
  name: sentinelRgName
  properties: {}
}

resource sentinelAutomationRg 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  location: location
  name: sentinelAutomationRgName
  properties: {}
}

module sentinel './modules/sentinel/deploy.bicep' = {
  scope: sentinelRg
  name: 'SentinelDeployment'
  params: {
    location: location
    workspaceName: workspaceName
    tenantId: tenantId
    enableEntityAnalytics:enableEntityAnalytics
    enableUeba:enableUeba
    enableEyesOn:enableEyesOn
    enableAnomalies:enableAnomalies
  }
}



