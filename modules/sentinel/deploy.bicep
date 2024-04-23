@description('Required. Name of the Log Analytics workspace.')
param workspaceName string

param location string


param tenantId string

module workspace 'br/public:avm/res/operational-insights/workspace:0.3.4' = {
  name: 'workspaceDeployment'
  params: {
    // Required parameters
    name: workspaceName
    // Non-required parameters
    location: location
    dataRetention: 60
    skuName: 'PerGB2018'
  }
}


resource sentinel 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {
  name: 'SecurityInsights(${workspaceName})'
  location:location
  properties:{
    workspaceResourceId: workspace.outputs.resourceId
  }
  plan: {
    name: 'SecurityInsights(${workspaceName})'
    product: 'OMSGallery/SecurityInsights'
    promotionCode: ''
    publisher: 'Microsoft'
  }
}

resource laws 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
 }


resource azureADDataConnector 'Microsoft.SecurityInsights/dataConnectors@2023-02-01-preview' = {
  name: '${workspaceName}-AzureActiveDirectory'
  kind: 'AzureActiveDirectory'
  scope: laws
  dependsOn: [
    sentinel
  ]
  properties: {
    dataTypes: {
      alerts: {
        state: 'Enabled'
      }
    }
    tenantId: tenantId
  }

}
