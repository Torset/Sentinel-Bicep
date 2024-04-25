@description('Required. Name of the Log Analytics workspace.')
param workspaceName string

@description('Optional. Location for all resources.')
param location string

@description('Optional. The tenant ID where the resources will be deployed.')
param tenantId string

@description('entityAnalyticsEntityProviders')
param entityAnalyticsEntityProviders array = [
  'AzureActiveDirectory'
]

@description('uebaDataSources')
param uebaDataSources array = [ 'AuditLogs'
  'AzureActivity'
  'SecurityEvent'
  'SigninLogs' ]

@description('Optional. Enable Entity Analytics')
param enableEntityAnalytics bool 

@description('Optional. Enable UEBA')
param enableUeba bool

@description('Optional. Enable EyesOn')
param enableEyesOn bool

@description('Optional. Enable Anomalies')
param enableAnomalies bool




module workspace 'br/public:avm/res/operational-insights/workspace:0.3.4' = {
  name: 'workspaceDeployment'
  params: {
    // Required parameters.
    name: workspaceName
    // Non-required parameters.
    location: location
    dataRetention: 60
    skuName: 'PerGB2018'
  }
}


resource sentinel 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {
  name: 'SecurityInsights(${workspaceName})'
  location:location
  dependsOn:[
    workspace
  ]
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

  /////////////////////
 // Data connectors //
/////////////////////

resource azureADDataConnector 'Microsoft.SecurityInsights/dataConnectors@2023-02-01-preview' = {
  name: '${workspaceName}-AzureActiveDirectory'
  kind: 'AzureActiveDirectory'
  scope: laws
  properties: {
    dataTypes: {
      alerts: {
        state: 'Enabled'
      }
    }
    tenantId: tenantId
  }
}

resource office365DataConnector 'Microsoft.SecurityInsights/dataConnectors@2023-02-01-preview' = {
  name: '${workspaceName}-Office365'
  kind: 'Office365'
  scope: laws
  properties: {
    dataTypes: {
      exchange: {
        state: 'Enabled'
      }
      sharePoint: {
        state: 'Enabled'
      }
      teams: {
        state: 'Enabled'
      }
    }
    tenantId: tenantId
  }
}

resource officeAtpDataConnector 'Microsoft.SecurityInsights/dataConnectors@2023-02-01-preview' = {
  name: '${workspaceName}-OfficeATP'
  kind: 'OfficeATP'
  scope: laws
  properties: {
    dataTypes: {
      alerts: {
        state: 'Enabled'
      }
    }
    tenantId: tenantId
  }
}

resource sentinelSettingsEntityAnalytics 'Microsoft.SecurityInsights/settings@2023-02-01-preview' = if (enableEntityAnalytics) {
  name: 'EntityAnalytics'
  kind: 'EntityAnalytics'
  scope: laws
  properties: {
    entityProviders: entityAnalyticsEntityProviders
  } 
}


resource sentinelSettingsUeba 'Microsoft.SecurityInsights/settings@2023-02-01-preview' = if (enableUeba) {
  name: 'Ueba'
  kind: 'Ueba'
  scope: laws
  dependsOn:[sentinelSettingsEntityAnalytics]
  // For remaining properties, see settings objects
  properties: {
    dataSources: uebaDataSources
  }
}

  
resource sentinelSettingsEyesOn 'Microsoft.SecurityInsights/settings@2023-02-01-preview' = if (enableEyesOn) {
  name: 'EyesOn'
  kind: 'EyesOn'
  scope: laws
  properties: {}
}

resource sentinelSettingsAnomalies 'Microsoft.SecurityInsights/settings@2023-02-01-preview' = if (enableAnomalies) {
  name: 'Anomalies'
  kind: 'Anomalies'
  scope: laws
  properties: {}
}


  module MFARejected 'analytic-rules/Microsoft Entra ID/MFARejectedbyUser.bicep' = {  
  name: 'MFARejected'
  params: {
    workspaceName: workspaceName
  }
}


