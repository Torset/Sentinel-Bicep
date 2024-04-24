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

resource sentinelSettingsEntityAnalytics 'Microsoft.SecurityInsights/settings@2024-01-01-preview' = if (enableEntityAnalytics) {
  name: 'EntityAnalytics'
  kind: 'EntityAnalytics'
  scope: laws
  etag: '*'
  properties: {
    entityProviders: entityAnalyticsEntityProviders
  } 
}


resource sentinelSettingsUeba 'Microsoft.SecurityInsights/settings@2024-01-01-preview' = if (enableUeba) {
  name: 'Ueba'
  kind: 'Ueba'
  scope: laws
  etag: '*'
  dependsOn:[sentinelSettingsEntityAnalytics]
  // For remaining properties, see settings objects
  properties: {
    dataSources: uebaDataSources
  }
}

  
resource sentinelSettingsEyesOn 'Microsoft.SecurityInsights/settings@2024-01-01-preview' = if (enableEyesOn) {
  name: 'EyesOn'
  kind: 'EyesOn'
  scope: laws
  properties: {}
}

resource sentinelSettingsAnomalies 'Microsoft.SecurityInsights/settings@2024-01-01-preview' = if (enableAnomalies) {
  name: 'Anomalies'
  kind: 'Anomalies'
  scope: laws
  properties: {}
}


  /////////////////
 // Alert rules //
/////////////////

resource MfaRejectedByUser 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: 'MFA Rejected by User'
  kind: 'Scheduled'
  scope: laws
  properties: {
    severity: 'Medium'
    alertRuleTemplateName: 'd99cf5c3-d660-436c-895b-8a8f8448da23'
    customDetails: {}
    description: 'Identifies occurances where a user has rejected an MFA prompt. This could be an indicator that a threat actor has compromised the username and password of this user account and is using it to try and log into the account.\r\n  Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts#monitoring-for-failed-unusual-sign-ins\r\n  This query has also been updated to include UEBA logs IdentityInfo and BehaviorAnalytics for contextual information around the results.'
    displayName: 'MFA Rejected by User'
    enabled: true
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'UserPrincipalName'
          }
          {
            identifier: 'Name'
            columnName: 'Name'
          }
          {
            identifier: 'UPNSuffix'
            columnName: 'UPNSuffix'
          }
        ]
      }
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'AadUserId'
            columnName: 'UserId'
          }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'IPAddress'
          }
        ]
      }
    ]
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
    incidentConfiguration: {
      createIncident: true
    }
    query: '''
    let riskScoreCutoff = 20; //Adjust this based on volume of results
    SigninLogs
    | where ResultType == 500121
    | extend additionalDetails_ = tostring(Status.additionalDetails)
    | extend UserPrincipalName = tolower(UserPrincipalName)
    | where additionalDetails_ =~ "MFA denied; user declined the authentication" or additionalDetails_ has "fraud"
    | summarize StartTime = min(TimeGenerated), EndTIme = max(TimeGenerated) by UserPrincipalName, UserId, AADTenantId, IPAddress
    | extend Name = tostring(split(UserPrincipalName,'@',0)[0]), UPNSuffix = tostring(split(UserPrincipalName,'@',1)[0])
    | join kind=leftouter (
        IdentityInfo
        | summarize LatestReportTime = arg_max(TimeGenerated, *) by AccountUPN
        | project AccountUPN, Tags, JobTitle, GroupMembership, AssignedRoles, UserType, IsAccountEnabled
        | summarize
            Tags = make_set(Tags, 1000),
            GroupMembership = make_set(GroupMembership, 1000),
            AssignedRoles = make_set(AssignedRoles, 1000),
            UserType = make_set(UserType, 1000),
            UserAccountControl = make_set(UserType, 1000)
        by AccountUPN
        | extend UserPrincipalName=tolower(AccountUPN)
    ) on UserPrincipalName
    | join kind=leftouter (
        BehaviorAnalytics
        | where ActivityType in ("FailedLogOn", "LogOn")
        | where isnotempty(SourceIPAddress)
        | project UsersInsights, DevicesInsights, ActivityInsights, InvestigationPriority, SourceIPAddress
        | project-rename IPAddress = SourceIPAddress
        | summarize
            UsersInsights = make_set(UsersInsights, 1000),
            DevicesInsights = make_set(DevicesInsights, 1000),
            IPInvestigationPriority = sum(InvestigationPriority)
        by IPAddress)
    on IPAddress
    | extend UEBARiskScore = IPInvestigationPriority
    | where  UEBARiskScore > riskScoreCutoff
    | sort by UEBARiskScore desc
    '''
    queryFrequency: 'PT1H'
    queryPeriod: 'P14D'
    suppressionEnabled: false
    suppressionDuration: 'PT1H'
    tactics: [
      'InitialAccess'
    ]
    techniques: [
      'T1078'
    ]
    templateVersion: '2.0.3'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
  }
}
