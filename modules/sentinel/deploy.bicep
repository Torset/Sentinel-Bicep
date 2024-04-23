@description('Required. Name of the Log Analytics workspace.')
param workspaceName string

@description('Optional. Location for all resources.')
param location string

@description('Optional. The tenant ID where the resources will be deployed.')
param tenantId string





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

resource UEBASetting 'Microsoft.SecurityInsights/settings@2023-02-01-preview' = {
  name: 'Ueba'
  kind: 'Ueba'
  scope: laws
  // For remaining properties, see settings objects
  properties: {
    dataSources: [
      'AuditLogs'
      'AzureActivity'
      'SecurityEvent'
      'SigninLogs'
    ]
  }
}

  

  /////////////////
 // Alert rules //
/////////////////

resource MfaRejectedByUser 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: 'MFA Rejected by User'
  kind: 'Scheduled'
  scope: laws
  // For remaining properties, see alertRules objects
  properties: {
    alertRuleTemplateName: 'd99cf5c3-d660-436c-895b-8a8f8448da23'
    customDetails: {}
    description: 'Identifies occurances where a user has rejected an MFA prompt. This could be an indicator that a threat actor has compromised the username and password of this user account and is using it to try and log into the account.\r\n  Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts#monitoring-for-failed-unusual-sign-ins\r\n  This query has also been updated to include UEBA logs IdentityInfo and BehaviorAnalytics for contextual information around the results.'
    displayName: 'MFA Rejected by User'
    enabled: true
    entityMappings: [
      {
        entityType: 'Host'
        fieldMappings: [
          {
            columnName: 'HostName'
            identifier: 'HostName'
          }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          {
            columnName: 'Address'
            identifier: 'IP_addr'
          }
        ]
      }
      {
        entityType: 'URL'
        fieldMappings: [
          {
            columnName: 'Url'
            identifier: 'Url'
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
    let dt_lookBack = 1h; // Lookback time for recent data, set to 1 hour
    let ioc_lookBack = 14d; // Lookback time for threat feed data, set to 14 days
    // Create a list of TLDs in our threat feed for later validation
    let list_tlds = ThreatIntelligenceIndicator
      | where TimeGenerated >= ago(ioc_lookBack)
      | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
      | where Active == true and ExpirationDateTime > now()
      | where isnotempty(DomainName)
      | extend parts = split(DomainName, '.')
      | extend tld = parts[(array_length(parts)-1)]
      | summarize count() by tostring(tld)
      | summarize make_list(tld);
    let Domain_Indicators = ThreatIntelligenceIndicator
      | where TimeGenerated >= ago(ioc_lookBack)
      | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
      | where Active == true and ExpirationDateTime > now()
      // Picking up only IOC's that contain the entities we want
      | where isnotempty(DomainName)
      | extend TI_DomainEntity = DomainName;
    Domain_Indicators
      // Using innerunique to keep performance fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated
      | join kind=innerunique (
        SecurityAlert
        | where TimeGenerated > ago(dt_lookBack)
        | extend MSTI = case(AlertName has "TI map" and VendorName == "Microsoft" and ProductName == 'Azure Sentinel', true, false)
        | where MSTI == false
        // Extract domain patterns from message
        | extend domain = todynamic(dynamic_to_json(extract_all(@"(((xn--)?[a-z0-9\-]+\.)+([a-z]+|(xn--[a-z0-9]+)))", dynamic([1,1]), tolower(Entities))))
        | mv-expand domain
        | extend domain = tostring(domain[0])
        | extend parts = split(domain, '.')
        // Split out the TLD
        | extend tld = parts[(array_length(parts)-1)]
        // Validate parsed domain by checking if the TLD is in the list of TLDs in our threat feed
        | where tld in~ (list_tlds)
        // Converting Entities into dynamic data type and use mv-expand to unpack the array
        | extend EntitiesDynamicArray = parse_json(Entities)
        | mv-apply EntitiesDynamicArray on
          (summarize
            HostName = take_anyif(tostring(EntitiesDynamicArray.HostName), EntitiesDynamicArray.Type == "host"),
            IP_addr = take_anyif(tostring(EntitiesDynamicArray.Address), EntitiesDynamicArray.Type == "ip")
          )
        | extend Alert_TimeGenerated = TimeGenerated
        | extend Alert_Description = Description
      ) on $left.TI_DomainEntity == $right.domain
      | where Alert_TimeGenerated < ExpirationDateTime
      | summarize Alert_TimeGenerated = arg_max(Alert_TimeGenerated, *) by IndicatorId, AlertName
      | project Alert_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore, DomainName, AlertName, Alert_Description, ProviderName, AlertSeverity, ConfidenceLevel, HostName, IP_addr, Url, Entities, Type, TI_DomainEntity
      | extend timestamp = Alert_TimeGenerated
    '''
    queryFrequency: 'PT1H'
    queryPeriod: 'P14D'
    sentinelEntitiesMappings: [
      {
        columnName: 'string'
      }
    ]
    severity: 'Medium'
    suppressionEnabled: false
    suppressionDuration: 'PT1H'
    tactics: [
      'Impact'
    ]
    techniques: [
  
    ]
    templateVersion: '1.4.1'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
  }
}
