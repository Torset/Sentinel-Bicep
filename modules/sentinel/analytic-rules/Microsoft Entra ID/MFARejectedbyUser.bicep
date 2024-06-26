@description('The name of the Log Analytics Workspace where Sentinel will be deployed.')
param workspaceName string


resource laws 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
 }


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
