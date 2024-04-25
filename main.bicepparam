using 'main.bicep'

param location = 'westeurope'

param workspaceName = 'Sentinel-LoganalyticsWorkspace' 

param tenantId = 'abf67dae-9a43-4bf0-aa92-151fd6a1d425' 

param sentinelRgName = 'New-Sentinel-RG'

param sentinelAutomationRgName = 'New-Sentinel-Automation-RG'


 // Sentinel settings//

param enableEntityAnalytics = true // Needs to be enabled manually in the portal until bug is fixed
param enableUeba = true // Needs to be enabled manually in the portal until bug is fixed
param enableAnomalies = true
param enableEyesOn = true

