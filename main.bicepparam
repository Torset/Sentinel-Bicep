using 'main.bicep'

param location = 'westeurope'

param workspaceName = 'Sentinel-LoganalyticsWorkspace' 

param tenantId = 'abf67dae-9a43-4bf0-aa92-151fd6a1d425' 



 // Sentinel settings//

param enableEntityAnalytics = false // Needs to be enabled manually in the portal
param enableUeba = false // Needs to be enabled manually in the portal
param enableAnomalies = true
param enableEyesOn = true

