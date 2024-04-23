using 'main.bicep'

param location = 'westeurope'

param workspaceName = 'Sentinel-LoganalyticsWorkspace' 

param tenantId = 'abf67dae-9a43-4bf0-aa92-151fd6a1d425' 


  /////////////////////
 // Data connectors //
/////////////////////

param azureADDataConnectorState = 'Enabled' // Needs Global- / Security Administrator
