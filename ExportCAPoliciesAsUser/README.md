# Export CA Policies As User

#### This function relies upon 3 separate modules for exporting Conditional Access Policies
##### AADInternals
###### Install-Module AADInternals
###### Get an access token for AAD API by running
###### Import-Module AADInternals
###### Get-AADIntAccessTokenForAADGraph -SaveToCache

##### MSOnline
##### AzureAD
Connect to AzureAD and Msol modules

##### Connect-AzureAD
##### Connect-MsolService




Import the function and run it as follows:

##### Export-TSxConditionalAccessPoliciesAsUser -OutputPath C:\Exports
