<#
.DESCRIPTION
   Exports all Conditional Access Policies in the tenant to a json file
   You need to run Connect-TSxAAD prior to running this cmdlet
.NOTES
   Author: Viktor Hedberg
.EXAMPLE
   Export-TSxConditionalAccessPoliciesAsUser -OutputPath C:\Exports
.PARAMETER OutputPath
   Specifies the OutputPath for the exports


#>
function Export-TSxAzureADConditionalAccessPoliciesAsUser{
    param (
        [parameter(Mandatory = $true)]
        [array]$OutputPath        
    )

    Write-Host "Gathering Conditional Access Policies" -ForegroundColor Yellow
    $TenantName = (Get-AzureADTenantDetail).DisplayName
    $AADIntCAPolicies = Get-AADIntConditionalAccessPolicies | Where-Object policyType -EQ "18" | Where-Object tenantDefaultPolicy -EQ $null
    $CurrentItem = 0
    $PercentComplete = 0
    $TotalItems = $AADIntCAPolicies.Count
    $Policies = forEach ($AADIntCAPolicy in $AADIntCAPolicies){
        Write-Progress -Activity "Gathering Conditional Access Policies" -Status "$PercentComplete% Complete:" -PercentComplete $PercentComplete
        $CurrentItem++
        $PercentComplete = [int](($CurrentItem / $TotalItems) * 100)
            
        $AADIntCAPolicyDetail = $AADIntCAPolicy.PolicyDetail | ConvertFrom-Json
        $PolicyId = $AADIntCAPolicy.ObjectId
        $PolicyDisplayName = $AADIntCAPolicy.DisplayName
        $PolicyState = $AADIntCAPolicyDetail.State
        $IncludedUsers = $AADIntCAPolicyDetail.Conditions.Users.Include.Users | Out-String
        $ExcludedUsers = $AADIntCAPolicyDetail.Conditions.Users.Exclude.Users | Out-String
        $IncludedGroups = $AADIntCAPolicyDetail.Conditions.Users.Include.Groups | Out-String
        $ExcludedGroups = $AADIntCAPolicyDetail.Conditions.Users.Exclude.Groups | Out-String
        $IncludedRoles = $AADIntCAPolicyDetail.Conditions.Users.Include.Roles | Out-String
        $ExcludedRoles = $AADIntCAPolicyDetail.Conditions.Users.Exclude.Roles | Out-String
        $IncludedApplications = $AADIntCAPolicyDetail.Conditions.Applications.Include.Applications | Out-String
        $ExcludedApplications = $AADIntCAPolicyDetail.Conditions.Applications.Exclude.Applications | Out-String
        $UserActionsOrAuthContexts = $AADIntCAPolicyDetail.Conditions.Applications.Include.Acrs | Out-String
        $IncludedPlatforms = $AADIntCAPolicyDetail.Conditions.DevicePlatforms.Include | Out-String
        $ExcludedPlatforms = $AADIntCAPolicyDetail.Conditions.DevicePlatforms.Exclude | Out-String
        $IncludedLocations = $AADIntCAPolicyDetail.Conditions.Locations.Include.Locations | Out-String
        $ExcludedLocations = $AADIntCAPolicyDetail.Conditions.Locations.Exclude.Locations | Out-String
        $UserRiskLevels = $AADIntCAPolicyDetail.Conditions.UserRisks.Include.UserRisks | Out-String
        $SignInRiskLevels = $AADIntCAPolicyDetail.Conditions.SignInRisks.Include.SignInRisks | Out-String
        $IncludedClientAppTypes = $AADIntCAPolicyDetail.Conditions.ClientTypes.Include.ClientTypes | Out-String
        $IncludedDevices = $AADIntCAPolicyDetail.Conditions.DevicePlatforms.Include.DevicePlatforms | Out-String
        $ExcludedDevices = $AADIntCAPolicyDetail.Conditions.DevicePlatforms.Exclude.DevicePlatforms | Out-String
        $DeviceFilterMode = $AADIntCAPolicyDetail.Conditions.Devices.Include.DeviceRule | Out-String
        $DeviceFilterRule = $AADIntCAPolicyDetail.Conditions.Devices.Exclude.DeviceRule | Out-String
        $GrantControls = $AADIntCAPolicyDetail.Controls.Control| Out-String
        $CustomAuthentictationFactors = $AADIntCAPolicyDetail.GrantControls.CustomAuthenticationFactors | Out-String
        $TermsOfUse = $AADIntCAPolicyDetail.GrantControls.TermsOfUse | Out-String
        $ApplicationEnforcedRestrictions = $AADIntCAPolicyDetail.SessionControls.ApplicationEnforceRestrictions | Out-String
        $SignInFrequencyValue = $AADIntCAPolicyDetail.SignInFrequencyTimeSpan | Out-String
        $SessionControls = $AADIntCAPolicyDetail.SessionControls
        $PersistenBrowser = $AADIntCAPolicyDetail.PersistentBrowserSessionMode | Out-String


        ##########################################################################
        # Lookup 'Included Users'                                                #
        ##########################################################################

        #Lookup 'Included Users' by performing data modification.
        #Convert to Json
        $IncludedUsersToJson = $IncludedUsers | ConvertTo-Json

        #Replace \r\n at the end of each object in the string with ,
        $ReplaceDataInJsonIncludedUsers = $IncludedUsersToJson.Replace('\r\n',',')
    
        #Replace " with nothing to make the string splittable
        $ReplaceDataInJsonSplittableIncludedUsers = $ReplaceDataInJsonIncludedUsers.Replace('"','')
    
        #Trim the last "," to construct correct amount of strings
        $TrimStringIncludedUsers = $ReplaceDataInJsonSplittableIncludedUsers.TrimEnd(',')
    
        #Split the string into multiple strings using "," as a separator
        $SplitStringIncludedUsers = $TrimStringIncludedUsers -split ","
    
        #Lookup AzureAD users by using the ObjectId value
        $IncludedUsersLookup = Get-AzureADUser -All:$true | Where-Object {$_.ObjectId -In $SplitStringIncludedUsers}

  


        ##########################################################################
        # Lookup 'Excluded Users'                                                #
        ##########################################################################

        #Lookup 'Excluded Users' by performing data modification.
        #Convert to Json
        $ExcludedUsersToJson = $ExcludedUsers | ConvertTo-Json

        #Replace \r\n at the end of each object in the string with ,
        $ReplaceDataInJsonExcludedUsers = $ExcludedUsersToJson.Replace('\r\n',',')

        #Replace " with nothing to make the string splittable
        $ReplaceDataInJsonSplittableExlucedUsers = $ReplaceDataInJsonExcludedUsers.Replace('"','')

        #Trim the last "," to construct correct amount of strings
        $TrimStringExcludedUsers = $ReplaceDataInJsonSplittableExlucedUsers.TrimEnd(',')

        #Split the string into multiple strings using "," as a separator
    
        $SplitStringExcludedUsers = $TrimStringExcludedUsers -split ","
    
    
        $ExcludedUsersLookup = Get-AzureADUser -All:$true | Where-Object {$_.ObjectId -In $SplitStringExcludedUsers}



        ##########################################################################
        # Lookup 'Included Groups'                                               #
        ##########################################################################

        #Lookup 'Included Groups' by performing data modification.
        #Convert to Json
        $IncludedGroupsToJson = $IncludedGroups | ConvertTo-Json

        #Replace \r\n at the end of each object in the string with ,
        $ReplaceDataInJsonIncludedGroups = $IncludedGroupsToJson.Replace('\r\n',',')

        #Replace " with nothing to make the string splittable
        $ReplaceDataInJsonSplittableIncludedGroups = $ReplaceDataInJsonIncludedGroups.Replace('"','')

        #Trim the last "," to construct correct amount of strings
        $TrimStringIncludedGroups= $ReplaceDataInJsonSplittableIncludedGroups.TrimEnd(',')

        #Split the string into multiple strings using "," as a separator
    
        $SplitStringIncludedGroups = $TrimStringIncludedGroups -split ","
    
    
        $IncludedGroupsLookup = Get-AzureADGroup -All:$true | Where-Object {$_.ObjectId -In $SplitStringIncludedGroups}
  


        ##########################################################################
        # Lookup 'Excluded Groups'                                               #
        ##########################################################################

        #Lookup 'Excluded Groups' by performing data modification.
        #Convert to Json
        $ExcludedGroupsToJson = $ExcludedGroups | ConvertTo-Json

        #Replace \r\n at the end of each object in the string with ,
        $ReplaceDataInJsonExcludedGroups = $ExcludedGroupsToJson.Replace('\r\n',',')

        #Replace " with nothing to make the string splittable
        $ReplaceDataInJsonSplittableExcludedGroups = $ReplaceDataInJsonExcludedGroups.Replace('"','')

        #Trim the last "," to construct correct amount of strings
        $TrimStringExcludedGroups= $ReplaceDataInJsonSplittableExcludedGroups.TrimEnd(',')

        #Split the string into multiple strings using "," as a separator
    
        $SplitStringExcludedGroups = $TrimStringExcludedGroups -split ","
    
    
        $ExcludedGroupsLookup = Get-AzureADGroup -All:$true | Where-Object {$_.ObjectId -In $SplitStringExcludedGroups}


        ##########################################################################
        # Lookup 'Included Roles'                                                #
        ##########################################################################

        #Lookup 'Included Roles' by performing data modification.
        #Convert to Json
        $IncludedRolesToJson = $IncludedRoles | ConvertTo-Json

        #Replace \r\n at the end of each object in the string with ,
        $ReplaceDataInJsonIncludedRoles = $IncludedRolesToJson.Replace('\r\n',',')

        #Replace " with nothing to make the string splittable
        $ReplaceDataInJsonSplittableIncludedRoles = $ReplaceDataInJsonIncludedRoles.Replace('"','')

        #Trim the last "," to construct correct amount of strings
        $TrimStringIncludedRoles= $ReplaceDataInJsonSplittableIncludedRoles.TrimEnd(',')

        #Split the string into multiple strings using "," as a separator
    
        $SplitStringIncludedRoles = $TrimStringIncludedRoles -split ","
    
     

        $IncludedRolesLookup = Get-MsolRole | Where-Object {$_.ObjectId -In $SplitStringIncludedRoles}


        ##########################################################################
        # Lookup 'Excluded Roles'                                                #
        ##########################################################################

        #Lookup 'Excluded Roles' by performing data modification.
        #Convert to Json
        $ExcludedRolesToJson = $ExcludedRoles | ConvertTo-Json

        #Replace \r\n at the end of each object in the string with ,
        $ReplaceDataInJsonExcludedRoles = $ExcludedRolesToJson.Replace('\r\n',',')

        #Replace " with nothing to make the string splittable
        $ReplaceDataInJsonSplittableExcludedRoles = $ReplaceDataInJsonExcludedRoles.Replace('"','')

        #Trim the last "," to construct correct amount of strings
        $TrimStringExcludedRoles= $ReplaceDataInJsonSplittableExcludedRoles.TrimEnd(',')

        #Split the string into multiple strings using "," as a separator
    
        $SplitStringExcludedRoles = $TrimStringExcludedRoles -split ","


        $ExcludedRolesLookup = Get-MsolRole | Where-Object {$_.ObjectId -In $SplitStringExcludedRoles}
    
    
        ##########################################################################
        # Lookup 'Included Applications'                                         #
        ##########################################################################

        #Lookup 'Included Applications' by performing data modification.
        #Convert to Json
        $IncludedAppsToJson = $IncludedApplications | ConvertTo-Json

        #Replace \r\n at the end of each object in the string with ,
        $ReplaceDataInJsonIncludedApps = $IncludedAppsToJson.Replace('\r\n',',')

        #Replace " with nothing to make the string splittable
        $ReplaceDataInJsonSplittableIncludedApps = $ReplaceDataInJsonIncludedApps.Replace('"','')

        #Trim the last "," to construct correct amount of strings
        $TrimStringIncludedApps= $ReplaceDataInJsonSplittableIncludedApps.TrimEnd(',')

        #Split the string into multiple strings using "," as a separator
    
        $SplitStringIncludedApps = $TrimStringIncludedApps -split ","
    
    
        $IncludedAppsLookup = Get-AzureADServicePrincipal -All:$true | Where-Object {$_.AppId -In $SplitStringIncludedApps}


        ##########################################################################
        # Lookup 'Excluded Applications'                                         #
        ##########################################################################

        #Lookup 'Excluded Applications' by performing data modification.
        #Convert to Json
        $ExcludedAppsToJson = $ExcludedApplications | ConvertTo-Json

        #Replace \r\n at the end of each object in the string with ,
        $ReplaceDataInJsonExcludedApps = $ExcludedAppsToJson.Replace('\r\n',',')

        #Replace " with nothing to make the string splittable
        $ReplaceDataInJsonSplittableExcludedApps = $ReplaceDataInJsonExcludedApps.Replace('"','')

        #Trim the last "," to construct correct amount of strings
        $TrimStringExcludedApps= $ReplaceDataInJsonSplittableExcludedApps.TrimEnd(',')

        #Split the string into multiple strings using "," as a separator
    
        $SplitStringExcludedApps = $TrimStringExcludedApps -split ","
    
    
        $ExcludedAppsLookup = Get-AzureADServicePrincipal -All:$true | Where-Object {$_.AppId -In $SplitStringExcludedApps}

        

        ##########################################################################
        # Lookup 'Exclude Device Rule'                                           #
        ##########################################################################

        $ExcludedDevicesToJson = $DeviceFilterRule | ConvertTo-Json

        $ExcludedDevicesRemoveRule = $ExcludedDevicesToJson -Replace('device.deviceId -eq'),('')
        $ExcludedDevicesRemoveOr = $ExcludedDevicesRemoveRule -replace ('-or'),('')

        #Replace \r\n at the end of each object in the string with ,
        $ReplaceDataInJsonExcludedDevices = $ExcludedDevicesRemoveOr.Replace('\r\n',',')

        #Replace " with nothing to make the string splittable
        $ReplaceDataInJsonSplittableExcludedDevices = $ReplaceDataInJsonExcludedDevices.Replace('"','')

        #Trim the last "," to construct correct amount of strings
        $TrimStringExcludedDevices = $ReplaceDataInJsonSplittableExcludedDevices.TrimEnd(',')

        #Split the string into multiple strings using "\," as a separator
        $SplitStringExcludedDevices = $ReplaceDataInJsonSplittableExcludedDevices.Split("\,")

        $ExcludedDevicesName = Get-AzureADDevice -All:$true | Where-Object {$_.DeviceId -in $SplitStringExcludedDevices}

    
    
        $CACustomObject = New-Object -TypeName PSObject
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Policy ObjectId" -Value $PolicyId
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $PolicyDisplayName
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "State" -Value $PolicyState
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Included Users" -Value $IncludedUsers
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Included Users (Lookup)" -Value $IncludedUsersLookup.UserPrincipalName
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Excluded Users" -Value $ExcludedUsers
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Excluded Users (Lookup)" -Value $ExcludedUsersLookup.UserPrincipalName
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Included Groups" -Value $IncludedGroups
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Included Groups (Lookup)" -Value $IncludedGroupsLookup.DisplayName
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Excluded Groups" -Value $ExcludedGroups
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Excluded Groups (Lookup)" -Value $ExcludedGroupsLookup.DisplayName
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Included Roles" -Value $IncludedRoles
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Included Roles (Lookup)" -Value $IncludedRolesLookup.Name
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Excluded Roles" -Value $ExcludedRoles
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Excluded Roles (Lookup)" -Value $ExcludedRolesLookup.Name
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Included Applications" -Value $IncludedApplications
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Included Applications (Lookup)" -Value $IncludedAppsLookup.DisplayName
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Excluded Applications" -Value $ExcludedApplications
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Excluded Applications (Lookup)" -Value $ExcludedAppsLookup.DisplayName
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "User Actions or Auth Contexts" -Value $UserActionsOrAuthContexts
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Included Device Platforms" -Value $IncludedPlatforms
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Excluded Device Platforms" -Value $ExcludedPlatforms
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Included Locations" -Value $IncludedLocations
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Excluded Locations" -Value $ExcludedLocations
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "User Risk Levels" -Value $UserRiskLevels
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Sign Risk Levels" -Value $SignInRiskLevels
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Client App Types" -Value $ClientAppTypes
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Included Devices" -Value $IncludedDevices
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Excluded Devices" -Value $ExcludedDevices
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Device Filter Mode" -Value $DeviceFilterMode
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Device Filter Rule" -Value $DeviceFilterRule
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Device Name" -Value $ExcludedDevicesName.DisplayName
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Grant Controls" -Value $GrantControls
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Grant Controls Custom Authentication Factors" -Value $CustomAuthentictationFactors
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Grant Controls Terms Of Use" -Value $TermsOfUse
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Application Enforced Restrictions" -Value $ApplicationEnforcedRestrictions
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "MCAS" -Value $MCAS
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Sign In Frequency Value" -Value $SignInFrequencyValue
        #$CACustomObject | Add-Member -MemberType NoteProperty -Name "Sign In Frequency Type" -Value $SignInFrequencyType
        $CACustomObject | Add-Member -MemberType NoteProperty -Name "Persistent Browser Mode" -Value $PersistenBrowser
        $CACustomObject

        }
    $CAResult = $Policies | Sort-Object DisplayName -Descending
    $CAExportResult = $CAResult | ConvertTo-Json
    $CAExportableResult = $CAExportResult.Replace('\r\n',',')
    $CAExportableResult | Out-File -FilePath $OutputPath\$TenantName-TSxCAPolicies.json -Encoding ascii 

    $CAMisconfig = $CAResult | Out-GridView -PassThru -Title "Select any misconfigured CA Policy and click 'OK' to export it. If none, select 'Cancel'."
    $CAMisconfigExport = $CAMisconfig | ConvertTo-Json
    $CAMisconfigExportable = $CAMisconfigExport.Replace('\r\n',',')
    $CAMisconfigExportable | Out-File -FilePath $OutputPath\$TenantName-TSxMisconfigCA.json -Encoding ascii


    Write-Host "DONE - Collected All Conditional Access Policies. Export can be found in $OutputPath\$TenantName-TSxCAPolicies.json and $OutputPath\$TenantName-TSxMisconfigCA.json for Misconfigured CA Policies" -ForegroundColor Yellow  
}
