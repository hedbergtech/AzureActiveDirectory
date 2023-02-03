<#
.VERSION 1.2
1.0 - Initial release
1.1 - Added Workaround for Conditional Access Policy export Linux error and some missing code from lookup functions regarding locations.
1.2 - Added TenantName variable for visibility in Exports
1.3 - Added flow for Exporting Admins if no Azure AD P2 license is in the tenant.
1.4 - Added Export of Users and Groups plus some progress bars.

.DESCRIPTION
This script exports a number of settings from Azure Active Directory to .csv or .json format to quickly be able to review current settings and provide improvements.

This script relies on 3 separate PowerShell modules for the time being.
As such, you need to have these 3 modules installed to be able to run the script:

AzureAD or AzureADPreview
MSOnline
AADInternals

All modules are available in the PSGallery and can be installed using the Install-Module cmdlet

Ensure that the disclaimer is read and understood before execution!

.PARAMETER OutputPath
Specify the OutputPath for file export when running the script.

.EXAMPLE
New-TSxAzureADExport.ps1 -OutputPath C:\tsdata

.NOTES
Author: Truesec Cyber Security Incident Response Team
Website: https://truesec.com/
Created: 2023-01-18

Compatibility: The script has been tested and verified on PowerShell version 5.1 (change if needed)

.DISCLAIMER (change to match script function)
Any of use of this script should be performed by qualified professionals with the necessary knowledge and skills to make independent conclusions.
The script does not guarantee or in any way ensure, promise or indicate that after successful execution, a system can be declared as safe.
The script should be used as a tool to help identify indicators of ..... precense on the system it is executed on.

#>



param (
    [parameter(Mandatory = $true)]
    [array]$OutputPath        
)

#Check for existence of OutputPath parameter.
$OutputPathExists = Test-Path $OutputPath

    if (!($OutputPathExists)) {
        Throw 'Specified OutputPath does not exist. Specify an exisiting folder for export.'
        } 
     

function Start-TSxAADReview{

#Check for AzureAD or AzureADPreview modules
$AzureADModuleExists = Get-Module -Name AzureAD, AzureADPreview -ListAvailable
    if (!($AzureADModuleExists)) {
      Throw 'AzureAD or AzureADPreview module needs to be installed'
    }

#Check for MSOL module
$MsolModuleExists = Get-Module -Name MSOnline -ListAvailable
    if (!($MsolModuleExists)) {
      Throw 'Msol module needs to be installed'
    }

#Check for AADInternals module
$AADIntModuleExists = Get-Module -Name AADInternals -ListAvailable
    if (!($AADIntModuleExists)) {
      Throw 'AADInternals module needs to be installed'
    }

#Connect to Azure AD
Write-Host "Connecting to AzureAD via Azure AD PowerShell Module." -ForegroundColor Cyan
Connect-AzureAD

Import-Module MSOnline
Write-Host "Connecting to Azure AD via Msol PowerShell Module." -ForegroundColor Cyan
Connect-MsolService

Import-Module AADInternals
Write-Host "Connecting to Azure AD Graph API via AADInternals PowerShell Module." -ForegroundColor Cyan
Get-AADIntAccessTokenForMSGraph -SaveToCache
Write-Host "Connecting to MS Graph API via AADInternals PowerShell Module." -ForegroundColor Cyan
Get-AADIntAccessTokenForAADGraph -SaveToCache
}

Start-TSxAADReview

function Export-TSxAzureADUsers{
Write-Host "Gathering All Azure AD Users" -ForegroundColor Yellow
$TenantName = (Get-AzureADTenantDetail).DisplayName

$CurrentItem = 0
$PercentComplete = 0

$AzureADUsers = Get-AzureADUser -All:$true | Select-Object ObjectId,AccountEnabled,UserPrincipalName,DisplayName,UserType,DirSyncEnabled,LastDirSyncTime,ImmutableId,RefreshTokensValidFromDateTime,ExtensionProperty
$TotalItems=$AzureADUsers.Count
    $AllAzureADUsers = foreach ($AzureADUser in $AzureADUsers){
            Write-Progress -Activity "Gathering All Azure AD Users" -Status "$PercentComplete% Complete:" -PercentComplete $PercentComplete
            $CurrentItem++
            $PercentComplete = [int](($CurrentItem / $TotalItems) * 100)
            
            $AADUserId = $AzureADUser.ObjectId
            $AADUserEnabled = $AzureADUser.AccountEnabled
            $AADUserPrincipalName = $AzureADUser.UserPrincipalName
            $AADUserDisplayName = $AzureADUser.DisplayName
            $AADUserType = $AzureADUser.UserType
            $AADUserDirSyncEnabled = $AzureADUser.DirsyncEnabled
            if (!($AADUserDirSyncEnabled)){
                $AADUserDirSyncEnabled = "N/A"
                }
            $AADUserLastDirSyncTime = $AzureADUser.LastDirSyncTime
            $AADUserImmutableId = $AzureADUser.ImmutableId
            $AADUserTokenRefresh = $AzureADUser.RefreshTokensValidFromDateTime
            $AADUserCreatedDateTime = $AzureADUser.ExtensionProperty.createdDateTime
            $AADUserOnPremDN = $AzureADUser.ExtensionProperty.onPremisesDistinguishedName
            if (!($AADUserOnPremDN)){
                $AADUserOnPremDN = "N/A"
                }
            
            
            $UserCustomObject = New-Object -TypeName psobject
            $UserCustomObject | Add-Member -MemberType NoteProperty -Name "ObjectId" -Value $AADUserId
            $UserCustomObject | Add-Member -MemberType NoteProperty -Name "AccountEnabled" -Value $AADUserEnabled
            $UserCustomObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $AADUserPrincipalName
            $UserCustomObject | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $AADUserDisplayName
            $UserCustomObject | Add-Member -MemberType NoteProperty -Name "UserType" -Value $AADUserType
            $UserCustomObject | Add-Member -MemberType NoteProperty -Name "SyncedOnPremAccount" -Value $AADUserDirSyncEnabled
            $UserCustomObject | Add-Member -MemberType NoteProperty -Name "ImmutableId" -Value $AADUserImmutableId
            $UserCustomObject | Add-Member -MemberType NoteProperty -Name "RefreshTokensValidFromDateTime" -Value $AADUserTokenRefresh
            $UserCustomObject | Add-Member -MemberType NoteProperty -Name "CreatedDateTime" -Value $AADCreatedDateTime
            $UserCustomObject | Add-Member -MemberType NoteProperty -Name "OnPremDN" -Value $AADOnPremDN
            $UserCustomObject
            
            }
$UserResult = $AllAzureADUsers
$UserResult | ConvertTo-Csv | Out-File -FilePath $OutputPath\$TenantName-TSxAzureADUsers.csv -Encoding ascii
$UserWShell = New-Object -ComObject WScript.Shell
$UserWShell.Popup("Finished gathering All User Accounts, click OK to continue.",0,"Done",0x1)
}

Export-TSxAzureADUsers

function Export-TSxAzureADGroups{
Write-Host "Gathering All Azure AD Groups" -ForegroundColor Yellow
$TenantName = (Get-AzureADTenantDetail).DisplayName

$CurrentItem = 0
$PercentComplete = 0

$AzureADGroups = Get-AzureADMSGroup -All:$true | Select-Object Id,CreatedDateTime,OnPremisesSyncEnabled,DisplayName,IsAssignableToRole,OnPremisesSecurityIdentifier,SecurityEnabled,MembershipRule
$TotalItems=$AzureADGroups.Count
    $AllAzureADGroups = foreach ($AzureADGroup in $AzureADGroups){
            Write-Progress -Activity "Gathering All Azure AD Groups" -Status "$PercentComplete% Complete:" -PercentComplete $PercentComplete
            $CurrentItem++
            $PercentComplete = [int](($CurrentItem / $TotalItems) * 100)
            
            $AADGroupId = $AzureADGroup.Id
            $AADGroupCreatedDateTime = $AzureADGroup.CreatedDateTime
            $AADGroupOnPremisesSyncEnabled = $AzureADGroup.OnPremisesSyncEnabled
            if (!($AADGroupOnPremisesSyncEnabled)){
                $AADGroupOnPremisesSyncEnabled = "N/A"
                }
            $AADGroupDisplayName = $AzureADGroup.DisplayName
            $AADGroupIsPAG = $AzureADGroup.IsAssignableToRole
            if (!($AADGroupIsPAG)){
                $AADGroupIsPAG = "False"
                }
            $AADGroupOnPremSID = $AzureADGroup.OnPremisesSecurityIdentifier
            if (!($AADGroupOnPremSID)){
                $AADGroupOnPremSID = "N/A"
                }
            $AADGroupIsSecurity = $AzureADGroup.SecurityEnabled
            $AADGroupMembershipRule = $AzureADGroup.MembershipRule
            
            
            $GroupCustomObject = New-Object -TypeName psobject
            $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "ObjectId" -Value $AADGroupId
            $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "CreatedDateTime" -Value $AADGroupCreatedDateTime
            $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $AADGroupDisplayName
            $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "PAG" -Value $AADGroupIsPAG
            $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "SyncedOnPremGroup" -Value $AADGroupOnPremisesSyncEnabled
            $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "OnPremSID" -Value $AADGroupOnPremSID
            $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "IsSecurityGroup" -Value $AADGroupIsSecurity
            $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "MembershipRule" -Value $AADGroupMembershipRule
            $GroupCustomObject
            
            }
$GroupResult = $AllAzureADGroups
$GroupResult | ConvertTo-Csv | Out-File -FilePath $OutputPath\$TenantName-TSxAzureADGroups.csv -Encoding ascii
$GroupWShell = New-Object -ComObject WScript.Shell
$GroupWShell.Popup("Finished gathering All Groups, click OK to continue.",0,"Done",0x1)
}

Export-TSxAzureADGroups

function Export-TSxAdminAccounts{
    <#param (
            [parameter(Mandatory = $true)]
            [array]$OutputPath
        
        )#>
Write-Host "Gathering Azure AD Admin Accounts" -ForegroundColor Yellow
$ExportDateTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss K"
#Inspect current Azure AD admins

# Fetch tenant ID.
$TenantID = (Get-AzureADTenantDetail).ObjectId
$TenantName = (Get-AzureADTenantDetail).DisplayName
$CurrentItem = 0
$PercentComplete = 0
# Fetch all Azure AD role definitions.
$AzureADRoleDefinitions = Get-AzureADMSPrivilegedRoleDefinition -ProviderId "aadRoles" -ResourceId $TenantID

    if (!($AzureADRoleDefinitions)){
        Write-Host "No AzureAD P2 license found. Exporting Admins without PIM." -ForegroundColor Red
        
        $InterestingDirectoryRoles = Get-MsolRole
        # Fetch Azure AD role details.
        $AzureADDirectoryRoles = Get-MsolRole

        # Fetch Azure AD role members for each role and format as custom object.
        $AzureADDirectoryRoleMembers = foreach ($AzureADDirectoryRole in $AzureADDirectoryRoles) {
            $RoleAssignments = Get-MsolRoleMember -RoleObjectId $AzureADDirectoryRole.ObjectId | Select-Object ObjectId,EmailAddress,DisplayName
            $TotalItems = $RoleAssignments.Count
            foreach ($RoleAssignment in $RoleAssignments) {
            Write-Progress -Activity "Gathering All Azure AD Admins" -Status "$PercentComplete% Complete:" -PercentComplete $PercentComplete
            $CurrentItem++
            $PercentComplete = [int](($CurrentItem / $TotalItems) * 100)
            $AdminCustomObject = New-Object -TypeName psobject
            $GroupCustomObject = New-Object -TypeName psobject
            $SPCustomObject = New-Object -TypeName psobject
            $ObjectLookup = Get-AzureADObjectByObjectId -ObjectIds $RoleAssignment.ObjectId | Select-Object ObjectType
            
            if ($ObjectLookup.ObjectType -eq "User"){
                $UserAccountDetails = Get-AzureADUser -ObjectId $RoleAssignment.ObjectId
                $IsSynced = (Get-AzureADUser -ObjectId $RoleAssignment.ObjectId | Where-Object {$_.DirSyncEnabled -eq $true}).DirSyncEnabled

                $LastLogon = (Get-AzureADAuditSignInLogs -top 1 -filter "UserId eq '$($AzureADDirectoryRoleAssignment.SubjectId)'" | Select-Object CreatedDateTime).CreatedDateTime

                    if ($LastLogon) {
                        $LastLogon = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((Get-Date -Date $LastLogon), (Get-TimeZone).Id)
                    }
                    $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "AzureADDirectoryRole" -Value $AzureADDirectoryRole.Name
                    $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "UserId" -Value $UserAccountDetails.ObjectId
                    $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "UserAccount" -Value $UserAccountDetails.DisplayName
                    $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $UserAccountDetails.UserPrincipalName
                    $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "AccountCreated" -Value $UserAccountDetails.ExtensionProperty.createdDateTime
                    $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "LastLogon" -Value $LastLogon
                        if ($IsSynced) {
                            $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "SyncedOnPremAccount" -Value 'True'
                        } 
                        else {
                            $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "SyncedOnPremAccount" -Value 'False'
                        }
                    $AdminCustomObject
                }
        if ($ObjectLookup.ObjectType -eq "Group"){
                $GroupDetails = Get-AzureADGroup -ObjectId $RoleAssignment.ObjectId
                $IsSynced = (Get-AzureADGroup -ObjectId $RoleAssignment.ObjectId | Where-Object {$_.DirSyncEnabled -eq $true}).DirSyncEnabled
        
                $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "AzureADDirectoryRole" -Value $AzureADDirectoryRole.Name
                $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "GroupId" -Value $GroupDetails.ObjectId
                $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $GroupDetails.DisplayName
                if ($IsSynced) {
                            $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "SyncedOnPremAccount" -Value 'True'
                        } 
                        else {
                            $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "SyncedOnPremAccount" -Value 'False'
                        }
                $GroupCustomObject
           
                }
        if ($ObjectLookup.ObjectType -eq "ServicePrincipal"){
                $ServicePrincipalDetails = Get-AzureADMSServicePrincipal -Id $RoleAssignment.ObjectId
            
                $SPCustomObject | Add-Member -MemberType NoteProperty -Name "AzureADDirectoryRole" -Value $AzureADDirectoryRole.Name
                $SPCustomObject | Add-Member -MemberType NoteProperty -Name "ServicePrincipalId" -Value $ServicePrincipalDetails.AppId
                $SPCustomObject | Add-Member -MemberType NoteProperty -Name "ServicePrincipalName" -Value $ServicePrincipalDetails.DisplayName
                $SPCustomObject
        
                }
        else{
        }

        
            }
        }
 
    # List all Azure AD role members (newest first).
    $AdminResult = $AzureADDirectoryRoleMembers
    $AdminDateTime = $ExportDateTime | Out-File -FilePath $OutputPath\$TenantName-TSxAzureAdmins.json -Encoding ascii
    $AdminResult | ConvertTo-Json | Out-File -FilePath $OutputPath\$TenantName-TSxAzureAdmins.json -Encoding ascii
    $AdminResult | Format-List |Out-File -FilePath $OutputPath\$TenantName-TSxAzureAdmins.txt -Encoding ascii


    Write-Host "DONE - Gathering Azure AD Admin Accounts. Export can be found in $OutputPath\$TenantName-TSxAzureAdmins.json and $OutputPath\$TenantName-TSxAzureAdmins.txt" -ForegroundColor Yellow
    $AdminWShell = New-Object -ComObject WScript.Shell
    $AdminWShell.Popup("Finished gathering Admin Accounts, click OK to continue.",0,"Done",0x1)
    }



    else{
    # Fetch all Azure AD PIM role assignments.
    $AzureADDirectoryRoleAssignments = Get-AzureADMSPrivilegedRoleAssignment -ProviderId "aadRoles" -ResourceId $TenantID | Where-Object { $_.RoleDefinitionId -in $AzureADRoleDefinitions.Id }
    $TotalItems = $AzureADDirectoryRoleAssignments.Count
    # Fetch Azure AD role members for each role and format as custom object.
    $AzureADDirectoryRoleMembers = foreach ($AzureADDirectoryRoleAssignment in $AzureADDirectoryRoleAssignments) {
        Write-Progress -Activity "Gathering All Azure AD Admins" -Status "$PercentComplete% Complete:" -PercentComplete $PercentComplete
        $CurrentItem++
        $PercentComplete = [int](($CurrentItem / $TotalItems) * 100)
        $AdminCustomObject = New-Object -TypeName psobject
        $GroupCustomObject = New-Object -TypeName psobject
        $SPCustomObject = New-Object -TypeName psobject
        $ObjectLookup = Get-AzureADObjectByObjectId -ObjectIds $AzureADDirectoryRoleAssignment.SubjectId | Select-Object ObjectType

        if ($ObjectLookup.ObjectType -eq "User"){
            $UserAccountDetails = Get-AzureADUser -ObjectId $AzureADDirectoryRoleAssignment.SubjectId
            $IsSynced = (Get-AzureADUser -ObjectId $AzureADDirectoryRoleAssignment.SubjectId | Where-Object {$_.DirSyncEnabled -eq $true}).DirSyncEnabled

            $LastLogon = (Get-AzureADAuditSignInLogs -top 1 -filter "UserId eq '$($AzureADDirectoryRoleAssignment.SubjectId)'" | Select-Object CreatedDateTime).CreatedDateTime

                if ($LastLogon) {
                    $LastLogon = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((Get-Date -Date $LastLogon), (Get-TimeZone).Id)
                }
                $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "AzureADDirectoryRole" -Value ($AzureADRoleDefinitions | Where-Object { $_.Id -eq $AzureADDirectoryRoleAssignment.RoleDefinitionId }).DisplayName
                $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "UserId" -Value $UserAccountDetails.ObjectId
                $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "UserAccount" -Value $UserAccountDetails.DisplayName
                $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $UserAccountDetails.UserPrincipalName
                $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "AccountCreated" -Value $UserAccountDetails.ExtensionProperty.createdDateTime
                $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "AssignmentState" -Value $AzureADDirectoryRoleAssignment.AssignmentState
                $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "LastLogon" -Value $LastLogon
                    if ($IsSynced) {
                        $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "SyncedOnPremAccount" -Value 'True'
                    } 
                    else {
                        $AdminCustomObject | Add-Member -MemberType NoteProperty -Name "SyncedOnPremAccount" -Value 'False'
                    }
                $AdminCustomObject
                }
        if ($ObjectLookup.ObjectType -eq "Group"){
                $GroupDetails = Get-AzureADGroup -ObjectId $AzureADDirectoryRoleAssignment.SubjectId
                $IsSynced = (Get-AzureADGroup -ObjectId $AzureADDirectoryRoleAssignment.SubjectId | Where-Object {$_.DirSyncEnabled -eq $true}).DirSyncEnabled
        
                $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "AzureADDirectoryRole" -Value ($AzureADRoleDefinitions | Where-Object { $_.Id -eq $AzureADDirectoryRoleAssignment.RoleDefinitionId }).DisplayName
                $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "GroupId" -Value $GroupDetails.ObjectId
                $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $GroupDetails.DisplayName
                $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "AssignmentState" -Value $AzureADDirectoryRoleAssignment.AssignmentState
                if ($IsSynced) {
                        $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "SyncedOnPremAccount" -Value 'True'
                    } 
                    else {
                        $GroupCustomObject | Add-Member -MemberType NoteProperty -Name "SyncedOnPremAccount" -Value 'False'
                    }
                $GroupCustomObject
                }
        if ($ObjectLookup.ObjectType -eq "ServicePrincipal"){
                $ServicePrincipalDetails = Get-AzureADMSServicePrincipal -Id $AzureADDirectoryRoleAssignment.SubjectId
            
                $SPCustomObject | Add-Member -MemberType NoteProperty -Name "AzureADDirectoryRole" -Value ($AzureADRoleDefinitions | Where-Object { $_.Id -eq $AzureADDirectoryRoleAssignment.RoleDefinitionId }).DisplayName
                $SPCustomObject | Add-Member -MemberType NoteProperty -Name "ServicePrincipalId" -Value $ServicePrincipalDetails.AppId
                $SPCustomObject | Add-Member -MemberType NoteProperty -Name "ServicePrincipalName" -Value $ServicePrincipalDetails.DisplayName
                $SPCustomObject | Add-Member -MemberType NoteProperty -Name "AssignmentState" -Value $AzureADDirectoryRoleAssignment.AssignmentState
                $SPCustomObject
                }
        else{
        }

        
    }

    # List all Azure AD role members (newest first).
    $AdminResult = $AzureADDirectoryRoleMembers
    $AdminJsonDateTime = $ExportDateTime | Out-File -FilePath $OutputPath\$TenantName-TSxAzureAdmins.json -Encoding ascii
    $AdminResult | ConvertTo-Json | Out-File -FilePath $OutputPath\$TenantName-TSxAzureAdmins.json -Encoding ascii -Append
    $AdminResult | Format-List |Out-File -FilePath $OutputPath\$TenantName-TSxAzureAdmins.txt -Encoding ascii

    Write-Host "DONE - Gathering Azure AD Admin Accounts. Export can be found in $OutputPath\$TenantName-TSxAzureAdmins.json and $OutputPath\$TenantName-TSxAzureAdmins.txt" -ForegroundColor Yellow
    $AdminWShell = New-Object -ComObject WScript.Shell
    $AdminWShell.Popup("Finished gathering Admin Accounts, click OK to continue.",0,"Done",0x1)
    }
}

Export-TSxAdminAccounts


#Export Conditional Access Policies and Details using PowerShell

function Export-TSxConditionalAccessPolicy{
    <#
        Still throws an error when trying to "Get" a Conditional Access Policy with Linux in Device Conditions.
        Workaround in place that exports all policies except for Linux one's which are left untouched right now.
        Will improve in next major release.
    #>
Write-Host "Gathering Conditional Access Policies" -ForegroundColor Yellow
$TenantName = (Get-AzureADTenantDetail).DisplayName
$AADIntCAPolicies = Get-AADIntConditionalAccessPolicies | Where-Object displayName -NE "Default Policy" | Select-Object objectId, policyDetail
$CurrentItem = 0
$PercentComplete = 0
$CAPolicies = foreach ($AADIntCAPolicy in $AADIntCAPolicies){
    Get-AzureADMSConditionalAccessPolicy -PolicyId $AADIntCAPolicy.objectid
    }
$TotalItems = $AADIntCAPolicies.Count
$ExportDateTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss K"
$Policies = forEach ($CAPolicy in $CAPolicies){
    Write-Progress -Activity "Gathering Conditional Access Policies" -Status "$PercentComplete% Complete:" -PercentComplete $PercentComplete
    $CurrentItem++
    $PercentComplete = [int](($CurrentItem / $TotalItems) * 100)
            
    
    $PolicyId = $CAPolicy.Id
    $PolicyDisplayName = $CAPolicy.DisplayName
    $PolicyState = $CAPolicy.State
    $IncludedUsers = $CAPolicy.Conditions.Users.IncludeUsers | Out-String
    $ExcludedUsers = $CAPolicy.Conditions.Users.ExcludeUsers | Out-String
    $IncludedGroups = $CAPolicy.Conditions.Users.IncludeGroups | Out-String
    $ExcludedGroups = $CAPolicy.Conditions.Users.ExcludeGroups | Out-String
    $IncludedRoles = $CAPolicy.Conditions.Users.IncludeRoles | Out-String
    $ExcludedRoles = $CAPolicy.Conditions.Users.ExcludeRoles | Out-String
    $IncludedApplications = $CAPolicy.Conditions.Applications.IncludeApplications | Out-String
    $ExcludedApplications = $CAPolicy.Conditions.Applications.ExcludeApplications | Out-String
    $UserActions = $CAPolicy.Conditions.Applications.IncludeUserActions | Out-String
    $AuthenticationContexts = $CAPolicy.Conditions.Applications.IncludeAuthenticationContextClassReferences | Out-String
    $IncludedPlatforms = $CAPolicy.Conditions.Platforms.IncludePlatforms | Out-String
    $ExcludedPlatforms = $CAPolicy.Conditions.Platforms.ExcludePlatforms | Out-String
    $IncludedLocations = $CAPolicy.Conditions.Locations.IncludeLocations | Out-String
    $ExcludedLocations = $CAPolicy.Conditions.Locations.ExcludeLocations | Out-String
    $UserRiskLevels = $CAPolicy.Conditions.UserRiskLevels | Out-String
    $SignInRiskLevels = $CAPolicy.Conditions.SignInRiskLevels | Out-String
    $ClientAppTypes = $CAPolicy.Conditions.ClientAppTypes | Out-String
    $IncludedDevices = $CAPolicy.Conditions.Devices.IncludeDevices | Out-String
    $ExcludedDevices = $CAPolicy.Conditions.Devices.ExcludeDevices | Out-String
    $DeviceFilterMode = $CAPolicy.Conditions.Devices.DeviceFilter.Mode | Out-String
    $DeviceFilterRule = $CAPolicy.Conditions.Devices.DeviceFilter.Rule | Out-String
    $GrantControls = $CAPolicy.GrantControls.BuiltInControls | Out-String
    $CustomAuthentictationFactors = $CAPolicy.GrantControls.CustomAuthenticationFactors | Out-String
    $TermsOfUse = $CAPolicy.GrantControls.TermsOfUse | Out-String
    $ApplicationEnforcedRestrictions = $CAPolicy.SessionControls.ApplicationEnforceRestrictions | Out-String
    $MCAS = $CAPolicy.SessionControls.CloudAppSecurity | Out-String
    $SignInFrequencyValue = $CAPolicy.SessionControls.SignInFrequency.Value | Out-String
    $SignInFrequencyType = $CAPolicy.SessionControls.SignInFrequency.Type | Out-String
    $PersistenBrowser = $CAPolicy.SessionControls.PersistentBrowser.Mode | Out-String


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
    $IncludedUsersLookup = Get-AzureADUser -All:$true | Where-Object {$_.ObjectId -In $TrimStringIncludedUsers}

  


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


    $ExcludedRolesLookup = Get-MsolRole| Where-Object {$_.ObjectId -In $SplitStringExcludedRoles}
    
    
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
    # Lookup 'Included Locations'                                         #
    ##########################################################################
    
    $IncludedLocationsToJson = $IncludedLocations | ConvertTo-Json

    #Replace \r\n at the end of each object in the string with ,
    $ReplaceDataInJsonIncludedLocations = $IncludedLocationsToJson.Replace('\r\n',',')

    #Replace " with nothing to make the string splittable
    $ReplaceDataInJsonSplittableIncludedLocations = $ReplaceDataInJsonIncludedLocations.Replace('"','')

    #Trim the last "," to construct correct amount of strings
    $TrimStringIncludedLocations = $ReplaceDataInJsonSplittableIncludedLocations.TrimEnd(',')

    #Split the string into multiple strings using "," as a separator
    $SplitStringIncludedLocations = $TrimStringIncludedLocations -split ","

    $IncludedLocationsName = Get-AzureADMSNamedLocationPolicy | Where-Object {$_.Id -in $SplitStringIncludedLocations}

    ##########################################################################
    # Lookup 'Excluded Locations'                                         #
    ##########################################################################

    $ExcludedLocationsToJson = $ExcludedLocations | ConvertTo-Json

    #Replace \r\n at the end of each object in the string with ,
    $ReplaceDataInJsonExcludedLocations = $ExcludedLocationsToJson.Replace('\r\n',',')

    #Replace " with nothing to make the string splittable
    $ReplaceDataInJsonSplittableExcludedLocations = $ReplaceDataInJsonExcludedLocations.Replace('"','')

    #Trim the last "," to construct correct amount of strings
    $TrimStringExcludedLocations = $ReplaceDataInJsonSplittableExcludedLocations.TrimEnd(',')

    #Split the string into multiple strings using "," as a separator
    $SplitStringExcludedLocations = $TrimStringExcludedLocations -split ","

    $ExcludedLocationsName = Get-AzureADMSNamedLocationPolicy | Where-Object {$_.Id -in $SplitStringExcludedLocations}
    
    
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
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "User Actions" -Value $UserActions
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Authentication Contexts" -Value $AuthenticationContexts
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Included Device Platforms" -Value $IncludedPlatforms
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Excluded Device Platforms" -Value $ExcludedPlatforms
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Included Locations" -Value $IncludedLocations
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Included Locations (Lookup)" -Value $IncludedLocationsName.DisplayName
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Excluded Locations" -Value $ExcludedLocations
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Excluded Locations (Lookup)" -Value $ExcludedLocationsName.DisplayName
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "User Risk Levels" -Value $UserRiskLevels
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Sign Risk Levels" -Value $SignInRiskLevels
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Client App Types" -Value $ClientAppTypes
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Included Devices" -Value $IncludedDevices
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Exclude Devices" -Value $ExcludedDevices
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Device Filter Mode" -Value $DeviceFilterMode
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Device Filter Rule" -Value $DeviceFilterRule
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Grant Controls" -Value $GrantControls
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Grant Controls Custom Authentication Factors" -Value $CustomAuthentictationFactors
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Grant Controls Terms Of Use" -Value $TermsOfUse
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Application Enforced Restrictions" -Value $ApplicationEnforcedRestrictions
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "MCAS" -Value $MCAS
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Sign In Frequency Value" -Value $SignInFrequencyValue
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Sign In Frequency Type" -Value $SignInFrequencyType
    $CACustomObject | Add-Member -MemberType NoteProperty -Name "Persistent Browser Mode" -Value $PersistenBrowser
    $CACustomObject

    }
$CAResult = $Policies | Sort-Object DisplayName -Descending
$CAExportResult = $CAResult | ConvertTo-Json
$CAExportableResult = $CAExportResult.Replace('\r\n',',')
$CADateTimeExport = $ExportDateTime | Out-File -FilePath $OutputPath\$TenantName-TSxCAPolicies.json -Encoding ascii
$CAExportableResult | Out-File -FilePath $OutputPath\$TenantName-TSxCAPolicies.json -Encoding ascii -Append

$CAMisconfig = $CAResult | Out-GridView -PassThru -Title "Select any misconfigured CA Policy and click 'OK' to export it. If none, select 'Cancel'."
$CAMisconfigExport = $CAMisconfig | ConvertTo-Json
$CAMisconfigExportable = $CAMisconfigExport.Replace('\r\n',',')
$CADateTimeMisconfig = $ExportDateTime | Out-File -FilePath $OutputPath\$TenantName-TSxMisconfigCA.json -Encoding ascii
$CAMisconfigExportable | Out-File -FilePath $OutputPath\$TenantName-TSxMisconfigCA.json -Encoding ascii -Append


Write-Host "DONE - Collected All Conditional Access Policies. Export can be found in $OutputPath\$TenantName-TSxCAPolicies.json and $OutputPath\$TenantName-TSxMisconfigCA.json for Misconfigured CA Policies" -ForegroundColor Yellow
$CAPolicyWShell = New-Object -ComObject WScript.Shell
$CAPolicyWShell.Popup("Finished gathering Conditional Access Policies, click OK to continue.",0,"Done",0x1)
  
}

Export-TSxConditionalAccessPolicy

 

#Get DirectorySettings in Azure AD
function Get-TSxAADDirectorySettings{
Write-Host "Gathering Directory Settingss" -ForegroundColor Yellow
$ExportDateTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss K"
$TenantName = (Get-AzureADTenantDetail).DisplayName
$DirectorySettingTemplates = Get-AzureADDirectorySetting


$DirectorySettings = foreach ($DirectorySettingTemplate in $DirectorySettingTemplates){

   $DirectorySettingId = $DirectorySettingTemplate.Id | Out-String
   $DirectorySettingDisplayName = $DirectorySettingTemplate.DisplayName | Out-String
   $DirectorySettingValueName = $DirectorySettingTemplate.Values.Name | Out-String
   $DirectorySettingValue = $DirectorySettingTemplate.Values.Value | Out-String

   $DirSettingCustomObject = New-Object -TypeName PSObject
   $DirSettingCustomObject | Add-Member -MemberType NoteProperty -Name "Directory Setting Id" -Value $DirectorySettingId
   $DirSettingCustomObject | Add-Member -MemberType NoteProperty -Name "Directory Setting Display Name" -Value $DirectorySettingDisplayName
   $DirSettingCustomObject | Add-Member -MemberType NoteProperty -Name "Directory Setting Value Name" -Value $DirectorySettingValueName
   $DirSettingCustomObject | Add-Member -MemberType NoteProperty -Name "Directory Setting Values" -Value $DirectorySettingValue
   $DirSettingCustomObject
   }

$DirectoryResult = $DirectorySettings | Sort-Object DisplayName -Descending
$DirectoryExportResult = $DirectoryResult | ConvertTo-Json
$DirectoryExportableResult = $DirectoryExportResult.Replace('\r\n',',')
$DirectoryExportTime = $ExportDateTime | Out-File -FilePath $OutputPath\$TenantName-TSxDirectorySettings.json -Encoding ascii
$DirectoryExportableResult | Out-File -FilePath $OutputPath\$TenantName-TSxDirectorySettings.json -Encoding ascii -Append
$DirectoryResult | Out-GridView -Wait -Title "Directory Settings"

Write-Host "DONE - Gathered Directory Settings. Export can be found in $OutputPath\$TenantName-TSxDirectorySettings.json" -ForegroundColor Yellow
$DirectorySettingWShell = New-Object -ComObject WScript.Shell
$DirectorySettingWShell.Popup("Finished gathering Directory Settings, click OK to continue.",0,"Done",0x1)

}

Get-TSxAADDirectorySettings




function Get-TSxMsolCompanyInfo {
Write-Host "Gathering Company Information" -ForegroundColor Yellow
$ExportDateTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss K"
$TenantName = (Get-AzureADTenantDetail).DisplayName
$CompanySettings = Get-MsolCompanyInformation

$CompanySettingTenantName = $CompanySettings.DisplayName | Out-String
$CompanySettingInitialDomain = $CompanySettings.InitialDomain | Out-String
$CompanySettingAppRegistrations = $CompanySettings.UsersPermissionToCreateLOBAppsEnabled | Out-String
$CompanySettingConsentToApps = $CompanySettings.UsersPermissionToUserConsentToAppEnabled | Out-String
$CompanySettingAADCServer = $CompanySettings.DirSyncClientMachineName | Out-String
$CompanySettingAADCVersion = $CompanySettings.DirSyncClientVersion | Out-String
$CompanySettingAADCAccount = $CompanySettings.DirSyncServiceAccount | Out-String
$CompanySettingAADCSyncEnabled = $CompanySettings.DirectorySynchronizationEnabled | Out-String
$CompanySettingAADCSyncStatus = $CompanySettings.DirectorySynchronizationStatus | Out-String
$CompanySettingAADCLastSync = $CompanySettings.LastDirSyncTime | Out-String
$CompanySettingAADCPHS = $CompanySettings.PasswordSynchronizationEnabled | Out-String
$CompanySettingAADCLastPHS = $CompanySettings.LastPasswordSyncTime | Out-String
$CompanySettingSSPR = $CompanySettings.SelfServePasswordResetEnabled | Out-String

$CompanyInfo = New-Object -TypeName PSObject
$CompanyInfo | Add-Member -MemberType NoteProperty -Name "Directory Tenant Name" -Value $CompanySettingTenantName
$CompanyInfo | Add-Member -MemberType NoteProperty -Name "Directory Initial Domain" -Value $CompanySettingInitialDomain
$CompanyInfo | Add-Member -MemberType NoteProperty -Name "Directory Setting App Registrations allowed" -Value $CompanySettingAppRegistrations
$CompanyInfo | Add-Member -MemberType NoteProperty -Name "Directory Setting Enterprise App Consent" -Value $CompanySettingConsentToApps
$CompanyInfo | Add-Member -MemberType NoteProperty -Name "Directory Azure AD Connect Server Name" -Value $CompanySettingAADCServer
$CompanyInfo | Add-Member -MemberType NoteProperty -Name "Directory Azure AD Connect Version" -Value $CompanySettingAADCVersion
$CompanyInfo | Add-Member -MemberType NoteProperty -Name "Directory Azure AD Connect Sync Account" -Value $CompanySettingAADCAccount
$CompanyInfo | Add-Member -MemberType NoteProperty -Name "Directory Azure AD Connect Sync Enabled" -Value $CompanySettingAADCSyncEnabled
$CompanyInfo | Add-Member -MemberType NoteProperty -Name "Directory Azure AD Connect Sync Status" -Value $CompanySettingAADCSyncStatus
$CompanyInfo | Add-Member -MemberType NoteProperty -Name "Directory Azure AD Connect Last Sync" -Value $CompanySettingAADCLastSync
$CompanyInfo | Add-Member -MemberType NoteProperty -Name "Password Hash Sync Enabled" -Value $CompanySettingAADCPHS
$CompanyInfo | Add-Member -MemberType NoteProperty -Name "Last Password Sync" -Value $CompanySettingAADCLastPHS
$CompanyInfo | Add-Member -MemberType NoteProperty -Name "SSPR" -Value $CompanySettingSSPR
$CompanyInfo

$CompanyInfoExportResult = $CompanyInfo | ConvertTo-Json
$CompanyInfoExportableResult = $CompanyInfoExportResult.Replace('\r\n',',')
$CompanyInfoExportTime = $ExportDateTime | Out-File -FilePath $OutputPath\$TenantName-TSxCompanyInfo.json -Encoding ascii
$CompanyInfoExportableResult | Out-File -FilePath $OutputPath\$TenantName-TSxCompanyInfo.json -Encoding ascii -Append
$CompanyInfo | Out-GridView -Wait -Title "Company Information"

Write-Host "DONE - Gathered Company Information. Export can be found in $OutputPath\$TenantName-TSxCompanyInfo.json" -ForegroundColor Yellow
$CompanyInfoWShell = New-Object -ComObject WScript.Shell
$CompanyInfoWShell.Popup("Finished gathering Company Info, click OK to continue.",0,"Done",0x1)

}

Get-TSxMsolCompanyInfo


function Get-TSxGuestSettings{
Write-Host "Gathering Guest Settings" -ForegroundColor Yellow
$ExportDateTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss K"
$TenantGuestSettings = Get-AADIntTenantGuestAccess
$TenantName = (Get-AzureADTenantDetail).DisplayName
if ($TenantGuestSettings.Access -ne "Full"){
    $RoleId = $TenantGuestSettings.RoleId
    $GuestRole = Get-MsolRole -ObjectId $RoleId
    }
else {
    $RoleId = $TenantGuestSettings.RoleId
    $GuestRole = "N/A"
    }

$GuestAccess = New-Object -TypeName PSObject
$GuestAccess | Add-Member -MemberType NoteProperty -Name "Guest Access Level" -Value $TenantGuestSettings.Access
$GuestAccess | Add-Member -MemberType NoteProperty -Name "Description" -Value $TenantGuestSettings.Description
$GuestAccess | Add-Member -MemberType NoteProperty -Name "Guest Role" -Value $GuestRole.Name
$GuestAccess | Add-Member -MemberType NoteProperty -Name "Guest Role Description" -Value $GuestRole.Description
$GuestAccess

$ExportableGuestAccess = $GuestAccess | ConvertTo-Json
$ExportTimeGuestAccess = $ExportDateTime | Out-File -FilePath $OutputPath\$TenantName-TSxGuestAccess.json
$ExportableGuestAccess | Out-File -FilePath $OutputPath\$TenantName-TSxGuestAccess.json -Append
$GuestAccess | Out-GridView -Wait -Title "Guest Access Settings"

Write-Host "DONE - Gathered Guest Settings. Export can be found in $OutputPath\$TenantName-TSxGuestAccess.json" -ForegroundColor Yellow
$GuestAccessWShell = New-Object -ComObject WScript.Shell
$GuestAccessWShell.Popup("Finished gathering Guest Access, click OK to continue.",0,"Done",0x1)
}

Get-TSxGuestSettings
