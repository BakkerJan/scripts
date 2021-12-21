## Find dangerous API permissions as a user
##Use modern auth to support MFA
Connect-AzAccount

function Get-AzureGraphToken
{
    $APSUser = Get-AzContext *>&1 
    $resource = "https://graph.microsoft.com"
    $Token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($APSUser.Account, $APSUser.Environment, $APSUser.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $resource).AccessToken
    $Headers = @{}
    $Headers.Add("Authorization","Bearer"+ " " + "$($token)")
    $Headers
}

$Headers = Get-AzureGraphToken

# Get list of app registrations:
$Uri = "https://graph.microsoft.com/v1.0/applications"
$Results = $null
$QueryResults = $null
$RegisteredAppIDs = $null
do {
$Results = Invoke-RestMethod -Headers $Headers -Uri $Uri -UseBasicParsing -Method "GET" -ContentType "application/json"
    if ($Results.value) {
        $QueryResults += $Results.value
    } else {
        $QueryResults += $Results
    }
    $uri = $Results.'@odata.nextlink'
} until (!($uri))
$RegisteredAppIDs = $QueryResults.appId

# Find the real id of each app's service principal:
# This may take several minutes to finish
$ServicePrincipalIDs = $null
$ServicePrincipals = $null
ForEach ($id in $RegisteredAppIDs){
    $URL = 'https://graph.microsoft.com/v1.0/servicePrincipals/?$filter=(appid eq ''{0}'')' -f $id
    $req = $null
	$req = Invoke-RestMethod -Headers $Headers `
        -Uri $URL `
        -Method GET
    $ServicePrincipals += $req.value
}
$ServicePrincipalIDs = ($ServicePrincipals).id

# Fetch the app roles assigned to each SP:
# This may take several minutes to finish
$AppRoles = $null
ForEach ($id in $ServicePrincipalIDs){
    $req = $null
	$URL = 'https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments' -f $id
	$req = Invoke-RestMethod -Headers $Headers `
        -Uri $URL `
        -Method GET
    $AppRoles += $req.value
}

# Find service principals with dangerous app roles
# These application roles allow you to promote yourself or any other principal to Global Admin:
# 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8 # RoleManagement.ReadWrite.Directory -> directly promote yourself to GA
# 06b708a9-e830-4db3-a914-8e69da51d44f # AppRoleAssignment.ReadWrite.All -> grant yourself the above role, then promote to GA
$DangerousAssignments = $null
ForEach ($RoleAssignment in $AppRoles){
    if ($RoleAssignment.appRoleId -eq "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" -Or $RoleAssignment.appRoleId -eq "06b708a9-e830-4db3-a914-8e69da51d44f") {
	    $RoleAssignment
	}
}