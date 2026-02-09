<#
.SYNOPSIS
    Reports device-bound passkeys registered in Entra ID that are not attested.

.DESCRIPTION
    This script efficiently finds all device-bound passkeys that lack attestation
    by first filtering users who have passkeys registered (via userRegistrationDetails),
    then checking their FIDO2 authentication methods for attestation status.
    
    This avoids querying all users in the tenant.

.PARAMETER OutputPath
    Optional path for CSV export. If not specified, outputs to console only.

.EXAMPLE
    .\Get-UnattestedPasskeys.ps1
    
.EXAMPLE
    .\Get-UnattestedPasskeys.ps1 -OutputPath "C:\Reports\UnattestedPasskeys.csv"

.NOTES
    Requires Microsoft.Graph.Reports and Microsoft.Graph.Authentication modules
    Required permissions: UserAuthenticationMethod.Read.All, Reports.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

# Function to ensure required modules are loaded
function Test-GraphModule {
    $requiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Reports', 'Microsoft.Graph.Users')
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -Name $module -ListAvailable)) {
            Write-Error "Required module '$module' is not installed. Install it with: Install-Module $module -Scope CurrentUser"
            return $false
        }
        
        if (-not (Get-Module -Name $module)) {
            Write-Verbose "Importing module: $module"
            Import-Module $module -ErrorAction Stop
        }
    }
    return $true
}

# Main script execution
try {
    Write-Host "Starting unattested device-bound passkey report..." -ForegroundColor Cyan
    
    # Check modules
    if (-not (Test-GraphModule)) {
        throw "Required modules are missing"
    }
    
    # Connect to Microsoft Graph if not already connected
    $context = Get-MgContext
    if (-not $context) {
        Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
        Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All", "Reports.Read.All" -NoWelcome
    } else {
        Write-Host "Already connected to Microsoft Graph as $($context.Account)" -ForegroundColor Green
    }
    
    # Step 1: Find users with passKeyDeviceBound registered
    Write-Host "`nStep 1: Querying users with device-bound passkeys..." -ForegroundColor Cyan
    
    $uri = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails"
    $filter = "methodsRegistered/any(m:m eq 'passKeyDeviceBound')"
    $select = "userPrincipalName,userDisplayName,id"
    
    $usersWithPasskeys = Invoke-MgGraphRequest -Method GET -Uri "$uri`?`$filter=$filter&`$select=$select" -Headers @{"ConsistencyLevel" = "eventual" }
    
    $totalUsers = $usersWithPasskeys.value.Count
    Write-Host "Found $totalUsers users with device-bound passkeys registered" -ForegroundColor Green
    
    if ($totalUsers -eq 0) {
        Write-Host "No users with device-bound passkeys found. Exiting." -ForegroundColor Yellow
        return
    }
    
    # Step 2: Check each user's FIDO2 methods for attestation status
    Write-Host "`nStep 2: Checking attestation status for each user..." -ForegroundColor Cyan
    
    $results = @()
    $currentUser = 0
    
    foreach ($user in $usersWithPasskeys.value) {
        $currentUser++
        Write-Progress -Activity "Checking FIDO2 methods" -Status "Processing user $currentUser of $totalUsers : $($user.userPrincipalName)" -PercentComplete (($currentUser / $totalUsers) * 100)
        
        try {
            # Get FIDO2 authentication methods for this user
            $fido2Uri = "https://graph.microsoft.com/beta/users/$($user.id)/authentication/fido2Methods"
            $fido2Methods = Invoke-MgGraphRequest -Method GET -Uri $fido2Uri
            
            # Filter for device-bound passkeys that are not attested
            $unattestedKeys = $fido2Methods.value | Where-Object { 
                $_.passkeyType -eq 'deviceBound' -and $_.attestationLevel -eq 'notAttested' 
            }
            
            if ($unattestedKeys.Count -gt 0) {
                foreach ($key in $unattestedKeys) {
                    $results += [PSCustomObject]@{
                        UserPrincipalName     = $user.userPrincipalName
                        UserDisplayName       = $user.userDisplayName
                        PasskeyDisplayName    = $key.displayName
                        PasskeyId             = $key.id
                        AAGUID                = $key.aaGuid
                        Model                 = $key.model
                        CreatedDateTime       = $key.createdDateTime
                        LastUsedDateTime      = $key.lastUsedDateTime
                        AttestationLevel      = $key.attestationLevel
                        PasskeyType           = $key.passkeyType
                        HasAttestationCerts   = ($key.attestationCertificates.Count -gt 0)
                    }
                }
            }
        }
        catch {
            Write-Warning "Error processing user $($user.userPrincipalName): $($_.Exception.Message)"
        }
    }
    
    Write-Progress -Activity "Checking FIDO2 methods" -Completed
    
    # Step 3: Display and optionally export results
    Write-Host "`n=== RESULTS ===" -ForegroundColor Cyan
    Write-Host "Total users checked: $totalUsers" -ForegroundColor White
    Write-Host "Unattested device-bound passkeys found: $($results.Count)" -ForegroundColor $(if ($results.Count -gt 0) { 'Yellow' } else { 'Green' })
    
    if ($results.Count -gt 0) {
        Write-Host "`nDetails:" -ForegroundColor Cyan
        $results | Format-Table UserPrincipalName, PasskeyDisplayName, Model, AttestationLevel, CreatedDateTime -AutoSize
        
        # Export to CSV if path specified
        if ($OutputPath) {
            $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            Write-Host "`nResults exported to: $OutputPath" -ForegroundColor Green
        }
        
        # Group by user for summary
        Write-Host "`nSummary by user:" -ForegroundColor Cyan
        $results | Group-Object UserPrincipalName | 
            Select-Object @{N='User';E={$_.Name}}, @{N='UnattestedKeys';E={$_.Count}} |
            Format-Table -AutoSize
    }
    else {
        Write-Host "`nNo unattested device-bound passkeys found. All device-bound passkeys are properly attested!" -ForegroundColor Green
    }
}
catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
}
finally {
    Write-Host "`nScript completed." -ForegroundColor Cyan
}
