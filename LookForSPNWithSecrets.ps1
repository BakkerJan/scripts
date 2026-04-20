<#
.SYNOPSIS
    Reports all Service Principals in the tenant that have one or more secrets.

.DESCRIPTION
    Queries Microsoft Graph for all Service Principals and filters those with
    active passwordCredentials. Highlights foreign SPs (homed in another tenant)
    as they represent the highest risk surface for the credential abuse attack
    described at: https://dirkjanm.io/azure-ad-privilege-escalation-application-admin/

.REQUIREMENTS
    - Microsoft.Graph PowerShell module
    - Application.Read.All or Directory.Read.All

.NOTES
    Author  : Jan Bakker
    Blog    : https://janbakker.tech
#>

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications

[CmdletBinding()]
param(
    [string]$TenantId,

    # Flag foreign SPs (homed in a different tenant)
    [switch]$HighlightForeign,

    # Export results to CSV
    [string]$ExportCsv
)

# ---------------------------------------------------------------
# 1. Connect
# ---------------------------------------------------------------
$connectParams = @{ Scopes = "Application.Read.All" }
if ($TenantId) { $connectParams.TenantId = $TenantId }

Connect-MgGraph @connectParams -NoWelcome

$tenantId = (Get-MgContext).TenantId
Write-Host "`n[+] Connected to tenant: $tenantId`n" -ForegroundColor Cyan

# ---------------------------------------------------------------
# 2. Fetch all SPs with passwordCredentials populated
# ---------------------------------------------------------------
Write-Host "[*] Fetching service principals..." -ForegroundColor Gray

$allSPs = Get-MgServicePrincipal -All `
    -Property "id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,passwordCredentials" |
    Where-Object { $_.PasswordCredentials.Count -gt 0 }

Write-Host "[+] Found $($allSPs.Count) SP(s) with at least one secret.`n" -ForegroundColor Green

# ---------------------------------------------------------------
# 3. Build report
# ---------------------------------------------------------------
$now    = Get-Date
$report = foreach ($sp in $allSPs) {

    $isForeign = $sp.AppOwnerOrganizationId -and
                 $sp.AppOwnerOrganizationId -ne $tenantId

    foreach ($cred in $sp.PasswordCredentials) {

        $isExpired = $cred.EndDateTime -and ($cred.EndDateTime -lt $now)
        $daysLeft  = if ($cred.EndDateTime) {
                         [math]::Round(($cred.EndDateTime - $now).TotalDays)
                     } else { $null }

        [PSCustomObject]@{
            SPDisplayName         = $sp.DisplayName
            SPObjectId            = $sp.Id
            AppId                 = $sp.AppId
            SPType                = $sp.ServicePrincipalType
            Hometenant            = $sp.AppOwnerOrganizationId ?? "N/A (Managed Identity)"
            IsForeignSP           = $isForeign
            SecretDisplayName     = $cred.DisplayName ?? "(no name)"
            KeyId                 = $cred.KeyId
            Hint                  = $cred.Hint
            SecretStart           = $cred.StartDateTime
            SecretExpiry          = $cred.EndDateTime ?? "No expiry set"
            DaysUntilExpiry       = $daysLeft
            IsExpired             = $isExpired
        }
    }
}

# ---------------------------------------------------------------
# 4. Display results
# ---------------------------------------------------------------
if (-not $report) {
    Write-Host "No service principals with secrets found." -ForegroundColor Yellow
    return
}

# Summary table
$report | Sort-Object IsForeignSP -Descending |
    Format-Table SPDisplayName, IsForeignSP, SecretDisplayName, SecretExpiry, IsExpired, DaysUntilExpiry `
        -AutoSize

# Risk summary
$foreignWithSecrets = $report | Where-Object { $_.IsForeignSP } |
    Select-Object -ExpandProperty SPDisplayName -Unique

$expiredSecrets     = $report | Where-Object { $_.IsExpired }
$noExpiry           = $report | Where-Object { $_.SecretExpiry -eq "No expiry set" }

Write-Host "`n--- Risk Summary ---" -ForegroundColor Yellow
Write-Host "  Total SPs with secrets  : $(($report | Select-Object SPObjectId -Unique).Count)"
Write-Host "  Total secrets           : $($report.Count)"
Write-Host "  Foreign SPs with secrets: $($foreignWithSecrets.Count) → $($foreignWithSecrets -join ', ')" `
    -ForegroundColor $(if ($foreignWithSecrets) { 'Red' } else { 'Green' })
Write-Host "  Secrets with no expiry  : $($noExpiry.Count)" `
    -ForegroundColor $(if ($noExpiry) { 'Red' } else { 'Green' })
Write-Host "  Expired secrets         : $($expiredSecrets.Count)" `
    -ForegroundColor $(if ($expiredSecrets) { 'Yellow' } else { 'Green' })

# ---------------------------------------------------------------
# 5. Optional CSV export
# ---------------------------------------------------------------
if ($ExportCsv) {
    $report | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`n[+] Exported to $ExportCsv" -ForegroundColor Cyan
}