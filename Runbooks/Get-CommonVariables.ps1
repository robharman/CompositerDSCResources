<#
    .SYNOPSIS
        Gets Automation Variables.
    .DESCRIPTION
        Gets common variables stored in Azure Automation.
    .NOTES
        Version:        1.0.0
        Author:         Rob Harman
        Written:        2021-11-17
        Version Notes:  Initial upload.
        REQUIRES:
        To Do:
#>
[cmdletbinding()]
param (
    [Parameter(Mandatory=$False)]
    [switch]$Azure,
    [Parameter(Mandatory=$False)]
    [switch]$Automation,
    [Parameter(Mandatory=$False)]
    [switch]$DevOps,
    [Parameter(Mandatory=$False)]
    [switch]$Email,
    [Parameter(Mandatory=$False)]
    [switch]$Kubernetes,
    [Parameter(Mandatory=$False)]
    [switch]$Linux,
    [Parameter(Mandatory=$False)]
    [switch]$LocalAdminCredential
)
Import-Module Orchestrator.AssetManagement.Cmdlets | Out-Null

# Always set common variables
$DomainController                   =   Get-AutomationVariable -Name 'AutomationDomainController'
Write-Verbose 'Successfully set $DomainController'

if ($Azure) {
    $AzureDSCRegistrationURL        =   Get-AutomationVariable -Name 'AzureDSCRegistrationURL'
    Write-Verbose 'Successfully imported $AzureDSCRegistrationURL'
    $AzureResourceGroupName         =   Get-AutomationVariable -Name 'AzureResourceGroupName'
    Write-Verbose 'Successfully imported $AzureResourceGroupName'
    $AzureAutomationAccountName     =   Get-AutomationVariable -Name 'AzureAutomationAccountName'
    Write-Verbose 'Successfully imported $AzureAutomationAccountName'
    $CommonAzureParams = @{
        ResourceGroupName           =   $AzureResourceGroupName
        AutomationAccountName       =   $AzureAutomationAccountName
    }
    Write-Verbose 'Successfully set $CommonAzureParams'
    $RunOnAccount                   =   Get-AutomationVariable -Name 'RunOnAccount'
    Write-Verbose 'Successfully imported $RunOnAccount'

}

if ($Automation) {
    $ADMgmtAccount                  =   Get-AutomationVariable -Name 'ADMgmtAccount'
    Write-Verbose 'Successfully imported $ADMgmtAccount'
    $BackupMgmtAccount              =   Get-AutomationVariable -Name 'BackupMgmtAccount'
    Write-Verbose 'Successfully imported $BackupMgmtAccount'
    $BuildCertPath                  =   Get-AutomationVariable -Name 'BuildCertPath'
    Write-Verbose 'Successfully imported $BuildCertPath'
    $LogName                        =   Get-AutomationVariable -Name 'LogName'
    Write-Verbose 'Successfully imported $LogName'
}

if ($LocalAdminCredential) {
    $LocalAdminAccount          =   Get-AutomationVariable -Name 'LocalAdminAccount'
    Write-Verbose 'Successfully imported $LocalAdminAccount'
}