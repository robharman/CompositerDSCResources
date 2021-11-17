<#
    .SYNOPSIS
        Hashtable to populate Azure Automation variables with Set-CommonVariables.ps1
    .DESCRIPTION
        Used to populate/update variables stored in Azure Automation.
    .NOTES
        Version:        1.0.0
        Author:         Rob Harman
        Written:        2021/11/17
        Version Notes:  Initial upload
        REQUIRES:
        To Do:

#>

[ordered]@{
    # Automation variable name          # Value
    # Common Variables
    AutomationDomainController      =   'SetDCToAvoidConflicts'

    # Azure Variables
    AzureDSCRegistrationURL         =   'Azure DSC Registration URL'
    AzureResourceGroupName          =   'Azure Automation RG'
    AzureAutomationAccountName      =   'AutomationAccount'
    RunOnAccount                    =   'RunOnAccount'

    # Automation Variables
    ADMgmtAccount                   =   'AD Management'
    BackupMgmtAccount               =   'Backup Management'
    BuildMgmtAcount                 =   'Build Management'
    BuildCertPath                   =   'Cert:\CurrentUser\My\CERTTHUMBPRINT'
    CertMgmtAccount                 =   'Certificate Management'
    LogName                         =   'LogName'

    # Windows
    LocalAdminAccount               =   'Local Admin Account'
}