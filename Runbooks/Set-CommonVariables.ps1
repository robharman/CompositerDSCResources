<#
.SYNOPSIS
    Sets variables in the Azure Automation account, emails if update fails.

.DESCRIPTION
    Iterates through $CommonVariables and sets each item in Azure Automation. Sends an email through the Send-HomeEmail
    runbook if an update fails.

    These variables are shared between runbooks, and the names are shared between automation accounts. We populate the
    variable values at the account level
.NOTES
    Requires:
    Version:        1.0.0
    Author:         Rob Harman
    Written:        2021-11-17
    Version Notes:  Initial version
    To Do:
#>
$ErrorActionPreference          =   "Stop"
$VerbosePreference              =   "Continue"
[string[]]$NewVariables         =  @()
[string[]]$UpdatedVariables     =  @()
$CommonVariables                =   . .\ConfigVariables.ps1
$From                           =   $CommonVariables.AutomationFromAddress
$CommonAzureParams = @{
    ResourceGroupName           =   $CommonVariables.AzureResourceGroupName
    AutomationAccountName       =   $CommonVariables.AzureAutomationAccountName
}

Write-Verbose "Connecting to Azure"
$AzConnection                   =   Get-AutomationConnection -Name AzureRunAsConnection
$ConnectionParams           =  @{
    ServicePrincipal            =   $True
    Tenant                      =   $AzConnection.TenantID
    ApplicationId               =   $AzConnection.ApplicationID
    CertificateThumbprint       =   $AzConnection.CertificateThumbprint
}
$AzConnectionResult             =   Connect-AzAccount @ConnectionParams

if ($AzConnectionResult) {
    Write-Verbose "Connected to Azure account..."
}else {
    throw "Could not connect to Azure account"
}

Write-Verbose "Setting Azure common variables..."
foreach ($VariableName in $CommonVariables.Keys) {
    Write-Verbose "Setting $VariableName..."
    $VariableParameters = @{
        Name                    =   $VariableName
        Value                   =   $CommonVariables.$VariableName
    }

    try {
        Set-AutomationVariable @VariableParameters
        $UpdatedVariables      +=   ("$VariableName`n")
        Write-Verbose "Updated $VariableName"
    }catch {
        $NewVariableAdded          =   $True
        $NewVariables          +=   ("$VariableName`n")
        Write-Output "Creating new AZ Variable name: $VariableName"
        New-AzAutomationVariable @VariableParameters @CommonAzureParams -Encrypted $True
    }
}

if ($NewVariableAdded) {
    $Body           =   "The following new variables were added:`n" + $NewVariables
    $MailMessage    =  @{
        To          = @("alertemail@domain.com")
        from        =   $From
        Subject     =   "Added $($NewVariables.Count) new variables to $($CommonAzureParams.AutomationAccountName)"
        Body        =   $Body
    }

    $RunBookParams  =   @{
        Name            =   "Send-Email"
        Parameters      =   $MailMessage
        RunOn           =   $CommonVariables.RunOnAccount
    }

    Start-AzAutomationRunbook @RunBookParams @CommonAzureParams
}

if ($UpdatedVariables.Count -gt 0) {
    $Body           =   "Updated the following variables:`n" + $UpdatedVariables
    $MailMessage    =  @{
        To          = @("automationreports@domain.com")
        From        =   $From
        Subject     =   "Updated $($UpdatedVariables.Count) variables on $($CommonAzureParams.AutomationAccountName)"
        Body        =   $Body
    }

    $RunBookParams  =   @{
        Name            =   "Send-Email"
        Parameters      =   $MailMessage
        RunOn           =   $CommonVariables.RunOnAccount
    }

    Start-AzAutomationRunbook @RunBookParams @CommonAzureParams
}