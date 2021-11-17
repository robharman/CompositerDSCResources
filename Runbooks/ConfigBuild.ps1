<#
    .SYNOPSIS
        Helper functions and shared variables that aren't pulled from Azure Automation
    .DESCRIPTION
        Helper functions for on-prem VM deployment, and variables that are not stored in the Azure Automation account
        which can be used in jobs without authenticating in the job back to Azure.
    .NOTES
        Version:        1.0.0
        Author:         Rob Harman
        Written:        2021/11/17
        Version Notes:  Initial upload
        REQUIRES:
        To Do:

#>

function Wait-ForDSCCompilationJob {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $CompilationJob
    )
    $Incomplete             =   $True
    While ($Incomplete){
        $CompilationJob     =   (Get-AzAutomationDscCompilationJob @CommonAzureParams -Id $CompilationJob.Id)
        switch ($CompilationJob.Status) {
            "New"       {
                Write-Output "Waiting for compilation job to start..." ;
                Start-Sleep 30
            }
            "Activating"  {
                Write-Output "Starting compilation job..." ;
                Start-Sleep 30
            }
            "Running"   {
                Write-Output "Compilation job running..." ;
                Start-Sleep 15
            }
            "Suspended" {
                Write-Error "Compilation jo suspended"
                throw "Compilation Job suspended."
            }
            "Completed" {
                $Incomplete         =   $False
            }
            default     {
                Write-Output "Waiting on compilation job..." ;
                Start-Sleep 5
            }
        }
    }

    return $True
}

# Set gateway to .1 in local network.
function Get-GateWay {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ipaddress]
        $IPAddress
    )
    return "$($IPAddress.tostring().substring(0,($IPAddress.tostring().LastIndexOf(".")))).1"
}

# Set here instead of as Azure Automation varibales to facilitate changes without authenticating into Azure and then
# pulling them out.

$PrimaryDNSServer           =   ''
$SecondaryDNSServer         =   ''
$AllowedAdminIPs            =   @()
$DNSDomain                  =   'DNS domain'

$HyperVHost                 =   'Hyper-V Server Name'
$HyperVMainSwitch           =   'Hyper-V Main Switch Name'

$VMConfigDir                =   '\\path\to\store\vmconfigfiles'

# Base OU used to seed Servers OU for different environments
$DEVBaseOU                  =   "OU=Computers,OU=Fill,DC=Fill,DC=this,DC=out"
$TestBaseOU                 =   "OU=Computers,OU=Fill,DC=Fill,DC=this,DC=out"
$ProdBaseOU                 =   "OU=Computers,OU=Fill,DC=Fill,DC=this,DC=out"