<#
    .SYNOPSIS
        Creates metaconfig info for specified VM
    .DESCRIPTION
        Creates Windows Admin Center config
        Compiles node specific DSC configuration
        Creates VM Metaconfig info and saves it to disk for injection in the deployment process.
    .NOTES
        Version:        1.0.0
        Author:         Rob Harman
        Written:        2021-11-17
        Version Notes:  Initial Upload
        REQUIRES:       Azure runbook. Requires PS 5.1+ on worker, if called directly, needs to be -runon an on-prem
                        worker node.
        To Do:
#>
#Requires -Version 5.1
[cmdletbinding()]
param (
    [Parameter(Mandatory)]
    [ValidateScript({
        # Checks to make sure we can get the configruation parameters and quits if not.
        # Copy $_ for error throwing.
        $VMToValidate = $_
        try {
            if (Test-Path "$VMConfigDir\$_\BuildParams.ps1") {
                return $true
            }else {
                throw "VM Configration file does not exist at $VMConfigDir\$VMToValidate"
            }
        }catch {
            throw "VM Configration file does not exist at $VMConfigDir\$VMToValidate"
        }
    })]
    [string]
    $NewVMName
)
$ErrorActionPreference          =   "Stop"
$VerbosePreference              =   "Continue"
Import-Module Orchestrator.AssetManagement.Cmdlets  | Out-Null
Import-Module Az.Accounts                           | Out-Null
Import-Module Az.Automation                         | Out-Null

$AzConnection                   =   Get-AutomationConnection -Name AzureRunAsConnection
$ConnectionParams           =  @{
    ServicePrincipal            =   $True
    Tenant                      =   $AzConnection.TenantID
    ApplicationId               =   $AzConnection.ApplicationID
    CertificateThumbprint       =   $AzConnection.CertificateThumbprint
}
$AzConnectionResult             =   Connect-AzAccount @ConnectionParams
$AzureContext                   =   Set-AzContext -SubscriptionId $AzConnection.SubscriptionId

if ($AzConnectionResult) {
    Write-Verbose "Connected to Azure account..."
}else {
    throw "Could not connect to Azure account"
}

. .\BuildConfig.ps1
. .\Get-CommonVariables.ps1 -Automation -Azure
[pscredential]$AzureDSCRegistration  =   Get-AutomationPSCredential -Name $AzureDSCRegistrationURL

Write-Verbose "Getting build params..."
$BuildParams                    =   "$VMConfigDir\$NewVMName\Buildparams.ps1"

Write-Verbose "Validating build params..."
if ((Get-AuthenticodeSignature $BuildParams).Status -eq "Valid"){
    $BuildParams = Get-Content $BuildParams -TotalCount (Get-Content $BuildParams).IndexOf("# SIG # Begin signature block")
    if ($PSVersionTable.PSEdition -like "Core") {
        $BuildParams = $BuildParams | ConvertFrom-Json -AsHashtable

    }else {
        # when using PS 5.1 which doesn't support importing JSON as a hashtable, which breaks literally
        # every part of this process.
        Add-Type -AssemblyName "System.Web.Extensions" -ErrorAction Stop

        $JsonSerializer = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        $BuildParams = $JsonSerializer.Deserialize($BuildParams,'Hashtable')
    }
}else {
    throw "$VMConfigDir\$NewVMName\Buildparams.ps1 does not have a valid AuthentiCode signature."
}

# Exit early
if ($BuildParams.Role -like 'Linux*') {
    $Return = @{Status = 'Completed'}
    return $Return
}

Write-Verbose "Setting configuration based on role..."
$DSCNodeConfigName              =   $BuildParams.Role

if ($BuildParams.Role -eq "DomainController"){
    Write-Verbose "Setting Domain Controller specific information..."

    $NodeParameters             =   @{
        NodeName                =   $BuildParams.NewVMName
        IPAddress               =   [string][ipaddress]$BuildParams.IPAddress.Address
        Owner                   =   "Domain Admins"
    }

}else {
    Write-Verbose "Getting Azure DSC Configuration data..."

    try {
        $DSCConfigParams = @{
            Name                =   $DSCNodeConfigName
            ErrorAction         =   "Stop"
            DefaultProfile      =   $AzureContext
        }
        Get-AzAutomationDscConfiguration @CommonAzureParams @DSCConfigParams

    }catch {
        throw "DSC Configuration does not exist. Please create a configuration for: $DSCNodeConfigName before deploying."
    }
}

Write-Verbose "Creating node parameters..."
$NodeParameters         =   @{
    Owner               =   $BuildParams.Owner
    NodeName            =   $BuildParams.NewVMName
    IPAddress           =   [string][ipaddress]$BuildParams.IPAddress.Address
    Environment         =   $BuildParams.Environment
    StorageRoot         =   $BuildParams.StorageRoot
}

if ($BuildParams.DSCParams -ne "") {
    Write-Verbose "Adding additional DSC Parameters..."
    $NodeParameters    +=   $BuildParams.DSCParams
}

Write-Verbose "Starting DSC Compilation Job..."
$CompilationParams = @{
    ConfigurationName               =   $DSCNodeConfigName
    Parameters                      =   $NodeParameters
    DefaultProfile                  =   $AzureContext
}

$CompilationJob                     =   Start-AzAutomationDscCompilationJob @CommonAzureParams @CompilationParams

Write-Verbose "Setting DSC Metaconfig info..."
if ($BuildParams.Environment -eq "Production") {
    $RefreshFrequencyMins           =   360
    $ConfigurationModeFrequencyMins =   360
    $RebootNodeIfNeeded             =   $True
    $ConfigurationMode              =   "ApplyAndAutoCorrect"

}elseif ($BuildParams.Environment -eq "Dev")  {
    $RefreshFrequencyMins           =   720
    $ConfigurationModeFrequencyMins =   720
    $RebootNodeIfNeeded             =   $True
    $ConfigurationMode              =   "ApplyAndAutoCorrect"

}elseif ($BuildParams.Environment -eq "Test")  {
    $RefreshFrequencyMins           =   300
    $ConfigurationModeFrequencyMins =   300
    $RebootNodeIfNeeded             =   $True
    $ConfigurationMode              =   "ApplyAndAutoCorrect"

}else {
    $RefreshFrequencyMins           =   1425
    $ConfigurationModeFrequencyMins =   1425
    $RebootNodeIfNeeded             =   $False
    $ConfigurationMode              =   "ApplyAndMonitor"
}

Write-Verbose "Building metaconfig..."
[DscLocalConfigurationManager()]
Configuration DscMetaConfigs {
    param (
        [Parameter(Mandatory=$True)]
        [String]$RegistrationUrl,
        [Parameter(Mandatory=$True)]
        [String]$RegistrationKey,
        [Parameter(Mandatory=$True)]
        [String[]]$ComputerName,
        [Int]$RefreshFrequencyMins = 30,
        [Int]$ConfigurationModeFrequencyMins = 15,
        [String]$ConfigurationMode = 'ApplyAndMonitor',
        [String]$NodeConfigurationName,
        [Boolean]$RebootNodeIfNeeded= $True,
        [String]$ActionAfterReboot = 'ContinueConfiguration',
        [Boolean]$AllowModuleOverwrite = $False,
        [Boolean]$ReportOnly
    )

    if (!$NodeConfigurationName -or $NodeConfigurationName -eq '') {
        $ConfigurationNames = $null
    }else {
        $ConfigurationNames = @($NodeConfigurationName)
    }

    if ($ReportOnly) {
        $RefreshMode = 'PUSH'
    }else {
        $RefreshMode = 'PULL'
    }

    Node $ComputerName {
        Settings {
            RefreshFrequencyMins           = $RefreshFrequencyMins
            RefreshMode                    = $RefreshMode
            ConfigurationMode              = $ConfigurationMode
            AllowModuleOverwrite           = $AllowModuleOverwrite
            RebootNodeIfNeeded             = $RebootNodeIfNeeded
            ActionAfterReboot              = $ActionAfterReboot
            ConfigurationModeFrequencyMins = $ConfigurationModeFrequencyMins
        }

        if(!$ReportOnly) {
            ConfigurationRepositoryWeb AzureAutomationStateConfiguration {
                ServerUrl          = $RegistrationUrl
                RegistrationKey    = $RegistrationKey
                ConfigurationNames = $ConfigurationNames
            }

            ResourceRepositoryWeb AzureAutomationStateConfiguration {
                ServerUrl       = $RegistrationUrl
                RegistrationKey = $RegistrationKey
            }
        }

        ReportServerWeb AzureAutomationStateConfiguration {
            ServerUrl       = $RegistrationUrl
            RegistrationKey = $RegistrationKey
        }
    }
}

Write-Verbose "Creating Windows Admin Centre configuration CSV..."
$WACCSV                 =   "$($BuildParams.ConfigurationDirectory)\$($BuildParams.NewVMName).WAC.csv"
$Headers                =   '"name","type","tags","groupId"'
$GroupID                =   "global"
$Type                   =   "msft.sme.connection-type.server"
$RawTags                =   @()

$RawTags               +=   $BuildParams.Environment
$RawTags               +=   $BuildParams.ServiceName.Replace(' ','')

if ($OS -eq "WO") {
    $RawTags           +=  "Server2012"
}elseif ($OS -eq "WL") {
    $RawTags           +=  "Server2016"
}else   {
    $RawTags           +=  "Server2019"
}

$RawTags               +=  $BuildParams.Role
$RawTags               +=  $BuildParams.WindowsAdminCenterTags
$RawTags               +=  "AutomatedBuild"

Write-Verbose "Converting tags..."
$RawTags | Foreach-Object {$Tags += "$_|"}
if ($Tags.EndsWith("|")){
    $Tags = $Tags.Substring(0,($Tags.Length -1))
}

"$Headers`n$($BuildParams.NewVMName),$Type,$Tags,$GroupID" | Out-File $WACCSV

$Params = @{
    RegistrationUrl                 =   $AzureDSCRegistration.UserName;
    RegistrationKey                 =   $AzureDSCRegistration.GetNetworkCredential().Password
    ComputerName                    =   $BuildParams.NewVMName;
    NodeConfigurationName           =   "$DSCNodeConfigName.$($BuildParams.NewVMName)";

    RefreshFrequencyMins            =   $RefreshFrequencyMins;
    ConfigurationModeFrequencyMins  =   $ConfigurationModeFrequencyMins;
    RebootNodeIfNeeded              =   $RebootNodeIfNeeded;
    AllowModuleOverwrite            =   $True;

    ConfigurationMode               =   $ConfigurationMode;
    ActionAfterReboot               =   'ContinueConfiguration';
    ReportOnly                      =   $False;  # Set to $True to have machines only report to AA DSC but not pull
}

Write-Verbose "Compiling MOF file..."
DscMetaConfigs @Params
Write-Verbose "Moving MOF file to config dir..."
Move-Item .\DscMetaConfigs\$($BuildParams.NewVMName).meta.mof $BuildParams.ConfigurationDirectory
Return $CompilationJob