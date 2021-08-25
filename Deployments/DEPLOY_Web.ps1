#region Common Config
# You SHOULD NOT change this region.
$VerbosePreference      =   "Continue"
$WarningPreference      =   "Continue"
$ErrorActionPreference  =   "Stop"

. .\Get-CommonVariables.ps1 -Automation -Azure
. .\ConfigBuild.ps1

Import-Module Orchestrator.AssetManagement.Cmdlets -ErrorAction SilentlyContinue
#endregion
#region Session configuration
# If you require access to any credentials or variables you MUST adjust the Get-CommonVariables request in the next line
# . .\Get-CommonVariables.ps1
#endregion
# $DeploymentConfig = @{ #
#region stack config
<#
    You MUST configure this region, and set appropriate DSC settings.

    All other settings are optional.
#>
$Owner                      =   "home\radmin"
$ServiceName                =   "Web Server"
$Role                       =   "Windows_Server_Web"
$BaseVMName                 =   "WD-TEST"
$LocalIP                    =   187

$LocalAdmins                =   @()
$AdditionalDrives           =   @()
$DSCParams                  =   @{
    AllowedAccessRanges     =   @('10.3.2.0/27')
}

<#

    If not deploying to a feature environment, and are fine with the defaults you can ignore the rest of this
    file.

    If you're deploying to a feature environment make sure to set the appropriate overrides below, and set
    $UseDefaults to $False

#>
$UseDefaults                    =   $True

#endregion

if ($UseDefaults) {
    switch -Wildcard ($BaseVMName) {
        #region Mainline Dev
        "DEV-*" {
            if ($BaseVMName -like "DEV-DC*") {
                $NWAddress      =   '10.0.0.'

            }else { $NWAddress  =   '10.0.2.' }

            $Environment        =   'dev'
            $EnvironmentLong    =   'Main Dev'

            $MinRAM             =   512MB
            $StartupRAM         =   2GB
            $MaxRAM             =   4GB
            $CPUCount           =   4
            $SystemDriveSizeGB  =   80GB
        }
        #endregion
        #region Mainline Test
        "TST-*" {
            if ($BaseVMName -like "TST-DC*") {
                $NWAddress      =   '10.1.0.'

            }else { $NWAddress  =   '10.1.2.' }

            $Environment        =   'test'
            $EnvironmentLong    =   'Main Test'

            $MinRAM             =   1GB
            $StartupRAM         =   2GB
            $MaxRAM             =   6GB
            $CPUCount           =   4
            $SystemDriveSizeGB  =   80GB
        }
        #endregion
        #region Production
        Default {
            if ($BaseVMName -like "DC*") {
                $NWAddress      =   '10.2.0.'

            }else { $NWAddress  =   '10.2.2.' }

            $Environment        =   'Production'
            $EnvironmentLong    =   $Null

            $MinRAM             =   2GB
            $StartupRAM         =   2GB
            $MaxRAM             =   8GB
            $CPUCount           =   4
            $SystemDriveSizeGB  =   80GB
        }
        #endregion
    }
}
#endregion
#region Single-Server Deployment
#region Configure deployment run


# Sanity checks.
if ($SystemDriveSizeGB -lt 80GB) {
    throw "Default image size is 80GB, cannot deploy to a system drive smaller than 80GB: $SystemDriveSizeGB"
}

# Force into non-DHCP range
if (!($OverrideIP)) {
    if ($IPAddress -lt 100) {$IPAddress += 100}
}

$IPAddress                      =   "$($NWAddress)$LocalIP"
$ServiceName                    =   "$EnvironmentLong $ServiceName".Trim()
$BaseVMName                     =   $BaseVMName.ToUpper()

# Build params
$MemberServer = @{
    BaseVMName                  =   $BaseVMName
    Environment                 =   $Environment
    IPAddress                   =   $IPAddress
    Role                        =   $Role

    ServiceName                 =   $ServiceName
    Owner                       =   $Owner

    MinRAM                      =   $MinRAM
    StartupRAM                  =   $StartupRAM
    MaxRAM                      =   $MaxRam
    CPUCount                    =   $CPUCount
    SystemDriveSizeGB           =   $SystemDriveSizeGB
    AdditionalDrives            =   $AdditionalDrives

    LocalAdmins                 =   $LocalAdmins
    DSCParams                   =   $DSCParams
}
#endregion
#region deployment scripts.
Write-Warning "BUILD"
$Build                          =   .\Build-OnPremVM.ps1 @MemberServer

Write-Warning "COMPILE"
$CompilationJob                 =   .\New-WindowsMetaconfig.ps1 $Build.NewVMName

Write-Warning "WAIT"
Wait-ForDSCCompilationJob $CompilationJob

Write-Warning "DEPLOY"
.\Deploy-OnPremVM.ps1 $Build.NewVMName
#endregion
#endregion
#endregion