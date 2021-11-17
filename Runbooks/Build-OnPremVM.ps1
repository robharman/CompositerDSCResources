<#
    .SYNOPSIS
        Builds configuration file for on-prem VM.
    .DESCRIPTION
        Creates VM BuildConfig file for deployment and configuration management.
    .NOTES
        Version:        1.0.0
        Author:         Rob Harman
        Written:        2021/11/17
        Version Notes:  Initial upload
        REQUIRES:
        To Do:

#>
[cmdletbinding()]
param (
    [Parameter(Mandatory)]
    [string]
    $BaseVMName,

    [Parameter(Mandatory)]
    [string]
    $Environment,

    [Parameter(Mandatory)]
    [ipaddress]
    $IPAddress,

    [Parameter(Mandatory)]
    [string]
    $Role,

    [Parameter(Mandatory)]
    [string]
    $Owner,

    [Parameter(Mandatory = $False)]
    [int64]
    $MinRAM                 =   1GB,

    [Parameter(Mandatory = $False)]
    [int64]
    $StartupRAM             =   2GB,

    [Parameter(Mandatory = $False)]
    [int64]
    $MaxRAM                 =   4GB,

    [Parameter(Mandatory = $False)]
    [int]
    $CPUCount               =   4,

    [Parameter(Mandatory = $False)]
    [int64]
    $SystemDriveSizeGB      =   80GB,

    [Parameter(Mandatory)]
    [string]
    $ServiceName,

    [Alias("HA")]
    [Parameter(Mandatory = $False)]
    [switch]
    $HighAvailability,

    [Parameter(Mandatory = $False)]
    [array]
    $WindowsAdminCenterTags =   @(),

    [Parameter(Mandatory = $False)]
    [ValidateScript({
        if ($_ -like "$DNSDomain") {
            throw "Custom DNS names must just be hostname, not : $_"
        }else {
            $True
        }
    })]
    [string]
    $CustomDNSName          =   "",

    [Parameter(Mandatory = $False)]
    [switch]
    $Gen1VM,

    [Parameter(Mandatory = $False)]
    [switch]
    $UseOldWindowsVersion,

    [Parameter(Mandatory = $False)]
    [string[]]
    $ServiceAccountNames    =   "",

    [Parameter(Mandatory = $False)]
    [string[]]
    $LocalAdmins            =   "",

    [Parameter(Mandatory = $False)]
    [string]
    $SQLVersion             =   "SQL2019Dev",

    [Parameter(Mandatory = $False)]
    [hashtable]
    $DSCParams              =   @{},

    [Parameter(Mandatory = $False)]
    [array]
    $AdditionalDrives       =   $null
)

[version]$Version                   =   "1.0.0"

Import-Module "ActiveDirectory"

. .\Get-CommonVariables.ps1 -Automation -Azure -LocalAdminCredential
. .\ConfigBuild.ps1

[pscredential]$ADMgmtCredential     =   Get-AutomationPSCredential -Name $ADMgmtAccount
$BuildCert                          =   ( Get-ChildItem $BuildCertPath )

$DSCParams.GatewayAddress           =   Get-GateWay $IPAddress
$DSCParams.AllowedAdminIPs          =   $AllowedAdminIPs

$DSCParams.ADMgmtAccount            =   $ADMgmtAccount
$DSCParams.BackupMgmtAccount        =   $BackupMgmtAccount
$DSCParams.LocalAdminAccount        =   $LocalAdminAccount
$DSCParams.LocalAdmins              =   $LocalAdmins

if ($AdditionalDrives.Count -gt 0) {
    $DSCParams.AdditionalDrives     =   $AdditionalDrives
}

# Automatically name newly deployed servers in sequence. Checks AD for previous incarnations of this servername
# and builds increments by one. Starts at 00 if there are no previous versions, or if there have been 256
# previous versions rolls back to 00.
# Note that serial numbers are in HEX 0-F, not decimal 0-9.

Write-Verbose "Validating configuration..."
if ($BaseVMName -like "Dev-*" -and $Environment -Like "*DEV") {
    Write-Verbose "VM and Environment are both Dev validated..."

}elseif ($BaseVMName -like "TST-*" -and $Environment -Like "*TEST") {
    Write-Verbose "VM and Environment are both Test validated..."

}elseif ($BaseVMName -notmatch '^DEV\b|^TST\b' -and $Environment -eq "Production") {
    Write-Verbose "VM and environment are both prod validated..."

}else {
    throw "Environment mismatch. Environment set to $Environment but VM Name set to $BaseVMName"
}

#region Infrastructure/issues/20
Write-Verbose "Searching for previous server versions..."
try {
    $PreviousServer        =   (Get-ADComputer -Server $DomainController -Filter * -Properties OperatingSystem |
    Where-Object {($_.name -like "$BaseVMName*")}).Name.substring(($BaseVMName.Length),2) |
    Sort-Object | Select-Object -Last 1
    Write-Verbose "Found previous server: $BaseVMName$PreviousServer"
}catch {
    $FirstPressing          =   $True
}

Write-Verbose "Converting $BaseVMName"
if ($FirstPressing){
    $NewVMName = "$($BaseVMName)00"
}elseif ([convert]::ToInt32(($PreviousServer),16) -gt 255) {
    $NewVMName = "$($BaseVMName)00"
}else {
    $NewVMName = $BaseVMName + ('{0:x}' -f ([convert]::ToInt32(($PreviousServer),16) + 1)).PadLeft(2,"0")
}
#endregion

# Set $Dev/$Test and strip designation for easier server metadata build.
if ($NewVMName -like "DEV-*"){
    Write-Verbose "Setting development environment..."
    $Dev        =   $True
}elseif ($NewVMName -like "TST-*"){
    Write-Verbose "Setting test environment..."
    $Test       =   $True
}

if ($Dev -or $Test) {
    $OS                         =   $NewVMName.Substring(4,2)

} else {
    $OS                         =   $NewVMName.Substring(0,2)
}

# Check we meant to deploy an old version of Windows.
if (($OS -like "WL" -or $OS -like "WO") -and !($UseOldWindowsVersion)) {
    throw "Trying to deploy old version of windows without specifying -UseOldWindowsVersion"
}

$ConfigurationDirectory         =   "$VMConfigDir\$NewVMName"
try {
    New-Item -ItemType Directory -Path $ConfigurationDirectory -Force
}catch {
    throw "Couldn't create configuration directory: $ConfigurationDirectory"
}

# Create domain account, and offline join file.
if ($OS -like "W*") {
    Write-Verbose "Creating offline join request..."
    $BaseOU                     = switch -wildcard ($Environment) {
        "*Dev"                  {   $DEVBaseOU  }
        "*Test"                 {   $TestBaseOU }
        "Production"            {   $ProdBaseOU }
        Default                 {   throw "Cannot map environment to base OU: $($Environment.split(".")[0])"}
    }

    Write-Verbose "Setting OU..."
    $DestinationOU              =   "OU=Servers,$BaseOU"

    djoin /dcname $DomainController /machineou $DestinationOU /provision /machine $NewVMName /domain $DNSDomain /savefile "$ConfigurationDirectory\ODJ.txt"
    if ($LASTEXITCODE -ne 0) {
        throw "Domain join failed, Last Exit Code was: $LASTEXITCODE"
    }

    Set-ADComputer -Identity $NewVMName -Description $ServiceName -Server $DomainController

}else {
    # Create dummy AD Object for Linux servers
    $BaseOU     = switch -wildcard ($Environment) {
        "*Dev"                  {   $DEVBaseOU  }
        "*Test"                 {   $TestBaseOU }
        "Production"            {   $ProdBaseOU }
        Default                 {   throw "Cannot map environment to base OU: $($Environment.split(".")[0])"}
    }

    Write-Verbose "Setting OU..."
    $DestinationOU              =   "OU=Servers,$BaseOU"

    $LinuxServer     =   @{
        Name            =   $NewVMName
        SAMAccountName  =   $NewVMName
        Enabled         =   $False
        Path            =   $DestinationOU
        Description     =   "$ServiceName Linux Node"
        Server          =   $DomainController
        Credential      =   $ADMgmtCredential
    }

    try {
        New-ADComputer @LinuxServer -ErrorAction "Stop"

    }catch {
        throw "Cannot create new AD Object: $_"
    }

    try {
        Import-Module -Name 'DNSServer' -ErrorAction 'Stop'

    }catch {
        throw "Cannot import DNSServer module: $_"
    }

    try {
        $DNSRecord  =   @{
            ComputerName    =   $DomainController
            Confirm         =   $False
            CreatePtr       =   $True
            IPv4Address     =   $IPAddress
            Name            =   $NewVMName
            ZoneName        =   $DNSDomain
        }

        Add-DnsServerResourceRecordA @DNSRecord -ErrorAction 'Stop'
    }catch {
        throw "Could not create $NewVMName.$DNSDomain DNS record: $_"
    }
}

$StorageRoot                    = switch -wildcard ($Environment) {
    Default                {   "\\home" }
}

# Configure "hardware" settings
$HyperVHost                     =   $HyperVHost
$HyperVDefaultStorage           =   "B:"
$HyperVDataDrive                =   "B:"
$HyperVSQLDBDrive               =   "B:"
$DSCParams.PrimaryDNSServer     =   $PrimaryDNSServer
$DSCParams.SecondaryDNSServer   =   $SecondaryDNSServer

#Adjust base paths as required
$VHDDirectory                   =   "B:\VM Data\$NewVMName\Virtual Hard Disks"
$DataVHDDirectory               =   "B:\VM Data\$NewVMName\Virtual Hard Disks"
$SQLDBVHDDirectory              =   "B:\SQL Data\$NewVMName\Virtual Hard Disks"
$DataVHDSetDirectory            =   "B:\Shared\$Environment\$($ServiceName)_$(Get-Date -Format yyMMddhhmm)\Virtual Hard Disks"

$DestinationVHD                 =   "$VHDDirectory\${NewVMName}.vhdx"

# Set base system disk
Write-Verbose "Setting base image..."
$BaseImage                  =   switch ($OS) {
    # Linux
    "LN" {
        "$HyperVDefaultStorage\Templates\Linux\Virtual Hard Disks\Linux.vhdx"
    }
    # Windows Server Core
    "WC" {
        "$HyperVDefaultStorage\Templates\2022\Virtual Hard Disks\2022.vhdx"
        $DSCParams.ServerCore       =   $True
    }
    # Windows Server Desktop
    "WD" {
        "$HyperVDefaultStorage\Templates\2022 Desktop\Virtual Hard Disks\2022 Desktop.vhdx"
    }
}

# Configure data drive.
Write-Verbose "Additional role-based config..."
switch -wildcard ($Role) {
    "Windows_Server_Archive" {
        $AdditionalVHD = @(
            @{
                Path            =   "B:\Archives\${NewVMName}_Data.vhdx"
                SizeBytes       =   8TB
            }
        )
    }

    "Windows_Server_Storage" {
        if ($DSCParams.HubServer) {
            $AdditionalVHD = @(
                @{
                    Path        =   "$DataVHDDirectory\${NewVMName}_Data.vhdx"
                    SizeBytes   =   6TB
                }
            )
        }else {
            $AdditionalVHD = @(
                @{
                    Path        =   "$DataVHDDirectory\${NewVMName}_Data.vhdx"
                    SizeBytes   =   3TB
                }
            )
        }
    }

    "Windows_Cluster" {
        $HAVHDSet       =   @(
            @{
                Path            =   "$DataVHDSetDirectory\Clu_${ServiceName}_Quorum.vhds"
                SizeBytes       =   1GB
            }
        )

        if ($DSCParams.InitialClusterNode) {
            # Pre-Stage cluster objects so that the AG setup works properly.

            $ClusterCNO     =   @{
                Name            =   $DSCParams.ClusterName
                SAMAccountName  =   $DSCParams.ClusterName
                Enabled         =   $False
                Path            =   $DestinationOU
                Description     =   "$ServiceName virtual cluster object"
                Server          =   $DomainController
                Credential      =   $ADMgmtCredential
            }

            try {
                New-ADComputer @ClusterCNO -ErrorAction "Stop"
                Write-Verbose "Created Windows Cluster Object"

            }catch {
                if ((Get-ADComputer $ClusterCNO.Name).Enabled) {
                    throw "Cluster CNO exists and is enabled, cannot create new cluster."

                }else {
                    throw "Cannot create Cluster CNO: $_"
                }
            }
        }
    }

    "Windows_Cluster_SQL_AG" {
        $HAVHDSet       =   @(
            @{
                Path            =   "$DataVHDSetDirectory\SQL_${ServiceName}_Quorum.vhds"
                SizeBytes       =   1GB
            }
        )
        $AdditionalVHD = @(
            @{
                Path            =   "$DataVHDDirectory\${NewVMName}_Temp.vhdx"
                SizeBytes       =   300GB
            },
            @{
                Path            =   "$DataVHDDirectory\${NewVMName}_Logs.vhdx"
                SizeBytes       =   200GB
            },
            @{
                Path            =   "$SQLDBVHDDirectory\${NewVMName}_Data.vhdx"
                SizeBytes       =   2TB
            }
        )

        if ($DSCParams.InitialClusterNode) {
            # Pre-Stage cluster objects so that the AG setup works properly.

            $ClusterCNO     =   @{
                Name            =   "$($ServiceName)clu"
                SAMAccountName  =   "$($ServiceName)clu"
                Enabled         =   $False
                Path            =   $DestinationOU
                Description     =   "$ServiceName virtual cluster object"
                Server          =   $DomainController
                Credential      =   $ADMgmtCredential
            }

            try {
                New-ADComputer @ClusterCNO -ErrorAction "Stop"
                Write-Verbose "Created Windows Cluster Object"

            }catch {
                if ((Get-ADComputer $ClusterCNO.Name).Enabled) {
                    throw "Cluster CNO exists and is enabled, cannot create new cluster."

                }else {
                    throw "Cannot create Cluster CNO: $_"
                }
            }

            $SQLCNO     =   @{
                Name            =   $ServiceName
                SAMAccountName  =   $ServiceName
                Enabled         =   $False
                Path            =   $DestinationOU
                Description     =   "$ServiceName AG Listener virtual object"
                Server          =   $DomainController
                Credential      =   $ADMgmtCredential
            }

            try {
                New-ADComputer @SQLCNO -ErrorAction "Stop"
                Write-Verbose "Created SQL AG Listerner Object"

            }catch {
                if ((Get-ADComputer $SQLCNO.Name -Server $DomainController).Enabled) {
                    throw "SQL Listener object exists and is enabled, cannot create new cluster."

                }else {
                    throw "Could not create SQL Listener CNO: $_"
                }
            }

            # # Allow WSFC to manage SQL AG CNO, sets full control perms on child object.

            $Path               =   (Get-ADComputer $SQLCNO.Name -Server $DomainController).DistinguishedName
            $TargetObject       =   [adsi]"LDAP://$DomainController/$Path"

            $Permission         =   [System.Security.AccessControl.AccessControlType]"Allow"
            $ADRights           =   [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"

            $FullControlSID     =   (Get-ADComputer $ClusterCNO.Name -Server $DomainController).SID
            $ACE =   New-Object System.DirectoryServices.ActiveDirectoryAccessRule $FullControlSID,$ADRights,$Permission

            $TargetObject.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
            $TargetObject.psbase.ObjectSecurity.AddAccessRule($ACE)
            $TargetObject.CommitChanges()
        }
    }

    "Windows_Server_SQL_DR" {
        $AdditionalVHD = @(
            @{
                Path            =   "$DataVHDDirectory\${NewVMName}_Temp.vhdx"
                SizeBytes       =   200GB
            },
            @{
                Path            =   "$DataVHDDirectory\${NewVMName}_Logs.vhdx"
                SizeBytes       =   200GB
            },
            @{
                Path            =   "$SQLDBVHDDirectory\${NewVMName}_Data.vhdx"
                SizeBytes       =   2TB
            }
        )
    }

    Default {
        $AdditionalVHD  =   @()
        foreach ($AdditionalDrive in $AdditionalDrives) {
            $AdditionalVHD += @{
                Path        =   "$DataVHDDirectory\${NewVMName}_$($AdditionalDrive.FSLabel.Trim().Replace(' ','_')).vhdx"
                SizeBytes   =   $AdditionalDrive.SizeBytes
            }
        }
    }
}

# Now put all that together into hashtables that we can process with the rest of the build job.
# The base VM that we deploy on Hyper-V
$NewVM          =   @{
    Name                    =   $NewVMName
    MemoryStartupBytes      =   $StartupRAM
    Generation              =   2
    Path                    =   "$HyperVDefaultStorage\VM Data"
    VHDPath                 =   $DestinationVHD
    SwitchName              =   $HyperVMainSwitch
}
if ($Gen1VM) {$NewVM.Generation = 1}

# The VM's memory configuration
$VMMemory       =   @{
    ComputerName            =   $HyperVHost
    VMName                  =   $NewVMName
    DynamicMemoryEnabled    =   $true
    MinimumBytes            =   $MinRAM
    StartupBytes            =   $StartupRAM
    MaximumBytes            =   $MaxRAM
}

# The VM's CPU configuration
$VMCPU          =   @{
    ComputerName            =   $HyperVHost
    VMName                  =   $NewVMName
    Count                   =   $CPUCount
}

# The VM's common Networking configuration
$VMNetworking   =   @{
    ComputerName            =   $HyperVHost
    VMName                  =   $NewVMName
}

# Grouped into one hashtable
$NewVMParams    =  @{
    HyperVHost              =   $HyperVHost
    NewVM                   =   $NewVM
    VMCPU                   =   $VMCPU
    VMMemory                =   $VMMemory
    VMNetworking            =   $VMNetworking
    BaseImage               =   $BaseImage
    SystemDriveSizeGB       =   $SystemDriveSizeGB
    VHDDirectory            =   $VHDDirectory
    DestinationVHD          =   $DestinationVHD
    AdditionalVHD           =   $AdditionalVHD
    HAVHDSet                =   $HAVHDSet
    Role                    =   $Role
}

Write-Verbose "Building output hashtable..."
# Build the final output with all its nesty goodness.
$BuildParams = [ordered]@{
    NewVMName               =   $NewVMName
    NewVMParams             =   $NewVMParams
    Environment             =   $Environment
    StorageRoot             =   $StorageRoot
    IPAddress               =   $IPAddress
    Role                    =   $Role
    ServiceName             =   $ServiceName
}
if ($Role -like "*SQL*") {
    $BuildParams.SQLVersion =   $SQLVersion
}

$BuildParams += @{
    Owner                   =   $Owner
    ServiceAccountNames     =   $ServiceAccountNames
    DSCParams               =   $DSCParams
    DeploymentScriptVersion =   $Version
    AutomaticRedeploy       =   $False
    ConfigurationDirectory  =   $ConfigurationDirectory
    WindowsAdminCenterTags  =   $WindowsAdminCenterTags
}

# We save as a .ps1 file instead of a .json file because Windows/PowerShell has no native SIP with which
# PowewerShell can sign them.
Write-Verbose "Dumping to Json..."
$BuildParams | ConvertTo-Json -Depth 99 | Out-File -Encoding unicode -FilePath "$ConfigurationDirectory\BuildParams.ps1"
Write-Verbose "Signing configuration file..."
Set-AuthenticodeSignature -Certificate $BuildCert -FilePath "$ConfigurationDirectory\BuildParams.ps1"
return $BuildParams