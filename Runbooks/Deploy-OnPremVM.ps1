<#
    .SYNOPSIS
        Deploys and on-prem VM and sets up full configuration settings
    .DESCRIPTION
        Azure Runbook. Must be run on Hybrid Worker, not in Azure

        Grabs configuration settings from $VMConfigDir\VMNAME and creates the VM and computer object settings.

        Builds a new Hyper-V VM, adds it to adds to AD, appies DSC config settings, and starts the VM.
    .NOTES
        Version:        1.0.0
        Author:         Rob Harman
        Written:        2021-11-17
        Version Notes:  Initial upload
        REQUIRES:       Azure runbook. Requires PS 5.1+ on worker, if called directly, needs to be -runon an on-prem
                        worker node.
        To Do:          None
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
            if (Test-Path "$VMConfigDir\$VMToValidate\BuildParams.ps1") {
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
# Transcribe job for email.
$TranscriptID                   =   "$((New-Guid).Guid)"
Start-Transcript  -Path ".\$TranscriptID.txt"

# Import credentials from Azure Automation Credential vault
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

[pscredential]$VMMgmtCredential =   Get-AutomationPSCredential -Name "VM Management"

. .\Get-CommonVariables.ps1 -Email

$ErrorActionPreference          =   "Stop"
$BuildParams                    =   "$VMConfigDir\$NewVMName\Buildparams.ps1"

if ((Get-AuthenticodeSignature $BuildParams).Status -eq "Valid") {

    $BuildInfo = Get-Content $BuildParams -TotalCount (Get-Content $BuildParams).IndexOf("# SIG # Begin signature block")

    if ($PSVersionTable.PSEdition -like "Core") {
        $BuildInfo = $BuildInfo | ConvertFrom-Json -AsHashtable

    }else {
        # when using PS 5.1 which doesn't support importing JSON as a hashtable, which breaks literally
        # every part of this process.

        Add-Type -AssemblyName "System.Web.Extensions" -ErrorAction Stop

        $JsonSerializer = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer

        $BuildInfo = Get-Content $BuildParams -TotalCount (Get-Content $BuildParams).IndexOf("# SIG # Begin signature block")
        $BuildInfo = $JsonSerializer.Deserialize($BuildInfo,'Hashtable')
    }

}else {

    throw "$VMConfigDir\$NewVMName\Buildparams.ps1 does not have a valid AuthentiCode signature."
}
# Set local objects for clearner stuff
$VMParams                       =   $BuildInfo.NewVMParams
$NewVM                          =   $BuildInfo.NewVMParams.NewVM
$IPAddress                      =   [string][ipaddress]$BuildInfo.IPAddress.Address

if ($BuildInfo.Role -like "Windows*") {
    $MetaconfigMof                  =   Get-Content "$($BuildInfo.ConfigurationDirectory)\${NewVMName}.meta.mof"
    Remove-Item -Force -Confirm:$false  "$($BuildInfo.ConfigurationDirectory)\${NewVMName}.meta.mof"
}

<#
    In order to provide more detailed error reporting, and to allow for a more modular approach to creating the VMs on
    our Hyper-V hosts, we open a new session on the Hyper-V host and invoke individual commands from the jobs server.
    This not only provides better error handling, but also avoids the Kerberos double-hop problem with Jobs servers, and
    allows them to be dynamically replaced, without having to constantly update Kerberos delegation for the new servers.
#>
Write-Verbose "Connecting remote session"
$Global:RemoteSession       =   New-PSSession -ComputerName $VMParams.HyperVHost -Credential $VMMgmtCredential

Write-Verbose "Verifying clean deployment..."
try {

    $VM = Invoke-Command -Session $Global:RemoteSession -script {
        param (
            $NewVMName
        )

        try {

            Get-VM $NewVMName -ea stop

        }catch {
            return $False
        }

    } -ArgumentList $NewVMName

}catch {

    Write-Verbose "VM does not exist on host. Making sure there's not an existing version on disk..."
}

if ($VM) {

    throw "The machine $NewVMName already exists on $($VMParams.HyperVHost)"
}

# Make sure that the VM directory doesn't exist
try {

    $VMPathExists       =   Invoke-Command -Session $Global:RemoteSession -script {
        param (
            $VMDirectory
        )
        Test-Path $VMDirectory

    } -ArgumentList $VMParams.VHDDirectory

}catch {

    Write-Verbose "VM Directory doesn't exist..."
}

if ($VMPathExists) {

    throw "VM Directory already exists on $($VMParams.HyperVHost)"
}

# Build the VM a cozy home, and a place to rest its weary hard drives.
Write-Verbose "Creating VM Directory..."
try {

    invoke-Command -Session $Global:RemoteSession -Script {
        param (
            $Path
        )

        New-Item -ItemType Directory -Path $Path

    } -ArgumentList $VMParams.VHDDirectory

}catch {

    throw "Could not create $($VMParams.VHDDirectory) on $($VMParams.HyperVHost): $_"
}

# Create the VM
Write-Verbose "Creating OS VHD..."
try {

    invoke-Command -Session $Global:RemoteSession -Script {
        param (
            $BaseImage,
            $DestinationVHD
        )

        Copy-Item $BaseImage $DestinationVHD

    } -ArgumentList $VMParams.BaseImage, $VMParams.DestinationVHD

}catch {

    throw "Could not copy base image to $DestinationVHD on ${HyperVHost}: $_"
}

Write-Verbose "Creating new VM..."
try {

    Invoke-Command -Session $Global:RemoteSession -Script {
        param (
            $NewVM
        )

        New-VM @NewVM

    } -ArgumentList $NewVM

}catch {

    throw "Could not create new VM $($VMParams.VMName) on $($VMParams.HyperVHost): $_"
}

Write-Verbose 'Configring new VM...'

if ($BuildParams.Environment -like '*Dev*') {
    $VMConfig       =   @{
        Name                        =   $NewVMName
        AutomaticStartAction        =   'StartIfRunning'
        AutomaticStartDelay         =   600
        AutomaticStopAction         =   'TurnOff'
        AutomaticCheckPointsEnabled =   $false
        LockOnDisconnect            =   'On'
    }

}elseif ($BuildParams.Environment -like '*Test*') {
    $VMConfig       =   @{
        Name                        =   $NewVMName
        AutomaticStartAction        =   'Nothing'
        AutomaticStopAction         =   'TurnOff'
        AutomaticCheckPointsEnabled =   $false
        LockOnDisconnect            =   'On'
    }

}else {
    $VMConfig       =   @{
        Name                        =   $NewVMName
        AutomaticStartAction        =   'Start'
        AutomaticStartDelay         =   0
        AutomaticStopAction         =   'ShutDown'
        AutomaticCheckPointsEnabled =   $True
        CheckpointType              =   'Production'
        LockOnDisconnect            =   'On'
    }
}

try {

    Invoke-Command -Session $Global:RemoteSession -Script {
        param (
            $VMConfig
        )

        Set-VM @VMConfig

    } -ArgumentList $VMConfig

}catch {

    throw "Could not set VM configuration settings for $($VMParams.VMName) on $($VMParams.HyperVHost): $_"
}

if ($BuildInfo.Role -in ('Linux_Kube*')) {
    Write-Verbose "Adding Kubernetes NIC..."
    try {

        Invoke-Command -Session $Global:RemoteSession -Script {
            param (
                $NewVMName
            )

            Add-VMNetworkAdapter -VMName $NewVMName -SwitchName 'k8s'

        } -ArgumentList $NewVMName

    }catch {

        throw "Failed adding NIC to $($VMParams.VMName) on $($VMParams.HyperVHost): $_"
    }

    Write-Verbose "Disabling Linux SecureBoot..."
    try {

        Invoke-Command -Session $Global:RemoteSession -Script {
            param (
                $NewVMName
            )

            Set-VMFirmware -VMName $NewVMName -EnableSecureBoot Off

        } -ArgumentList $NewVMName

    }catch {

        throw "Disable SecureBoot for $($VMParams.VMName) on $($VMParams.HyperVHost): $_"
    }
}

Write-Verbose "Updating CPU settings..."
try {

    Invoke-Command -Session $Global:RemoteSession -Script {
        param (
            $VMCPU
        )

        Set-VMProcessor @VMCPU

    } -ArgumentList $VMParams.VMCPU

}catch {

    throw "Could not set CPU settings for $($VMParams.VMName) on $($VMParams.HyperVHost): $_"
}

Write-Verbose "Updating memory settings..."
try {

    Invoke-Command -Session $Global:RemoteSession -Script {
        param (
            $VMMemory
        )

        Set-VMMemory @VMMemory

    } -ArgumentList $VMParams.VMMemory

}catch {

    throw "Could not set VMMemory for $($VMParams.VMName) on $($VMParams.HyperVHost): $_"
}

# Additional/optional tasks
if ($SystemDriveSizeGB -gt 80GB) {
    Write-Verbose "Expanding OS Drive..."
    try {

        Invoke-Command -Session $Global:RemoteSession -Script {
            param (
                $DestinationVHD,
                $SystemDriveSizeGB
            )

            Resize-VHD -Path $DestinationVHD -SizeBytes $SystemDriveSizeGB

        } -ArgumentList $VMParams.DestinationVHD, $VMParams.SystemDriveSizeGB

    }catch {

        throw "Could not resize $($VMParams.DestinationVHD) on $($VMParams.HyperVHost): $_"
    }
}

# Add shared VHD Sets for cluster drives if applicable.
IF ($null -ne $VMParams.HAVHDSet) {

    foreach ($VHDSet in $VMParams.HAVHDSet) {
        Write-Output "Creating Data VHD Set..."
        Invoke-Command -Session $Global:RemoteSession -Script {
            param (
                $VHDSet
            )

            # Create the VHDSet's directory, or don't if it already exists.
            New-Item $VHDSet.Path.Substring(0,$VHDSet.Path.LastIndexof("\")) -ErrorAction SilentlyContinue

            if (Test-Path $VHDSet.Path -ErrorAction Stop) {
                # Do nothing because the set already exists.

            }else {
                Write-Output $VHDSet.Path
                New-VHD -Path $Using:VHDSet.Path -SizeBytes $Using:VHDSet.SizeBytes
            }
        }   -ArgumentList $VHDSet

        Write-Output "Adding VHD Set to VM..."
        Invoke-Command -Session $Global:RemoteSession -Script {
            param (
                $NewVMName,
                $VHDSet
            )

            Add-VMHardDiskDrive -VMName $NewVMName -Path $VHDSet.Path -ShareVirtualDisk

        } -ArgumentList $NewVMName, $VHDSet
    }
}

# Add additional VHDs
foreach ($AdditionalVHD in $VMParams.AdditionalVHD) {
    Write-Verbose "Creating Data VHD..."

    Invoke-Command -Session $Global:RemoteSession -Script {
        param (
            $AdditionalVHD
        )

        New-VHD @AdditionalVHD

    } -ArgumentList $AdditionalVHD

    Write-Verbose "Adding VHD to VM..."
    Invoke-Command -Session $Global:RemoteSession -Script {
        param (
            $NewVMName,
            $AdditionalVHD
        )

        Add-VMHardDiskDrive -VMName $NewVMName -Path $AdditionalVHD.Path

    } -ArgumentList $NewVMName, $AdditionalVHD
}

<#
    Deploy role specific software requirements. This is probably going to get unweildy at some point as we add more
    special considerations for server deployments. If it grows beyond five or so different deployments it should be
    moved out of the main Deploy-OnPremVM script and into a separate runbook for copying software to the new VM.
#>

if ($null -ne $BuildInfo.SQLVersion) {
    Write-Verbose "Mounting system drive for SQL installation"

    switch -Wildcard ($VMParams.HyperVHost) {
        "*HQ*"          { $SQLInstallPath = "B:\ISO\$($BuildInfo.SQLVersion)\*" }
        "*DC*"          { $SQLInstallPath = "B:\ISO\$($BuildInfo.SQLVersion)\*" }
    }

    Invoke-Command -Session $Global:RemoteSession -Script {
        param (
            $NewVMName,
            $SQLInstallPath,
            $SystemDrive
        )

        $MountPath = "C:\Temp\$NewVMName\mount"
        New-Item -Path $MountPath -Verbose -ItemType Directory
        Mount-WindowsImage -ImagePath $SystemDrive -Path $MountPath -Index 1

        Write-Verbose "Injecting SQL..."
        New-Item -Path "$MountPath\SQLInstaller" -ItemType Directory -Force
        Copy-Item $SQLInstallPath "$MountPath\SQLInstaller\" -Recurse -Force

        Dismount-WindowsImage -Path $Mountpath -Save
        Remove-Item $MountPath -Force -Confirm:$False

    } -ArgumentList $NewVMName, $SQLInstallPath, $VMParams.DestinationVHD
}

if ($BuildInfo.Role -Like 'Windows*') {
    # Join to domain and delete ODJ file
    $ODJRequest                 =   Get-Content "$VMConfigDir\$NewVMName\ODJ.txt"
    Remove-Item "$VMConfigDir\$NewVMName\ODJ.txt"

    Write-Verbose "Mounting OS VHD..."
    Invoke-Command -Session $Global:RemoteSession -Script {
        param ($Args)

        $MountPath = "C:\Temp\$($Using:NewVMName)\mount"
        New-Item -Path $MountPath -Verbose -ItemType Directory
        Mount-WindowsImage -ImagePath $Using:VMParams.DestinationVHD -Path $MountPath -Index 1

        Write-Verbose "Injecting offline join..."
        New-Item -Path "$MountPath\tmp" -ItemType Directory -Force
        Set-Content -Path "$MountPath\tmp\ODJ.txt" $Using:ODJRequest -Encoding unicode

        djoin.exe /REQUESTODJ /LOADFILE "$MountPath\tmp\ODJ.txt" /WINDOWSPATH "$MountPath\Windows"
        Remove-Item "$MountPath\tmp\ODJ.txt"

        Write-Verbose "Injecting DSC Metaconfig for first boot..."
        Set-Content -Path "$MountPath\Windows\System32\Configuration\MetaConfig.mof" $Using:MetaconfigMof -Encoding unicode

        Write-Verbose "Cleaning up..."
        Remove-Item "$MountPath\tmp\" -Recurse
        Dismount-WindowsImage -Path $Mountpath -Save
        Remove-Item $MountPath -Force -Confirm:$False

    } -ArgumentList $ODJRequest, $NewVMName, $VMParams.DestinationVHD, $MetaconfigMof
}

Write-Output "Initializing $NewVMName..."
if ($BuildInfo.Role -like "Linux_*") {
    Write-Output "Running Linux first boot setup..."
    try {

        $VMBootAddress  =   Invoke-Command -Session $Global:RemoteSession -Script {
            param (
                $NewVMName
            )

            Start-VM $NewVMName

            Start-Sleep 30

            try {
                $RunningVM = Get-VM $NewVMName -ErrorAction 'Stop'

            } catch {
                Start-Sleep 15

                try {
                    $RunningVM = Get-VM $NewVMName -ErrorAction 'Stop'

                } catch {

                    throw "Couldn't get running VM Info: $_"
                }
            }

            $VMBootAddress  =   ($RunningVM | Select-Object -ExpandProperty NetworkAdapters).IPAddresses[0]

            $VMBootAddress

        } -ArgumentList $NewVMName

        # Ignore ssh hostkey for initial config
        $ErrorActionPreference  =   'Continue'

        $SSHCommand     =   "sudo /root/setup.ps1 -HostName $NewVMName -IPAddress $IPAddress"
        Write-Output $SSHCommand
        Write-Warning "& ssh -o StrictHostKeyChecking=no svc_build@$VMBootAddress '$SSHCommand'"
        & ssh -o StrictHostKeyChecking=no svc_build@$VMBootAddress $SSHCommand
        $ErrorActionPreference  =   'Stop'

    }catch {

        throw "Couldn't run setup script: $_"
    }

} else {
    Write-Output 'Initializing Windows node...'
    Invoke-Command -Session $Global:RemoteSession -Script {
        param($NewVMName)

        Start-VM $NewVMName

        Start-Sleep 30

        if ((Get-VM -Name $NewVMName).State -eq 'Running') {
            try {
                Stop-VM $NewVMName

            } catch {
                Write-Output 'Could not stop machine gracefully, waiting...'
            }
        }

        $SleepCount = 0
        while ((Get-VM -Name $NewVMName).State -ne 'Off') {
            Start-Sleep 1
            $SleepCount++

            if ($SleepCount -lt 100) {
                If ((Get-VM $NewVMName).State -eq 'Stopping')  {
                    Start-Sleep 5
                }

            }else {
                try {
                    # Force it to stop
                    Stop-VM $NewVMName -ErrorAction 'Stop' -Force

                } catch {
                    # Kill it with fire
                    Stop-VM $NewVMName -ErrorAction 'Stop' -Force -TurnOff
                }
            }
        }
        Start-VM $NewVMName
    } -ArgumentList $NewVMName
}

Remove-PSSession $Global:RemoteSession

if ($BuildInfo.CustomDNSName) {
    Import-Module -Name 'DNSServer'

    try {
        $DNSRecord  =   @{
            ComputerName    =   $DomainController
            Confirm         =   $False
            CreatePtr       =   $True
            IPv4Address     =   $IPAddress
            Name            =   $BuildInfo.CustomDNSName
            ZoneName        =   $DNSDomain
        }

        Add-DnsServerResourceRecordA @DNSRecord -ErrorAction 'Stop'

    }catch {
        throw "could not $($BuildInfo.CustomDNSName).$DNSDomain DNS record: $_"
    }
}

Write-Output "Sending job complete message."
$DeploymentLogs     =   Get-Content -Path ".\$TranscriptID.txt"
Set-Content -Path "$($BuildInfo.ConfigurationDirectory)\${NewVMName}_Deployment.log" -Value $DeploymentLogs
$MailMessage    =  [ordered]@{
    To              = @($AutomationReports)
    from            =   "Deploy-OnPremVM@$DNSDomain"
    Subject         =   "Deployed $NewVMName to $HyperVServerName"
    Body            =   "Deployed $NewVMName to $HyperVServerName"
}

$RunBookParams  =   @{
    Name            =   "Send-Email"
    Parameters      =   $MailMessage
}

Start-AzAutomationRunbook @RunBookParams @CommonAzureParams

return $true