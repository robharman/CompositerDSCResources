Configuration Windows_Server {
    param (
        #Common Windows Server DSC Parametrs
        [Parameter(Mandatory)]
        [string]
        $Environment,

        [Parameter(Mandatory)]
        [string]
        $StorageRoot,

        [Parameter(Mandatory)]
        [string]
        $NodeName,

        [Parameter(Mandatory)]
        [string]
        $Owner,

        [Parameter(Mandatory)]
        [ipaddress]
        $IPAddress,

        [Parameter(Mandatory)]
        [string]
        $GatewayAddress,

        [Parameter(Mandatory)]
        [ipaddress]
        $PrimaryDNSServer,

        [Parameter(Mandatory)]
        [ipaddress]
        $SecondaryDNSServer,

        [Parameter(Mandatory)]
        [string[]]
        $AllowedAdminIPs,

        [Parameter(Mandatory)]
        [string]
        $ADMgmtAccount,

        [Parameter(Mandatory)]
        [string]
        $BackupMgmtAccount,

        [Parameter(Mandatory)]
        [string]
        $LocalAdminAccount,

        [Parameter(Mandatory=$False)]
        [string[]]
        $LocalAdmins              =   @(),

        [Parameter(Mandatory=$False)]
        [array]
        $ManagedFolders,

        [Parameter(Mandatory=$False)]
        [switch]
        $ServerCore,

        [Parameter(Mandatory = $False)]
        [array]
        $AdditionalDrives
    )

    Import-DscResource -ModuleName "Home.DSC.Windows.Common"
    Import-DscResource -ModuleName "Home.DSC.Windows.Server"

    Import-DscResource -ModuleName "ComputerManagementDsc"
    Import-DscResource -ModuleName "PSDscResources"
    Import-DscResource -ModuleName "NetworkingDSC"

    # Import credentials from Azure Automation Credential vault, configure Service Account Names, and add required
    # local admin accounts.
    Import-Module Orchestrator.AssetManagement.Cmdlets | Out-Null
    [pscredential]$ADCredentials            =   Get-AutomationPSCredential -Name $ADMgmtAccount
    [pscredential]$BackupCredentials        =   Get-AutomationPSCredential -Name $BackupMgmtAccount
    [pscredential]$LocalAdminCredentials    =   Get-AutomationPSCredential -Name $LocalAdminAccount

    $BackupMgmtAccount                      =   $BackupCredentials.UserName
    if ($LocalAdmins.Count -eq 0) {
        [string[]]$LocalAdmins              =  ($Owner, $ADCredentials.UserName)
    }else {
        $LocalAdmins                       +=  ("$Owner", "$($ADCredentials.UserName)")
    }

    # Build paths dynamically
    $HomeScripts                            =   "$StorageRoot\Scripts"
    $HomeScriptAssets                       =   "$HomeScripts\Assets"
    $HomePKI                                =   '\\home\PKI'

    node $NodeName {
        #region Windows Defaults
        DefaultEnvironment BaseConfiguration {
            Environment                     =   $Environment
            StorageRoot                     =   $StorageRoot
            HomeScripts                     =   $HomeScripts
            HomeScriptAssets                =   $HomeScriptAssets
            HomePKI                         =   $HomePKI
        }

        DefaultRegistry SetDefaultRegistry {}

        DefaultTimeZone SetTimeZoneToEST {}

        DefaultPSExecutionPolicy SetRemoteSigned {
            ExecutionPolicy                 =   "RemoteSigned"
        }

        DefaultScriptSettings SetHomeScriptsDefaultSettings {}

        DefaultCA_Root SetRootCAtoCERT00 {
            Dependson                       =   "[DefaultEnvironment]BaseConfiguration"
            HomePKI                         =   $HomePKI
        }

        DefaultCA_Enterprise SetEnterpriseCAtoCert00 {
            Dependson                       =   "[DefaultCA_Root]SetRootCAtoCERT00"
            HomePKI                         =   $HomePKI
        }

        DefaultTrustedPublishers SetTrustedPublishers {
            Dependson                       =   "[DefaultCA_Enterprise]SetEnterpriseCAtoCert00"
            HomePKI                         =   $HomePKI
        }
        #endregion Windows Defaults
        #region Windows Server Configuration
        DefaultNetworking SetDefaultNetworking {
            PrimaryDNSServer                =   $PrimaryDNSServer
            SecondaryDNSServer              =   $SecondaryDNSServer
            InterfaceAlias                  =   "Ethernet"
        }

        <# WindowsServerCommonDefaults sets the following defaults:
            WindowsServerLocale                 =   EN-CA
            WindowsServerPowerPlan              =   Performance
            WindowsServerHardening              =   MS Security Baseline
            WindowsServerEventLog_Application   =   Common settings
            WindowsServerEventLog_Security      =   Common settings
            WindowsServerEventLog_System        =   Common settings
            WindowsServerRemoteManagement       =   Enable psremoting and RDP
        #>
        WindowsServerCommonDefaults SetWindowsServerCommonDefaults {}

        WindowsServerLocalAdmin SetLocalAdmins {
            Owner                           =   $Owner
            ADMgmtAccount                   =   $ADCredentials
            LocalAdminPassword              =   $LocalAdminCredentials
            LocalAdmins                     =   $LocalAdmins
        }

        WindowsServerBackups SetBackupAccount  {
            ADMgmtAccount                   =   $ADCredentials
            BackupMgmtAccount               =   $BackupMgmtAccount
        }

        WindowsServerFirewall EnableRDPandWSManInbound {
            AllowedRanges                   =   $AllowedAdminIPs
        }

        if ($NodeName -notlike "*AZ*") {
            WindowsServerActivation ActivateWindows {}
        }

        if ($ServerCore) {
            WindowsServerCore SetServerCoreDefaults {}
        }
        #endregion Windows Server Configuration
        #region Server specific config
        NetIPInterface DisableDHCPPrimaryNIC {
            InterfaceAlias                  =   "Ethernet"
            AddressFamily                   =   "IPv4"
            DHCP                            =   "Disabled"
        }

        IPAddress SetDefaultNIC {
            IPAddress                       =   "$IPAddress/24"
            InterfaceAlias                  =   "Ethernet"
            AddressFamily                   =   "IPv4"
        }

        DefaultGatewayAddress SetDefaultGateway {
            Address                         =   $GatewayAddress
            InterfaceAlias                  =   'Ethernet'
            AddressFamily                   =   'IPv4'
        }

        DnsConnectionSuffix AddSpecificSuffix {
            InterfaceAlias                  =   'Ethernet'
            ConnectionSpecificSuffix        =   'home.RobHarman.me'
        }

        if ($AdditionalDrives.DiskID | Group-Object | Where-Object {$_.Count -gt 1}) {
            throw "Cannot set duplicate disk IDs"
        }

        foreach ($AdditionalDrive in $AdditionalDrives) {
            WindowsServerDataDrive "Add $($AddtionalDrive.DriveLetter): Drive" {
                DriveLetter                 =   $AdditionalDrive.DriveLetter
                DiskID                      =   $AdditionalDrive.DiskID
                FSLabel                     =   $AdditionalDrive.FSLabel
                EnableDedup                 =   $AdditionalDrive.EnableDedup
                OptimizeInUseFiles          =   $AdditionalDrive.OptimizeInUseFiles
                OptimizePartialFiles        =   $AdditionalDrive.OptimizePartialFiles
                MinimumFileAgeDays          =   $AdditionalDrive.MinimumFileAgeDays
            }
        }

        foreach ($ManagedFolder in $ManagedFolders) {
            WindowsServerManagedFolder $ManagedFolder.FolderPath {
                FolderPath                  =   $ManagedFolder.FolderPath
                FullControl                 =   $ManagedFolder.FullControl
                Change                      =   $ManagedFolder.Change
                Read                        =   $ManagedFolder.Read
            }
        }
        #endregion Server Specific config
        #region Remove legacy features
        WindowsServerRemoveLegacyFeatures RemoveLegacySMB {
            FeatureName                     =   "FS-SMB1"
        }

        WindowsServerRemoveLegacyFeatures RemoveLegacyPowerShell {
            FeatureName                     =   "PowerShell-V2"
        }
        #endregion
    }
}