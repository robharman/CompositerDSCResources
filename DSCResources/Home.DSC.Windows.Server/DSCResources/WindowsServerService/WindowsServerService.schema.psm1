Configuration WindowsServerService {
    param (
        [parameter(Mandatory)]
        [string]
        $Service,

        [parameter(Mandatory)]
        [string]
        $ExecutablePath,

        [parameter(Mandatory)]
        [string]
        $DisplayName,

        [parameter(Mandatory)]
        [string]
        $Description,

        [parameter(Mandatory)]
        [pscredential]
        $ServiceAccount
    )

    Import-DscResource -ModuleName 'PSDscResources'

    Service $Service {
        Ensure          =   'Present'

        Name            =   $Service
        DisplayName     =   $DisplayName
        Description     =   $Description
        Path            =   $ExecutablePath

        Credential      =   $ServiceAccount

        StartupType     =   'Automatic'
        State           =   'Running'
    }
}