Configuration WebFirewall {
    param (
        [parameter(Mandatory)]
        [string[]]
        $AllowedAccessRanges,

        [Parameter(Mandatory = $False)]
        [switch]
        $AllowInsecureHTTP
    )

    Import-DscResource -ModuleName 'NetworkingDSC'

    Firewall AllowInboundHTTPS {
        Name            =   'AllowInboundHTTPS'
        DisplayName     =   'Allow Inbound HTTPS'
        Action          =   'Allow'
        Direction       =   'Inbound'
        LocalPort       =   '443'
        Protocol        =   'TCP'
        Profile         =   'Any'
        Enabled         =   'True'
        RemoteAddress   =   $AllowedAccessRanges
    }

    if ($AllowInsecureHTTP) {
        Firewall AllowInsecureHTTP {
            Name            =   'AllowInboundHTTP'
            DisplayName     =   'Allow Inbound HTTP'
            Action          =   'Allow'
            Direction       =   'Inbound'
            LocalPort       =   '80'
            Protocol        =   'TCP'
            Profile         =   'Any'
            Enabled         =   'True'
            RemoteAddress   =   $AllowedAccessRanges
        }
    }
}