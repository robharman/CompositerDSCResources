Configuration WindowsServerFirewall {
    param (
        [Parameter(Mandatory)]
        [string[]]
        $AllowedRanges
    )
    Import-DscResource -ModuleName 'NetworkingDSC'

    Firewall AllowInboundRDP {
        Name            =   'AllowInboundRDP'
        DisplayName     =   'Allow Inbound RDP'
        Action          =   'Allow'
        Direction       =   'Inbound'
        LocalPort       =   '3389'
        Protocol        =   'TCP'
        Profile         =   'Any'
        Enabled         =   'True'
        RemoteAddress   =   $AllowedRanges
    }

    Firewall AllowInboundWSManListener {
        Name            =   'AllowinboundWSManListener'
        DisplayName     =   'Allow inbound WSMan Listener'
        Action          =   'Allow'
        Direction       =   'Inbound'
        LocalPort       =   ('5985', '5986')
        Protocol        =   'TCP'
        Profile         =   'Any'
        Enabled         =   'True'
        RemoteAddress   =   $AllowedRanges
    }

    Firewall AllowPing4 {
        Name            =   'CoreNet-Diag-ICMP4-EchoRequest-In'
        Enabled         =   'True'
    }

    Firewall AllowPing6 {
        Name            =   'CoreNet-Diag-ICMP6-EchoRequest-In'
        Enabled         =   'True'
    }
}