Configuration DefaultNetworking {
    param (
        [Parameter(Mandatory=$False)]
        [string]
        $PrimaryDNSServer   =   '10.10.10.53',

        [Parameter(Mandatory=$False)]
        [string]
        $SecondaryDNSServer =   '10.10.11.53',

        [Parameter(Mandatory=$False)]
        [string]
        $InterfaceAlias     =   'Ethernet'
    )

    Import-DscResource -ModuleName 'NetworkingDSC'

    Script DefaultFirewallProfiles {
        GetScript = {
            @{
                Result      =   (Get-NetFirewallProfile -All | Select-Object Name,Enabled,Default*)
            }
        }

        SetScript = {

            Set-NetFirewallProfile -All -Enabled 'True' -DefaultInboundAction 'Block' -DefaultOutboundAction 'Allow'
        }
        TestScript = {

            Get-NetFirewallProfile -All | ForEach-Object {
                if (-not($_.Enabled)) {
                    Write-Verbose "Firewall profile $($_.Name) is not Enabled"
                    return $false
                }

                if ($_.DefaultInboundAction -ne 'Block') {
                    Write-Verbose "Firewall profile $($_.Name) Default Inbound Action is not Block"
                    return $false
                }

                if ($_.DefaultOutboundAction -ne 'Allow') {
                    Write-Verbose "Firewall profile $($_.Name) Default Outbound Action is not Allow"
                    return $false

                }else {
                    return $true
                }
            }
        }
    }

    DnsClientGlobalSetting DefaultDNSClientSettings {
        IsSingleInstance    =   'Yes'
        SuffixSearchList    =   ('home.robharman.me')
    }

    DnsServerAddress DefaultPrimaryAndSecondaryDNS {
        Address             =    ($PrimaryDNSServer,$SecondaryDNSServer)
        InterfaceAlias      =    $InterfaceAlias
        AddressFamily       =    'IPv4'
    }
}