configuration WindowsServerMyCertificates {
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [pscredential]
        $Credential,

        [Parameter()]
        [string]
        $NodeName,

        [Parameter(Mandatory = $False)]
        [string]
        $CustomDNSName,

        [Parameter(Mandatory = $False)]
        [switch]
        $HTTPSCert,

        [Parameter(Mandatory = $False)]
        [switch]
        $RDPCert
    )

    Import-DscResource -ModuleName CertificateDsc

    WaitForCertificateServices DCWD-Cert00 {
        CARootName                  =   'Cert00-CA'
        CAServerFQDN                =   'cert.home.robharman.me'
    }

    if ($HTTPSCert) {
        CertReq SSLCert {
            Subject                 =   "$NodeName.home.robharman.me"
            Exportable              =   $false
            CertificateTemplate     =   $CertTemplate
            SubjectAltName          =   "dns=$NodeName&dns=$NodeName.home.robharman.me&dns=$NodeName$DNSDomain"
            AutoRenew               =   $true
            FriendlyName            =   "$NodeName SSL Certificate"
            Credential              =   $Credential
            CAType                  =   "Enterprise"
            DependsOn               =   '[WaitForCertificatetServices]DCWD-Cert00'

        }
    }

    if ($RDPCert) {
        CertReq SSLCert {
            Subject                 =   "$NodeName.home.robharman.me"
            Exportable              =   $false
            CertificateTemplate     =   $CertTemplate
            SubjectAltName          =   "dns=$NodeName&dns=$NodeName.home.robharman.me"
            AutoRenew               =   $true
            FriendlyName            =   "$NodeName RDP Certificate"
            Credential              =   $Credential
            CAType                  =   "Enterprise"
            DependsOn               =   '[WaitForCertificatetServices]DCWD-Cert00'
        }
    }
}