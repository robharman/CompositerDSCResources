Configuration DefaultCA_Enterprise {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $HomePKI
    )
    Import-DscResource -ModuleName 'CertificateDSC'

    CertificateImport CERT00-SubCA {
        Ensure              =   'Present'
        Thumbprint          =   'ENTERTHUMBPRINT'
        Location            =   'LocalMachine'
        Store               =   'CA'

        Path                =   "$HomePKI\Home-CERT00-CA.crt"
        FriendlyName        =   'Intermediate CA'
    }
}