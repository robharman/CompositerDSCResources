Configuration DefaultCA_Root {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $HomePKI
    )
    Import-DscResource -ModuleName 'CertificateDSC'

    # Configure $Home Certificates
    CertificateImport CERT00-RootCA {
        Ensure              =   'Present'
        Thumbprint          =   'ENTERTHUMBPRINT'
        Location            =   'LocalMachine'
        Store               =   'Root'

        Path                =   "$HomePKI\Home-CERT00-CA.crt"
        FriendlyName        =   'Home Trusted Offline Root'
    }
}
