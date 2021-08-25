Configuration DefaultTrustedPublishers {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $HomePKI
    )
    Import-DscResource -ModuleName 'CertificateDSC'

    # Configure Home Certificates
    CertificateImport TrustedPublisher_RobbieCrash {
        Ensure              =   'Present'
        Thumbprint          =   'THUMBPRINT'
        Location            =   'LocalMachine'
        Store               =   'TrustedPublisher'

        Path                =   "$HomePKI\CodeSigning_RobHarman.cer"
        FriendlyName        =   'Rob Code Signing'
    }

    CertificateImport TrustedPublisher_Svc_Build {
        Ensure              =   'Present'
        Thumbprint          =   'THUMBPRINT'
        Location            =   'LocalMachine'
        Store               =   'TrustedPublisher'
        Path                =   "$HomePKI\CodeSigning_Svc_Build.cer"
        FriendlyName        =   'Svc_Build Code Signing'
    }
}
