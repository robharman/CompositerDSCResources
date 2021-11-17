Configuration DefaultTrustedPublishers {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $HomePKI
    )
    Import-DscResource -ModuleName 'CertificateDSC'

    # Configure Home Certificates
    # CertificateImport TrustedPublisher {
    #     Ensure              =   'Present'
    #     Thumbprint          =   'THUMBPRINT'
    #     Location            =   'LocalMachine'
    #     Store               =   'TrustedPublisher'

    #     Path                =   "$HomePKI\CodeSigning_RobHarman.cer"
    #     FriendlyName        =   'Rob Code Signing'
    # }
}
