configuration WindowsServerAddLegacyFeatures {
    param
    (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $FeatureName
    )
    Import-DSCResource -ModuleName 'PSDSCResources'

    WindowsFeature FeatureToAdd {
        Ensure          =   'Present'
        Name            =   $FeatureName
    }
}