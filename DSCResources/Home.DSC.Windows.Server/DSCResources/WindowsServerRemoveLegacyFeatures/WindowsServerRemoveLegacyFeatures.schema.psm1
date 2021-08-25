configuration WindowsServerRemoveLegacyFeatures {
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $FeatureName
    )

    Import-DSCResource -ModuleName 'PSDSCResources'

    WindowsFeature FeatureToRemove {
        Ensure          =   'Absent'
        Name            =   $FeatureName
    }
}