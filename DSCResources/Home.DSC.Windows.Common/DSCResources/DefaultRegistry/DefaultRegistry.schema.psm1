Configuration DefaultRegistry {
    Import-DSCResource -ModuleName 'PSDscResources'

    Registry SecureDotNetCryptox64 {
        Ensure              =   'Present'
        Key                 =   'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319'
        ValueName           =   'SchUseStrongCrypto'
        ValueData           =   '1'
    }

    Registry SecureDotNetCryptox86 {
        Ensure              =   'Present'
        Key                 =   'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319'
        ValueName           =   'SchUseStrongCrypto'
        ValueData           =   '1'
    }
}