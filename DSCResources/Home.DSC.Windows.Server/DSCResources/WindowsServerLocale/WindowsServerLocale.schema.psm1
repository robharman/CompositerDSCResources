Configuration WindowsServerLocale {
    Import-DscResource -ModuleName 'ComputerManagementDSC'

    SystemLocale SetLocaleTo_En-CA {
        IsSingleInstance = 'Yes'
        SystemLocale     = 'en-CA'
    }
}