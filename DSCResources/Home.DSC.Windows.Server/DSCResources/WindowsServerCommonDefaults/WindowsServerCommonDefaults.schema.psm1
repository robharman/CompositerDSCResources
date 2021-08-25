Configuration WindowsServerCommonDefaults {
    # This resource just sets defaults so that we can cleanup configurations unless there's a reason to overide these
    # defaults.

    Import-DscResource -ModuleName 'Home.DSC.Windows.Server'

    WindowsServerLocale                 SetLocaleToEn-CA {}
    WindowsServerPowerPlan              SetHighPerformancePowerPlan {}
    WindowsServerHardening              HardenServer {}

    WindowsServerEventLog_Application   SetApplicationLogs {}
    WindowsServerEventLog_Security      SetSecurityLogs {}
    WindowsServerEventLog_System        SetSystemLogs {}

    WindowsServerRemoteManagement       EnableRDPandWSMan {}
}