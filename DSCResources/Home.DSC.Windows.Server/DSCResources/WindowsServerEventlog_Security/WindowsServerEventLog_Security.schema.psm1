Configuration WindowsServerEventLog_Security {
    Import-DSCResource -ModuleName 'ComputerManagementDSC'

    WindowsEventLog Security {
        LogName             =   'Security'
        IsEnabled           =   $true
        MaximumSizeInBytes  =   67108864
        LogMode             =   'AutoBackup'
        LogRetentionDays    =   90
    }
}