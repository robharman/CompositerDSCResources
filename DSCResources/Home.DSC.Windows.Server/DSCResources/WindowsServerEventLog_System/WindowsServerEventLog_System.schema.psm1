Configuration WindowsServerEventLog_System {
    Import-DSCResource -ModuleName 'ComputerManagementDSC'

    WindowsEventLog SystemLog {
        LogName             =   'System'
        IsEnabled           =   $true
        MaximumSizeInBytes  =   67108864
        LogMode             =   'AutoBackup'
        LogRetentionDays    =   90
    }
}