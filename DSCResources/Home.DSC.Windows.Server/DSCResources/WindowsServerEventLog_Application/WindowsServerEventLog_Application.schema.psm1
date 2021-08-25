Configuration WindowsServerEventLog_Application {
    Import-DSCResource -ModuleName 'ComputerManagementDSC'

    WindowsEventLog ApplicationLog {
        LogName             =   'Application'
        IsEnabled           =   $true
        MaximumSizeInBytes  =   67108864
        LogMode             =   'AutoBackup'
        LogRetentionDays    =   90
    }
}