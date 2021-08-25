Configuration WindowsServerBackups {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $BackupMgmtAccount,

        [Parameter(Mandatory)]
        [pscredential]
        $ADMgmtAccount
    )
    Import-DscResource -ModuleName 'PSDscResources'

    Group Backups {
        Ensure                  =   'Present'
        GroupName               =   'Backup Operators'
        Members                 =   $BackupMgmtAccount
        Credential              =   $ADMgmtAccount
    }
}