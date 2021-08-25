Configuration WindowsServerManagedFolder {
    param (
        [Parameter(Mandatory)]
        [string]
        $FolderPath,

        [Parameter( Mandatory = $False )]
        [AllowEmptyString()]
        [string[]]
        $FullControl            =   @(),

        [Parameter( Mandatory = $False )]
        [AllowEmptyString()]
        [string[]]
        $Change                 =   @(),

        [Parameter( Mandatory = $False )]
        [AllowEmptyString()]
        [string[]]
        $Read                   =   @()
    )
    Import-DscResource -ModuleName 'ComputerManagementDSC'
    Import-DscResource -ModuleName 'FileSystemDsc'

    $FullControlAccess          = @('Administrators', 'home\Domain Admins')
    $ChangeAccess               = @()
    $ReadAccess                 = @()

    File "$FolderPath" {
        Ensure                      =   'Present'
        Type                        =   'Directory'
        DestinationPath             =   $FolderPath
    }

    # Ugly permissions setting due to limitations in Azure Automation's endless desire to deserialize nested hashtables
    # and prevent us from using a nice dictionary to do this.

    if ($FullControl.Count -gt 0) {
        $FullControlAccess     +=   $FullControl
    }

    foreach ($Identity in $FullControlAccess) {

        FileSystemAccessRule "$($Directory)_$($Identity)_FullControl" {
            Path                    =   $FolderPath
            Identity                =   $Identity
            Rights                  =   @('FullControl')
        }
    }

    if ($Change.Count -gt 0) {
        $ChangeAccess              +=   $Change
    }

    foreach ($Identity in $ChangeAccess) {

        FileSystemAccessRule "$($Directory)_$($Identity)_Change" {
            Path                    =   $FolderPath
            Identity                =   $Identity
            Rights                  =   @('Modify','DeleteSubdirectoriesAndFiles')
        }
    }

    if ($Read.Count -gt 0) {
        $ReadAccess                +=   $Read
    }

    foreach ($Identity in $ReadAccess) {
        FileSystemAccessRule "$($Directory)_$($Identity)_Read" {
            Path                    =   $FolderPath
            Identity                =   $Identity
            Rights                  =   @('ReadAndExecute')
        }
    }
}