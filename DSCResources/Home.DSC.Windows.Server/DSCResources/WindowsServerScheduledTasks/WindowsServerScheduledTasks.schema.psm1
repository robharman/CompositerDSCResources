Configuration WindowsServerScheduledTasks {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]
        $TaskName,

        [Parameter(Mandatory)]
        [string[]]
        $TaskPath,

        [Parameter(Mandatory)]
        [string[]]
        $Executable,

        [Parameter(Mandatory)]
        [ValidateScript({
            if (@('Once', 'Daily', 'Weekly', 'AtStartup', 'AtLogOn', 'OnEvent').Contains($_)) { return $true
            }else {
                throw "Schedlue type must be one of 'Once', 'Daily', 'Weekly', 'AtStartup', 'AtLogOn', 'OnEvent'. Not $_"
            }
        })]
        [string[]]
        $ScheduleType,

        [Parameter(Mandatory)]
        [pscredential]
        $RunAsCredentials,

        [Parameter(Mandatory=$false)]
        [string[]]
        $OpenIn                         =   (Get-Location).Path,

        [Parameter(Mandatory=$false)]
        [string[]]
        $Arguments                      =   '',

        [Parameter(Mandatory=$false)]
        [string[]]
        $RepeatInterval                 =   '00:00:00',

        [Parameter(Mandatory=$false)]
        [string[]]
        $RepititionDuration             =   '00:00:00',

        [Parameter(Mandatory=$false)]
        [string[]]
        $ExecutionTimeLimit             =   '00:00:00',

        [Parameter(Mandatory=$false)]
        [bool[]]
        $Enabled                        =   $True,

        [Parameter(Mandatory=$false)]
        [string[]]
        $RandomDelay                    =   '00:01:00',

        [Parameter(Mandatory=$false)]
        [bool[]]
        $RunOnlyIfIdle                  =   $False,

        [Parameter(Mandatory=$false)]
        [int32[]]
        $Priority                       =   9,

        [Parameter(Mandatory=$false)]
        [ValidateScript({
            if (@('Limited','Highest').Contains($_)){ return $True
            }else {
                throw "Run level must be either 'Limited' or 'Highest,' not $_"
            }
        })]
        [string[]]
        $RunLevel                       =   'Limited'

    )
    Import-DscResource -ModuleName ComputerManagementDsc

    ScheduledTask "CreateTask_$TaskName" {
        Ensure                      =   'Present'
        TaskName                    =   $TaskName
        TaskPath                    =   $TaskPath
        ActionExecutable            =   $Executable
        ActionWorkingPath           =   $OpenIn
        ActionArguments             =   $Arguments
        ExecuteAsCredential         =   $RunAsCredentials
        ScheduleType                =   $ScheduleType
        RepeatInterval              =   $RepeatInterval
        RepetitionDuration          =   $RepititionDuration
        ExecutionTimeLimit          =   $ExecutionTimeLimit
        Enable                      =   $Enabled
        RandomDelay                 =   $RandomDelay
        RunOnlyIfIdle               =   $RunOnlyIfIdle
        Priority                    =   $Priority
    }
}