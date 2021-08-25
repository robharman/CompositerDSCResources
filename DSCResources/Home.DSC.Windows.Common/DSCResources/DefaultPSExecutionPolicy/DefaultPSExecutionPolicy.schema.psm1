Configuration DefaultPSExecutionPolicy {
    param
    (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ExecutionPolicy
    )

    Import-DscResource -ModuleName 'ComputerManagementDsc'

    PowerShellExecutionPolicy DefaultPSExecutionPolicy {
        ExecutionPolicyScope    =   'LocalMachine'
        ExecutionPolicy         =   $ExecutionPolicy
    }
}