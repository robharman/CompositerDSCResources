Configuration WindowsServerEnvVar {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $EnvVarName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $EnvVarValue
    )
    Import-DscResource -ModuleName 'PSDscResources'

    Environment "PlanEnv_$EnvVarName" {
        Ensure              =   'Present'
        Name                =   $EnvVarName
        Value               =   $EnvVarValue
    }
}