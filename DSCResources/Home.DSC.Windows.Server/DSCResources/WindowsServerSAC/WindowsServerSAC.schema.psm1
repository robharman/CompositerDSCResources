Configuration NullWindowsServerSAC {
    [CmdletBinding()]
    param (
        [Parameter()]
        [TypeName]
        $ParameterName
    )

    Import-DscResource -ModuleName 'PSDscResources'


}