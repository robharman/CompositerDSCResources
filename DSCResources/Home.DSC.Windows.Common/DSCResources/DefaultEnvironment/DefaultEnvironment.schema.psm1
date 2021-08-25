Configuration DefaultEnvironment {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Environment,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $StorageRoot,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $HomeScripts,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $HomeScriptAssets,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $HomePKI
    )

    Import-DscResource -ModuleName 'PSDscResources'

    Environment HomeEnvironment {
        Ensure              =   'Present'
        Name                =   'HomeEnvironment'
        Value               =   $Environment
    }

    Environment HomeStorageRoot {
        Ensure              =   'Present'
        Name                =   'HomeStorageRoot'
        Value               =   $StorageRoot
    }

    Environment HomeScripts {
        Ensure              =   'Present'
        Name                =   'HomeScripts'
        Value               =   $HomeScripts
    }

    Environment HomeScriptAssets {
        Ensure              =   'Present'
        Name                =   'HomeScriptAssets'
        Value               =   $HomeScriptAssets
    }

    Environment HomePKI {
        Ensure              =   'Present'
        Name                =   'HomePKI'
        Value               =   $HomePKI
    }
}