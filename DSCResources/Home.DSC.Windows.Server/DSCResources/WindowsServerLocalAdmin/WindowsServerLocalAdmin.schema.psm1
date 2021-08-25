Configuration WindowsServerLocalAdmin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Owner,

        [Parameter(Mandatory)]
        [pscredential]
        $ADMgmtAccount,

        [Parameter(Mandatory)]
        [pscredential]
        $LocalAdminPassword,

        [Parameter(Mandatory=$False)]
        [AllowEmptyString()]
        [string[]]
        $LocalAdmins  =  @()
    )
    Import-DscResource -ModuleName 'PSDscResources'

    $Members                    = @('home\Domain Admins', 'HomeAdmin')

    if ($LocalAdmins.Count -gt 0) {
        $Members               +=  $LocalAdmins
    }

    Group LocalOwner {
        Ensure                  =   'Present'
        GroupName               =   'Owner'
        Members                 =   $Owner
        Description             =   'This group contains the user responsible for whatever is running on this server.'
    }

    User LocalAdminAccount {
        Ensure                  =   'Present'
        UserName                =   'HomeAdmin'
        Password                =   $LocalAdminPassword
        Description             =   'Non-Default local Admin account.'
    }

    Group LocalAdmin {
        Ensure                  =   'Present'
        GroupName               =   'Administrators'
        Members                 =   $Members
        Credential              =   $ADMgmtAccount
    }
}