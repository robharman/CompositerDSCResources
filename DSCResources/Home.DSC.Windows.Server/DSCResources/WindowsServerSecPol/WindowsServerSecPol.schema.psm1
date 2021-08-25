Configuration WindowsServerSecPol {
    param (
        [Parameter(Mandatory=$False)]
        [string[]]
        $ServiceAccounts        =   @(),

        [Parameter(Mandatory=$False)]
        [string[]]
        $BatchAccounts          =   @()
    )

    Import-DscResource -ModuleName SecurityPolicyDSC

    $ServiceAccounts       +=   @('NT SERVICE\ALL SERVICES')

    UserRightsAssignment LogOnAsAService {
        Policy              =   'Log_on_as_a_service'
        Identity            =   $ServiceAccounts
    }

    $BatchAccounts         += @('home\svc_automation', 'Backup Operators', 'Performance Log Users',
                                'Administrators')

    UserRightsAssignment LogOnAsABatchJob {
        Policy              =   'Log_on_as_a_batch_job'
        Identity            =   $BatchAccounts
    }
}