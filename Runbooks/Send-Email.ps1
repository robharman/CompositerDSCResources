<#
.SYNOPSIS
    Azure Runbook to send email messages via on-prem server.

.DESCRIPTION
    Runs Send-MailMessage from on-prem worker to relay internal messages.

    Must be run on Hybrid Runbook worker, not on Azure.
.NOTES
    Requires:       Must be run on on-prem hybrid worker!
    Version:        1.0.0
    Author:         Rob Harman
    Written:        2021-07-01
    Version Notes:  Initial upload
    To Do:          None.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string[]]$To,
    [Parameter(Mandatory)]
    [string]$From,
    [Parameter(Mandatory)]
    [string]$Subject,
    [Parameter(Mandatory)]
    [string]$Body,
    [Parameter(Mandatory=$False)]
    [string[]]$CC       =   @(),
    [Parameter(Mandatory=$False)]
    [string[]]$BCC      =   @()
)

$MailMessage    =  @{
    To          =   $To
    from        =   $From
    Subject     =   $Subject
    Body        =   $Body
    UseSSL      =   $False
}

if ($CC) {$MailMessage.CC = $CC}
if ($BCC) {$MailMessage.CC = $BCC}

$PSEmailServer      =   'mailserveraddress'

Send-MailMessage @MailMessage