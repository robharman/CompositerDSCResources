Configuration WindowsServerCore {
    # Sets default shell to PowerShell so that we don't just get dumped into a Command Prompt.

    Import-DSCResource -ModuleName PSDscResources

    Registry SetPowerShellToDefault {
        Ensure      =   'Present'
        Key         =   'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName   =   'Shell'
        ValueType   =   'String'
        ValueData   =   'PowerShell.exe -NoExit'
        Force       =   $True
    }
}