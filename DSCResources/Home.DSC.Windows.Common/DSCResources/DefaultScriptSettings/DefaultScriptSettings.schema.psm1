Configuration DefaultScriptSettings {

    Import-DSCResource -ModuleName 'PSDSCResources'

    Script CreateHomeScriptsEventLog {

        TestScript = {

            if (!([System.Diagnostics.EventLog]::Exists('HomeScripts'))) {Return $False}

            $RegisteredSources =  Get-WmiObject -Class Win32_NTEventLOgFile |
                Where-Object { $_.FileName -eq 'HomeScripts'} |  Select-Object Sources

            @('Home Scripts', 'Event Log Cleanup') | ForEach-Object {
                if ($RegisteredSources -notcontains $_) {
                    return $False
                }
            }

            return $true
        }

        GetScript = {

            try {
                @{Result    =   (Get-EventLog HomeScripts)}

            }catch {
                @{Result    =   'Not installed'}
            }
        }

        SetScript = {
            @('Home Scripts', 'Event Log Cleanup') | ForEach-Object {
                try {
                    New-EventLog -LogName 'HomeScripts' -Source $_
                }catch [InvalidOperationException]{} # Log source exists
            }
        }
    }
}