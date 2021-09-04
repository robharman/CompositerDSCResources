Configuration WebCommon {
    Import-DSCResource -ModuleName 'PSDscResources'

    WindowsFeature Web-Server {
        Ensure  =   'Present'
        Name    =   'Web-Server'
    }

    WindowsFeature WebManagementService {
        Name    =   'Web-Mgmt-Service'
        Ensure  =   'Present'
    }

    WindowsFeature ASPNet45 {
        Name    =   'Web-Asp-Net45'
        Ensure  =   'Present'
    }

    WindowsFeature HTTPRedirection {
        Name    =   'Web-Http-Redirect'
        Ensure  =   'Present'
    }

    WindowsFeature CustomLogging {
        Name    =   'Web-Custom-Logging'
        Ensure  =   'Present'
    }

    WindowsFeature LogginTools {
        Name    =   'Web-Log-Libraries'
        Ensure  =   'Present'
    }

    WindowsFeature RequestMonitor {
        Name    =   'Web-Request-Monitor'
        Ensure  =   'Present'
    }

    WindowsFeature Tracing {
        Name    =   'Web-Http-Tracing'
        Ensure  =   'Present'
    }

    WindowsFeature BasicAuthentication {
        Name    =   'Web-Basic-Auth'
        Ensure  =   'Present'
    }

    WindowsFeature WindowsAuthentication {
        Name    =   'Web-Windows-Auth'
        Ensure  =   'Present'
    }

    WindowsFeature ApplicationInitialization {
        Name    =   'Web-AppInit'
        Ensure  =   'Present'
    }
}