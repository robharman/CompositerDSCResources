Configuration WindowsServerRemoteManagement {
    
    Import-DscResource -ModuleName 'ComputerManagementDsc'
    Import-DscResource -ModuleName 'WSManDSC'

    RemoteDesktopAdmin EnableRemoteDesktop {
        IsSingleInstance    =   'Yes'
        Ensure              =   'Present'
        UserAuthentication  =   'Secure'
    }

    WSManListener SetRemoteListeners {
        Ensure              =   'Present'
        Transport           =   'HTTP'
        SubjectFormat       =   'Both'
        Issuer              =   'CN=Home-CERT00-CA,DC=home,DC=robbiecrash,DC=me'
    }
}