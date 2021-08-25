Configuration WindowsCommonDefaults {
    Import-DscResource -ModuleName 'Home.DSC.Windows.Common'

    DefaultRegistry             SetDefaultRegistry      {}

    DefaultTimeZone             SetTimeZoneToEST        {}

    DefaultPSExecutionPolicy    SetRemoteSigned         {
        ExecutionPolicy     =   'RemoteSigned'
    }

    DefaultScriptSettings       SetHomeScriptsDefaults  {}

    DefaultCA_Root              SetRootCAtoCERT00       {
        HomePKI             =   '\\Home\pki'
    }

    DefaultCA_Enterprise        SetEnterpriseCAtoCert00 {
        Dependson           =   '[DefaultCA_Root]SetRootCAtoCERT00'
        HomePKI             =   '\\Home\pki'
    }

    DefaultTrustedPublishers    SetTrustedPublishers    {
        Dependson           =   '[DefaultCA_Enterprise]SetEnterpriseCAtoCert00'
        HomePKI             =   '\\Home\pki'
    }
}