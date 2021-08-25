Configuration DefaultTimeZone {

    Import-DSCResource -ModuleName 'ComputerManagementDsc'

    TimeZone DefaultTimeZone {
        TimeZone            =   'Eastern Standard Time'
        IsSingleInstance    =   'Yes'
    }
}